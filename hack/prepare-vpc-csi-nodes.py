#!/usr/bin/env python3
# Copyright 2026 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Check VPC worker identities, then optionally apply CSI metadata labels.

Without --apply or --server-dry-run, only Kubernetes GETs are performed. This tool
never enables driver placement, changes providerID, or touches disks/services.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def metadata_labels(item):
    return {
        "ibm-cloud.kubernetes.io/worker-id": item["instance_id"],
        "ibm-cloud.kubernetes.io/vpc-instance-id": item["instance_id"],
        "ibm-cloud.kubernetes.io/machine-type": "upi",
        "failure-domain.beta.kubernetes.io/region": item["region"],
        "failure-domain.beta.kubernetes.io/zone": item["zone"],
        "topology.kubernetes.io/region": item["region"],
        "topology.kubernetes.io/zone": item["zone"],
    }


def make_plan(inventory, nodes):
    if not isinstance(inventory, dict) or not inventory:
        raise ValueError("Inventory must be a nonempty node-name-to-metadata object")
    by_name = {node["metadata"]["name"]: node for node in nodes}
    instance_ids, addresses, plan = set(), set(), []
    for name, item in sorted(inventory.items()):
        if not isinstance(item, dict):
            raise ValueError(f"{name}: expected a metadata object")
        for key in ("instance_id", "region", "zone", "internal_ip"):
            if not isinstance(item.get(key), str) or not item[key]:
                raise ValueError(f"{name}: missing {key}")
        if not re.fullmatch(r"[a-z0-9-]+_[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", item["instance_id"]):
            raise ValueError(f"{name}: invalid VPC instance ID")
        ipaddress.ip_address(item["internal_ip"])
        if not re.fullmatch(r"[a-z]{2}-[a-z]+", item["region"]) or not re.fullmatch(
                re.escape(item["region"]) + r"-[0-9]+", item["zone"]):
            raise ValueError(f"{name}: zone does not belong to region")
        if item["instance_id"] in instance_ids:
            raise ValueError("Inventory maps multiple nodes to the same instance")
        if item["internal_ip"] in addresses:
            raise ValueError("Inventory maps multiple nodes to the same InternalIP")
        instance_ids.add(item["instance_id"])
        addresses.add(item["internal_ip"])
        if name not in by_name:
            raise ValueError(f"{name}: node does not exist")
        node = by_name[name]
        ips = {a["address"] for a in node["status"]["addresses"] if a["type"] == "InternalIP"}
        if item["internal_ip"] not in ips:
            raise ValueError(f"{name}: VPC InternalIP does not match Kubernetes")
        if node["status"]["nodeInfo"]["architecture"] != "s390x":
            raise ValueError(f"{name}: expected an s390x node")
        labels = node["metadata"].get("labels", {})
        if any(k in labels for k in ("node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master")):
            raise ValueError(f"{name}: control-plane nodes are excluded")
        if not any(c["type"] == "Ready" and c["status"] == "True"
                   for c in node["status"].get("conditions", [])):
            raise ValueError(f"{name}: node is not Ready")
        desired = metadata_labels(item)
        conflicts = [key for key, value in desired.items() if key in labels and labels[key] != value]
        if conflicts:
            raise ValueError(f"{name}: existing CSI labels conflict: {conflicts}")
        if any(labels.get(key) != value for key, value in desired.items()):
            plan.append({"name": name, "uid": node["metadata"]["uid"],
                         "before": {key: labels.get(key) for key in desired}, "after": desired})
    return plan


def json_patch(entry, current, rollback=False):
    """Use optimistic concurrency, preserving every unrelated label."""
    if current["metadata"]["uid"] != entry["uid"]:
        raise ValueError(f"{entry['name']}: node UID changed; refusing patch")
    labels = current["metadata"].get("labels", {})
    # Only change labels that this invocation planned to add/change.
    changes = {k: v for k, v in entry["after"].items() if entry["before"][k] != v}
    expected = entry["after"] if rollback else entry["before"]
    for key, value in changes.items():
        observed = labels.get(key)
        if observed != expected[key] and not (not rollback and observed == value):
            raise ValueError(f"{entry['name']}: concurrent CSI label conflict: {key}")
    result = [
        {"op": "test", "path": "/metadata/uid", "value": entry["uid"]},
        {"op": "test", "path": "/metadata/resourceVersion", "value": current["metadata"]["resourceVersion"]},
    ]
    if "labels" not in current["metadata"]:
        result.append({"op": "add", "path": "/metadata/labels", "value": {}})
    for key, value in changes.items():
        desired = entry["before"][key] if rollback else value
        if labels.get(key) == desired:
            continue
        path = "/metadata/labels/" + key.replace("~", "~0").replace("/", "~1")
        result.append({"op": "remove", "path": path} if desired is None else
                      {"op": "add", "path": path, "value": desired})
    return result


def patch_with_retry(kubectl, entry, dry_run=False, rollback=False):
    for attempt in range(3):
        current = kubectl("get", "node", entry["name"], "-o", "json")
        patch = json_patch(entry, current, rollback)
        if len(patch) == 2:
            return
        argv = ["patch", "node", entry["name"], "--type=json", "-p", json.dumps(patch), "-o", "json"]
        if dry_run:
            argv.append("--dry-run=server")
        try:
            kubectl(*argv)
            return
        except subprocess.CalledProcessError as error:
            message = error.stderr or ""
            if attempt == 2 or not any(s in message.lower() for s in ("conflict", "test failed", "test operation")):
                raise


def write_private(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(value, f, indent=2)
        f.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True, type=Path)
    parser.add_argument("--expected-server", required=True)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--server-dry-run", action="store_true")
    parser.add_argument("--backup-file", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if not args.kubeconfig.is_file():
        parser.error("kubeconfig does not exist")
    if args.apply and not args.backup_file:
        parser.error("--apply requires a new --backup-file")
    for path in (args.backup_file, args.report):
        if path and path.exists():
            parser.error(f"Refusing to overwrite {path}")

    def kubectl(*argv):
        result = subprocess.run(
            ["kubectl", "--kubeconfig", str(args.kubeconfig), "--request-timeout=30s", *argv],
            check=True, capture_output=True, text=True)
        return json.loads(result.stdout)

    config = kubectl("config", "view", "--minify", "-o", "json")
    server = config["clusters"][0]["cluster"]["server"]
    if server != args.expected_server:
        raise ValueError("Kubeconfig API server does not match --expected-server")
    nodes = kubectl("get", "nodes", "-o", "json")["items"]
    plan = make_plan(json.loads(args.inventory.read_text()), nodes)
    if args.apply or args.server_dry_run:
        for entry in plan:
            patch_with_retry(kubectl, entry, dry_run=True)
    report = {"server": server, "mode": "apply" if args.apply else "check",
              "nodes_checked": len(json.loads(args.inventory.read_text())),
              "nodes_requiring_labels": [e["name"] for e in plan]}
    print(json.dumps(report))
    if args.report:
        write_private(args.report, report)
    if not args.apply or not plan:
        return
    write_private(args.backup_file, {"server": server, "plan": plan})
    applied = []
    try:
        for entry in plan:
            # Include the current entry in rollback if a timeout leaves its result ambiguous.
            applied.append(entry)
            patch_with_retry(kubectl, entry)
    except Exception:
        for entry in reversed(applied):
            try:
                patch_with_retry(kubectl, entry, rollback=True)
            except (ValueError, subprocess.CalledProcessError):
                print(f"{entry['name']}: rollback not completed; inspect backup", file=sys.stderr)
        raise


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"VPC CSI node preparation failed: {error}", file=sys.stderr)
        sys.exit(1)
