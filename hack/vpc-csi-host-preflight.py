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

"""Read-only verification of an existing worker's static runtime disk.

Run on the intended worker with trusted Terraform output as --storage-inventory.
No mount, format, service operation, package installation or Kubernetes mutation
is performed. A passing result does not itself enable CSI placement.
"""

import argparse
import ast
import json
from pathlib import Path
import re
import subprocess
import sys


def runtime_root(argv, config):
    for i, arg in enumerate(argv):
        if arg == "--root" and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith("--root="):
            return arg.split("=", 1)[1]
    top = config.split("\n[")[0]
    match = re.search(r"(?m)^\s*root\s*=\s*([\"'].+?[\"'])\s*$", top)
    return ast.literal_eval(match[1]) if match else "/var/lib/containerd"


def verify_storage(expected, actual):
    failures = []
    root, mount, uuid = (expected[k] for k in ("containerd_root", "mount_path", "filesystem_uuid"))
    if len(actual["containerd_roots"]) != 1 or actual["containerd_roots"][0] != root:
        failures.append("running containerd root does not match inventory")
    if actual["mount"].get("target") != mount or actual["mount"].get("uuid") != uuid:
        failures.append("runtime disk is not mounted at the expected path/UUID")
    if actual["mount"].get("fstype") != "ext4":
        failures.append("expected the existing ext4 filesystem")
    matches = [b for b in actual["blockdevices"] if b.get("uuid") == uuid]
    if len(matches) != 1 or not matches[0].get("serial") or not expected["attachment_id"].startswith(matches[0]["serial"]):
        failures.append("host disk serial/UUID does not match cloud attachment")
    if not any(f[0] == "UUID=" + uuid and f[1] == mount and f[2] == "ext4" and
               "noauto" not in f[3].split(",") for f in actual["fstab"]):
        failures.append("expected persistent UUID mount is missing from fstab")
    if not root.startswith(mount + "/"):
        failures.append("expected containerd root is outside the configured disk")
    return failures


def collect(expected):
    def read_json(*argv):
        result = subprocess.run(argv, check=True, capture_output=True, text=True)
        return json.loads(result.stdout)

    roots = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if (proc / "comm").read_text().strip() != "containerd":
                continue
            argv = (proc / "cmdline").read_bytes().decode().strip("\0").split("\0")
            config_path = "/etc/containerd/config.toml"
            for i, arg in enumerate(argv):
                if arg in ("--config", "-c") and i + 1 < len(argv):
                    config_path = argv[i + 1]
                elif arg.startswith("--config="):
                    config_path = arg.split("=", 1)[1]
            path = Path(config_path)
            roots.append(runtime_root(argv, path.read_text() if path.exists() else ""))
        except FileNotFoundError:
            continue  # Process exited during the read.
    devices = read_json("lsblk", "-J", "-o", "NAME,UUID,SERIAL")["blockdevices"]
    def flatten(devices):
        return [b for d in devices for b in [d, *flatten(d.get("children", []))]]
    fstab = [line.split() for line in Path("/etc/fstab").read_text().splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    mount = read_json("findmnt", "-J", "-T", expected["containerd_root"],
                      "-o", "TARGET,SOURCE,FSTYPE,UUID")["filesystems"][0]
    return {"containerd_roots": roots, "mount": mount, "blockdevices": flatten(devices),
            "fstab": [f[:4] for f in fstab if len(f) >= 4]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True)
    parser.add_argument("--storage-inventory", required=True, type=Path,
                        help="terraform output -json worker_data_storage (not a full state file)")
    args = parser.parse_args()
    inventory = json.loads(args.storage_inventory.read_text())
    matches = [d for d in inventory.values() if d["node_name"] == args.node and d.get("containerd_root")]
    if len(matches) != 1:
        raise ValueError("Expected exactly one static containerd disk for this worker")
    expected = matches[0]
    actual = collect(expected)
    failures = verify_storage(expected, actual)
    print(json.dumps({"node": args.node, "mode": "read-only", "ready": not failures,
                      "failures": failures, "containerd_roots": actual["containerd_roots"],
                      "mount": actual["mount"], "volume_id": expected["volume_id"]}))
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"VPC CSI host preflight failed: {error}", file=sys.stderr)
        sys.exit(1)
