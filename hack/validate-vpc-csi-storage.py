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

"""Read existing VPC CSI PVC evidence; --run explicitly creates a retained test.

--cleanup additionally permits deleting only this invocation's test resources.
Without --run the tool performs GETs only, plus optional read-only Pod exec.
"""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import time
import uuid

IMAGE = ("docker.io/library/python:3.13-alpine@sha256:"
         "2d9aefe2fef018a7eb2c13064c89c71929800fd2e5dccdbf52ea5da5bb8d929a")


def write_evidence(path, evidence):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")


def verify_claim_volume(claim, pv, namespace):
    ref = pv["spec"].get("claimRef", {})
    if (ref.get("uid") != claim["metadata"]["uid"] or
            ref.get("namespace") != namespace or
            ref.get("name") != claim["metadata"]["name"] or
            pv["spec"].get("csi", {}).get("driver") != "vpc.block.csi.ibm.io"):
        raise ValueError("PV does not belong to the expected VPC CSI claim")


def cleanup_allowed(namespace, expected_uid, run_id):
    return (namespace["metadata"]["uid"] == expected_uid and
            namespace["metadata"].get("labels", {}).get("storage.ibmcloud.k8s.io/validation-run") == run_id)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("kubeconfig", "expected-server", "namespace", "storage-class",
                 "result-path"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--run", action="store_true", help="Create a dedicated storage test; resources are retained by default")
    parser.add_argument("--cleanup", action="store_true", help="With --run, delete only this invocation's owned test resources")
    parser.add_argument("--first-node")
    parser.add_argument("--second-node")
    parser.add_argument("--existing-pvc", default="data")
    parser.add_argument("--existing-pod", help="Optional existing Python consumer; read /data/probe and filesystem size")
    parser.add_argument("--probe-file", default="/data/probe", help="Existing proof file under /data; read-only mode only")
    args = parser.parse_args()
    if not args.probe_file.startswith("/data/") or ".." in PurePosixPath(args.probe_file).parts:
        parser.error("--probe-file must be beneath /data")
    if args.cleanup and not args.run:
        parser.error("--cleanup requires --run")
    if args.run and not (args.first_node and args.second_node):
        parser.error("--run requires --first-node and --second-node")
    if not args.namespace.startswith("vpc-csi-validation-"):
        parser.error("Use a new namespace beginning vpc-csi-validation-")
    if args.run and args.first_node == args.second_node:
        parser.error("Reattachment requires two different nodes")
    result_path = Path(args.result_path)
    if result_path.exists():
        parser.error("result-path already exists")
    prefix = ["kubectl", "--kubeconfig", args.kubeconfig, "--request-timeout=30s"]

    def command(*argv, obj=None, expect_json=True):
        cmd = [*prefix, *argv]
        if expect_json:
            cmd += ["-o", "json"]
        proc = subprocess.run(cmd, input=json.dumps(obj) if obj else None,
                              capture_output=True, text=True, check=True)
        return json.loads(proc.stdout) if expect_json else proc.stdout.strip()

    config = command("config", "view", "--minify")
    if config["clusters"][0]["cluster"]["server"] != args.expected_server:
        raise ValueError("Unexpected Kubernetes API server")
    sc = command("get", "storageclass", args.storage_class)
    if (sc["provisioner"] != "vpc.block.csi.ibm.io" or
            sc.get("volumeBindingMode") != "WaitForFirstConsumer"):
        raise ValueError("Expected a VPC CSI StorageClass with delayed binding")
    if not args.run:
        claim = command("get", "pvc", args.existing_pvc, "-n", args.namespace)
        if claim.get("status", {}).get("phase") != "Bound" or claim["spec"].get("storageClassName") != args.storage_class:
            raise ValueError("Expected a Bound claim using the requested StorageClass")
        pv = command("get", "pv", claim["spec"]["volumeName"])
        verify_claim_volume(claim, pv, args.namespace)
        evidence = {"mode": "read-only", "server": args.expected_server, "namespace": args.namespace,
                    "pvc": args.existing_pvc, "pv": pv["metadata"]["name"],
                    "volume_handle": pv["spec"]["csi"]["volumeHandle"],
                    "capacity": claim["status"].get("capacity"), "reclaim_policy": pv["spec"]["persistentVolumeReclaimPolicy"],
                    "status": "passed", "cleanup": "not requested"}
        if args.existing_pod:
            pod = command("get", "pod", args.existing_pod, "-n", args.namespace)
            volumes = {v["name"] for v in pod["spec"].get("volumes", [])
                       if v.get("persistentVolumeClaim", {}).get("claimName") == args.existing_pvc}
            containers = [c["name"] for c in pod["spec"]["containers"]
                          if any(v["name"] in volumes and v["mountPath"] == "/data" for v in c.get("volumeMounts", []))]
            if len(containers) != 1:
                raise ValueError("Expected exactly one consumer mounting this PVC at /data")
            evidence["filesystem"] = json.loads(command(
                "exec", "-n", args.namespace, args.existing_pod, "-c", containers[0], "--", "python3", "-c",
                f"import hashlib,json,os,pathlib; p=pathlib.Path({args.probe_file!r}); s=os.statvfs('/data'); "
                "print(json.dumps({'probe_exists':p.is_file(),'filesystem_bytes':s.f_blocks*s.f_frsize,"
                "'probe_sha256':hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None}))",
                expect_json=False))
            if not evidence["filesystem"]["probe_exists"]:
                raise ValueError("Expected retained test probe file is absent")
        write_evidence(result_path, evidence)
        print(json.dumps(evidence))
        return
    if sc.get("reclaimPolicy") != "Retain" or not sc.get("allowVolumeExpansion"):
        raise ValueError("The test requires a Retain StorageClass with expansion enabled")
    zones = set()
    for name in (args.first_node, args.second_node):
        node = command("get", "node", name)
        labels = node["metadata"].get("labels", {})
        if (node["status"]["nodeInfo"]["architecture"] != "s390x" or
                labels.get("storage.ibmcloud.k8s.io/vpc-csi-ready") != "true" or
                node.get("spec", {}).get("unschedulable", False)):
            raise ValueError(f"{name}: node is not enabled and schedulable")
        zones.add(labels.get("topology.kubernetes.io/zone"))
    if None in zones or len(zones) != 1:
        raise ValueError("Both nodes must have the same verified VPC zone")

    evidence = {"server": args.expected_server, "namespace": args.namespace,
                "storage_class": args.storage_class, "checks": []}
    claim_uid = None
    pv_name = None
    namespace_created = False
    namespace_uid = None
    run_id = str(uuid.uuid4())
    expected = str(uuid.uuid4())

    def check(name):
        evidence["checks"].append(name)
        print(name, flush=True)

    def consumer(node, initialize=False):
        # A replacement consumer must only read. Recreating a missing file
        # would conceal data loss during detach/reattach.
        action = ("assert not p.exists(); p.write_text(expected); " if initialize
                  else "assert p.is_file(), 'persistent file disappeared'; ")
        script = ("from pathlib import Path, PurePosixPath; import time; "
                  "p=Path('/data/probe'); "
                  f"expected={expected!r}; " + action +
                  "assert p.read_text()==expected; "
                  "print('persistent write/read passed', flush=True); "
                  "time.sleep(3600)")
        pod = {"apiVersion": "v1", "kind": "Pod",
               "metadata": {"name": "consumer", "namespace": args.namespace},
               "spec": {"restartPolicy": "Never",
                        "nodeSelector": {"kubernetes.io/hostname": node},
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000,
                                            "runAsGroup": 2000, "fsGroup": 2000,
                                            "seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [{"name": "consumer", "image": IMAGE,
                                        "command": ["python3", "-u", "-c", script],
                                        "securityContext": {"allowPrivilegeEscalation": False,
                                                            "readOnlyRootFilesystem": True,
                                                            "capabilities": {"drop": ["ALL"]}},
                                        "resources": {"requests": {"cpu": "10m", "memory": "32Mi"},
                                                      "limits": {"cpu": "100m", "memory": "64Mi"}},
                                        "volumeMounts": [{"name": "data", "mountPath": "/data"}]}],
                        "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "data"}}]}}
        namespace = command("get", "namespace", args.namespace)
        if not cleanup_allowed(namespace, namespace_uid, run_id):
            raise ValueError("Refusing consumer creation: namespace ownership changed")
        created = command("create", "-f", "-", obj=pod)
        command("wait", "-n", args.namespace, "--for=condition=Ready", "pod/consumer",
                "--timeout=600s", expect_json=False)
        actual = command("exec", "-n", args.namespace, "consumer", "--", "python3", "-c",
                         "from pathlib import Path, PurePosixPath; print(Path('/data/probe').read_text())",
                         expect_json=False)
        if actual != expected:
            raise ValueError("Persistent data does not match the first write")
        return created["metadata"]["uid"]

    try:
        created_namespace = command("create", "-f", "-", obj={"apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": args.namespace, "labels": {"storage.ibmcloud.k8s.io/validation-run": run_id}}})
        namespace_uid = created_namespace["metadata"]["uid"]
        namespace_created = True
        pvc = {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
               "metadata": {"name": "data", "namespace": args.namespace},
               "spec": {"storageClassName": args.storage_class,
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {"requests": {"storage": "10Gi"}}}}
        claim_uid = command("create", "-f", "-", obj=pvc)["metadata"]["uid"]
        consumer_uid = consumer(args.first_node, initialize=True)
        claim = command("get", "pvc", "data", "-n", args.namespace)
        if claim["status"]["phase"] != "Bound" or claim["metadata"]["uid"] != claim_uid:
            raise ValueError("Expected the original PVC to be Bound")
        pv_name = claim["spec"]["volumeName"]
        pv = command("get", "pv", pv_name)
        evidence["volume_handle"] = pv["spec"]["csi"]["volumeHandle"]
        evidence["pv"] = pv_name
        check("PVC Bound; non-root filesystem write/read passed")
        command("delete", "--raw", "/api/v1/namespaces/" + args.namespace + "/pods/consumer", "-f", "-",
                obj={"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": consumer_uid}},
                expect_json=False)
        command("wait", "-n", args.namespace, "--for=delete", "pod/consumer", "--timeout=120s", expect_json=False)
        consumer(args.second_node)
        check("Data persisted after detach/reattach on a different node")
        command("patch", "pvc", "data", "-n", args.namespace, "--type=json", "-p", json.dumps([
            {"op": "test", "path": "/metadata/uid", "value": claim_uid},
            {"op": "replace", "path": "/spec/resources/requests/storage", "value": "20Gi"}]))
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            claim = command("get", "pvc", "data", "-n", args.namespace)
            if claim.get("status", {}).get("capacity", {}).get("storage") == "20Gi":
                break
            time.sleep(5)
        else:
            raise TimeoutError("PVC filesystem expansion did not finish")
        size = int(command("exec", "-n", args.namespace, "consumer", "--", "python3", "-c",
                           "import os; s=os.statvfs('/data'); print(s.f_blocks*s.f_frsize)",
                           expect_json=False))
        if size < 18 * 1024 ** 3:
            raise ValueError("PVC reports 20Gi but the mounted filesystem did not grow")
        evidence["filesystem_bytes"] = size
        check("Online PVC expansion from 10Gi to 20Gi passed")
        evidence["status"] = "passed"
    except Exception as error:
        evidence["status"] = "failed"
        evidence["error"] = str(error)
        raise
    finally:
        evidence["cleanup"] = "retained (default)"
        if args.cleanup and namespace_created:
            try:
                if namespace_created:
                    namespace = command("get", "namespace", args.namespace)
                    if not cleanup_allowed(namespace, namespace_uid, run_id):
                        raise ValueError("Refusing cleanup: namespace ownership changed")
                if claim_uid:
                    claim = command("get", "pvc", "data", "-n", args.namespace)
                    if claim["metadata"]["uid"] != claim_uid:
                        raise ValueError("Refusing cleanup: claim UID changed")
                    pv_name = claim.get("spec", {}).get("volumeName")
                    if pv_name:
                        pv = command("get", "pv", pv_name)
                        verify_claim_volume(claim, pv, args.namespace)
                        command("patch", "pv", pv_name, "--type=json", "-p", json.dumps([
                            {"op": "test", "path": "/metadata/uid", "value": pv["metadata"]["uid"]},
                            {"op": "test", "path": "/metadata/resourceVersion", "value": pv["metadata"]["resourceVersion"]},
                            {"op": "replace", "path": "/spec/persistentVolumeReclaimPolicy", "value": "Delete"}]))
                if namespace_created:
                    # UID precondition prevents deleting a replacement namespace.
                    command("delete", "--raw", "/api/v1/namespaces/" + args.namespace, "-f", "-",
                        obj={"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": namespace_uid}},
                        expect_json=False)
                if pv_name:
                    command("wait", "--for=delete", "pv/" + pv_name, "--timeout=300s", expect_json=False)
                evidence["cleanup"] = "completed"
            except Exception as error:
                evidence["cleanup"] = "failed: " + str(error)
        write_evidence(result_path, evidence)
        if evidence["cleanup"].startswith("failed:"):
            raise RuntimeError(evidence["cleanup"])


if __name__ == "__main__":
    main()
