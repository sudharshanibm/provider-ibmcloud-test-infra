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

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


def load(filename):
    spec = importlib.util.spec_from_file_location(filename.replace("-", "_"), Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


storage = load("validate-vpc-csi-storage.py")
host = load("vpc-csi-host-preflight.py")


class RetainedStorageValidation(unittest.TestCase):
    def test_existing_mode_performs_only_reads(self):
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            args = argv[4:]
            if args[:2] == ["config", "view"]:
                value = {"clusters": [{"cluster": {"server": "https://test:6443"}}]}
            elif args[:2] == ["get", "storageclass"]:
                value = {"provisioner": "vpc.block.csi.ibm.io", "volumeBindingMode": "WaitForFirstConsumer"}
            elif args[:2] == ["get", "pvc"]:
                value = {"metadata": {"name": "data", "uid": "claim-uid"}, "spec": {"volumeName": "pv-1", "storageClassName": "retain"}, "status": {"phase": "Bound", "capacity": {"storage": "20Gi"}}}
            elif args[:2] == ["get", "pv"]:
                value = {"metadata": {"name": "pv-1"}, "spec": {"claimRef": {"namespace": "vpc-csi-validation-test", "name": "data", "uid": "claim-uid"}, "csi": {"driver": "vpc.block.csi.ibm.io", "volumeHandle": "vol-1"}, "persistentVolumeReclaimPolicy": "Retain"}}
            else:
                raise AssertionError("Unexpected non-read command")
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(value))
        with tempfile.TemporaryDirectory() as tmp:
            result = Path(tmp) / "result.json"
            argv = ["validator", "--kubeconfig", "/unused/test", "--expected-server", "https://test:6443", "--namespace", "vpc-csi-validation-test", "--storage-class", "retain", "--result-path", str(result)]
            with patch.object(sys, "argv", argv), patch.object(storage.subprocess, "run", side_effect=run):
                storage.main()
            evidence = json.loads(result.read_text())
            self.assertEqual(evidence["mode"], "read-only")
            self.assertEqual(result.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(calls), 4)

    def test_failed_run_retains_resources_by_default(self):
        calls = []
        owned_namespace = {}
        def run(argv, **kwargs):
            calls.append(argv)
            args = argv[4:]
            if args[:2] == ["config", "view"]:
                value = {"clusters": [{"cluster": {"server": "https://test"}}]}
            elif args[:2] == ["get", "storageclass"]:
                value = {"provisioner": "vpc.block.csi.ibm.io", "volumeBindingMode": "WaitForFirstConsumer", "reclaimPolicy": "Retain", "allowVolumeExpansion": True}
            elif args[:2] == ["get", "node"]:
                value = {"metadata": {"labels": {"storage.ibmcloud.k8s.io/vpc-csi-ready": "true", "topology.kubernetes.io/zone": "eu-de-1"}}, "status": {"nodeInfo": {"architecture": "s390x"}}}
            elif args[:2] == ["get", "namespace"]:
                value = owned_namespace
            elif args[:2] == ["create", "-f"]:
                body = json.loads(kwargs["input"])
                if body["kind"] == "Namespace":
                    owned_namespace.update(body)
                    owned_namespace["metadata"]["uid"] = "owned-uid"
                if body["kind"] == "Pod":
                    raise subprocess.CalledProcessError(1, argv, stderr="simulated consumer failure")
                value = {"metadata": {"uid": "owned-uid"}}
            else:
                raise AssertionError("Unexpected cleanup operation: " + str(args))
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(value))
        with tempfile.TemporaryDirectory() as tmp:
            result = Path(tmp) / "retained.json"
            argv = ["validator", "--kubeconfig", "/unused/test", "--expected-server", "https://test", "--namespace", "vpc-csi-validation-test", "--storage-class", "retain", "--result-path", str(result), "--run", "--first-node", "worker-1", "--second-node", "worker-2"]
            with patch.object(sys, "argv", argv), patch.object(storage.subprocess, "run", side_effect=run), self.assertRaises(subprocess.CalledProcessError):
                storage.main()
            evidence = json.loads(result.read_text())
            self.assertEqual(evidence["status"], "failed")
            self.assertEqual(evidence["cleanup"], "retained (default)")
        self.assertFalse(any(c[4] in ("delete", "patch") for c in calls))

    def test_cleanup_requires_explicit_run(self):
        argv = ["validator", "--kubeconfig", "unused", "--expected-server", "https://test", "--namespace", "vpc-csi-validation-test", "--storage-class", "retain", "--result-path", "unused", "--cleanup"]
        with patch.object(sys, "argv", argv), self.assertRaises(SystemExit), patch.object(storage.subprocess, "run") as run:
            storage.main()
        run.assert_not_called()

    def test_cleanup_refuses_replaced_or_unowned_namespace(self):
        namespace = {"metadata": {"uid": "original", "labels": {"storage.ibmcloud.k8s.io/validation-run": "run-1"}}}
        self.assertTrue(storage.cleanup_allowed(namespace, "original", "run-1"))
        self.assertFalse(storage.cleanup_allowed(namespace, "new-uid", "run-1"))
        self.assertFalse(storage.cleanup_allowed(namespace, "original", "another-run"))

    def test_rejects_volume_claim_uid_mismatch(self):
        claim = {"metadata": {"name": "data", "uid": "original"}}
        pv = {"spec": {"claimRef": {"name": "data", "uid": "other", "namespace": "test"}, "csi": {"driver": "vpc.block.csi.ibm.io"}}}
        with self.assertRaisesRegex(ValueError, "expected VPC CSI claim"):
            storage.verify_claim_volume(claim, pv, "test")


class HostStorageValidation(unittest.TestCase):
    def setUp(self):
        self.expected = {"containerd_root": "/mnt/tier/containerd", "mount_path": "/mnt/tier", "filesystem_uuid": "disk-uuid", "attachment_id": "attachment-full-id"}
        self.actual = {"containerd_roots": ["/mnt/tier/containerd"], "mount": {"target": "/mnt/tier", "uuid": "disk-uuid", "fstype": "ext4"}, "blockdevices": [{"uuid": "disk-uuid", "serial": "attachment"}], "fstab": [["UUID=disk-uuid", "/mnt/tier", "ext4", "defaults"]]}

    def test_command_line_root_takes_precedence_over_config(self):
        self.assertEqual(host.runtime_root(["containerd", "--root", "/mnt/tier/containerd"], "root = '/var/lib/containerd'"), "/mnt/tier/containerd")
        self.assertEqual(host.runtime_root(["containerd", "--root=/mnt/tier/containerd"], ""), "/mnt/tier/containerd")
        self.assertEqual(host.runtime_root(["containerd"], "root = '/custom'"), "/custom")

    def test_validates_existing_disk_without_mutation(self):
        self.assertEqual(host.verify_storage(self.expected, self.actual), [])

    def test_refuses_boot_disk_fallback_wrong_serial_and_missing_fstab(self):
        for field in ["mount", "blockdevices", "fstab", "containerd_roots"]:
            actual = copy.deepcopy(self.actual)
            actual[field] = {} if field == "mount" else []
            self.assertTrue(host.verify_storage(self.expected, actual))


if __name__ == "__main__":
    unittest.main()
