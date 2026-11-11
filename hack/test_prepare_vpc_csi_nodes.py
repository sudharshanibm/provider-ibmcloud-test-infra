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
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "prepare_nodes", Path(__file__).with_name("prepare-vpc-csi-nodes.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class InventoryValidation(unittest.TestCase):
    def setUp(self):
        self.inventory = {"worker-1": {
            "instance_id": "02b7_11111111-1111-1111-1111-111111111111",
            "region": "eu-de", "zone": "eu-de-1", "internal_ip": "10.0.0.1"}}
        self.node = {"metadata": {"name": "worker-1", "uid": "node-uid", "resourceVersion": "10"},
                     "status": {"addresses": [{"type": "InternalIP", "address": "10.0.0.1"}],
                                "nodeInfo": {"architecture": "s390x"},
                                "conditions": [{"type": "Ready", "status": "True"}]}}

    def test_rejects_wrong_node_ip(self):
        self.inventory["worker-1"]["internal_ip"] = "10.0.0.2"
        with self.assertRaisesRegex(ValueError, "InternalIP"):
            module.make_plan(self.inventory, [self.node])

    def test_rejects_existing_identity_conflict(self):
        self.node["metadata"]["labels"] = {
            "ibm-cloud.kubernetes.io/vpc-instance-id": "another-instance"}
        with self.assertRaisesRegex(ValueError, "conflict"):
            module.make_plan(self.inventory, [self.node])

    def test_rejects_reused_instance_id(self):
        self.inventory["worker-2"] = copy.deepcopy(self.inventory["worker-1"])
        node2 = copy.deepcopy(self.node)
        node2["metadata"]["name"] = "worker-2"
        with self.assertRaisesRegex(ValueError, "same instance"):
            module.make_plan(self.inventory, [self.node, node2])

    def test_preserves_unrelated_labels_and_is_idempotent(self):
        self.node["metadata"]["labels"] = {"unrelated": "preserve"}
        original = copy.deepcopy(self.node)
        plan = module.make_plan(self.inventory, [self.node])
        self.assertEqual(self.node, original)
        self.assertEqual(len(plan[0]["after"]), 7)
        self.node["metadata"]["labels"].update(plan[0]["after"])
        self.assertEqual(module.make_plan(self.inventory, [self.node]), [])

    def test_rejects_not_ready_and_control_plane(self):
        self.node["status"]["conditions"] = []
        with self.assertRaisesRegex(ValueError, "not Ready"):
            module.make_plan(self.inventory, [self.node])
        self.node["metadata"]["labels"] = {"node-role.kubernetes.io/control-plane": ""}
        with self.assertRaisesRegex(ValueError, "control-plane"):
            module.make_plan(self.inventory, [self.node])

    def test_rejects_zone_region_mismatch(self):
        self.inventory["worker-1"]["zone"] = "eu-gb-1"
        with self.assertRaisesRegex(ValueError, "zone"):
            module.make_plan(self.inventory, [self.node])

    def test_uid_guard_and_only_owned_labels_are_patched(self):
        self.node["metadata"]["labels"] = {"other": "keep"}
        entry = module.make_plan(self.inventory, [self.node])[0]
        patch = module.json_patch(entry, self.node)
        self.assertEqual(patch[0], {"op": "test", "path": "/metadata/uid", "value": "node-uid"})
        self.assertEqual(patch[1]["path"], "/metadata/resourceVersion")
        self.assertFalse(any(x["path"].endswith("/other") for x in patch))
        self.node["metadata"]["uid"] = "replacement"
        with self.assertRaisesRegex(ValueError, "UID changed"):
            module.json_patch(entry, self.node)

    def test_refuses_rollback_if_another_operator_changed_an_owned_label(self):
        entry = module.make_plan(self.inventory, [self.node])[0]
        self.node["metadata"]["labels"] = dict(entry["after"])
        self.node["metadata"]["labels"]["ibm-cloud.kubernetes.io/worker-id"] = "changed"
        with self.assertRaisesRegex(ValueError, "conflict"):
            module.json_patch(entry, self.node, rollback=True)

    def test_default_cli_checks_plan_without_patch_requests(self):
        import json
        import subprocess
        import sys
        import tempfile
        from unittest.mock import patch
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            if argv[4:6] == ["config", "view"]:
                value = {"clusters": [{"cluster": {"server": "https://test"}}]}
            elif argv[4:6] == ["get", "nodes"]:
                value = {"items": [self.node]}
            else:
                raise AssertionError("Default mode must not patch")
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(value))
        with tempfile.TemporaryDirectory() as tmp:
            kubeconfig = Path(tmp) / "config"
            kubeconfig.touch()
            inventory = Path(tmp) / "inventory.json"
            inventory.write_text(json.dumps(self.inventory))
            argv = ["prepare", "--kubeconfig", str(kubeconfig), "--expected-server", "https://test", "--inventory", str(inventory)]
            with patch.object(sys, "argv", argv), patch.object(module.subprocess, "run", side_effect=run):
                module.main()
        self.assertEqual(len(calls), 2)

    def test_retries_version_conflict_after_reread(self):
        import subprocess
        entry = module.make_plan(self.inventory, [self.node])[0]
        calls = []
        def kubectl(*args):
            calls.append(args)
            if args[0] == "get":
                node = copy.deepcopy(self.node)
                node["metadata"]["resourceVersion"] = str(len(calls))
                return node
            if len(calls) == 2:
                raise subprocess.CalledProcessError(1, "kubectl", stderr="Conflict: test failed")
            return {}
        module.patch_with_retry(kubectl, entry)
        self.assertEqual([c[0] for c in calls], ["get", "patch", "get", "patch"])
        import json
        self.assertEqual(json.loads(calls[-1][calls[-1].index("-p") + 1])[1]["value"], "3")


if __name__ == "__main__":
    unittest.main()
