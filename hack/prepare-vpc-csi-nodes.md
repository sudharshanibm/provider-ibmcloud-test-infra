# VPC CSI preparation on existing s390x workers

These opt-in tools support existing self-managed VPC clusters. They do not run
kubeadm, provision VSIs, install/upgrade the runtime/network, change providerID,
format/mount disks, or install the driver. PowerVS behavior/defaults are unchanged.
The cluster driver/StorageClass/credentials are owned by k8s.io GitOps/Terraform.

Requires Python 3 and kubectl on the operator machine, an explicit kubeconfig,
trusted inventory and the intended API server. Use current provider main's
API-key-file flags for any separate kubetest2 workflow; do not place cloud keys
in these inventories. Keep production and disposable test-cluster state separate.

## Identity check (GETs only by default)

Obtain a node-name mapping from k8s.io's `worker_csi_metadata` output:

```json
{"worker-s390x-1":{"instance_id":"02b7_11111111-1111-1111-1111-111111111111","internal_ip":"10.0.0.1","region":"eu-de","zone":"eu-de-1"}}
```

```sh
python3 hack/prepare-vpc-csi-nodes.py \
  --kubeconfig /secure/test.kubeconfig \
  --expected-server https://TEST-API-SERVER:6443 \
  --inventory /secure/worker-csi-metadata.json \
  --report /secure/new-node-check.json
```

The tool checks exact name/InternalIP/instance mapping, architecture, region/zone,
readiness and conflicting existing CSI labels; control-plane nodes are excluded.
Its default performs GETs only. `--server-dry-run` additionally checks patches
without persistence. A separately requested label change requires
`--apply --backup-file /secure/new-label-backup.json`; all patches are dry-run
checked first. Backups/reports must be new files and are mode 0600.

Patches test node UID/resourceVersion, retry concurrent version changes with
reread/revalidation, and preserve unrelated labels/taints/providerID. Rollback
only touches this invocation's changed labels when identity/current values still
match; otherwise inspect the backup. A timeout after a write has an ambiguous
result and also enters guarded rollback. An already-prepared cluster is a no-op.

## Existing host disk preflight

Export `worker_data_storage` from k8s.io (only that non-secret output, not raw
state). Run on the intended worker using existing authorized SSH/exec access:

```sh
python3 vpc-csi-host-preflight.py \
  --node worker-s390x-1 --storage-inventory /secure/worker-data-storage.json
```

The script reads the running containerd command line (which overrides config),
findmnt, lsblk serial/UUID and fstab. It verifies the existing ext4 disk and mount
against the cloud attachment identity without changing anything. Use the host's
mount/PID namespaces when invoking through an existing privileged container; do
not create a diagnostic Pod just to run this check.

All production workers currently use their tier disk for containerd. Worker 5's
root is `/mnt/s390x-infra-tier10/containerd`; other workers use
`/mnt/s390x-tier10-workerN/containerd`. Preserve these and their UUIDs. The
ordinary `/var/lib/containerd` path alone does not establish the active root.
Device letters are not stable identifiers. Do not rerun the general runtime role
or format an existing disk to make preflight pass.

Before separately enabling placement, also verify kubelet root/device mounts,
node-driver image architecture/tools and topology/CSI registration. The metadata
script deliberately does **not** add `storage.ibmcloud.k8s.io/vpc-csi-ready=true`.
Operator opt-in is separate, after those checks. Existing ready labels are
preserved; preparation does not restart the driver.

## Read existing PVC evidence (default)

```sh
python3 hack/validate-vpc-csi-storage.py \
  --kubeconfig /secure/test.kubeconfig \
  --expected-server https://TEST-API-SERVER:6443 \
  --namespace vpc-csi-validation-existing --storage-class ibmc-vpc-block-retain-general-purpose \
  --existing-pvc data --result-path /secure/new-pvc-evidence.json
```

This verifies Bound claim/StorageClass, PV claim UID/driver/volume handle and
records evidence with no mutation. With a Python consumer already mounting the
claim at `/data`, add `--existing-pod consumer --probe-file /data/probe` to read the
proof hash and filesystem size. The file must already exist; the tool never
recreates it to conceal data loss. Consumers without Python can be inspected
separately with a read-only command such as `cat`.

## Explicit storage test (test cluster first)

Add `--run --first-node worker-1 --second-node worker-2`, using a unique new
namespace/result path. This explicitly creates a 10Gi PVC and a non-root consumer,
checks data after same-zone reattachment on the second worker, and expands the
claim/filesystem to 20Gi. It deletes/recreates its own consumer for reattachment,
but **retains namespace, PVC, PV and disk by default**, including after failure.
Read/write/reattach/resize require a separately authorized run; no such run is
performed by unit tests or the default CLI.

Only `--run --cleanup` enables deletion of this invocation's owned test namespace
and disk. It validates namespace run label/UID, claim UID, PV identity and driver,
then explicitly changes only its test PV to Delete. Namespace deletion uses a UID
precondition. Cleanup can fail safely under concurrent changes: inspect evidence;
never force-delete unrelated/finalized resources. Do not use cleanup on production
proof PVCs. The shared StorageClass is never modified.

Run fixture-only safety checks with `make verify-vpc-csi-tools`. No cloud keys or
cluster are needed. Validated on the production s390x cluster using read-only
checks only; see `hack/VPC-CSI-VALIDATION.md` for results and limits.
