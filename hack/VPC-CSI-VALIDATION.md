# VPC CSI tool validation — 11 November 2026

Branches start from current canonical upstream main:
- k8s.io `81b3fe050e5b3ee17c1f8b99d28edbc1780b055f`.
- provider-ibmcloud-test-infra `2d237aa9bc53609ca2262123d0e1f199170b50ba`.

## Terraform

Terraform 1.13.4, IBM provider 1.82.1 (time 0.13.1, null 3.2.4).
Both roots passed formatting/schema validation and isolated plans, including
fully refreshed cloud reads. Source roots were copied to a private scratch
location; only the scratch backend was changed from COS to local, and existing
state snapshots were copied privately. No remote lock/write or apply occurred.
Do not publish raw state/plan/logs: they can contain credential payloads.

| Root | Managed resources considered | Imports | Adds/updates/deletes/replacements |
|---|---:|---:|---:|
| build cluster | 48 | 22 | 0 |
| dedicated CSI identity | 4 | 0 | 0 |

Imports cover ten tier disks, one explicitly separate worker-3 legacy GP disk,
and their eleven existing attachments. All sixteen existing VSI resources and
all other managed build resources remain no-op. Wrong-account negative validation
rejected all sixteen instance preconditions. Imports were planned, not applied;
the production backend still needs separately authorized state adoption later.

## Kubernetes and host checks

- Full kube-system Kustomization renders 26 resources. It includes exactly one
  non-default Retain/WFFC/expansion-enabled StorageClass and no static Secret.
- Declared controller, node DaemonSet and reload CronJob Pod templates match
  live GETs; declared selectors/strategy/replicas also match. No adoption-driven
  rollout is required by those templates. Generated reload ConfigMap name/data
  match the existing object.
- ApplicationSet template rendered for s390x, ppc64le and a non-IBM cluster:
  only s390x gets the exact credential-annotation ignores/sync option; others
  receive an empty object patch.
- Three credential-reloader unit tests passed without a cluster.
- Eighteen provider safety unit tests passed without a cluster. Tests include
  GET-only defaults, identity/UID/concurrency guards, runtime-root overrides,
  disk identity/fstab checks and resource retention after a failed explicit run.
- New node-preparation tool ran in default check mode against production:
  ten workers checked, zero labels needing changes, no patch requests.
- New host preflight ran through existing authorized host namespaces on all ten
  workers: all passed attachment serial/UUID, mount, fstab and active containerd
  root checks. No scripts/files/Pods were installed on the nodes.
- Existing 20GiB and 10GiB proof claims remain Bound/Retain with matching cloud
  volume handles. Existing files were read without rewriting them; the 20GiB
  mounted filesystem was 20,974,882,816 bytes. No new PVC test was created.
- CSI remained healthy: ten of ten node agents and one controller replica Ready.
  Existing CSI workload UIDs are unchanged. The existing automatic credential
  reloader changed only its hash annotation at 12:05 UTC; the controller/node
  generations advanced as expected. No rotation/restart was forced by validation.
- All sixteen persistent VSI IDs and previously attached volume IDs still exist.
  The four production COS state serials (267/30/36/1) and object modification
  times are unchanged. No resources were destroyed, detached, formatted or moved.
- Existing monitoring values/ApplicationSet are unchanged from upstream.

## Limits and activation

These are local checks and authenticated read-only comparisons, not a newly
published Prow run. No Terraform import/apply, GitOps sync, label apply, fresh
storage write/reattach/resize, forced credential rotation or cleanup was run.
The safety guards have fixture coverage. A fresh cloud write/reattachment/resize
lifecycle still needs an explicitly authorized isolated test-cluster run if
reviewers require that evidence. Prior production qualification is separate.

Merging the active kube-system Kustomization inclusion enables Argo reconciliation.
Review the generated Argo diff/ownership and staging-image policy before merge.
The deployment/StorageClass/CSIDriver/ExternalSecret use pruning confirmation.
Existing canary/proof resources are excluded. Do not delete the CSI path as a
rollback. Terraform state adoption is a separate operator action, with a fresh
reviewed import-only plan. Existing account/state/inventory must be rechecked.
