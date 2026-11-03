# PeerPod controller patch selection

The PeerPod controller is part of the CAA repository. Its independent build uses
two patches from `../cloud-api-adaptor/`, in this order:

1. [generic/0003: confirm instance absence](../cloud-api-adaptor/generic/0003-alibabacloud-confirm-delete-absence.patch)
   fixes the existing instance-deletion path. It can be applied without disk
   support and does not require `DescribeDisks`.
2. [provider/0002: protect retained disks](../cloud-api-adaptor/provider/0002-alibabacloud-retained-delete-guard.patch)
   adds the retained-volume safety profile. This is ordinary retained-disk provider support, independent of the
   confidential-volume metadata and encryption contract.

The queue does not include the adapter's attachment or guest code. The base and
result tree are pinned in [sources.lock.json](../../deployment/build/sources.lock.json).

After an otherwise unhandled DeleteInstance failure, the patch reads the exact
instance with the same client. Only typed `InvalidInstanceId.NotFound` confirms
absence; a present instance or other read failure retains the original error.
Before every delete attempt, the retained-volume guard reads the complete attached-disk
inventory and rejects unsafe retention settings or a security operation lock.
Unknown or incomplete inventory fails closed. A finalizer regression verifies
that failure retains the PeerPod and a successful retry completes deletion.
The deployed controller role requires `DescribeDisks` as well as exact-instance
reads and scoped deletion. Run `prepare-sources.sh peerpod-ctrl` and use
the [controller build recipe](../../docs/build.md#peerpod-controller).
