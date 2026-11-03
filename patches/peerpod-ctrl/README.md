# PeerPod controller deletion protection

The [shared deletion patch](../shared/alibabacloud-retained-instance-deletion.patch)
is applied independently to CAA v0.23.0 for the Alibaba-enabled PeerPod manager;
it does not include the adapter's attachment or guest code. The base and result
tree are pinned in [sources.lock.json](../../deployment/build/sources.lock.json).

After an otherwise unhandled DeleteInstance failure, the patch reads the exact
instance with the same client. Only typed `InvalidInstanceId.NotFound` confirms
absence; a present instance or other read failure retains the original error.
Before every delete attempt, the shared guard reads the complete attached-disk
inventory and rejects unsafe retention settings or a security operation lock.
Unknown or incomplete inventory fails closed. A finalizer regression verifies
that failure retains the PeerPod and a successful retry completes deletion.
The deployed controller role requires `DescribeDisks` as well as exact-instance
reads and scoped deletion. Run `prepare-sources.sh peerpod-ctrl` and use
the [controller build recipe](../../docs/build.md#peerpod-controller).
