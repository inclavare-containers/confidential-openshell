# PeerPod controller deletion backport

One generic patch is applied independently to CAA v0.23.0 for the Alibaba-enabled
PeerPod manager; it does not include the CAA adapter queue. The base and result
tree are pinned in [sources.lock.json](../../deployment/build/sources.lock.json).

After an otherwise unhandled DeleteInstance failure, the patch reads the exact
instance with the same client. Only typed `InvalidInstanceId.NotFound` confirms
absence; a present instance or other read failure retains the original error.
Existing read permission is reused. Run `prepare-sources.sh peerpod-ctrl` and use
the [controller build recipe](../../docs/build.md#peerpod-controller).
