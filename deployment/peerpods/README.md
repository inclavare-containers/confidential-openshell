# PeerPods configuration

CAA/CSI/Kata Helm values and RuntimeClass settings for the confidential cluster.
Use the [deployment runbook](../../docs/deployment.md) for installation and
[build preparation](../../docs/build.md#peerpod-controller) for controller packaging.
Keep private values, credentials and runtime state outside the checkout.

The PeerPod manager needs the Alibaba Cloud backend. Its official runtime supplies
the CA bundle; [Dockerfile.controller](Dockerfile.controller) replaces only
`/manager`. `images.peerpod_ctrl_runtime` in the [runtime lock](../runtime/artifacts.lock.json)
is the base image; `build_outputs.peerpod_ctrl` records the built output. Set
`resourceCtrl.image` to the digest published in your trusted registry. Fresh
builds must record their own binary/archive/image hashes.

The controller's [independent backport](../../patches/peerpod-ctrl/README.md) confirms
absence after an otherwise unhandled DeleteInstance failure. Only a same-client,
exact-ID read returning typed `InvalidInstanceId.NotFound` converts that failure
to success; other results preserve the delete error. It reuses existing read
permission. Provider initialization also requires `vpc:DescribeVSwitchAttributes`
scoped to the configured vSwitch. The controller queue is separate from the CAA
adapter queue.
