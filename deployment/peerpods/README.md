# PeerPods configuration

CAA/CSI/Kata Helm values and RuntimeClass settings for the confidential cluster.
Use the [deployment runbook](../../docs/deployment.md) for installation and
[build preparation](../../docs/build.md#peerpod-controller) for controller packaging.
Keep private values, credentials and runtime state outside the checkout.

Deployment images are pulled anonymously, like public images. Do not configure
registry usernames/passwords, Pod or ServiceAccount `imagePullSecrets`, or guest
registry credentials for this profile. The deployment registry already permits
anonymous pulls. HTTPS server certificate verification and digest-pinned image
references remain enabled; the registry CA supplies trust without authenticating
the client.

The PeerPod manager needs the Alibaba Cloud backend. Its official runtime supplies
the CA bundle; the build overlays only `/manager` using `crane append`. `images.peerpod_ctrl_runtime` in the [runtime lock](../runtime/artifacts.lock.json)
is the base image; `build.peerpod_ctrl` supplies the local repository and tag. Set
`resourceCtrl.image` to the digest published in your trusted registry. Fresh
builds must record their own binary/archive/image hashes.

The controller's [CAA patch selection](../../patches/peerpod-ctrl/README.md) confirms
absence after an otherwise unhandled DeleteInstance failure. Only a same-client,
exact-ID read returning typed `InvalidInstanceId.NotFound` converts that failure
to success; other results preserve the delete error. This generic fix reuses
existing read permission. A separate retained-volume patch checks attached disks
and security locks before deletion, requiring `ecs:DescribeDisks` as well.
Provider initialization also requires `vpc:DescribeVSwitchAttributes`
scoped to the configured vSwitch. The controller queue is separate from the CAA
adapter queue.
