# PeerPod controller patch selection

The controller is part of CAA. Its independent queue references these CAA patches:

1. [Exact absence](../cloud-api-adaptor/generic/0004-alibabacloud-confirm-delete-absence.patch): preserve deletion errors unless an exact typed read confirms absence.
2. [Deletion completion](../cloud-api-adaptor/generic/0009-alibabacloud-delete-completion.patch): reconcile accepted or ambiguous deletion with bounded waiting and retries.
3. [Retained-disk guard](../cloud-api-adaptor/provider/0001-alibabacloud-retained-delete-guard.patch): check retention attributes and security locks before every deletion attempt.

The first two are independently useful without disk support. The third supplies
ordinary retained-disk protection and needs `ecs:DescribeDisks`. Finalizer tests
verify that failures retain the PeerPod and a later successful retry completes it.
Attachment, retained-disk release waiting and guest encryption are outside this
controller queue.

The exact base/result tree is in
[sources.lock.json](../../deployment/build/sources.lock.json). Use
`prepare-sources.sh peerpod-ctrl` and the
[controller build recipe](../../docs/build.md#peerpod-controller).
