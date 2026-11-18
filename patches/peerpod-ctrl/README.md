# PeerPod controller patch selection

The controller is part of CAA. Its independent queue applies the
[exact-absence error-handling fix](../cloud-api-adaptor/generic/0002-alibabacloud-confirm-delete-absence.patch):
preserve deletion errors unless a typed response confirms that the target instance
does not exist, and handle non-SDK errors without a type-assertion panic.

Attachment and guest encryption are outside this controller queue.

The exact base/result tree is in
[sources.lock.json](../../deployment/build/sources.lock.json). Use
`prepare-sources.sh peerpod-ctrl` and the
[controller build recipe](../../docs/build.md#peerpod-controller).
