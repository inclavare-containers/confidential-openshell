# Kata 4.2's stock allow_storage(image_guest_pull) validates mount shape but
# leaves source and driver_options unconstrained. Bind the requested guest
# image to the digest-pinned image in this measured, per-Pod policy.

openshell_guest_pull(p_oci, i_storages) if {
    p_oci.Annotations["io.kubernetes.cri.container-type"] == "sandbox"
    p_oci.Annotations["io.katacontainers.pkg.oci.container_type"] == "pod_sandbox"
    count([storage | storage := i_storages[_]; storage.driver == "image_guest_pull"]) == 1
    storage := i_storages[_]
    storage.driver == "image_guest_pull"
    storage.source == "pause"
    openshell_pull_metadata(storage, p_oci)
}

openshell_guest_pull(p_oci, i_storages) if {
    p_oci.Annotations["io.kubernetes.cri.container-type"] == "container"
    p_oci.Annotations["io.katacontainers.pkg.oci.container_type"] == "pod_container"
    count([storage | storage := i_storages[_]; storage.driver == "image_guest_pull"]) == 1
    image := p_oci.Annotations["io.kubernetes.cri.image-name"]
    regex.match("^[a-z0-9._:/-]+@sha256:[a-f0-9]{64}$", image)
    storage := i_storages[_]
    storage.driver == "image_guest_pull"
    storage.source == image
    openshell_pull_metadata(storage, p_oci)
}

openshell_pull_metadata(storage, p_oci) if {
    count(storage.driver_options) == 1
    option := storage.driver_options[0]
    startswith(option, "image_guest_pull=")
    pull := json.unmarshal(trim_prefix(option, "image_guest_pull="))
    count(pull) == 1
    metadata := pull.metadata
    is_object(metadata)
    metadata["io.kubernetes.cri.container-type"] == p_oci.Annotations["io.kubernetes.cri.container-type"]
    metadata["io.katacontainers.pkg.oci.container_type"] == p_oci.Annotations["io.katacontainers.pkg.oci.container_type"]
    image := p_oci.Annotations["io.kubernetes.cri.image-name"]
    metadata["io.kubernetes.cri.image-name"] == image
}

openshell_pull_metadata(storage, p_oci) if {
    count(storage.driver_options) == 1
    option := storage.driver_options[0]
    startswith(option, "image_guest_pull=")
    pull := json.unmarshal(trim_prefix(option, "image_guest_pull="))
    count(pull) == 1
    metadata := pull.metadata
    is_object(metadata)
    p_oci.Annotations["io.kubernetes.cri.container-type"] == "sandbox"
    metadata["io.kubernetes.cri.container-type"] == "sandbox"
    metadata["io.katacontainers.pkg.oci.container_type"] == "pod_sandbox"
}
