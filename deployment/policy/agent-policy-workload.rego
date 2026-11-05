# CAA replaces PVC shared-folder mounts with measured guest cloud volumes.
CLOUD_VOLUMES_KEY = "io.confidentialcontainers.org.cloud_volumes"
WORKSPACE_MOUNTS = __WORKSPACE_MOUNTS__

workspace_mount_destination(destination) if {
    some container
    destination in WORKSPACE_MOUNTS[container]
}

workspace_cloud_volume(encoded, destination) := volumes[name] if {
    volumes := json.unmarshal(encoded)
    some name
    volumes[name].mount_point == destination
    object.get(volumes[name], "fs_group", "") == "__WORKLOAD_FSGROUP__"
}

workspace_cloud_mount(container_name, p_mount) if {
    p_mount.destination in WORKSPACE_MOUNTS[container_name]
    p_mount.type_ == "bind"
}

allow_anno_key_value(i_key, i_value, p_container) if {
    i_key == CLOUD_VOLUMES_KEY
    some p_mount in p_container.OCI.Mounts
    workspace_cloud_mount(p_container.OCI.Annotations["io.kubernetes.cri.container-name"], p_mount)
    workspace_cloud_volume(i_value, p_mount.destination)
}

check_mount(p_mount, i_mount, bundle_id, sandbox_id) if {
    workspace_cloud_mount(input.OCI.Annotations["io.kubernetes.cri.container-name"], p_mount)
    i_mount.destination == p_mount.destination
    i_mount.type_ == p_mount.type_
    i_mount.options == p_mount.options
    encoded := input.OCI.Annotations[CLOUD_VOLUMES_KEY]
    volumes := json.unmarshal(encoded)
    some name, volume in volumes
    volume == workspace_cloud_volume(encoded, p_mount.destination)
    volume.readonly == ("ro" in p_mount.options)
    i_mount.source == concat("", ["/run/cloud-volumes/", volume.disk_id])
}
