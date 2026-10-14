# Extra rules for CAA's one retained workspace disk. Kata genpolicy models
# the Kubernetes PVC as a shared folder; CAA substitutes a guest-local bind
# mount after it has validated and attached the corresponding cloud disk.

CLOUD_VOLUMES_KEY = "io.confidentialcontainers.org.cloud_volumes"
CLOUD_VOLUME_SOURCE = "/run/cloud-volumes/vol-0"

workspace_cloud_volume(encoded, destination) := volume if {
    count(encoded) <= 512
    volumes := json.unmarshal(encoded)
    count(volumes) == 1
    volume := volumes["vol-0"]
    count(volume) == 6
    volume.mount_point == destination
    volume.fs_type == "ext4"
    volume.lun == "0"
    regex.match("^d-[A-Za-z0-9]+$", volume.disk_id)
    count(volume.disk_id) <= 128
    volume.readonly == false
    volume.fs_group == "__WORKLOAD_FSGROUP__"
}

workspace_cloud_mount(container_name, p_mount) if {
    container_name == "agent"
    p_mount.destination == "/sandbox"
    p_mount.source == "$(sfprefix)sandbox$"
    p_mount.type_ == "bind"
    p_mount.options == ["rbind", "rprivate", "rw"]
}

# workspace-init mounts the same retained PVC at its staging path. CAA's APF
# changes only this known mount source after validating the one disk descriptor.
workspace_cloud_mount(container_name, p_mount) if {
    container_name == "workspace-init"
    p_mount.destination == "/mnt/openshell-workspace"
    p_mount.source == "$(sfprefix)openshell\\-workspace$"
    p_mount.type_ == "bind"
    p_mount.options == ["rbind", "rprivate", "rw"]
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
    i_mount.source == CLOUD_VOLUME_SOURCE
    i_mount.type_ == p_mount.type_
    i_mount.options == p_mount.options
    encoded := input.OCI.Annotations[CLOUD_VOLUMES_KEY]
    workspace_cloud_volume(encoded, p_mount.destination)
}
