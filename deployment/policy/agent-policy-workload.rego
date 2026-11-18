# CAA describes guest-mounted workspace disks in this runtime annotation.
allow_anno_key_value(i_key, i_value, p_container) if {
    i_key == "io.confidentialcontainers.org.cloud_volumes"
    name := p_container.OCI.Annotations["io.kubernetes.cri.container-name"]
    approved := policy_data.workspace_mounts[name]
    volumes := json.unmarshal(i_value)
    count(volumes) > 0
    every _, volume in volumes {
        approved[volume.mount_point] == volume.disk_id
    }
}
