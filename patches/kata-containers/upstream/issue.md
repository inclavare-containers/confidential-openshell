# runtime: exec drops no_new_privileges required by agent policy

## Description of problem

The Go runtime drops `NoNewPrivileges` when converting an exec command to
`grpc.Process`. For a container with `allowPrivilegeEscalation: false`,
`genpolicy` requires this value to be `true`. The agent receives `false` and
rejects an exec probe even when its command is explicitly allowed.

We discovered this while investigating an OpenShell supervisor health probe
running on Kata / CoCo PeerPods.

## Minimal reproduction

1. Use the Kata Go runtime with QEMU and generated agent policy enforcement.
   Configure a long-running BusyBox container with an exec probe:

   ```yaml
   apiVersion: v1
   kind: Pod
   metadata:
     name: exec-nnp
   spec:
     containers:
       - name: probe
         image: quay.io/prometheus/busybox:latest
         command: [/bin/sleep, "3600"]
         securityContext:
           runAsUser: 10001
           runAsGroup: 10001
           allowPrivilegeEscalation: false
         livenessProbe:
           exec:
             command: [/bin/true]
   ```

2. Generate its policy with official `genpolicy`, using settings matching the
   runtime's guest-pull mode and OCI version. Our QEMU test used the shipped
   `10-non-coco-drop-in.json` and `20-oci-1.3.0-drop-in.json`:

   ```sh
   genpolicy -y pod.yaml -p rules.rego -j settings/
   ```

   Pass the generated `io.katacontainers.config.hypervisor.cc_init_data`
   annotation to the Pod sandbox. The policy allows `/bin/true` and requires
   `Process.NoNewPrivileges=true`.

3. Create and start the sandbox/container through CRI. Set the container's
   `linux.security_context.no_new_privs=true`, corresponding to the Pod setting
   above. Confirm the container is running and its OCI process has
   `noNewPrivileges=true`, then execute the allowed probe:

   ```sh
   crictl --config crictl.yaml exec --sync --timeout 10 "$container" /bin/true
   ```

4. Stop/remove the container and sandbox, replace the shim with the same source
   plus the fix, and repeat with the same policy, guest image, and configuration.
   Restore the original shim and repeat once more.

## Expected result

Preserve the caller's flag so the allowed probe passes the unchanged agent
policy. Preserve `false` as well.

## Actual result

Tested with Kata 4.2.0 guest/kernel/agent/genpolicy assets, QEMU/KVM, containerd
2.3.4, and crictl 1.35.0. Both the 4.2.0 Go shim and `main` at
`46c507fe445370f0728aeefbfd16c49cead0493d` produced the same results:

| Observation | Original | Fixed | Original restored |
| --- | --- | --- | --- |
| Container start | Success | Success | Success |
| Exec `NoNewPrivileges` received by agent | false | true | false |
| Allowed `/bin/true` via CRI ExecSync | Policy denial | Exit 0 | Policy denial |
| Unapproved command / exec requested as UID 0 | Deny | Deny | Deny |

The original shim returns `ExecProcessRequest is blocked by policy`. The agent
log shows policy `NoNewPrivileges=true` and request `NoNewPrivileges=false`.
Corresponding exec Process objects differ only in this field after the fix.
The same generated policy and released agent are used throughout.

## Further information

`pkg/containerd-shim-v2/exec.go` already copies the OCI process flag into
`types.Cmd`. `virtcontainers/kata_agent.go:cmdToKataProcess` omits it when
constructing `grpc.Process`. The agent's upstream `allow_process_common` rule
compares the policy and request values, causing the denial. The fix is to copy
`cmd.NoNewPrivileges` into the agent process.
