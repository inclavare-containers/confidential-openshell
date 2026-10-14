# runtime: preserve no_new_privileges in exec requests

An allowed exec probe is rejected by the agent policy when its container uses
`allowPrivilegeEscalation: false`: the generated policy requires
`NoNewPrivileges=true`, but `cmdToKataProcess` drops the flag and sends `false`.
We discovered this while investigating an OpenShell supervisor health probe
running on Kata / CoCo PeerPods.

Copy `cmd.NoNewPrivileges` into `grpc.Process`. The shim already obtains this
value from the OCI exec process; this preserves both true and false without
changing the agent or policy rules.

## Validation

Reproduced through CRI ExecSync with a long-running BusyBox container running
as UID/GID 10001, `allowPrivilegeEscalation=false`, and a genpolicy-approved
`/bin/true` probe. Used QEMU/KVM, released Kata 4.2.0 guest/agent/genpolicy
assets, and containerd 2.3.4. Tested both the 4.2.0 shim and the PR base
`46c507fe445370f0728aeefbfd16c49cead0493d`, each as original → fixed → original.
Only the shim changed; the generated policy, guest, and configuration stayed
fixed, and each container started successfully before exec.

| Check | Original | Fixed | Original restored |
| --- | --- | --- | --- |
| Agent receives `NoNewPrivileges` | false | true | false |
| Allowed `/bin/true` probe | Policy denial | Exit 0 | Policy denial |
| Unapproved command / UID 0 | Deny | Deny | Deny |

Agent input logs confirm that corresponding Process objects differ only in
`NoNewPrivileges`. The original denial is `ExecProcessRequest is blocked by policy`.

The existing `TestCmdToKataProcess` now covers false and true; the true assertion
fails without the fix and passes with it. Targeted tests,
`go vet ./virtcontainers`, gofmt, and the official static Go shim build passed on the
PR base with Go 1.26.8.

Fixes: #14024
