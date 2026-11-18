# OpenShell configuration reference

OpenShell v0.1.9 Gateway/driver units, private driver configuration, Kubernetes
RBAC and network policies. Supervisors connect directly to the trusted Gateway
using sandbox-scoped JWTs over TLS. The Gateway authenticates operator client
certificates and rejects anonymous user requests. Operator private keys stay on
the trusted host; the driver seals launch credentials for attested guests.

The external driver is registered as `confidential` in both the Gateway unit
(`--compute-driver confidential`) and its configuration
(`[openshell.drivers.confidential]`). Its backend still uses Kubernetes. When
upgrading an installation registered as `kubernetes`, rename that driver table
and the `compute_driver` setting together, preserving any custom admission
settings, and install the updated unit. Existing sandbox annotations retain
the driver name recorded at their last start; the next native Stop/Start updates
`internal.openshell.ai/compute-driver` to `confidential`. Do not rewrite the
Gateway database to change this display. After upgrading the gateway and driver, set
`enable_sandbox_updates = true` in `[openshell.gateway]` of the installed
`/etc/openshell-confidential/gateway.toml` and restart the gateway.

Follow the [sequential deployment runbook](../../docs/deployment.md) for
installation and checks. Edit private operator copies outside
the checkout; keep credentials and runtime state out of this directory.

When upgrading from the namespace-wide ingress policy, stop existing sandboxes
and the driver, then remove only the previous managed fences before restarting:

```sh
kubectl -n openshell delete networkpolicy confidential-ingress-default-deny --ignore-not-found
kubectl -n openshell delete networkpolicy -l openshell.ai/managed-by=openshell,openshell.ai/component=sandbox-supervisor-egress
```

The driver recreates supervisor egress policies with upstream behavior on the
next sandbox start. Workload and control-connection policies remain managed
by the driver.
