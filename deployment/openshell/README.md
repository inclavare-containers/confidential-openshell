# OpenShell configuration reference

OpenShell v0.1.3 Gateway/driver units, private driver configuration, Kubernetes
RBAC and network policies. Supervisors connect directly to the trusted Gateway
using sandbox-scoped JWTs over TLS. The Gateway authenticates operator client
certificates and rejects anonymous user requests. Operator private keys stay on
the trusted host; the driver seals launch credentials for attested guests.

Follow the [sequential deployment runbook](../../docs/deployment.md) for
installation and checks. Edit private operator copies outside
the checkout; keep credentials and runtime state out of this directory.
