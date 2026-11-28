# Clovisor beside Agent Substrate's egress gateway

Clovisor as the additional `ext_proc` of Substrate's egress gateway
(milestone 7.4). Substrate verifies each Actor and applies its
`EgressPolicy`. Clovisor then decides each request Substrate allowed
against the Actor's profile, narrates its refusals, and keeps each
Actor's timeline.

- `clovisor.yaml`: namespace, ServiceAccount, Service and Deployment
  (`${CLOVISOR_IMAGE}` is substituted when applied).
- `Dockerfile`: built by `make substrate-image`.
- `policy/`: a profile and ceiling for Substrate's egress demo, loaded
  from the `clovisor-policy` ConfigMap.
- `ate-setup-hook-attributes.patch`: Substrate's `ate-setup` (at
  7319f1af), patched so the hook also sends the address the Actor
  dialed. Without it, Clovisor refuses every request.

Install and operation are in `docs/operator-guide.md`, "Beside
Substrate's egress gateway". The end-to-end check is `make substrate-e2e`
(`integration/substrate/e2e.sh`).
