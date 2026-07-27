# 1. Purpose & scope

`mcp-sso` is a spec-correct **OAuth 2.1 layer for remote MCP servers** with
two halves, in one framework-free core:

- a **resource-server verifier** — RFC 9728 Protected Resource Metadata (PRM),
  `WWW-Authenticate` challenges, fail-closed audience validation, scope step-up; and
- a small **AS-lite bridge** — RFC 7591 Dynamic Client Registration (DCR),
  authorization-code + PKCE S256, consent, refresh rotation with replay detection,
  revocation, JWKS, and RFC 8414/9728 metadata.

The bridge mints its **own audience-bound tokens**. An upstream identity provider
(Cloudflare Access, Microsoft Entra ID, any OIDC) stays the identity source behind
a pluggable `IdentityPort`; **upstream identity credentials never pass through to
MCP clients and are never forwarded** (token passthrough is forbidden by the MCP
spec).

**v0.1 includes:** the framework-free verifier + bridge core, the store port with
memory + sqlite + mysql reference adapters and a shared conformance suite, and the
identity-port boundary.

**v0.1 did NOT include:** multi-tenant/SaaS, UI beyond the consent page,
generic-OIDC-provider support (the `GenericOidcIdentity` port + Google preset
landed in v0.2/S4a; v0.1 shipped only Cloudflare Access + Entra as concrete
identity ports), token introspection, or the CIMD implementation (its port
boundary is defined now; impl is v0.2). Framework
adapters (`/fastify` `/express` `/hono`), the Cloudflare Access/Entra identity
ports, and a runnable example were originally Phase 3/4 scope and have since
shipped — see §16 for the current conformance matrix and `docs/threat-model.md`
for the boundary.

**v0.2 contracts are locked in §17** (CIMD, `client_credentials`, device flow,
Entra group authorization, console pairing, generic OIDC + GitHub/Google,
audit sinks, quickstart secret persistence). Written 2026-07-04, before any
implementation, per the contract-first house rule. Nothing in §17 is shipped
until §16 says so.
