# Capability reference

This page lists the surfaces shipped by the current package. It does not describe planned work.

| Area | Shipped surface |
| --- | --- |
| Client registration | CIMD. `POST /oauth/register` with stateless or stored DCR |
| Identity providers | Cloudflare Access. Microsoft Entra ID. Google. Generic OIDC. Console pairing |
| Framework adapters | Fastify. Express. Hono |
| Stores | Memory. SQLite. MySQL |
| OAuth grants | Authorization code with PKCE S256. Refresh token. `client_credentials` |
| Resource protection | RFC 9728 metadata and challenge. Audience verification. Scope enforcement |
| Audit adapters | JSONL file. Webhook. Combined sinks. Custom `AuditPort` |
| Rate limiting | Custom `RateLimitPort`. Redis or Valkey adapter. Fastify protected-resource helper |
| Runtime dependency | `jose` |

## Deployment limits

One `BridgeConfig` protects one exact `resource` audience. Use separate bridge configurations for separate resources.

The memory store is process-local. SQLite is for one host. MySQL provides shared `StorePort` state for multiple replicas.

The generated server uses console pairing and is limited to loopback. The repository examples demonstrate composition and live verification. They are not complete production topologies.

`POST /oauth/register` remains for clients that use DCR. CIMD is the preferred client-registration mechanism.
