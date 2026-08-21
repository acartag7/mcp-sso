# 2. The two roles

The library plays two OAuth roles against a **single shared configuration**:

| Role | Owns | Endpoints | Tokens |
|---|---|---|---|
| **Resource Server (RS)** | `/mcp` protection, PRM (RFC 9728), 401 challenge, 403 step-up | served by the host app at its resource origin | **verifies** access tokens (audience = resource) |
| **AS-lite bridge (AS)** | DCR, authorize/approve, token, refresh, revoke, JWKS, AS metadata (RFC 8414) | served by the host app at its issuer origin | **mints** access + refresh tokens |

Both halves are framework-free use-cases in the core. A framework adapter wires them to HTTP. The split matters because the RS challenge and audience fail-closed logic must be testable without a framework, and because the PRM is published at the **resource** origin while the AS metadata is published at the **issuer** origin. These may be different hosts.
