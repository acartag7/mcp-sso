# mcp-idp-bridge

**OAuth 2.1 for remote MCP servers — a spec-correct resource-server verifier plus a
small AS-lite bridge, one runtime dependency (`jose`).**

MCP clients (claude.ai, ChatGPT, Claude Code, Cursor) expect **Dynamic Client
Registration** to self-onboard against a remote MCP server. Your identity provider
(Microsoft Entra ID, Okta, Cloudflare Access, …) **does not do DCR** — so the MCP
client hits a wall it cannot get past. This library is the bridge:

- **Verifier** — spec-correct resource-server protection for any Streamable HTTP
  `/mcp`: RFC 9728 Protected Resource Metadata (root **and** path-inserted),
  `WWW-Authenticate: Bearer resource_metadata=…` challenges, scope step-up, and
  **fail-closed audience validation**.
- **Bridge** — a small authorization server that speaks DCR + PKCE S256 + consent +
  refresh rotation to MCP clients, while your IdP stays the identity source. It mints
  its **own** audience-bound tokens; upstream IdP tokens never pass through.

Extracted from a production MCP deployment, behind a published threat model.

> **Status: pre-release** (`0.0.0`, private until `v0.1`). Not yet on npm. The
> framework adapters (`/fastify` `/express` `/hono`) and identity ports
> (`/identity/cloudflare-access`, `/identity/entra`) ship from this repo; the
> runnable example + the end-to-end official-MCP-SDK verify gate are green.

## Why this exists

Entra ID is the canonical case. A remote MCP server wants to trust Entra for
identity, but MCP clients **must** DCR, and Entra has no DCR endpoint. So either the
server breaks MCP clients, or it ships bespoke OAuth. `mcp-idp-bridge` is the
reusable, audited answer: the bridge does DCR/PKCE/consent/rotation with MCP
clients, validates the upstream Entra (or Cloudflare Access, or any OIDC) identity,
and issues its own tokens. One library, any IdP, real MCP clients.

## Quickstart (Fastify + sqlite + Cloudflare Access)

```ts
import { createCloudflareAccessIdentity } from "mcp-idp-bridge/identity/cloudflare-access";
// see examples/fastify-sqlite/ for the full app (OAuth routes + a protected /mcp)
```

The runnable example (`examples/fastify-sqlite/`) wires the bridge to Fastify + a
`node:sqlite` store + the Cloudflare Access identity port, and serves a minimal MCP
server at `/mcp`. Cloudflare Access sits in front and injects `Cf-Access-Jwt-Assertion`;
the bridge verifies it and mints an audience-bound token the MCP client presents to `/mcp`.

```bash
OAUTH_ISSUER=https://auth.example.com \
OAUTH_RESOURCE=https://api.example.com/mcp \
OAUTH_CONSENT_SIGNING_SECRET=$(openssl rand -hex 32) \
OAUTH_SIGNING_PRIVATE_JWK='{"kty":"EC","crv":"P-256",...}' \
CF_ACCESS_AUDIENCE=... CF_ACCESS_CERTS_URL=... CF_ACCESS_ISSUER=... \
node examples/fastify-sqlite/index.ts
```

For local dev without Cloudflare Access, set `DEV_STUB_SUBJECT=user@localhost` (the
identity port accepts any non-empty assertion) and `OAUTH_ALLOW_INSECURE_LOCALHOST=true`
(http on loopback only). Then point Claude Code or claude.ai at `https://api.example.com/mcp`.

## What's implemented

- **Verifier (RS):** RFC 9728 PRM (root + path-inserted), 401 `resource_metadata` +
  `scope` challenge, 403 `insufficient_scope` step-up, ES256 audience-fail-closed,
  cached verification key.
- **Bridge (AS-lite):** RFC 7591 DCR (stateless + stored-client modes),
  auth-code + PKCE S256, consent (Approve + Deny), refresh rotation with **family
  replay-revocation**, RFC 6749 §6 client binding, RFC 7009 revoke, RFC 6749 §4.1.2.1
  error-redirect channels, RFC 9207 `iss`, JWKS, RFC 8414 AS metadata.
- **Identity ports:** Cloudflare Access (https trust roots, optional email allowlist);
  Entra ID (OIDC auth-code + PKCE, iss/aud/tid validation, oid→subject, multi-tenant,
  nonce binding) — claim validation is unit-testable without the JWKS fetch.
- **Stores:** `node:sqlite` + in-memory, sharing a conformance suite (rotation
  backfill, family-validity sweep, single-use consent JTI) that any downstream SQL
  adapter must pass.
- **Adapters:** `/fastify`, `/express`, `/hono` (thin wiring; all logic in the core).

Full surface: [`docs/contracts.md`](docs/contracts.md). Conformance matrix: §16.

## Security is the product

- **Fail-closed everywhere** — ambiguous config, a missing identity, an unknown
  audience, or a replayed token is a hard failure, never a degraded default. There is
  no unauthenticated bypass.
- **Supply chain** — `jose` is the only runtime dep; every pin is ≥15 days old
  (`minimumReleaseAge` in minutes); CI actions are SHA-pinned; npm publish is
  `--provenance` from GitHub Actions OIDC (no local publishes). See
  [`docs/dependency-ledger.md`](docs/dependency-ledger.md).
- **Threat model** — [`docs/threat-model.md`](docs/threat-model.md): STRIDE table,
  the replay-detection control, the accepted boundaries, and the implementation gates.
- Hashed single-use codes/tokens, separate consent/access keys, alg pinning,
  timing-safe PKCE, anchored redirect allowlists + RFC 8252 loopback rules,
  metadata-only audit.

## Verify

```bash
pnpm install          # via corepack (packageManager pin); minimumReleaseAge = 15d
pnpm typecheck && pnpm check:lines && pnpm test && pnpm build
```

The suite includes an **end-to-end gate** (`test/e2e-mcp-sdk.test.ts`) that drives
the full OAuth flow and calls the protected `/mcp` through the **official MCP SDK
client** with a bridge-minted token — register → authorize → token → `/mcp` → refresh
→ replay-revocation observed → revoke.

## Live client verification

The automated gate uses the official MCP SDK client. Verifying against the real
MCP clients (Claude Code, claude.ai) is a manual step. Status:

| Client | Status | Date | Environment / caveat |
| --- | --- | --- | --- |
| OAuth flow + `/mcp` (curl) | ✅ verified | 2026-07-04 | `examples/fastify-sqlite` locally, full dance + tokenless 401 challenge |
| Official MCP SDK client | ✅ verified | 2026-07-04 | `test/e2e-mcp-sdk.test.ts` |
| Claude Code | ⏳ pending | — | local `http://localhost` (no tunnel needed); interactive OAuth |
| claude.ai custom connector | ⏳ pending | — | needs a public `https` tunnel |

**`DEV_STUB_SUBJECT` caveat:** local verification uses the example's stub identity,
which **bypasses identity** (every authorize resolves to the stub subject) so MCP
clients — which do not send `Cf-Access-Jwt-Assertion` — can complete the OAuth dance
without Cloudflare Access. The real CF Access identity leg (header-injected, fail-closed)
is validated in the production swap, not locally.

To run the client checks yourself:

```bash
# 1. Start the example locally (Claude Code can reach http://localhost directly):
OAUTH_ISSUER=http://localhost OAUTH_RESOURCE=http://localhost/mcp \
OAUTH_CONSENT_SIGNING_SECRET=$(openssl rand -hex 32) \
OAUTH_SIGNING_PRIVATE_JWK='{"kty":"EC","crv":"P-256",...}' \
OAUTH_ALLOW_INSECURE_LOCALHOST=true DEV_STUB_SUBJECT=local@dev \
node examples/fastify-sqlite/index.ts

# 2a. Claude Code (local — no tunnel):
claude mcp add --transport http my-bridge http://localhost:3000/mcp
#   → a browser opens to the consent page; approve; the tool is callable.

# 2b. claude.ai (needs a public https URL): expose the server, then set
#     OAUTH_ISSUER/OAUTH_RESOURCE to the tunnel URL and restart so metadata matches:
cloudflared tunnel --url http://localhost:3000   # → https://<random>.trycloudflare.com
#   → in claude.ai, add the tunnel URL as a custom connector; approve; connect.
```

> A cloudflared quick tunnel registers within seconds but "may take some time to be
> reachable"; if the edge still returns 404 after ~90s, run it from a non-sandboxed
> environment (quick-tunnel inbound routing is environment-dependent).

## License

MIT
