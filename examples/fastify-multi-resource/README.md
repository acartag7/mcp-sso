# Two MCP resources behind one mcp-sso issuer

One issuer, one signing key, one client registry, one consent screen — and two
independently addressable MCP resources:

| Resource | Scopes | PRM document |
| --- | --- | --- |
| `https://<host>/grafana/mcp` | `mcp:read`, `grafana:admin` | `/.well-known/oauth-protected-resource/grafana/mcp` |
| `https://<host>/memory/mcp` | `mcp:read`, `memory:curate` | `/.well-known/oauth-protected-resource/memory/mcp` |

A client connects only to the endpoint whose tools it needs. **A token minted for
`/grafana/mcp` is refused at `/memory/mcp`** — both resources publish `mcp:read`,
so the audience binding is the only thing separating them. That is the property
this example exists to demonstrate, and
[`test/example-multi-resource.test.ts`](../../test/example-multi-resource.test.ts)
asserts it against this exact code.

## Run it locally

```bash
OAUTH_ISSUER=https://<your-host> \
OAUTH_CONSENT_SIGNING_SECRET=$(openssl rand -hex 32) \
OAUTH_SIGNING_PRIVATE_JWK='{"kty":"EC","crv":"P-256",...}' \
OAUTH_SIGNING_KEY_ID=k1 \
OAUTH_REDIRECT_ALLOWLIST=https://claude.ai/api/mcp/auth_callback \
CF_ACCESS_AUDIENCE=<your-app-aud> \
CF_ACCESS_CERTS_URL=https://<team>.cloudflareaccess.com/cdn-cgi/access/certs \
CF_ACCESS_ISSUER=https://<team>.cloudflareaccess.com \
CF_ACCESS_EMAIL_ALLOWLIST=you@example.com \
SQLITE_FILE=./mcp-sso.db \
node examples/fastify-multi-resource/index.ts
```

Every value above is required. A blank string is treated as missing config and
fails the boot — no listener binds until the whole config parses.

## Cloudflare Access scoping

Scope the Access application to **`/oauth/authorize*` only**, never the whole
hostname. CF Access is the assertion-injecting proxy for the browser authorize
leg; the paths the MCP client calls server-side — `/.well-known/*`,
`/oauth/register`, `/oauth/token`, `/oauth/revoke`, and both `/mcp` endpoints
(protected by the bridge's own audience-bound tokens) — must stay public. A
whole-hostname Access app returns a login redirect on every path and the flow
cannot complete.

Two capture landmines: `CF_ACCESS_ISSUER` has **no trailing slash** (jose matches
`iss` exactly), and `CF_ACCESS_AUDIENCE` is the app's hex **AUD tag**, not the
hostname.

## The Origin gate is not reusable from the single-resource examples

`app.ts` installs its own `onRequest` Origin check (MCP Streamable HTTP
DNS-rebinding protection) keyed on the **configured resource paths**.

The single-resource examples use the exported `isMcpPath` helper, which
hard-codes the pathname `/mcp` ([`src/adapters/http.ts:130`](../../src/adapters/http.ts)).
It returns `false` for `/grafana/mcp`, so reusing it in a multi-resource
deployment would leave the gate installed but never firing. If you change
`RESOURCE_PATHS`, the gate follows automatically; if you copy this wiring
elsewhere, keep the path set and the gate in sync.

## Serving more or fewer resources

Edit `RESOURCE_PATHS` and `SCOPES` in [`app.ts`](app.ts). Each entry becomes a
configured resource, a PRM document, a mounted endpoint and a pinned
`RequestAuthorizer`. Two colliding paths are a boot failure, not a silent
override.

## Client compatibility (verified live 2026-07-30)

Two resources on one host, driven through each client's real connector flow:

| Client | Result |
| --- | --- |
| Claude Code 2.1.220 | both resources; CIMD and DCR |
| ChatGPT connector | both resources; CIMD and DCR |
| Codex CLI 0.147.0 | works via DCR only — [no CIMD support](https://github.com/openai/codex/issues/13200) |
| claude.ai connector | **fails**: rejects `/grafana/mcp` before contacting the server ([#738](https://github.com/anthropics/claude-ai-mcp/issues/738)) |

claude.ai connects to the same server at `/mcp`, so the blocker is the
multi-segment path, not this example. If you need claude.ai, run one resource per
subdomain, each mounted at `/mcp`.

Two operator scripts support a live run:

```bash
node scripts/live-multi-resource-env.mjs https://<your-host> > live.env
node scripts/live-multi-resource-check.mjs https://<your-host>
```

The first generates real signing material (CF Access fields left to fill); the
second checks per-resource PRM discovery, metadata and scope isolation, the
Origin gate, and that the OAuth API paths are not behind the identity proxy.
Exit 0 means the deployment is sound before any client is involved.

## Adapting it

The example uses Cloudflare Access and SQLite because they need no extra
infrastructure. Swap `buildIdentity` for any identity adapter (`mcp-sso/identity/entra`,
`mcp-sso/identity/google`, `mcp-sso/identity/generic-oidc`) and `openSqliteStore`
for `mcp-sso/store/mysql` without touching the resource wiring.
