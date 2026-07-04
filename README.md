# mcp-sso

**OAuth in your MCP server, not an API key in your MCP client's config.**

## The problem

Every remote MCP server needs to answer "who is calling me?" The fast answer is
an API key: generate one, paste it into the client's config, done.

```json
{
  "mcpServers": {
    "my-server": {
      "url": "https://api.example.com/mcp",
      "headers": { "Authorization": "Bearer sk-live-8f2c...N9f2" }
    }
  }
}
```

That key now lives forever in a plaintext config file, on every machine that
talks to the server, with no expiry, no per-user identity, and no revocation
story short of rotating the one key everyone shares. It's the thing security
reviews flag and the thing that leaks in a `git add .` or a support screenshot.

The MCP spec's actual answer is OAuth 2.1 with Dynamic Client Registration —
the client self-registers, the user sees a real sign-in/consent screen, and
the token that comes back is short-lived, per-user, and revocable:

```json
{
  "mcpServers": {
    "my-server": { "url": "https://api.example.com/mcp" }
  }
}
```

No secret in the config. The first connection pops a browser consent screen;
after that, the client holds a token it refreshes itself. That's the
trade — a login flow instead of a static credential — and it's why this
library exists: **OAuth in MCP servers, instead of API keys.**

The catch: MCP clients (claude.ai, ChatGPT, Claude Code, Cursor) require DCR
to self-onboard, and most real identity providers (Microsoft Entra ID, Okta,
Cloudflare Access) **don't implement DCR**. `mcp-sso` is the bridge: it speaks
DCR + PKCE + consent to the MCP client, while your IdP stays the identity
source of truth. Upstream IdP tokens never pass through — the bridge mints
its **own** audience-bound tokens.

## What ships today

> **Status: pre-release** (`0.0.0`, private until `v0.1`). Not yet on npm.
> Everything below is implemented, tested, and passes the conformance suite
> on `main` — nothing in this section is aspirational.

- **Resource-server verifier** — RFC 9728 Protected Resource Metadata (root
  **and** path-inserted), `WWW-Authenticate: Bearer resource_metadata=…`
  challenges, `insufficient_scope` 403 step-up, and **fail-closed audience
  validation** — an ambiguous or wrong `aud` is a hard rejection, never a
  degraded default.
- **AS-lite bridge** — DCR (RFC 7591, stateless or stored-client mode), PKCE
  S256, consent (approve + deny), refresh-token rotation with **family
  replay-detection**, RFC 6749 §5.2 wire error bodies, RFC 9207 `iss`, JWKS,
  RFC 8414 AS metadata.
- **Identity, pluggable:**
  - **Cloudflare Access** — verifies the header CF injects in front of your
    app; optional email allowlist.
  - **Microsoft Entra ID** — OIDC auth-code + PKCE, multi-tenant `iss`-from-
    `tid`, nonce binding, `oid`-primary allowlist.
  - **Dev stub** (`DEV_STUB_SUBJECT`) — for local development only, bypasses
    identity entirely so you can run the OAuth dance without standing up an
    IdP. Never for production; see the caveat in "Live client verification"
    below.
- **Framework adapters** — `/fastify`, `/express`, `/hono`: thin route
  wiring, all logic lives in the framework-free core.
- **Stores** — `node:sqlite` (built into Node 24, **the recommended
  zero-ops production store** for a single-instance MCP server) and an
  in-memory store for tests, sharing one conformance suite (rotation
  backfill, family-validity sweep, single-use consent JTI) that any
  downstream SQL adapter must also pass.
- **Supply-chain posture** — `jose` is the **only runtime dependency**; every
  pin (runtime and dev) is verified ≥15 days old before it's accepted
  (`docs/dependency-ledger.md`); CI actions are SHA-pinned; npm publish runs
  `--provenance` from GitHub Actions OIDC only, no local publishes.
- **A published threat model** (`docs/threat-model.md`) — STRIDE table, the
  replay-detection control, accepted boundaries, implementation gates.
- **An end-to-end verify gate** (`test/e2e-mcp-sdk.test.ts`) that drives the
  full flow — register → authorize → token → call the protected `/mcp` →
  refresh → replay-revocation observed → revoke — through the **official MCP
  SDK client**, not a hand-rolled stand-in.

Full contract surface: [`docs/contracts.md`](docs/contracts.md). Spec
conformance matrix: §16 there.

## Quickstart (Fastify + sqlite + Cloudflare Access)

```ts
import { createCloudflareAccessIdentity } from "mcp-sso/identity/cloudflare-access";
// see examples/fastify-sqlite/ for the full app (OAuth routes + a protected /mcp)
```

`examples/fastify-sqlite/` wires the bridge to Fastify + a `node:sqlite` store
+ the Cloudflare Access identity port, and serves a minimal MCP server at
`/mcp`. Cloudflare Access sits in front and injects `Cf-Access-Jwt-Assertion`;
the bridge verifies it and mints an audience-bound token the MCP client
presents to `/mcp`.

```bash
OAUTH_ISSUER=https://auth.example.com \
OAUTH_RESOURCE=https://api.example.com/mcp \
OAUTH_CONSENT_SIGNING_SECRET=$(openssl rand -hex 32) \
OAUTH_SIGNING_PRIVATE_JWK='{"kty":"EC","crv":"P-256",...}' \
CF_ACCESS_AUDIENCE=... CF_ACCESS_CERTS_URL=... CF_ACCESS_ISSUER=... \
node examples/fastify-sqlite/index.ts
```

For local dev without Cloudflare Access, set `DEV_STUB_SUBJECT=user@localhost`
(the identity port accepts any non-empty assertion) and
`OAUTH_ALLOW_INSECURE_LOCALHOST=true` (http on loopback only). Then point
Claude Code or claude.ai at `https://api.example.com/mcp`.

## Enterprise: the Entra DCR wall

Microsoft Entra ID is the canonical hard case. A remote MCP server wants to
trust Entra for identity, but MCP clients **must** DCR, and Entra has no DCR
endpoint. So either the server breaks every MCP client, or someone ships
bespoke OAuth glue per deployment. `mcp-sso` is the reusable, audited answer:
the bridge does DCR/PKCE/consent/rotation with MCP clients, validates the
upstream Entra (or Cloudflare Access, or any OIDC provider) identity, and
issues its own tokens. One library, any IdP, real MCP clients.

## Security is the product

- **Fail-closed everywhere** — ambiguous config, a missing identity, an
  unknown audience, or a replayed token is a hard failure, never a degraded
  default. There is no unauthenticated bypass in production configuration.
- **Supply chain** — `jose` is the only runtime dep; every pin is ≥15 days
  old (`minimumReleaseAge` in minutes); CI actions are SHA-pinned; npm
  publish is `--provenance` from GitHub Actions OIDC (no local publishes).
  See [`docs/dependency-ledger.md`](docs/dependency-ledger.md).
- **Threat model** — [`docs/threat-model.md`](docs/threat-model.md): STRIDE
  table, the replay-detection control, the accepted boundaries, and the
  implementation gates.
- Hashed single-use codes/tokens, separate consent/access signing keys, alg
  pinning, timing-safe PKCE, anchored redirect allowlists + RFC 8252 loopback
  rules, metadata-only audit.

## Alternatives

There is no one-size answer here — pick based on what you already have.

| Project | What it is | Choose it if… |
| --- | --- | --- |
| **mcp-sso** (this repo) | RS verifier **+** AS-lite bridge with pluggable identity (Cloudflare Access, Entra ID, dev stub). Bridges DCR for IdPs that don't speak it. | Your IdP doesn't support DCR (Entra, Okta, most enterprise SSO) and you want one library to own both the resource-server check and the client-facing OAuth dance. |
| [`mcp-auth`](https://github.com/mcp-auth/js) | Plug-and-play RS-side auth for Node MCP servers — connects to an already MCP-compliant provider. | Your identity provider **already** speaks DCR/OAuth 2.1 the way MCP expects (see their [provider compatibility list](https://mcp-auth.dev/provider-list)) — you just need the resource-server wiring, not a bridge. |
| [`mcp-oauth-server`](https://github.com/wille/mcp-oauth-server) | A generic OAuth 2.1 authorization server for MCP, built on the official MCP TypeScript SDK's `OAuthServerProvider`. Supports `authorization_code`, `refresh_token`, `client_credentials`, and device-code (RFC 8628) grants today. | You want to **run your own AS from scratch** (BYO storage/consent/identity model) and need `client_credentials` or device-flow support now — both are on our v0.2 roadmap, not yet shipped here. |
| [`workers-oauth-provider`](https://github.com/cloudflare/workers-oauth-provider) | Cloudflare's OAuth 2.1 provider library, KV-backed, for Workers. | Your MCP server **is** a Cloudflare Worker and you're fine with Workers KV as the token store. |
| Hosted SaaS (Stytch, WorkOS, Auth0, etc.) | Fully managed AS + identity, MCP-flavored onboarding guides. | You want zero self-hosted auth infrastructure and are fine with a vendor dependency and its pricing. |

## Roadmap — not yet shipped

Nothing in this section is available today. It's here so the scope is
explicit, not implied.

- **First-run console-pairing identity** — a one-time code printed to the
  server console, pasted at consent: real OAuth with zero IdP setup, meant to
  be *easier* than generating an API key. Replaces `DEV_STUB_SUBJECT` as the
  quickstart path.
- **GitHub / Google identity presets** — `GenericOidcIdentity` plus
  ready-made presets, refactoring the Entra port onto the same generic base.
- **Quickstart ergonomics** — auto-generate the signing key + consent secret
  on first boot (persisted, fail-closed), likely an `npx mcp-sso init`.
- **CIMD** over the already-present SSRF-guarded `FetcherPort` boundary.
- **`client_credentials` grant** (the official MCP extension
  `io.modelcontextprotocol/oauth-client-credentials`, for headless/M2M
  agents that can't do interactive consent).
- A `/store/mysql` adapter (MySQL/MariaDB/PlanetScale-compatible, protocol
  level) as the second production store option alongside sqlite.

## Conformance

### Spec conformance

Full requirement-by-requirement matrix (RFC 9728, 8414, 7591, 7009, 8707,
9207, PKCE, redirect policy, etc.): [`docs/contracts.md`](docs/contracts.md)
§16.

### Live client verification

The automated suite exercises the full flow through the **official MCP SDK
client**. Verifying against the real-world MCP clients people actually use is
a manual step, tracked here:

| Client | Status | Date | Environment / caveat |
| --- | --- | --- | --- |
| OAuth flow + `/mcp` (curl) | ✅ verified | 2026-07-04 | `examples/fastify-sqlite` locally, full dance + tokenless 401 challenge |
| Official MCP SDK client | ✅ verified | 2026-07-04 | `test/e2e-mcp-sdk.test.ts`, 83/83 |
| Claude Code | ✅ verified | 2026-07-04 | local `http://localhost`, `claude mcp add --transport http`; consent screen showed correct scopes, `ping` round-tripped |
| claude.ai custom connector | ✅ verified | 2026-07-04 | named Cloudflare tunnel on a real domain; consent screen showed correct scopes, `ping` round-tripped |

**`DEV_STUB_SUBJECT` caveat:** local client verification uses the example's
stub identity, which **bypasses identity** (every authorize resolves to the
stub subject) so MCP clients — which do not send `Cf-Access-Jwt-Assertion` —
can complete the OAuth dance without standing up Cloudflare Access. The real
CF Access identity leg (header-injected, fail-closed) is validated in the
production swap, not locally. Never run the stub against a public URL for
longer than a verification window — see the reproduction steps below.

**Tunnel notes from the 2026-07-04 verification session**, kept here because
they cost real time to work out and aren't obvious from `cloudflared --help`:

- **Anonymous quick tunnels (`cloudflared tunnel --url ...`, no account)
  were unreliable and are not what was ultimately used.** Three independent
  quick tunnels each registered cleanly with Cloudflare's edge (zero errors in
  the connector log) and the same local server answered correctly over plain
  `http://localhost` throughout — but every public request through each
  tunnel's hostname returned a `404` straight from Cloudflare's edge, never
  reaching the app. That combination (healthy backend, healthy connector log,
  edge-level 404) is consistent with the anonymous quick tunnel's
  single-connector, no-redundancy design — `cloudflared`'s own CLI disclaims
  "no uptime guarantee" for these on every startup. It was not a bug in the
  OAuth/DCR code path, which the Claude Code check above already exercised
  successfully with the identical server.
- **What actually worked: a named (account-backed) tunnel on a real domain,
  with an explicit `ingress:` hostname rule in a config file** — not the
  ad-hoc `cloudflared tunnel run --url <url> <tunnel>` shortcut. The ad-hoc
  form also produced clean edge-level `404`s in this session, even with a
  named tunnel and a brand-new DNS record; switching to a config file with
  an explicit `hostname:`/`service:` ingress rule (plus the required
  catch-all `http_status:404`) fixed it immediately. If you're setting this
  up yourself, prefer the config-file form from the start.
- **A sharp edge if you already run other named tunnels on the same
  machine:** `cloudflared`'s default `~/.cloudflared/config.yml` (the
  `tunnel:`/`credentials-file:` it points at) can silently override which
  credentials get used even when you pass a *different* tunnel ID or name on
  the command line — producing a confusing auth-retry loop
  (`control stream encountered a failure while serving`) that looks like a
  network problem, not a wrong-credentials problem. Pass `--credentials-file`
  explicitly (or a full `--config`) to be sure which tunnel you're actually
  authenticating as.

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

# 2b. claude.ai (needs a public https URL). A named Cloudflare tunnel on a
#     domain you control is the reliable option (see the tunnel notes above
#     for why the ad-hoc `cloudflared tunnel --url`/`tunnel run --url` forms
#     were unreliable in practice):
cat > tunnel-config.yml <<CFG
tunnel: <your-tunnel-id>
credentials-file: /path/to/<your-tunnel-id>.json
ingress:
  - hostname: mcp-sso-verify.yourdomain.com
    service: http://localhost:3000
  - service: http_status:404
CFG
cloudflared tunnel route dns <your-tunnel-id> mcp-sso-verify.yourdomain.com
cloudflared tunnel --config tunnel-config.yml run
#   → set OAUTH_ISSUER/OAUTH_RESOURCE to https://mcp-sso-verify.yourdomain.com
#     before starting the server, so the metadata matches.
#   → in claude.ai, add https://mcp-sso-verify.yourdomain.com/mcp as a custom
#     connector; approve; connect.
```

## Verify

```bash
pnpm install          # via corepack (packageManager pin); minimumReleaseAge = 15d
pnpm typecheck && pnpm check:lines && pnpm test && pnpm build
```

The suite includes an **end-to-end gate** (`test/e2e-mcp-sdk.test.ts`) that
drives the full OAuth flow and calls the protected `/mcp` through the
**official MCP SDK client** with a bridge-minted token — register →
authorize → token → `/mcp` → refresh → replay-revocation observed → revoke.

## License

MIT
