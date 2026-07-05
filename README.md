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
talks to the server. It has no expiry, no per-user identity, and no
revocation story short of rotating the one key everyone shares. It's what
security reviews flag, and what leaks in a `git add .` or a support
screenshot.

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
after that, the client holds a token and refreshes it on its own. This
trade-off — a login flow instead of a static credential — is why this
library exists: **OAuth in MCP servers, instead of API keys.**

The catch: MCP clients (claude.ai, ChatGPT, Claude Code, Cursor) require
Dynamic Client Registration (DCR) to self-onboard — the client calls a
registration endpoint on the identity provider to enroll itself
automatically. Many enterprise identity providers (Microsoft Entra ID, Okta,
Cloudflare Access) never built that endpoint. `mcp-sso` is the bridge: it
speaks DCR, PKCE, and consent to the MCP client, while your IdP stays the
identity source of truth. Upstream IdP tokens never pass through — the
bridge mints its **own** audience-bound tokens.

## What ships today

> **Status:** `v0.1.1` is live on npm ([`npm i mcp-sso`](https://www.npmjs.com/package/mcp-sso)).
> We've implemented and tested everything below; it passes the conformance
> suite on `main` — nothing here is aspirational. Not-yet-built work is
> called out separately in [Roadmap](#roadmap--not-yet-shipped).

- **Resource-server verifier** (RS = Resource Server) — protects your `/mcp`
  endpoint:
  - Publishes discovery metadata so clients can find the authorization
    server (RFC 9728, served at the root and per-path).
  - Returns a proper `WWW-Authenticate` challenge when a token is missing or
    invalid, with a scope-based 403 step-up when more permission is needed.
  - **Fails closed on audience** — a token minted for a different resource
    is a hard rejection, never a degraded default.
- **AS-lite bridge** (AS = Authorization Server) — issues short-lived tokens
  instead of a static key:
  - Clients self-register (RFC 7591 DCR) and prove they hold the right
    authorization code with PKCE S256 (Proof Key for Code Exchange — proves
    the client that started the flow is the one finishing it).
  - Users see a real consent screen (approve or deny).
  - Refresh tokens rotate on every use, with theft detection if an old one
    gets replayed.
  - Wire-compatible error bodies and metadata (RFC 6749 §5.2, RFC 9207,
    RFC 8414) so official MCP SDK clients just work.
- **Identity, pluggable:**
  - **Cloudflare Access** — verifies the header Cloudflare injects in front
    of your app, with an optional email allowlist.
  - **Microsoft Entra ID** — verifies OIDC (OpenID Connect, an identity
    layer on top of OAuth) tokens via auth-code + PKCE, resolves the right
    tenant automatically, checks the token wasn't replayed (nonce), and
    allowlists users by their stable object ID.
  - **Console pairing** (`/identity/console-pairing`) — zero-setup identity for
    single-operator deployments: a one-time code prints to the server console
    and is pasted at the consent step. Real OAuth with **no IdP to stand up** —
    meant to be easier than generating an API key. It replaced the old
    `DEV_STUB_SUBJECT` dev bypass; see the single-operator boundary under
    [Live client verification](#live-client-verification) below.
- **Framework adapters** — `/fastify`, `/express`, `/hono`: thin route
  wiring, all logic lives in the framework-free core.
- **Stores** — `node:sqlite` (built into Node 24, **the recommended
  zero-ops production store** for a single-instance MCP server), `/store/mysql`
  (pooled `mysql2` — MySQL/MariaDB/PlanetScale-compatible, the scale path to a
  shared DB; optional peer dep), and an in-memory store for tests, all sharing
  one conformance suite (rotation backfill, family-validity sweep, single-use
  consent JTI) that any further downstream SQL adapter must also pass.
- **Supply-chain posture** — `jose` is the only runtime dependency, every
  pin is at least 15 days old before we accept it, and npm publishes run
  only through GitHub Actions with Sigstore provenance — never from a local
  machine. Full policy in [Security is the product](#security-is-the-product)
  below.
- **A published threat model** (`docs/threat-model.md`) — a STRIDE table
  (the standard framework for categorizing threats), the replay-detection
  control, accepted boundaries, implementation gates.
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

For zero-setup local dev (no IdP, no signing material to generate), the
standalone example auto-generates + persists its signing key and consent secret
([§17.8](docs/contracts.md)) and uses console pairing ([§17.5](docs/contracts.md)):
just `node examples/fastify-sqlite/index.ts` and paste the code printed to the
console. (Loopback http is permitted by default; override `OAUTH_ISSUER` /
`OAUTH_RESOURCE` to a real `https://` origin for a deployment.)

## Enterprise: the Entra DCR wall

Microsoft Entra ID is the canonical hard case. A remote MCP server wants to
trust Entra for identity. But MCP clients must DCR, and Entra has no DCR
endpoint. So either the server breaks every MCP client, or someone
hand-rolls bespoke OAuth glue per deployment.

`mcp-sso` backs the bridge with a published threat model, not just an
unverifiable "trust us." It handles DCR, PKCE, consent, and refresh rotation
for the client. It verifies the upstream identity — Cloudflare Access or
Entra ID today, a generic OIDC port on the roadmap — and issues its own
tokens.

## Security is the product

- **Fail-closed everywhere** — ambiguous config, a missing identity, an
  unknown audience, or a replayed token is a hard failure, never a degraded
  default. There is no unauthenticated bypass in production configuration —
  see the fail-closed gates in [`docs/threat-model.md`](docs/threat-model.md).
- **Supply chain** — `jose` is the only runtime dep; we check every pin is
  at least 15 days old before accepting it (`minimumReleaseAge`, in minutes);
  CI actions are pinned by commit SHA; npm publishes run only through GitHub
  Actions with Sigstore provenance, never from a local machine. See
  [`docs/dependency-ledger.md`](docs/dependency-ledger.md).
- **Threat model** — [`docs/threat-model.md`](docs/threat-model.md): STRIDE
  table, the replay-detection control, the accepted boundaries, and the
  implementation gates.
- **Codes and tokens are hashed and single-use** — a leaked database dump
  doesn't hand out live credentials.
- **Separate signing keys for consent vs. access tokens, with algorithm
  pinning** — stops an attacker downgrading or reusing a key across
  purposes.
- **Timing-safe PKCE verification** — stops a timing side-channel from
  leaking the code verifier.
- **Redirect URIs are matched against an explicit allowlist** (RFC 8252
  loopback rules for native/local clients) — stops an open-redirect
  takeover of the auth flow.
- **Audit logging is metadata-only** — no tokens or codes ever land in a
  log. Reference sinks ship and are fail-open by design: a JSONL file sink
  (`0600`, append-only, log-injection-safe), an https-only no-redirect webhook
  sink, and `combineAudit(...sinks)` fan-out — an audit-write failure never
  blocks the auth flow. Deployer guide (three delivery paths, fail-open
  residual): [`docs/audit-deployment.md`](docs/audit-deployment.md).

## Alternatives

**Start here:** does your identity provider already speak DCR/OAuth 2.1? If
yes, you don't need a bridge — see `mcp-auth` below. If no (true for Entra,
Okta, and most enterprise SSO), that's exactly what this library does.

| Project | What it is | Choose it if… |
| --- | --- | --- |
| **mcp-sso** (this repo) | Resource-server verifier + a DCR/PKCE/consent bridge, with pluggable identity (Cloudflare Access, Entra ID, console pairing). | Your IdP doesn't speak DCR — Entra, Okta, most enterprise SSO. |
| [`mcp-auth`](https://github.com/mcp-auth/js) | Resource-server-only auth for Node MCP servers. | Your IdP **already** speaks DCR/OAuth 2.1 — [check the compatibility list](https://mcp-auth.dev/provider-list) — and you just need the resource-server wiring. |
| [`mcp-oauth-server`](https://github.com/wille/mcp-oauth-server) | A full OAuth 2.1 authorization server for MCP; ships `client_credentials` and device-code (RFC 8628) today. | You need `client_credentials` or device-flow **today** — both are on our v0.2 roadmap (contracts locked, not yet shipped) — and are fine bringing your own storage/consent/identity model. |
| [`workers-oauth-provider`](https://github.com/cloudflare/workers-oauth-provider) | Cloudflare's OAuth 2.1 provider library, KV-backed. | Your MCP server **is** a Cloudflare Worker. |
| Hosted SaaS (Stytch, WorkOS, Auth0, etc.) | Fully managed AS + identity. | You want zero self-hosted auth infrastructure and are fine with a vendor dependency and its pricing. |

## Roadmap — not yet shipped

- **GitHub / Google identity presets** — `GenericOidcIdentity` plus
  ready-made presets, refactoring the Entra port onto the same generic base.
- **Quickstart CLI** — an `npx mcp-sso init` wrapper around the shipped
  `loadOrCreateQuickstartSecrets` helper (the helper itself already ships).
- **CIMD** over the already-present SSRF-guarded `FetcherPort` boundary.
- **`client_credentials` grant** (the official MCP extension
  `io.modelcontextprotocol/oauth-client-credentials`, for headless/M2M
  agents that can't do interactive consent).
- **Device authorization flow (RFC 8628)** — for a human who must authorize
  from a device that can't receive a browser redirect (a CLI over SSH, a
  coding agent in sandboxed CI). Standard OAuth, not part of the MCP spec
  itself — a different problem than `client_credentials`, which has no human
  at all.

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
| Claude Code | ✅ verified† | 2026-07-04 | local `http://localhost`, `claude mcp add --transport http`; consent + scopes + `ping` round-trip confirmed |
| claude.ai custom connector | ✅ verified† | 2026-07-04 | named Cloudflare tunnel on a real domain; same as above |

† **These two rows verify the DCR/OAuth mechanics, not the production
identity leg.** Both originally ran against the example's `DEV_STUB_SUBJECT`
stub (now **removed** — replaced by console pairing, [§17.5](docs/contracts.md)),
which let the OAuth dance complete without Cloudflare Access (MCP clients don't
send `Cf-Access-Jwt-Assertion` on their own). The console-pairing flow is covered
by the automated e2e (`test/e2e-pairing.test.ts`); the real Cloudflare Access
identity check — header-injected, fail-closed — still needs its own live-client
verification. Console pairing is for single-operator/private-console deployments
only — never expose it on a public URL; see the reproduction steps below.

**Tunnel gotchas:** anonymous quick tunnels are unreliable for this; use a
named tunnel with an explicit `ingress:` config. Full write-up:
[`docs/troubleshooting.md`](docs/troubleshooting.md).

To run the client checks yourself:

```bash
# 1. Start the example locally — zero-config: signing key + consent secret are
#    auto-generated (§17.8) and identity is console pairing (§17.5). Paste the
#    code printed to the console:
node examples/fastify-sqlite/index.ts

# 2a. Claude Code (local — no tunnel):
claude mcp add --transport http my-bridge http://localhost:3000/mcp
#   → a browser opens to the consent page; approve; the tool is callable.

# 2b. claude.ai (needs a public https URL). A named Cloudflare tunnel on a
#     domain you control is the reliable option — see docs/troubleshooting.md
#     for why the ad-hoc `--url` forms aren't:
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

## Contributing

Building, testing, and verifying changes locally is a development concern,
not a using-the-library one — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

MIT
