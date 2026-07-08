# Live client verification matrix

The automated suite (`test/e2e-*.test.ts`, `test/integration-*.test.ts`) drives the
full OAuth flow through the **official MCP SDK client**. Verifying against the
real-world MCP clients people actually use (claude.ai, ChatGPT, Claude Code, curl)
is a manual step, tracked in this file as a **provider × client matrix**. This is
the single source of truth for live verification — the README's [Live client
verification](../README.md#live-client-verification) section points here.

> **The rule for this table — never overclaim.** A row is `✅ verified` ONLY when the
> named flow was actually driven against the named provider and client, and the
> outcome recorded here with a date. `✅†` means "DCR/OAuth mechanics verified, but
> NOT the production identity leg" (see the dagger note below). `⬜ unverified` rows
> carry an exact owner-run checklist; they flip to `✅` **only when the owner runs
> them** and appends the date + observed result. A session that did not drive a flow
> MUST NOT mark it verified — leave it `⬜`. False green here is worse than an empty
> row: people choose an identity provider based on these checkmarks.

## What "verified" distinguishes

Two things get conflated; this table keeps them separate:

1. **DCR/OAuth mechanics** — the client self-registers, the user sees a real
   consent screen, the bridge mints + the client presents an audience-bound token,
   the tool round-trips. This works regardless of the *identity* backend (a local
   stub is enough).
2. **The production identity leg** — the upstream IdP (Cloudflare Access / Entra /
   etc.) actually authenticates the user and the bridge verifies THAT identity
   fail-closed. This is what an enterprise deployment depends on.

The four rows verified on 2026-07-04 cover **(1)** only. **(2)** against a real IdP
with a live client is the open work the `⬜` rows track.

## Matrix

| Provider | Client | Flow driven | Status | Date | Caveat / environment |
| --- | --- | --- | --- | --- | --- |
| local stub identity | curl | full OAuth dance + tokenless 401 challenge | ✅ | 2026-07-04 | `examples/fastify-sqlite` locally; DCR/PKCE/consent/token mechanics. Identity was the example's stub; **not** a real-IdP identity leg. |
| local stub identity | Official MCP SDK client | register→authorize→token→`/mcp`→refresh→replay-revoke→revoke | ✅ | 2026-07-04 | `test/e2e-mcp-sdk.test.ts` (automated; the current equivalent suite stays green). Stub identity; **not** a real-IdP identity leg. |
| local stub identity | Claude Code | consent (correct scopes) + `ping` round-trip | ✅† | 2026-07-04 | `claude mcp add --transport http` against local `http://localhost`. Originally ran against `DEV_STUB_SUBJECT` (since removed — replaced by console pairing). Mechanics only. |
| local stub identity | claude.ai (custom connector) | consent (correct scopes) + `ping` round-trip | ✅† | 2026-07-04 | Via a **named Cloudflare tunnel** (transport) on a real domain — see [`troubleshooting.md`](troubleshooting.md) for why ad-hoc `--url` tunnels are unreliable. Originally ran against `DEV_STUB_SUBJECT`. Mechanics only. |
| Cloudflare Access (production identity leg) | Claude Code (CLI), Codex CLI, claude.ai, ChatGPT, Official MCP SDK client | full flow against CF-Access-injected identity; fail-closed on policy, allowlist, and bypass | ✅ | 2026-07-07 | `examples/fastify-sqlite` behind a named cloudflared tunnel on `mcp-sso.<zone>` (team `arnoldcartagena`). Driven against **five live clients** — Claude Code (CLI), Codex CLI, claude.ai (custom connector), ChatGPT (custom connector), and the official `@modelcontextprotocol/sdk` client — each completing register→authorize (CF Access OTP)→consent→token→`/mcp` `ping` with the bridge token `sub` = the CF opaque `sub` (UUID `f74dc462-…`, **not** the email; `pong` echoes it); each minted a distinct DCR `client_id` (audited; the clientId→client-name mapping is owner-asserted — the audit carries opaque clientIds with no `software_id`/user-agent field — and shows 9 registrations / 6 completers, the gap being re-runs and one abandoned attempt, not 9 distinct clients). The Codex CLI authorize URL carried the RFC 9728 `resource` parameter (observed in its login URL; per-client `resource`-sending for the other four was not separately verified — the audit's `resource` field is server-defaulted from `OAUTH_RESOURCE`, so it cannot prove any individual client's PRM behavior). Denied (non-policy) email is blocked at the CF Access edge — "That account does not have access", no OTP issued, never reaches the gateway (observed at the CF sign-in screen; by design there is no audit row for this — the block is upstream of the gateway). Removing the admitted email from `CF_ACCESS_EMAIL_ALLOWLIST` while keeping it in the Access policy → `access_jwt_email_not_allowed` (audit-confirmed; non-empty list — the empty-list foot-gun was avoided). Direct no-auth `POST /mcp` → 401 + `WWW-Authenticate resource_metadata`; direct `GET /oauth/authorize` with no `Cf-Access-Jwt-Assertion` → `access_jwt_missing`. **Caveat:** the CF Access app MUST be path-scoped to `/oauth/authorize*` — a whole-hostname app also gates `/mcp`+`/oauth/token` and breaks the client (see checklist A). Wrong-`aud` Access JWT rejection not separately live-driven here; covered by the unit suite (`access_jwt_bad_claim`) + jose exact-`aud` match. |
| Entra ID (redirect flow, §17.11) | Claude Code | register→authorize→Entra login→consent→token→/mcp tools | ✅ | 2026-07-08 | Real enterprise deployment using mcp-sso@0.2.0. Claude Code created a dynamic client (`mcpdc_…`), used PKCE S256, redirected through Entra, showed the mcp-sso consent screen, returned to the callback, and connected with scoped tools. Internal hostname, scopes, and OAuth parameters redacted. See [`docs/field-report-api-key-gateway.md`](field-report-api-key-gateway.md). |
| Entra ID (redirect flow, §17.11) | Claude Desktop | register→authorize→Entra login→consent→token→/mcp tools | ✅ | 2026-07-08 | Same enterprise deployment. Claude Desktop connected with scoped tools; identical flow (DCR + PKCE S256 + Entra redirect + mcp-sso consent). |
| Entra ID (redirect flow, §17.11) | claude.ai (custom connector) | full flow against Entra identity | ⬜ | — | Owner-run checklist B (claude.ai variant). |
| Entra ID (redirect flow, §17.11) | ChatGPT (custom connector) | consent + tool round-trip against Entra identity | ⬜ | — | Owner-run checklist C (Entra variant). CF × ChatGPT is ✅ (row below); this tracks the Entra-backed ChatGPT case the old "CF or Entra" placeholder covered. |
| Cloudflare Access | ChatGPT custom connector | consent + tool round-trip | ✅ | 2026-07-07 | Same CF Access deployment as the row above (`mcp-sso.<zone>`). ChatGPT's custom connector completed register→authorize (CF Access OTP)→consent→token→`/mcp` `ping`; bridge `sub` = the CF opaque `sub` (`f74dc462-…`). Entra × ChatGPT remains ⬜. |
| console pairing / Cloudflare Access / Entra | **api-key-gateway example** (this repo) | full proxied round trip: client → gateway → token-only backend | ⬜ | — | Owner-run checklist D. The example + its automated integration test shipped; the live-client run is owner-pending. |

### † Dagger note (the four 2026-07-04 rows)

These four rows verify the **DCR/OAuth mechanics, not the production identity leg.**
At verification time the example used `DEV_STUB_SUBJECT`, a dev bypass that let the
OAuth dance complete with no real identity provider (MCP clients don't send
`Cf-Access-Jwt-Assertion` on their own). `DEV_STUB_SUBJECT` is now **removed** —
replaced by console pairing ([§17.5](contracts.md)) — and the same DCR/OAuth
mechanics are covered by the automated e2e (`test/e2e-pairing.test.ts`). The real
Cloudflare Access identity check — header-injected, fail-closed — is now live-verified
across Claude Code (CLI), Codex CLI, claude.ai, ChatGPT, and the official MCP SDK
client (matrix row above, 2026-07-07). Console pairing is for
single-operator/private-console deployments only; **never expose it on a public URL**
(it erases per-user attribution — see [`gateway-deployment.md`](gateway-deployment.md)).

---

## Owner-run checklists

Each `⬜` row flips to `✅ <date>` only after the owner runs its checklist and records
the observed result (and any caveat) back into the matrix row above.

### A — Cloudflare Access (production identity leg) × a live client

The goal: prove a real MCP client completes the flow when Cloudflare Access — not a
local stub — is the identity source, and that a user NOT in the Access policy is
rejected.

**Create the Access application path-scoped to `/oauth/authorize*` — not the whole
hostname.** CF Access is the assertion-injecting proxy for the *browser authorize leg
only*: it must inject `Cf-Access-Jwt-Assertion` on `/oauth/authorize` (the consent
`/oauth/authorize/approve` is authenticated by the signed `consent_token`, not the CF
JWT — gating it under `/oauth/authorize*` is optional session-coherence defense-in-depth,
not required for the flow). The API paths the MCP client calls server-side —
`/.well-known/*`, `/oauth/register`, `/oauth/token`, `/oauth/revoke`, and `/mcp` (which
is protected by the bridge's own audience-bound token) — must stay **public**. A
whole-hostname Access app gates `/mcp` and `/oauth/token` too, so the client's
no-cookie requests get a login redirect instead of reaching the verifier and the flow
cannot complete. (Verified the hard way on 2026-07-07: a whole-hostname app returned
`302 → login` on every path; rescoping to `/oauth/authorize` + `/oauth/authorize/approve`
left only the authorize leg gated and the flow completed.) Two capture landmines when
filling the env below: `CF_ACCESS_ISSUER` is `https://<team>.cloudflareaccess.com` with
**no trailing slash** (jose matches `iss` exactly); `CF_ACCESS_AUDIENCE` is the app's
hex **AUD tag**, not the hostname.

```bash
# 1. Real signing material + the Cloudflare Access production path on a public https origin:
OAUTH_ISSUER=https://<your-host> \
OAUTH_RESOURCE=https://<your-host>/mcp \
OAUTH_CONSENT_SIGNING_SECRET=$(openssl rand -hex 32) \
OAUTH_SIGNING_PRIVATE_JWK='{"kty":"EC","crv":"P-256",...}' \
CF_ACCESS_AUDIENCE=<your-app-aud> \
CF_ACCESS_CERTS_URL=https://<team>.cloudflareaccess.com/cdn-cgi/access/certs \
CF_ACCESS_ISSUER=https://<team>.cloudflareaccess.com \
CF_ACCESS_EMAIL_ALLOWLIST=you@example.com \
node examples/fastify-sqlite/index.ts &

# 2. Expose it via a NAMED Cloudflare tunnel (ad-hoc --url tunnels are unreliable —
#    see docs/troubleshooting.md):
cloudflared tunnel route dns <tunnel-id> <your-host>
cloudflared tunnel --config tunnel-config.yml run

# 3. In the client (Claude Code: `claude mcp add --transport http`; claude.ai: add a
#    custom connector), point at https://<your-host>/mcp. You should hit the Cloudflare
#    Access sign-in first; after Access approves you, the mcp-sso consent screen appears;
#    approve; the tool is callable.
```

**Flips to ✅ when:** a user in the Access policy completes the flow and a tool
round-trips; AND a user NOT in the policy (or with a wrong-audience/`aud` Access JWT)
is rejected (fail-closed, direct 401 — never a bypass). Record the date + the Access
policy shape.

### B — Entra ID (redirect flow) × a live client

The goal: prove the §17.11 upstream redirect-leg orchestrator (`createEntraRedirectIdentity`)
works against a real Entra tenant, end-to-end through a browser, with a live MCP client.

- Register an Entra app; note `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`,
  and set `ENTRA_REDIRECT_URI=https://<your-host>/callback` (the orchestrator boot-asserts
  `identity.redirectUri === originOf(OAUTH_ISSUER) + callbackPath`; `/callback` here is the
  path you choose — the examples derive `callbackPath` from the URI's pathname).
- Use the api-key-gateway example (or fastify-sqlite) with `ENTRA_TENANT_ID` set, on a
  public https origin behind a named tunnel.
- In Claude Code / claude.ai, point at `https://<your-host>/mcp`. The mcp-sso authorize
  route redirects to Entra; after Entra sign-in + consent, the mcp-sso consent screen
  appears; approve; the tool is callable.

**Flips to ✅ when:** a real Entra user completes the redirect flow through a browser
and a tool round-trips; AND a user outside `ENTRA_SUBJECT_ALLOWLIST` / the wrong tenant
is rejected. The manual checklist at the top of `src/identity/entra-redirect.ts` is the
gate before claiming live-complete — record the live result (incl. guest/B2B + overage
behavior) there too.

### C — ChatGPT (custom connector) × a live client

The goal: prove mcp-sso works with ChatGPT's custom-connector OAuth client (never driven
yet). Pick **Cloudflare Access or Entra** as the identity backend when you run it (don't
use console pairing on a public URL).

- Stand up the example on a public https origin behind a named tunnel, with a real IdP
  (checklist A or B).
- In ChatGPT, add the connector at `https://<your-host>/mcp`; complete the OAuth flow;
  call a tool.

**Flips to ✅ when:** ChatGPT completes registration + consent and a tool round-trips.
Record which IdP you used as the provider in the matrix row.

### D — api-key-gateway example × a live client

The goal: prove the worked gateway example (`examples/api-key-gateway/`) runs standalone
and that the backend credential is genuinely injected server-side and never reaches the
client — observed through a real MCP client, not just the automated test.

```bash
# 1. Set the backend credential (the static key the gateway injects for the backend):
BACKEND_API_KEY=$(openssl rand -hex 32) \
node examples/api-key-gateway/index.ts
#    → prints the gateway URL + the backend it proxies to; identity is console pairing
#      (paste the one-time code) by default. For a multi-user run, use the CF Access or
#      Entra env-switch instead (docs/gateway-deployment.md).

# 2. In Claude Code: claude mcp add --transport http gw http://localhost:3000/mcp
#    → consent; call the `status` tool; the response comes from the BACKEND through the
#      gateway (the backend's marker proves the proxy round trip).

# 3. Verify the backend credential never leaked: it is NOT in the client, NOT in any
#      response the client saw, NOT in ./.mcp-sso/audit.jsonl (the default state dir
#      when MCP_SSO_DIR is unset and the server is started from the repo root).
#      (The automated test test/integration-gateway.test.ts asserts this probe already;
#      the live run confirms it against a real client.)
```

**Flips to ✅ when:** a real client completes the flow through the gateway, a proxied
backend tool round-trips, and a manual check confirms the backend credential appears in
no client-visible output. Record the identity backend used (console pairing / CF Access /
Entra) in the matrix row.

---

## Tunnel note

Anonymous quick tunnels (`cloudflared tunnel --url`) are unreliable for OAuth callback
flows; use a **named tunnel** with an explicit `ingress:` config. Full write-up:
[`troubleshooting.md`](troubleshooting.md).
