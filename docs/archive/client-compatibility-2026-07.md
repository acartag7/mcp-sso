# Client compatibility archive, July to August 2026

This archive preserves client and provider results recorded during July 2026. These rows apply to the named versions and commits. They do not describe the latest client matrix. See [Client compatibility](../client-compatibility.md) for current results.

## 2026-07-04 OAuth mechanics

| Identity | Client | Flow driven | Result | Limits |
| --- | --- | --- | --- | --- |
| Local stub | curl | Full OAuth flow and tokenless 401 challenge | Verified | Ran against `examples/fastify-sqlite`. This established DCR, PKCE, consent, and token behavior without a production identity provider. |
| Local stub | Official MCP SDK client | `POST /oauth/register` → authorization → token → `/mcp` → refresh → replay rejection → revocation | Verified | Ran through `test/e2e-mcp-sdk.test.ts`. The current equivalent suite remains automated. |
| Local stub | Claude Code | Consent with the expected scopes and a `ping` round trip | Verified | Ran with `DEV_STUB_SUBJECT`, which was later removed and replaced by console pairing. |
| Local stub | claude.ai custom connector | Consent with the expected scopes and a `ping` round trip | Verified | Used a named Cloudflare tunnel and `DEV_STUB_SUBJECT`. This established OAuth mechanics, not a production identity flow. |

`DEV_STUB_SUBJECT` bypassed the identity-provider leg. Console pairing replaced it and is covered by `test/e2e-pairing.test.ts`. Console pairing is limited to private, single-operator deployments because it removes per-user attribution. See [Gateway deployment](../gateway-deployment.md).

## 2026-07-07 Cloudflare Access

| Client | Flow driven | Result | Limits |
| --- | --- | --- | --- |
| Claude Code, Codex CLI, claude.ai, ChatGPT, and Official MCP SDK client | `POST /oauth/register` → authorization → Cloudflare Access identity → consent → token → `/mcp` | Verified | A denied account stopped at the Access edge. The gateway audit recorded allowlist and missing-assertion rejections. The Access application covered the browser authorization path. The suite covered wrong-`aud` rejection, but the live campaign did not run it separately. The Codex CLI result applies to the client version used on this date. |
| ChatGPT custom connector | Consent and `/mcp` `ping` | Verified | Used the same sanitized Cloudflare Access deployment. |

## 2026-07-08 Entra ID

| Client | Flow driven | Result | Limits |
| --- | --- | --- | --- |
| Claude Code | `POST /oauth/register` → authorization → Entra ID login → consent → token → `/mcp` tools | Verified | Used `mcp-sso@0.2.0`. See the [2026-07-08 API-key gateway field report](2026-07-08-api-key-gateway-field-report.md). |
| Claude Desktop | `POST /oauth/register` → authorization → Entra ID login → consent → token → `/mcp` tools | Verified | Used `mcp-sso@0.2.0`. |

## 2026-07-10 Google

| Client | Flow driven | Result | Limits |
| --- | --- | --- | --- |
| Claude Code and Official MCP SDK client | `POST /oauth/register` → authorization → Google login → callback → consent → token → `/mcp` `ping` | Verified | The run also covered a tokenless 401 challenge and hosted-domain rejection. The provider subject remained stable for each account and differed across accounts. No subject values are retained here. Google was the only generic OIDC provider driven in this campaign. |

## 2026-07-26 and 2026-07-27 Entra ID campaign

| Client | Cases | Result | Limits |
| --- | --- | --- | --- |
| Owner browser with provider harness | Wrong tenant, allowlist, and guest/B2B outcomes | Not verified | Observed on a patched, uncommitted checkout based on `ee8994a`. The exact tree was not archived, so these cases require another run from a named commit. |

## 2026-07-28 release campaign

| Provider | Client | Flow driven | Result | Limits |
| --- | --- | --- | --- | --- |
| Cloudflare Access | Claude Code 2.1.220 | CIMD `client_id` → authorization → Access identity → consent → token → `/mcp` `status` | Verified | Runtime commit `af2a61f1aa772a7f3963acfa9dab15c47f676607`. The audit recorded the CIMD client ID, identity, approval, token exchange, and protected call. |
| Google | Claude Code 2.1.220 | CIMD `client_id` → authorization → Google identity → consent → token → `/mcp` `status` | Verified | Runtime commit `af2a61f1aa772a7f3963acfa9dab15c47f676607`. |
| Google | Owner browser and refresh harness | `POST /oauth/register` → authorization → Google login → callback → consent → token. Refresh A → B → C. Replay A. Try C. | Verified | Runtime commit `af2a61f1aa772a7f3963acfa9dab15c47f676607`. Replay A returned HTTP 400 `invalid_grant`. Current token C then returned HTTP 400 `invalid_grant`, which established family revocation. |
| Entra ID | Claude Code 2.1.220 | CIMD `client_id` → authorization → Entra ID identity → consent → token → `/mcp` `status` | Verified | Runtime commit `af2a61f1aa772a7f3963acfa9dab15c47f676607`. |
| Cloudflare Access, Entra ID, and Google | Claude Code 2.1.220 with `examples/api-key-gateway` | CIMD flow through the gateway to a token-only backend | Verified | Runtime commit `af2a61f1aa772a7f3963acfa9dab15c47f676607`. Each `status` call returned the expected allowlisted shape. Retained client results and the three audit logs contained no backend-key match. |

Codex CLI 0.144.1 failed its RFC 9207 `iss` callback during this campaign. The [current compatibility page](../client-compatibility.md#client-versions) records the later clear run and its evidence limit.

## 2026-08-19 superseded harness limit

On 2026-08-19, the example supplied a bounded limiter only when `OAUTH_DCR_MODE=stored`. CLI clients required loopback callbacks, while stateless mode rejected the generic loopback configuration at boot. Hosted connectors used CIMD and did not call `POST /oauth/register`. The harness could therefore establish a complete CIMD flow under stateless configuration but could not reach stateless `POST /oauth/register`.

The source tree changed on 2026-08-21. Both examples and the live preflight now supply the bounded limiter in stateless mode. The [current compatibility page](../client-compatibility.md#registration-modes) states what remains unverified.
