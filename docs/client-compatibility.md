# Client compatibility

This reference records the latest client and identity-provider results that apply to v0.4.0 or the current source tree. Earlier results are in the [client compatibility archive](archive/client-compatibility-2026-07.md). Full dated receipts are in the [verification archive](archive/verification-history.md).

## Evidence levels

| Evidence | Meaning |
| --- | --- |
| OAuth mechanics | The client completes registration or CIMD discovery, authorization, consent, token exchange, and a protected `/mcp` call. A local identity stub can establish this level. |
| Production identity | The upstream identity provider authenticates the user, and `mcp-sso` accepts or rejects that identity through the configured identity adapter. |

A row is `Verified` only when the named flow was driven against the named provider and client and the outcome was recorded with a date and the runtime commit. `Verified with limit` names the step that was not driven. A session that did not drive a flow must not mark it `Verified`: a false green here is worse than an empty row, because people choose an identity provider from this table.

## Current matrix

| Provider | Client | Flow driven | Status | Date | Limits |
| --- | --- | --- | --- | --- | --- |
| Entra ID | Owner browser with three provisioned deny fixtures | No-group, no-mapped-group, and group-overage denials | Verified | 2026-08-19 | Runtime commit `d6143b3`. Each fixture produced its audit reason once: `entra_no_groups`, `entra_no_mapped_groups`, or `entra_groups_overage`. This proves distinct server-side reason codes. It does not prove distinct client-facing text or cover wrong-tenant, allowlist, and guest/B2B outcomes. |
| Entra ID | claude.ai custom connector | CIMD `client_id` → authorization → Entra identity → consent → token → `/mcp` | Verified | 2026-08-19 | Runtime commit `d6143b3`. |
| Entra ID | ChatGPT custom connector | CIMD `client_id` → authorization → Entra identity → consent → token → `/mcp` | Verified | 2026-08-19 | Runtime commit `d6143b3`. ChatGPT reports a denial as a cancelled connection. The audit trail carries the denial result. |
| Cloudflare Access, Entra ID, and Google | Claude Code and Codex CLI on all three providers. claude.ai on all three providers. ChatGPT on Cloudflare Access and Entra ID | CIMD or DCR → authorization → provider identity → consent → token → `/mcp`. Clients also exercised refresh rotation and revocation. | Verified | 2026-08-19 | Runtime commit `d6143b3`. Eleven flows completed: four on Cloudflare Access, four on Entra ID, and three on Google. Google with ChatGPT was not run. A non-admitted Cloudflare account stopped at the Access edge and produced no gateway audit row, which was the expected result. The clients exercised `oauth.token.refresh` on all three providers and `oauth.revoke` on Entra ID. |
| Entra ID | claude.ai custom connector | Deployment configured with `OAUTH_DCR_MODE=stateless`: CIMD `client_id` → authorization → Entra identity → consent → token → refresh → `/mcp` | Verified with limit | 2026-08-19 | Runtime commit `8c08c36`, later merged without runtime changes as `7909642`. The audit contained one `oauth.cimd.fetch` event and no `oauth.register` event. This row proves a complete CIMD flow under stateless configuration. It does not exercise stateless `POST /oauth/register`. |

## Public export live evidence

These rows record the release matrix run against real MySQL and Redis services. They prove that the named package entry point participated in the listed executable release row. They do not claim that a real external identity provider was contacted; the provider matrix above owns that separate claim.

| Export | Live evidence | Runtime commit |
| --- | --- | --- |
| `.` | `RM.1`, `RM.18` | `28d9744e0f155d67dbb79389971be2d470491003` |
| `./store/memory` | `RM.4`, `RM.10` | `28d9744e0f155d67dbb79389971be2d470491003` |
| `./store/sqlite` | `RM.1`, `RM.2`, `RM.10` | `28d9744e0f155d67dbb79389971be2d470491003` |
| `./store/mysql` | `RM.3`, `RM.10` | `28d9744e0f155d67dbb79389971be2d470491003` |
| `./rate-limit/redis` | `RM.2`, `RM.10`, `RM.18` | `28d9744e0f155d67dbb79389971be2d470491003` |
| `./fastify/protected-resource-rate-limit` | `RM.2` | `28d9744e0f155d67dbb79389971be2d470491003` |
| `./fastify` | `RM.1`, `RM.2`, `RM.6`, `RM.18` | `28d9744e0f155d67dbb79389971be2d470491003` |
| `./express` | `RM.3`, `RM.6`, `RM.18` | `28d9744e0f155d67dbb79389971be2d470491003` |
| `./hono` | `RM.4`, `RM.6`, `RM.18` | `28d9744e0f155d67dbb79389971be2d470491003` |
| `./identity/cloudflare-access` | `RM.2`, `RM.5` | `28d9744e0f155d67dbb79389971be2d470491003` |
| `./identity/entra` | `RM.3`, `RM.5` | `28d9744e0f155d67dbb79389971be2d470491003` |
| `./identity/console-pairing` | `RM.1`, `RM.5` | `28d9744e0f155d67dbb79389971be2d470491003` |
| `./identity/generic-oidc` | `RM.4`, `RM.5` | `28d9744e0f155d67dbb79389971be2d470491003` |
| `./identity/google` | `RM.5` | `28d9744e0f155d67dbb79389971be2d470491003` |
| `./testing/store-conformance` | `RM.16` | `28d9744e0f155d67dbb79389971be2d470491003` |
| `./testing/client-store-conformance` | `RM.16` | `28d9744e0f155d67dbb79389971be2d470491003` |

## Client versions

The 2026-08-19 matrix used Codex CLI 0.148.0 and Claude Code 2.1.235. The operator supplied the Codex CLI version because the clients ran on a different machine from this checkout.

Codex CLI 0.144.1 had failed its RFC 9207 `iss` callback on 2026-07-28. Codex CLI 0.148.0 completed all three provider flows on 2026-08-19. Both the client and this library changed between those runs, so the later result does not identify which change removed the failure.

## Registration modes

The 2026-08-19 client matrix used `OAUTH_DCR_MODE=stored` with CIMD enabled. The separate stateless row used CIMD, so it did not call `POST /oauth/register`.

In v0.4.0, the live harness could not run stateless `POST /oauth/register` with a CLI loopback callback because the example supplied the bounded limiter only in stored mode. The current source tree supplies the bounded core limiter in stateless mode, so the harness can boot with stateless DCR and a generic loopback callback. A live CLI run has not yet established that path.

The shipped example enables both CIMD and `POST /oauth/register`. It cannot demonstrate a CIMD-only configuration because `BridgeConfig.dcr.mode` has no disabled value. The library supports DCR without CIMD because `BridgeConfig.cimd` is optional. `test/release-registration-matrix.test.ts` covers the DCR-only behavior. The example cannot select it because both composition sites enable CIMD.
