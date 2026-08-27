# Client compatibility

This reference records the latest client and identity-provider results that apply to v0.4.0 or the current source tree. Earlier results are in the [client compatibility archive](archive/client-compatibility-2026-07.md). Full dated receipts are in the [verification archive](archive/verification-history.md).

## Evidence levels

| Evidence | Meaning |
| --- | --- |
| OAuth mechanics | The client completes registration or CIMD discovery, authorization, consent, token exchange, and a protected `/mcp` call. A local identity stub can establish this level. |
| Production identity | The upstream identity provider authenticates the user, and `mcp-sso` accepts or rejects that identity through the configured identity adapter. |

A row is `Verified` only when the named flow was driven against the named provider and client and the outcome was recorded with a date and the runtime commit. The `Recorded by` cell says who drove it: `rehearsal` for a row the release rehearsal drives and rewrites on every recorded run, `operator` for a row a person drove through a real client against a served leg. The release gate reads that cell to decide what ages the row, so it is recorded rather than inferred from the wording. `Verified with limit` names the step that was not driven. A session that did not drive a flow must not mark it `Verified`: a false green here is worse than an empty row, because people choose an identity provider from this table.

## Current matrix

| Provider | Client | Flow driven | Recorded by | Status | Date | Limits |
| --- | --- | --- | --- | --- | --- | --- |
| Entra ID | claude.ai custom connector | CIMD `client_id` → authorization → Entra identity → consent → token → `/mcp` | operator | Verified | 2026-08-27 | Runtime commit `c9cec910258e08f3f8cae4bdb8d485b2e01d9a1b`. Eight protected `/mcp` requests followed the token. |
| Entra ID | ChatGPT custom connector | CIMD `client_id` → authorization → Entra identity → consent → token → refresh → `/mcp` | operator | Verified | 2026-08-27 | Runtime commit `c9cec910258e08f3f8cae4bdb8d485b2e01d9a1b`. Ten protected `/mcp` requests and three refreshes. |
| Entra ID | claude.ai custom connector, stateless deployment | Deployment configured with `OAUTH_DCR_MODE=stateless`: CIMD `client_id` → authorization → Entra identity → consent → token → `/mcp` | operator | Verified with limit | 2026-08-27 | Runtime commit `c9cec910258e08f3f8cae4bdb8d485b2e01d9a1b`. Limit: the connector identifies through CIMD, so this flow does not exercise stateless `POST /oauth/register`, which `probe-e2e:stateless` covers. Eight protected `/mcp` requests followed the token. |
| Cloudflare Access | claude.ai custom connector | CIMD `client_id` → authorization → Access login → consent → token → `/mcp` | operator | Verified | 2026-08-27 | Runtime commit `c9cec910258e08f3f8cae4bdb8d485b2e01d9a1b`. Eighteen protected `/mcp` requests followed the token. |
| Cloudflare Access | ChatGPT custom connector | CIMD `client_id` → authorization → Access login → consent → token → `/mcp` | operator | Verified | 2026-08-27 | Runtime commit `c9cec910258e08f3f8cae4bdb8d485b2e01d9a1b`. Ten protected `/mcp` requests followed the token. |
| Google | claude.ai custom connector | CIMD `client_id` → authorization → Google identity → consent → token → `/mcp` | operator | Verified | 2026-08-27 | Runtime commit `c9cec910258e08f3f8cae4bdb8d485b2e01d9a1b`. Twelve protected `/mcp` requests followed the token. |
| Google | Claude Code | CIMD `client_id` → `claude mcp login` → Google identity → consent → the CLI's loopback callback → token → `/mcp` | operator | Verified | 2026-08-27 | Runtime commit `c9cec910258e08f3f8cae4bdb8d485b2e01d9a1b`. Four protected `/mcp` requests, from the CLI's own connection check. Client version 2.1.247. |
| Google | Codex CLI | `codex mcp add` → the client identity Codex chose → Google identity → consent → the CLI's loopback callback → token | operator | Verified with limit | 2026-08-27 | Runtime commit `c9cec910258e08f3f8cae4bdb8d485b2e01d9a1b`. Limit: no tool call ran, so this row proves the login and the code exchange only. Codex presented a per-instance CIMD document rather than a dynamic registration. Client version 0.150.1. |
| Entra ID | Official MCP SDK client, driven by the rehearsal | DCR → authorization → Entra identity through the headless driver as the member test user → consent → token → `/mcp` → refresh | rehearsal | Verified | 2026-08-27 | Runtime commit `be886778f5cf3018b48fa43511b5a07d892f5d2d`. |
| Entra ID | Rehearsal deny fixtures | No-group, no-mapped-group, group-overage, wrong-tenant, and subject-allowlist denials | rehearsal | Verified | 2026-08-27 | Runtime commit `be886778f5cf3018b48fa43511b5a07d892f5d2d`. Each fixture produced its audit reason once (`entra_no_groups`, `entra_no_mapped_groups`, `entra_groups_overage`, `entra_bad_tid`, `entra_subject_not_allowed`) and the client received `access_denied` with the documented description. |
| Cloudflare Access | Official MCP SDK client, driven by the rehearsal | DCR → Access login through the Entra login method as the member test user → consent → token → `/mcp` → refresh; a non-admitted test user stopped at the Access edge | rehearsal | Verified | 2026-08-27 | Runtime commit `be886778f5cf3018b48fa43511b5a07d892f5d2d`. |
| Cloudflare Access and Entra ID | Claude Code, driven by the rehearsal | CIMD `client_id` → `claude mcp login --no-browser` → provider identity through the headless driver as the member test user → consent → the CLI's loopback callback → token → connection check on `/mcp` | rehearsal | Verified | 2026-08-27 | Runtime commit `be886778f5cf3018b48fa43511b5a07d892f5d2d`. Client version 2.1.227. |
| Cloudflare Access and Entra ID | Codex CLI, driven by the rehearsal | `codex mcp add` → the client identity Codex chose, CIMD document or dynamic registration → provider identity through the headless driver as the member test user → consent → the CLI's loopback callback → token | rehearsal | Verified with limit | 2026-08-27 | Runtime commit `be886778f5cf3018b48fa43511b5a07d892f5d2d`. Limit: a tool call runs only when the client-keys file supplies `OPENAI_API_KEY`. Client version 0.147.0. |
| Google | Provider probe, driven by the rehearsal | Discovery through the shipped resolver, the JWKS, and the authorize redirect | rehearsal | Verified with limit | 2026-08-27 | Runtime commit `be886778f5cf3018b48fa43511b5a07d892f5d2d`. Limit: the Google sign-in was not driven. |

## Public export live evidence

These rows record the release matrix run against real MySQL and Redis services at live worktree commit `28d9744e0f155d67dbb79389971be2d470491003`. GitHub squash-merged the same runtime tree as main commit `965d8f410b0dfd0b219a9b26a0bfe555fd2488db`. The table records the main commit.

Each row proves that the package entry point participated in the listed executable release row. The rows do not prove contact with an external identity provider. The provider matrix above owns that claim.

| Export | Live evidence | Runtime commit |
| --- | --- | --- |
| `.` | `RM.1`, `RM.17` | `be886778f5cf3018b48fa43511b5a07d892f5d2d` |
| `./store/memory` | `RM.1` | `be886778f5cf3018b48fa43511b5a07d892f5d2d` |
| `./store/sqlite` | `RM.1` | `be886778f5cf3018b48fa43511b5a07d892f5d2d` |
| `./store/mysql` | `RM.1` | `be886778f5cf3018b48fa43511b5a07d892f5d2d` |
| `./rate-limit/redis` | `RM.1` | `be886778f5cf3018b48fa43511b5a07d892f5d2d` |
| `./fastify` | `RM.1` | `be886778f5cf3018b48fa43511b5a07d892f5d2d` |
| `./fastify/protected-resource-rate-limit` | `RM.1` | `be886778f5cf3018b48fa43511b5a07d892f5d2d` |
| `./express` | `RM.1` | `be886778f5cf3018b48fa43511b5a07d892f5d2d` |
| `./hono` | `RM.1` | `be886778f5cf3018b48fa43511b5a07d892f5d2d` |
| `./identity/cloudflare-access` | `RM.1` | `be886778f5cf3018b48fa43511b5a07d892f5d2d` |
| `./identity/entra` | `RM.1` | `be886778f5cf3018b48fa43511b5a07d892f5d2d` |
| `./identity/console-pairing` | `RM.1` | `be886778f5cf3018b48fa43511b5a07d892f5d2d` |
| `./identity/generic-oidc` | `RM.1` | `be886778f5cf3018b48fa43511b5a07d892f5d2d` |
| `./identity/google` | `RM.1` | `be886778f5cf3018b48fa43511b5a07d892f5d2d` |
| `./testing/store-conformance` | `RM.1`, `RM.16` | `be886778f5cf3018b48fa43511b5a07d892f5d2d` |
| `./testing/client-store-conformance` | `RM.1`, `RM.16` | `be886778f5cf3018b48fa43511b5a07d892f5d2d` |

## Client versions

The 2026-08-19 matrix used Codex CLI 0.148.0 and Claude Code 2.1.235. The operator supplied the Codex CLI version because the clients ran on a different machine from this checkout.

The 2026-08-27 matrix used Codex CLI 0.150.1 and Claude Code 2.1.247, both resolved from this machine's `PATH` at the time of the run. Codex CLI 0.150.1 identified itself with a per-instance client-id metadata document rather than a dynamic registration; both paths are accepted, and the served audit must record the one the client id claimed.

Codex CLI 0.144.1 had failed its RFC 9207 `iss` callback on 2026-07-28. Codex CLI 0.148.0 completed all three provider flows on 2026-08-19. Both the client and this library changed between those runs, so the later result does not identify which change removed the failure.

## Registration modes

The 2026-08-19 client matrix used `OAUTH_DCR_MODE=stored` with CIMD enabled. The separate stateless row used CIMD, so it did not call `POST /oauth/register`.

In v0.4.0, the live harness could not run stateless `POST /oauth/register` with a CLI loopback callback because the example supplied the bounded limiter only in stored mode. The current source tree supplies the bounded core limiter in stateless mode, so the harness can boot with stateless DCR and a generic loopback callback. A live CLI run has not yet established that path.

The shipped example enables both CIMD and `POST /oauth/register`. It cannot demonstrate a CIMD-only configuration because `BridgeConfig.dcr.mode` has no disabled value. The library supports DCR without CIMD because `BridgeConfig.cimd` is optional. `test/release-registration-matrix.test.ts` covers the DCR-only behavior. The example cannot select it because both composition sites enable CIMD.
