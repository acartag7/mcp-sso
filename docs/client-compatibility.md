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
| Entra ID | claude.ai custom connector | CIMD `client_id` → authorization → Entra identity → consent → token → `/mcp` | Verified | 2026-08-27 | Runtime commit `c9cec910258e08f3f8cae4bdb8d485b2e01d9a1b`. Eight protected `/mcp` requests followed the token. |
| Entra ID | ChatGPT custom connector | CIMD `client_id` → authorization → Entra identity → consent → token → refresh → `/mcp` | Verified | 2026-08-27 | Runtime commit `c9cec910258e08f3f8cae4bdb8d485b2e01d9a1b`. Ten protected `/mcp` requests and three refreshes. ChatGPT reports a denial as a cancelled connection; the audit trail carries the result. |
| Entra ID | claude.ai custom connector, stateless deployment | Deployment configured with `OAUTH_DCR_MODE=stateless`: CIMD `client_id` → authorization → Entra identity → consent → token → `/mcp` | Verified with limit | 2026-08-27 | Runtime commit `c9cec910258e08f3f8cae4bdb8d485b2e01d9a1b`. Limit: the connector identifies through CIMD, so this flow does not exercise stateless `POST /oauth/register`, which `probe-e2e:stateless` covers. Eight protected `/mcp` requests followed the token. |
| Cloudflare Access | claude.ai custom connector | CIMD `client_id` → authorization → Access login → consent → token → `/mcp` | Verified | 2026-08-27 | Runtime commit `c9cec910258e08f3f8cae4bdb8d485b2e01d9a1b`. Eighteen protected `/mcp` requests followed the token. |
| Cloudflare Access | ChatGPT custom connector | CIMD `client_id` → authorization → Access login → consent → token → `/mcp` | Verified | 2026-08-27 | Runtime commit `c9cec910258e08f3f8cae4bdb8d485b2e01d9a1b`. Ten protected `/mcp` requests followed the token. |
| Google | claude.ai custom connector | CIMD `client_id` → authorization → Google identity → consent → token → `/mcp` | Verified | 2026-08-27 | Runtime commit `c9cec910258e08f3f8cae4bdb8d485b2e01d9a1b`. Twelve protected `/mcp` requests followed the token. |
| Google | Claude Code | CIMD `client_id` → `claude mcp login` → Google identity → consent → the CLI's loopback callback → token → `/mcp` | Verified | 2026-08-27 | Runtime commit `c9cec910258e08f3f8cae4bdb8d485b2e01d9a1b`. Four protected `/mcp` requests, from the CLI's own connection check. Client version 2.1.247. |
| Google | Codex CLI | `codex mcp add` → the client identity Codex chose → Google identity → consent → the CLI's loopback callback → token | Verified with limit | 2026-08-27 | Runtime commit `c9cec910258e08f3f8cae4bdb8d485b2e01d9a1b`. Limit: no tool call ran, so this row proves the login and the code exchange only. Codex presented a per-instance CIMD document rather than a dynamic registration. Client version 0.150.1. |

## Public export live evidence

These rows record the release matrix run against real MySQL and Redis services at live worktree commit `28d9744e0f155d67dbb79389971be2d470491003`. GitHub squash-merged the same runtime tree as main commit `965d8f410b0dfd0b219a9b26a0bfe555fd2488db`. The table records the main commit.

Each row proves that the package entry point participated in the listed executable release row. The rows do not prove contact with an external identity provider. The provider matrix above owns that claim.

| Export | Live evidence | Runtime commit |
| --- | --- | --- |
| `.` | `RM.1`, `RM.17` | `965d8f410b0dfd0b219a9b26a0bfe555fd2488db` |
| `./store/memory` | `RM.1` | `965d8f410b0dfd0b219a9b26a0bfe555fd2488db` |
| `./store/sqlite` | `RM.1` | `965d8f410b0dfd0b219a9b26a0bfe555fd2488db` |
| `./store/mysql` | `RM.1` | `965d8f410b0dfd0b219a9b26a0bfe555fd2488db` |
| `./rate-limit/redis` | `RM.1` | `965d8f410b0dfd0b219a9b26a0bfe555fd2488db` |
| `./fastify/protected-resource-rate-limit` | `RM.1` | `965d8f410b0dfd0b219a9b26a0bfe555fd2488db` |
| `./fastify` | `RM.1` | `965d8f410b0dfd0b219a9b26a0bfe555fd2488db` |
| `./express` | `RM.1` | `965d8f410b0dfd0b219a9b26a0bfe555fd2488db` |
| `./hono` | `RM.1` | `965d8f410b0dfd0b219a9b26a0bfe555fd2488db` |
| `./identity/cloudflare-access` | `RM.1` | `965d8f410b0dfd0b219a9b26a0bfe555fd2488db` |
| `./identity/entra` | `RM.1` | `965d8f410b0dfd0b219a9b26a0bfe555fd2488db` |
| `./identity/console-pairing` | `RM.1` | `965d8f410b0dfd0b219a9b26a0bfe555fd2488db` |
| `./identity/generic-oidc` | `RM.1` | `965d8f410b0dfd0b219a9b26a0bfe555fd2488db` |
| `./identity/google` | `RM.1` | `965d8f410b0dfd0b219a9b26a0bfe555fd2488db` |
| `./testing/store-conformance` | `RM.1`, `RM.16` | `965d8f410b0dfd0b219a9b26a0bfe555fd2488db` |
| `./testing/client-store-conformance` | `RM.1`, `RM.16` | `965d8f410b0dfd0b219a9b26a0bfe555fd2488db` |

## Client versions

The 2026-08-19 matrix used Codex CLI 0.148.0 and Claude Code 2.1.235. The operator supplied the Codex CLI version because the clients ran on a different machine from this checkout.

The 2026-08-27 matrix used Codex CLI 0.150.1 and Claude Code 2.1.247, both resolved from this machine's `PATH` at the time of the run. Codex CLI 0.150.1 identified itself with a per-instance client-id metadata document rather than a dynamic registration; both paths are accepted, and the served audit must record the one the client id claimed.

Codex CLI 0.144.1 had failed its RFC 9207 `iss` callback on 2026-07-28. Codex CLI 0.148.0 completed all three provider flows on 2026-08-19. Both the client and this library changed between those runs, so the later result does not identify which change removed the failure.

## Registration modes

The 2026-08-19 client matrix used `OAUTH_DCR_MODE=stored` with CIMD enabled. The separate stateless row used CIMD, so it did not call `POST /oauth/register`.

In v0.4.0, the live harness could not run stateless `POST /oauth/register` with a CLI loopback callback because the example supplied the bounded limiter only in stored mode. The current source tree supplies the bounded core limiter in stateless mode, so the harness can boot with stateless DCR and a generic loopback callback. A live CLI run has not yet established that path.

The shipped example enables both CIMD and `POST /oauth/register`. It cannot demonstrate a CIMD-only configuration because `BridgeConfig.dcr.mode` has no disabled value. The library supports DCR without CIMD because `BridgeConfig.cimd` is optional. `test/release-registration-matrix.test.ts` covers the DCR-only behavior. The example cannot select it because both composition sites enable CIMD.
