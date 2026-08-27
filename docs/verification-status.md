# Current verification status

This page describes the published release and the current source tree. Superseded receipts are in the [verification archive](archive/verification-history.md). The [client compatibility reference](client-compatibility.md#current-matrix) records the latest provider and client runs.

## Published release

| Item | Status |
| --- | --- |
| npm package and tag | `mcp-sso@0.5.0` and `v0.5.0` |
| MCP Authorization target | `2026-07-28` |
| Conformance claim | Conformant with two recorded deviations |
| First release with this claim | `v0.4.0` |
| Earlier releases | `v0.4.0` carries the same claim. `v0.3.5` has no conformance claim. `v0.3.4` retains the `2025-11-25` baseline. |

The [section 16 conformance matrix](contracts/16-spec-conformance-matrix.md) maps all 44 statements from CIMD draft `-00`. It records 29 conformant rows, one conformant row with a development-only caveat, two deviations, and 12 rows that do not apply. No row has an unresolved evidence gap or a runtime mismatch.

The two deviations are D00-4.2.1 and D00-4.2.2. Both ask the authorization server to operate a CIMD Metadata Document Service. `mcp-sso` is a library and does not operate that service.

## Client compatibility

`v0.4.0` includes both client fixes that were absent from `v0.3.5`:

- A CIMD loopback redirect may vary only its port when `application_type` is `"native"` or absent. An explicit `"web"` value requires an exact redirect URI match. This permits Claude Code's published metadata document.
- `OAUTH_DCR_MODE=stored` exposes the stored DCR and SQLite configuration in the Fastify example. Codex CLI uses this configuration for its ephemeral loopback callback.

The 2026-08-19 live campaign completed 11 flows across Cloudflare Access, Entra ID, and Google at runtime commit `d6143b3`. Codex CLI `0.148.0` completed all three identity paths. The campaign also tested Claude Code and claude.ai.

That campaign does not prove the current source tree, and its rows have been replaced. On 2026-08-27 eight client flows were driven at runtime commit `c9cec91`: the claude.ai connector on Cloudflare Access, Entra ID, and Google, the ChatGPT connector on Cloudflare Access and Entra ID, the claude.ai connector against a deployment configured with `OAUTH_DCR_MODE=stateless`, and Claude Code and Codex CLI on the Google leg. Each was read from the served leg's audit trail rather than from the client's own report. The rehearsal then drove five Entra denial fixtures unattended at the same commit and recorded them: no-group, no-mapped-group, group-overage, wrong-tenant, and subject-allowlist. Each produced its documented audit reason and the client received `access_denied` with the documented description. Guest and B2B outcomes are still not driven.

The remaining live gaps are:

- Entra wrong-tenant, subject-allowlist, and guest or B2B rejection.
- A second generic OIDC provider other than Google.
- The GitHub identity port and device flow. Both remain contract-only and are not release claims.

## What v0.5.0 adds

`createUpstreamRedirectFlow` accepts `complete: "identity"` with an `onIdentity` callback. The flow runs the same state, nonce, PKCE, single-use flow cookie, callback validation, and exchange it already ran, then hands verified `IdentityClaims` to the host instead of calling `bridge.handleAuthorize`. There is no consent page and no MCP token. `complete: "bridge"` stays the default and is unchanged.

The host owns what happens next: its own session cookie, its own user binding, and any further gating on `emailVerified` for data it stores. `mcp-sso` never sets a session cookie.

Remote JWKS documents are byte-capped on every identity port. Both runnable examples create a finite process-local `RateLimitPort` in stateless as well as stored DCR mode, and pass that same instance to `createUpstreamRedirectFlow`, so a default stateless deployment no longer leaves upstream authorize and callback uncounted.

## Current source tree

The current source keeps the `v0.5.0` protocol and conformance claims.

In those examples, direct identity authorization uses `authorize:<ip>`. Upstream authorize and callback requests share `upstream:<ip>`. The library still defaults to `noopRateLimit` when a composition does not supply a `RateLimitPort`.

## Configurations rejected at boot

These refusals were introduced in `v0.4.0` and still apply in `v0.5.0`. Each one previously started and behaved in a way that read as safe:

| Configuration | Result |
| --- | --- |
| `BridgeConfig.dcr.mode === "stored"` without a bounded `RateLimitPort` | `AuthConfigError` |
| Hono with `BridgeConfig.dcr.mode === "stored"` and no `clientIp` extractor | `AuthConfigError` |
| Stateless DCR with no bounded `RateLimitPort`, unless the allowlist has an application-specific HTTPS redirect and retains no generic loopback entry | `AuthConfigError`. A generic loopback entry is not rescued by an application-specific HTTPS entry beside it. Two compositions are exempt: a `dev.allowInsecureLocalhost` deployment whose issuer and resource are both loopback, and a composition that passes `acknowledgeUnsafeStatelessDefaults`, which is itself refused unless the issuer and resource are both loopback |

If `RateLimitPort.check` throws during `POST /oauth/register` in stored DCR mode, `Bridge.handleRegister` returns 503 before it selects body fields, writes registration state, or emits a registration success audit. The same exception does not block `POST /oauth/register` in stateless DCR mode.

Windows permission checks remain limited. The first persistent-state call in a Node worker warns once when Windows cannot enforce the POSIX ownership and mode checks. The warning contains no path. Windows confidentiality still depends on the inherited DACL.
