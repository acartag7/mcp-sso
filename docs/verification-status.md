# Current verification status

This page describes the published release and the current source tree. Dated
receipts live in [verification history](verification-history.md). The
[live-client matrix](live-verification.md#matrix) records provider and client
runs.

## Published release

| Item | Status |
| --- | --- |
| npm package and tag | `mcp-sso@0.4.0` and `v0.4.0` |
| MCP Authorization target | `2026-07-28` |
| Conformance claim | Conformant with two recorded deviations |
| First release with this claim | `v0.4.0` |
| Earlier releases | `v0.3.5` has no conformance claim. `v0.3.4` retains the `2025-11-25` baseline. |

The [section 16 conformance matrix](contracts/16-spec-conformance-matrix.md)
maps all 44 statements from CIMD draft `-00`. It records 29 conformant rows,
one conformant row with a development-only caveat, two deviations, and 12
rows that do not apply. No row has an unresolved evidence gap or a runtime
mismatch.

The two deviations are D00-4.2.1 and D00-4.2.2. Both ask the authorization
server to operate a CIMD Metadata Document Service. `mcp-sso` is a library and
does not operate that service.

## Client compatibility

`v0.4.0` includes both client fixes that were absent from `v0.3.5`:

- A CIMD loopback redirect may vary only its port when `application_type` is
  `"native"` or absent. An explicit `"web"` value requires an exact redirect
  URI match. This permits Claude Code's published metadata document.
- `OAUTH_DCR_MODE=stored` exposes the stored DCR and SQLite configuration in
  the Fastify example. Codex CLI uses this configuration for its ephemeral
  loopback callback.

The 2026-08-19 live campaign completed 11 flows across Cloudflare Access,
Entra ID, and Google at runtime commit `d6143b3`. Codex CLI `0.148.0` completed
all three identity paths. The campaign also tested Claude Code and claude.ai.

That campaign does not prove the current source tree. The source has changed
since `d6143b3`. CI covers the later stored-registration outage behavior, but
no live campaign covers the current head.

The remaining live gaps are:

- Entra wrong-tenant, subject-allowlist, and guest or B2B rejection.
- A second generic OIDC provider other than Google.
- The GitHub identity port and device flow. Both remain contract-only and are
  not release claims.

## Current source tree

The current source keeps the `v0.4.0` protocol and conformance claims. It also
contains a post-release correction for issue #280. Both runnable examples now
create a finite process-local `RateLimitPort` in stateless and stored DCR modes.
They pass the same `RateLimitPort` instance to
`createUpstreamRedirectFlow`.

In those examples, direct identity authorization uses `authorize:<ip>`.
Upstream authorize and callback requests share `upstream:<ip>`. The library
still defaults to `noopRateLimit` when a composition does not supply a
`RateLimitPort`.

## `v0.4.0` boot changes

`v0.4.0` rejects these configurations at boot:

| Configuration | Result |
| --- | --- |
| `OAUTH_DCR_MODE=stored` without a bounded `RateLimitPort` | `AuthConfigError` |
| Hono with `OAUTH_DCR_MODE=stored` and no `clientIp` extractor | `AuthConfigError` |
| Stateless DCR with generic loopback redirect trust, no bounded `RateLimitPort`, and no application-specific HTTPS redirect | `AuthConfigError`, except for an acknowledged local-only composition whose issuer and resource are both loopback |

If `RateLimitPort.check` throws during `POST /oauth/register` in stored DCR
mode, `Bridge.handleRegister` returns 503 before it selects body fields, writes
registration state, or emits a registration success audit. The same exception
does not block `POST /oauth/register` in stateless DCR mode.

Windows permission checks remain limited. The first persistent-state call in a
Node worker warns once when Windows cannot enforce the POSIX ownership and mode
checks. The warning contains no path. Windows confidentiality still depends on
the inherited DACL.
