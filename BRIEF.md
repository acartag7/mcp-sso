# Project Brief

## What it is

`mcp-sso` removes static API keys from remote MCP client configuration. It gives
MCP server authors an OAuth 2.1 resource-server verifier and a small authorization
bridge that works with enterprise identity providers. The visible result is an
MCP client that signs in, receives an audience-bound token, and calls a protected
`/mcp` endpoint without receiving the upstream identity-provider token.

## Why it exists

Enterprise identity providers such as Entra ID and Cloudflare Access identify
users, but they do not provide the complete MCP-facing OAuth flow. `mcp-sso`
bridges that gap while keeping authorization and token policy inside the MCP
server deployment.

## How it works

An MCP client discovers metadata from the routes mounted by an adapter in
`src/adapters/`. It identifies itself through a Client ID Metadata Document
(CIMD) or Dynamic Client Registration (DCR), starts authorization with PKCE, and
is verified through an identity port from `src/identity/`. The framework-free
core in `src/` applies redirect, scope, consent, and token rules. A store in
`src/store/` keeps single-use authorization and refresh state. The bridge mints
its own token, and `RequestAuthorizer` verifies that token before the adapter
allows the protected `/mcp` call.

## The map

| Directory or file | What lives there |
|---|---|
| `src/` | Framework-free OAuth use cases, configuration, token verification, and public exports. |
| `src/ports/` | Interfaces for stores, identity, audit, clocks, fetching, and rate limits. |
| `src/adapters/` | Fastify, Express, Hono, consent, pairing, and upstream-flow wiring. |
| `src/store/` | Memory, SQLite, and MySQL implementations covered by one conformance suite. |
| `src/identity/` | Cloudflare Access, Entra, OIDC, Google, and console-pairing identity adapters. |
| `examples/` | Runnable remote MCP server and API-key gateway compositions. |
| `test/` | Unit, integration, official MCP SDK, process-spawn, CLI, and frozen acceptance proof. |
| `docs/contracts/` | The numbered product and security contracts that govern implementation. |
| `docs/threat-model.md` | Trust boundaries, threats, controls, and remaining risk. |
| `.github/workflows/` | CI, analysis, packaging, publication, and provenance automation. |
| `scripts/verify` | The repository-owned complete verification and packed-artifact command. |

## Sharp edges

- Authentication and authorization failures must fail closed. Empty or ambiguous
  security configuration is not a degraded mode.
- The acceptance tests under `test/acceptance/` are hash-protected. Phase 1 keeps
  that protection and all old checks running.
- The library has optional framework and store peers. Importing the core must not
  require an optional peer.
- Publishing is tag-only through GitHub Actions with npm provenance. Local
  publication is not a supported path.
- The final MCP Authorization conformance target still has documented runtime and
  evidence gaps in `docs/verification.md`; this process migration does not change
  that status.

## How to run and test it

```text
node examples/fastify-sqlite/index.ts
./scripts/verify
```

The example prints its listening address and identity-provider status. Successful
verification reports passing static checks, dependency policy, the full test suite,
the exact real-entrypoint tests, a clean build, an allowed npm tarball manifest,
and successful import and CLI execution from the installed packed artifact.

## State and next milestone

- Current version or phase: `0.3.2`; configurable Engineering OS migration Phase 1.
- Frozen or compatibility-sensitive parts: `test/acceptance/**`, OAuth wire behavior,
  public exports, store parity, and the published package shape.
- Next milestone: merge the Phase 1 migration, observe the new check green on
  `main`, and require its exact emitted context before any Phase 2 cleanup.

Maintenance rule: update this file in the same pull request that changes architecture,
adds or removes a module, or changes run or test commands.

**Enforcement:** pull-request review plus monthly audit; no fleet-wide mechanical
check enforces this template yet.
