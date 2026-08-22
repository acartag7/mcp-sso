# Release verification reference

This file maps shipped behavior to deterministic evidence. `scripts/check-release-matrix.mjs` requires every `RM.N` section to remain in this file.

- [Current verification status](verification-status.md)
- [Verification design](verification-design.md)
- [Release checklist](release-checklist.md)
- [Live evidence fields](verification-live.md)
- [Archived verification receipts](archive/verification-history.md)
- [Current client compatibility](client-compatibility.md#current-matrix)

## Minimum evidence

| Change | Minimum evidence |
| --- | --- |
| Pure parsing or validation | The focused test and the full source-tree gates. |
| Store, adapter, generated project, or protocol flow | The test must run through the real service or shipped entry point, followed by the release matrix. |
| Package export or release content | The packed artifact checks in this file. |
| Provider or client compatibility claim | A live campaign after the deterministic and packed-artifact checks. |

## Shipped-feature release gate

`pnpm run test:release` runs the full test suite and validates this inventory against `test/release-matrix.json`. It prints one result for every `RM.N` row. The command requires `RUN_INTEGRATION=true`, `MYSQL_URL`, and `REDIS_URL`.

The command fails for a missing service variable, missing evidence, skipped selected test, undocumented row, removed export, or removed shipped example. Live provider behavior is outside this deterministic gate.

### Shipped-feature inventory

The evidence class names describe what each test runs. `test/release-matrix.json` lists the release rows. The full suite remains part of the release gate.

| Shipped feature | Current evidence class | Durable evidence |
|---|---|---|
| Protected-resource metadata and challenge | Complete protocol flow | `test/e2e-mcp-sdk.test.ts`. RM.10 |
| Authorization-server metadata | Complete protocol flow | `test/integration-full-flow.test.ts`. RM.3/RM.4 |
| Stateless DCR | Complete protocol flow | `test/e2e-mcp-sdk.test.ts` |
| Stored DCR | Complete protocol flow | `test/authorize-ceiling.test.ts`. RM.2/RM.3 |
| CIMD resolution and authorization | Route integration | RM.4/RM.6 |
| PKCE S256 | Packed-artifact flow | RM.1 |
| Consent approve and deny | Complete protocol flow | RM.1/RM.3 plus `test/bridge.test.ts` |
| Authorization-code exchange | Packed-artifact flow | RM.1 |
| Exact resource/audience binding | Complete protocol flow | RM.7/RM.8 |
| Refresh rotation | Packed-artifact flow | RM.1 |
| Replay-family revocation | Packed-artifact flow | RM.1 |
| RFC 7009 revocation | Packed-artifact flow | RM.1 |
| Stored scope accumulation | Complete protocol flow | `test/authorize-ceiling.test.ts`. RM.2 |
| Scope ceilings | Complete protocol flow | `test/authorize-entra-ceiling.test.ts`. RM.2/RM.3 |
| Machine `client_credentials` | Complete protocol flow | RM.7 |
| Access-token verification and protected `/mcp` | Complete protocol flow | RM.1-RM.4, RM.7, RM.9 |
| Fastify adapter | Complete protocol flow | RM.1/RM.2 |
| Express adapter | Complete protocol flow | RM.3 |
| Hono adapter and Request path | Complete protocol flow | RM.4 |
| Origin gate | Route integration | RM.2/RM.9 |
| Adapter request normalization | Route integration | `test/lib/adapter-header-flow.ts`. Full suite |
| Hono request-body and failed-stream bounds | Route integration | `test/hono-body-limit.test.ts`. RM.4 |
| Direct/header identity | Route integration | RM.5 |
| Cloudflare Access | Complete protocol flow | `test/integration-example.test.ts`. RM.2/RM.5 |
| Entra header/group mapping | Route integration | RM.5 plus `test/authorize-entra-ceiling.test.ts` |
| Entra redirect | Complete protocol flow | `test/integration-upstream-redirect.test.ts`. RM.3/RM.5 |
| Google redirect | Complete protocol flow | `test/integration-upstream-redirect.test.ts`. RM.5 |
| Generic OIDC redirect | Complete protocol flow | `test/integration-upstream-redirect.test.ts`. RM.4/RM.5 |
| Console pairing | Packed-artifact flow | RM.1/RM.5 |
| Memory store | Complete protocol flow | RM.4/RM.10 |
| SQLite persistence, restart, migration, trusted opening | Packed-artifact flow | RM.1 plus `test/sqlite-open-admission.test.ts` |
| MySQL real service, migration, and concurrency | Complete protocol flow | RM.3/RM.10 |
| Redis real service, shared window, and operation-specific outage behavior | Route integration | RM.2/RM.10 plus `test/stored-dcr-rate-limit.test.ts` and the three-adapter shared flow |
| JSONL audit and no-secret evidence | Packed-artifact flow | RM.1 |
| Webhook/combine audit behavior | Route integration | `test/audit-flow.test.ts`, `test/audit-webhook.test.ts`. Full suite |
| Configuration snapshots | Unit only | `test/config-snapshot.test.ts`. Full suite |
| Opaque stateless DCR | Complete protocol flow | `test/e2e-mcp-sdk.test.ts` |
| Opaque stored DCR | Complete protocol flow | RM.2/RM.3 |
| HTTPS-shaped CIMD `client_id` through routes | Route integration | RM.4/RM.6 |
| Machine/predefined credentials | Complete protocol flow | RM.7 |
| No silent CIMD/DCR fallback | Route integration | RM.4/RM.6 |
| Generated `mcp-sso init` server | Packed-artifact flow | RM.1 |
| Fastify-SQLite example | Complete protocol flow | RM.2 plus `test/integration-example.test.ts` |
| API-key gateway example | Complete protocol flow | RM.9 |
| Installed npm tarball and installed bin | Packed-artifact flow | RM.1 |
| Official MCP SDK protected tool call with visible `pong` | Packed-artifact flow | RM.1 |
| Published package exports | Packed-artifact flow | RM.1 plus the manifest integrity check |
| Two single-resource bridges sharing state | Complete protocol flow | RM.8 |
| Cross-resource consent/code/refresh/scope isolation | Complete protocol flow | RM.8 |
| Cross-resource machine isolation | Complete protocol flow | RM.7 |
| Wrong-resource rejection before success audit/state mutation | Complete protocol flow | RM.7/RM.8 |

### RM.1 — Packed generated server

The row packs the npm artifact in a private directory and installs it with scripts disabled. It invokes the installed `.bin/mcp-sso` command and installs the generated project from its exact dependency pins.

The generated server completes stored DCR, PKCE, consent approval and denial, token exchange, an official MCP SDK `ping`, refresh rotation, replay-family revocation, reauthorization, and RFC 7009 revocation. The row restarts both the server and SQLite during the flow. It checks the JSONL audit for secrets.

The row imports every published export. `jose` is the only runtime dependency.

### RM.2 — Fastify production-style header flow

The row runs a real Fastify socket with stored DCR and SQLite. It verifies a locally signed Cloudflare Access JWT through the injected JWKS transport.

The flow accumulates scopes within the identity ceiling, rejects a foreign Origin, calls protected `/mcp` through the official MCP SDK, and refreshes after SQLite reopens. A real Redis denial returns 429. A Redis `WRONGTYPE` error does not block authorization. The full suite covers the separate Fastify and SQLite example.

### RM.3 — Express redirect flow

The row runs a real Express socket with MySQL 8.4, stored DCR, and the Entra redirect port. It injects local token and signature transports.

The flow applies the Entra group scope ceiling, exercises consent denial and approval, calls protected `/mcp` through the official MCP SDK, rotates a refresh token, detects replay, reauthorizes, and revokes the new token family.

### RM.4 — Hono CIMD flow

The row runs a real Hono `Request` stack with an HTTPS CIMD `client_id`. The flow performs counted DNS resolution, guarded fetch, document validation, and redirect matching. It injects Generic OIDC discovery, exchange, and signature verification.

The client authorizes, calls protected `/mcp` through the official MCP SDK, refreshes, and revokes without a DCR write. An under-limit request stream that throws returns 400 before `Bridge` runs.

### RM.5 — Identity sibling proof

Direct identity, Cloudflare Access, Entra header, Entra redirect, Google, Generic OIDC, and console pairing each reach a shipped authorization route. Tests inject local signing, discovery, token, and JWKS transports. Tier 3 owns claims about real provider accounts.

### RM.6 — Three-adapter CIMD route parity

The same HTTPS CIMD `client_id` authorizes through Fastify, Express, and Hono. Each route calls the resolver, continues to the redirect, and writes no DCR state. The row does not repeat the refresh lifecycle for each adapter.

### RM.7 — Machine credential lifecycle

A credential bound to resource A authenticates with both `client_secret_basic` and `client_secret_post`. It obtains a token through `POST /oauth/token`, calls protected `/mcp`, rotates through its grace period, and becomes disabled.

Resource B shares the client store. It cannot authenticate the credential, rotate or disable it, mutate its row, or emit a success audit.

### RM.8 — Cross-resource OAuth lifecycle

Two Fastify route sets share durable OAuth state. Resource B rejects resource A's consent token, authorization code, refresh token, and stored scopes. Those rejections produce no success audit or state change.

Resource A completes the valid lifecycle. Replaying A's refresh token revokes its successor.

### RM.9 — Gateway

The API-key gateway example completes console pairing, token issuance, and a backend tool call through the official MCP SDK. The backend credential stays on the server. The Origin check and the absolute-request-target check run before the gateway forwards the request. The gateway returns the documented backend authorization statuses without returning the credential.

### RM.10 — Store and service parity

Memory, persistent SQLite, and real MySQL each complete an OAuth lifecycle. The MySQL cases include migration and concurrent refresh rotation. The Redis cases include a shared rate-limit window and a thrown Redis error.

If `RateLimitPort.check` throws, `POST /oauth/register` returns 503 in stored DCR mode before a state write or success audit. The same exception does not block stateless registration, authorization, consent approval, token exchange, or revocation. A limiter denial returns 429.

The release command fails before these rows when `MYSQL_URL` or `REDIS_URL` is absent.

### RM.11 — Redirect allowlist mode

The row covers all four readers of `redirectAllowlistMode` separately: `POST /oauth/register`, stateless authorize, stored-client revalidation, and consent approve or deny. In `"replace"` mode, each reader rejects a built-in origin that is absent from the configured allowlist. Authorize rejects the origin directly. It does not redirect to that origin.

Readers 3 and 4 prove the time split, not only the reader. Reader 3 seeds a client registered while the built-ins were trusted and proves that it stops authorizing after a restart into `"replace"`. Reader 4 mints a consent token under `"extend"` and proves that both approve and deny are refused under `"replace"`, because a consent token outlives the process that issued it. A test that checks the four readers inside one single-policy process does not satisfy this row.

The configured origin still registers and reaches consent. Omitting `redirectAllowlistMode` retains `"extend"`. An empty allowlist in `"replace"` mode fails at boot.

### RM.12 — Identity display name

Both shipped OIDC ports return `claims.name` for a verified identity. They omit the value when `email_verified` is not exactly `true` or the name exceeds the length limit. Google keeps its raw `sub`. The generic OIDC port keeps its issuer-namespaced subject.

### RM.13 — Audit sink fan-out

`JsonlFileAudit`, `WebhookAudit`, and `combineAudit` are root exports. The row runs registration and authorization through Fastify with both sinks. Each sink receives the same number of events.

Neither sink receives the consent token, PKCE verifier, identity header value, consent signing secret, or webhook collector credential. The test injects the webhook transport and makes no network call; it proves the wiring and the payload. The row fails if the webhook sink reports a delivery failure, because `WebhookAudit` itself logs the failure and continues, so without that assertion a webhook that never accepted anything would still read as a green fan-out. The unit tests in `test/audit-webhook.test.ts` are what simulate a delivery failure and prove the diagnostic appears.

### RM.14 — CIMD and DCR coexistence

One `Bridge` with `cimd.enabled` and stored DCR serves both client kinds for the same subject and store. The opaque stored DCR client accumulates its own grants. The CIMD client does not accumulate grants. Neither client inherits the other client's grants.

With CIMD disabled, an HTTPS `client_id` fails before a DCR store read. A stored opaque client still reaches the DCR store as a positive control. The row uses a token exchange because `findGrantedScopes` reads active refresh records.

### RM.15 — Registration dispatch matrix

`BridgeConfig.dcr` is required. The row crosses `cimd.enabled` true or false with `dcr.mode` set to `"stateless"` or `"stored"`.

All four configurations accept an opaque DCR client and reach consent. When CIMD is enabled, a lowercase HTTPS `client_id` enters CIMD resolution. When CIMD is disabled, the same `client_id` fails before DCR lookup. Stored DCR configurations supply a bounded `RateLimitPort`.

The frozen native-loopback suite covers Claude Code's published metadata document and the allowed port difference. The frozen CIMD dispatch suite covers other URL schemes in direct and redirect flows.

### RM.16 — Shipped conformance suite

The row packs and installs the npm artifact. It runs `runStoreConformance` and `runClientStoreConformance` through the public `mcp-sso/testing/*` exports.

Importing `mcp-sso/testing/store-conformance-grants` fails with `ERR_PACKAGE_PATH_NOT_EXPORTED`. Only the two complete suite entry points are public.

### RM.17 — Claims-only redirect completion

This row starts `createUpstreamRedirectFlow({ complete: "identity" })` through the public `/login` route, completes the callback with verified `IdentityClaims`, and confirms that no consent response or MCP token is produced. It proves that both legs charge `website-login:<ip>`, callback replay cannot invoke the identity provider or `onIdentity` twice, and IdP denial and verified identity rejection use the same direct response.

The failure cases prove that a thrown, timed-out, or malformed host completion returns the fixed `completion_failed` response after the jti is consumed. A late completion result is discarded. The adapter cases run Fastify, Express, and Hono. They require both the host session cookie and the flow-cookie deletion to survive response mapping. They also require a redirect's validated status, `Location`, `Content-Type`, custom header, and empty body; a string response's status, `Content-Type`, custom header, and Unicode body; and a bodyless 2xx response's status and custom header without an inferred `Content-Type` to remain identical across the three frameworks.

## Harness helpers

Shared helpers:

| Helper | Purpose |
|---|---|
| `test/lib/adapter-flow.ts` | Shared authorize/token flow assertions for Fastify, Express, and Hono. |
| `test/lib/adapter-header-flow.ts` | Shared raw-header and duplicate-header assertions across adapters. |
| `test/lib/store-conformance.ts` | Single source for StorePort invariants across memory, sqlite, and mysql. |

Other integration and release checks use their named `test/*.test.ts` or `scripts/*.mjs` entry points.

## Packed artifact checks

Run these checks after the source-tree gates and before tagging a release.

| Scenario | Required result |
| --- | --- |
| Source-tree gates | `pnpm run typecheck`, `pnpm run check:lines`, `pnpm run check:seams`, `pnpm run check:deps`, `pnpm test`, and `pnpm run build` pass from a clean tree. |
| `npm pack --dry-run` | The tarball contains `dist/`, `docs/`, `README.md`, `LICENSE`, and `package.json` at its root. |
| Install the packed artifact in a temporary project | Public exports import without source files. |
| Run a metadata smoke test from the installed package | A configuration created from the packed artifact serves the expected metadata. |
| Check optional peers | Importing the core does not require Fastify, Express, Hono, MySQL, or Redis unless that adapter is imported. |
| Check dependency records | Every dependency and optional peer has its version, publication date, and age in the dependency ledger. |

The archived [internal test catalog](archive/internal-test-catalog-2026-08-21.md) preserves the retired implementation-batch identifiers and their detailed scenarios.
