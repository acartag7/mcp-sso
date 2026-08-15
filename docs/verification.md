# Verification plan — integration tests & pre-release gates

How mcp-sso proves a release actually works.

## Current status

> Status: **v0.3.5**. This package line is based on exact merged implementation
> commit `bfdd7b562cafce91c000c5d17c160aa289d5bee6`. It carries v0.3.4 forward and
> packages the source-tree work targeting MCP Authorization 2026-07-28: issuer
> identifiers on library-owned authorization error redirects, an optional
> exact-resource scope implication graph, native-only CIMD loopback-port
> elasticity, and the remaining governed CIMD evidence. It also centralizes
> release and conformance status, routes the contract index by task, and permits
> recorded file-limit exceptions. Registry and tag evidence belongs in the
> release and verification receipts.
>
> The §17 feature contracts are locked; CIMD §17.1, generic OIDC, and the
> Google preset are implemented. Google has reproducible
> historical live verification; CIMD was live-verified through exact runtime
> commit `af2a61f` with Cloudflare Access, Entra ID, and Google on 2026-07-28.
> A second, non-Google generic-OIDC issuer remains pending. Device flow §17.3 and the
> dedicated GitHub port in §17.6 remain contract-only. Source-tree spec
> conformance target: **MCP Authorization 2026-07-28**. Version v0.3.5 packages
> this work without making a published-artifact conformance claim; published
> v0.3.4 retains the 2025-11-25 baseline. The official stable
> [`2026-07-28`](https://github.com/modelcontextprotocol/modelcontextprotocol/releases/tag/2026-07-28)
> artifact was manually re-verified on 2026-08-02. Its DCR deprecation and
> client-side DCR `application_type` requirement align with the v0.3.2
> registration surface. On this source branch, RFC 9207 error redirects include
> the configured issuer, closing the advertised-support mismatch. The optional,
> exact-resource scope implication graph closes the scope-hierarchy runtime gap
> without changing exact behavior when policy is omitted. CIMD D00-4.5.2 gates
> the loopback port exception on exact `application_type: "native"`, and its
> dedicated frozen suite is active. The final artifact's referenced draft `-00`
> is completely mapped; D00-4.1.4 media types, D00-4.4.2 shared-cache handling,
> and D00-4.5.2 native-app policy are conformant, with no unresolved runtime or
> evidence row. This is not a published-artifact conformance claim. See the matrix in
> [§16.1](contracts/16-spec-conformance-matrix.md#161-cimd-draft--00-requirement-matrix)
> and the completed [spec-release re-verification](#spec-release-re-verification-completed-2026-08-02).
>
> Threat-model delta: v0.3.5 carries the v0.3.4 controls forward. Library-owned
> authorization error redirects now identify the configured issuer; scope
> implication is available only through a bounded, boot-validated,
> exact-resource policy; and a CIMD document receives loopback-port elasticity
> only when it declares an exact native application type. The client-auth,
> three-adapter, served-metadata, and inert document-URL evidence closes the four
> previously incomplete CIMD rows. Existing live-provider evidence and residuals
> are unchanged: CIMD has dated Cloudflare Access, Entra ID, and Google evidence;
> a second non-Google generic-OIDC issuer and the Entra deny/ceiling sweep remain
> pending. Device flow (§17.3) and the dedicated GitHub port (§17.6) remain
> contract-only.

Three tiers:

- **Tier 1 — CI tests.** Loopback servers and injected fakes only; no public network, no real provider accounts. This is the definition of "implemented".
- **Tier 2 — packed-artifact gate.** Proves the npm package shape works, not just the source tree.
- **Tier 3 — manual live verification.** Real IdPs, real MCP clients, production dogfood evidence.

Use the smallest tier that proves the claim, then keep the tiers below it green:

| You changed… | Run at minimum | What it proves |
| --- | --- | --- |
| Pure parsing or validation | Tier 1 plus the full source-tree gates | The implementation and its negative cases are deterministic. |
| A store, adapter, generated project, or protocol flow | Tier 1 with the real service or shipped entrypoint, then the release matrix | The integration works outside a unit seam. |
| Package exports or release contents | Tier 2 | The packed artifact installs and runs as users receive it. |
| A provider or client compatibility claim | Tier 3 after Tiers 1 and 2 | The named external system worked on a dated, recorded version. |

The release command is the short path through the deterministic evidence:

```bash
pnpm run build
RUN_INTEGRATION=true MYSQL_URL='mysql://…' REDIS_URL='redis://…' pnpm run test:release
```

It must end with every `RM.*` row passing. Tier 3 remains a separate owner-run
check because CI cannot prove behavior in a real tenant or signed-in client.

The contracts these tests enforce live in
[§17](contracts/17-v0-2-feature-contracts.md); the
threat rows they close are 13 and 17-25 in [`docs/threat-model.md`](threat-model.md).

Baseline (v0.1): `test/e2e-mcp-sdk.test.ts` drives register → authorize → token →
protected `/mcp` with the official MCP SDK client → refresh → replay/family
revocation → revoke. The shared store-conformance suite covers memory, sqlite,
and mysql.
Everything below extends that baseline; nothing replaces it.

## Rules

A feature is done when its real-flow Tier-1 row is covered — not when its unit
tests pass.

Tier-1 tests must be deterministic:

- Native TypeScript on Node's built-in test runner, matching the current suite.
- Loopback servers, adapter injection, fake resolvers, or fake transports. No
  public DNS, public HTTP, provider uptime, tunnels, or manual browser state.
- Injected `ClockPort` or explicit test clocks for expiry. Avoid real sleeps
  except for sub-deadline transport tests that cannot be modeled otherwise.
- Every new store-record invariant goes into the shared store-conformance suite,
  so memory/sqlite/mysql prove identical behavior.
- Keep the baseline official MCP SDK flow green after every session.

Tier-3 live checks are still required for provider/client claims. Live checks
never replace CI security tests.

## Complete shipped-feature release gate

`pnpm run test:release` is the named composition gate for the final merged tree.
Run `pnpm run build` first and provide `RUN_INTEGRATION=true`, `MYSQL_URL`, and
`REDIS_URL`. The command runs the normal full suite, checks this inventory against
the executable manifest, then prints one pass/fail receipt for every `RM.*` row.
Missing service variables, missing evidence, a skipped selected test, an
undocumented row, a removed export, or a removed shipped example makes the
command nonzero. Tier-3 provider behavior is deliberately outside this
deterministic gate.

### Shipped-feature inventory

The evidence classes are intentionally strict: unit evidence is not promoted to
a complete protocol flow, and route evidence for one sibling is not evidence for
the others. `test/release-matrix.json` is the small executable allowlist; the
normal full suite remains part of the release gate and is not duplicated here.

| Shipped feature | Current evidence class | Durable evidence |
|---|---|---|
| Protected-resource metadata and challenge | Complete protocol flow | `test/e2e-mcp-sdk.test.ts`; RM.10 |
| Authorization-server metadata | Complete protocol flow | `test/integration-full-flow.test.ts`; RM.3/RM.4 |
| Stateless DCR | Complete protocol flow | `test/e2e-mcp-sdk.test.ts` |
| Stored DCR | Complete protocol flow | `test/authorize-ceiling.test.ts`; RM.2/RM.3 |
| CIMD resolution and authorization | Route integration | RM.4/RM.6 |
| PKCE S256 | Packed-artifact flow | RM.1 |
| Consent approve and deny | Complete protocol flow | RM.1/RM.3 plus `test/bridge.test.ts` |
| Authorization-code exchange | Packed-artifact flow | RM.1 |
| Exact resource/audience binding | Complete protocol flow | RM.7/RM.8 |
| Refresh rotation | Packed-artifact flow | RM.1 |
| Replay-family revocation | Packed-artifact flow | RM.1 |
| RFC 7009 revocation | Packed-artifact flow | RM.1 |
| Stored scope accumulation | Complete protocol flow | `test/authorize-ceiling.test.ts`; RM.2 |
| Scope ceilings | Complete protocol flow | `test/authorize-entra-ceiling.test.ts`; RM.2/RM.3 |
| Machine `client_credentials` | Complete protocol flow | RM.7 |
| Access-token verification and protected `/mcp` | Complete protocol flow | RM.1-RM.4, RM.7, RM.9 |
| Fastify adapter | Complete protocol flow | RM.1/RM.2 |
| Express adapter | Complete protocol flow | RM.3 |
| Hono adapter and Request path | Complete protocol flow | RM.4 |
| Origin gate | Route integration | RM.2/RM.9 |
| Adapter request normalization | Route integration | `test/lib/adapter-header-flow.ts`; full suite |
| Hono request-body and failed-stream bounds | Route integration | `test/hono-body-limit.test.ts`; RM.4 |
| Direct/header identity | Route integration | RM.5 |
| Cloudflare Access | Complete protocol flow | `test/integration-example.test.ts`; RM.2/RM.5 |
| Entra header/group mapping | Route integration | RM.5 plus `test/authorize-entra-ceiling.test.ts` |
| Entra redirect | Complete protocol flow | `test/integration-upstream-redirect.test.ts`; RM.3/RM.5 |
| Google redirect | Complete protocol flow | `test/integration-upstream-redirect.test.ts`; RM.5 |
| Generic OIDC redirect | Complete protocol flow | `test/integration-upstream-redirect.test.ts`; RM.4/RM.5 |
| Console pairing | Packed-artifact flow | RM.1/RM.5 |
| Memory store | Complete protocol flow | RM.4/RM.10 |
| SQLite persistence, restart, migration, trusted opening | Packed-artifact flow | RM.1 plus `test/sqlite-open-admission.test.ts` |
| MySQL real service, migration, and concurrency | Complete protocol flow | RM.3/RM.10 |
| Redis real service, shared window, and outage behavior | Route integration | RM.2/RM.10 |
| JSONL audit and no-secret evidence | Packed-artifact flow | RM.1 |
| Webhook/combine audit behavior | Route integration | `test/audit-flow.test.ts`, `test/audit-webhook.test.ts`; full suite |
| Configuration snapshots | Unit only | `test/config-snapshot.test.ts`; full suite |
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

An actual private-directory npm tarball is shape-checked, installed with scripts
disabled, and invoked through its installed `.bin/mcp-sso`. The unchanged
exact-pinned scaffold is installed, typechecked, booted, paired, and driven through
stored DCR across a process restart, PKCE, approve and deny, token,
official-SDK `ping`/visible `pong`, refresh,
replay-family revocation, reauthorization, RFC 7009 revocation, SQLite restart,
and JSONL no-secret checks. Every published export root is imported from the
installed artifact and its only runtime dependency is `jose`.

### RM.2 — Fastify production-style header flow

A single real Fastify socket stack accepts a locally signed Cloudflare Access JWT
through its controlled JWKS seam, persists OAuth state in SQLite, uses stored DCR,
accumulates scopes across grants under the identity ceiling, enforces a real Redis
denial, fails open on a real Redis WRONGTYPE error, completes a protected SDK call,
rejects a foreign Origin, and refreshes after reopening SQLite.
The separately shipped Fastify-SQLite example remains covered by the full suite.

### RM.3 — Express redirect flow

A single real Express socket stack uses MySQL 8.4, stored DCR, and the shipped Entra
redirect port with deterministic local token/signature seams. It exercises the
group-derived ceiling, consent deny and approve, protected SDK call, refresh,
replay-family revocation, reauthorization, and RFC 7009 revocation.

### RM.4 — Hono CIMD flow

A single real Hono `Request` stack carries an HTTPS-shaped CIMD client through
counted DNS resolution, guarded fetch, validation, redirect matching, deterministic
generic-OIDC discovery/exchange/signature verification, authorization, protected
SDK call, refresh, and revoke without a DCR write. A failed under-cap request stream
is rejected on that same Hono app before Bridge work.

### RM.5 — Identity sibling proof

Direct identity, Cloudflare Access, Entra header, Entra redirect, Google, generic
OIDC, and console pairing each reach a shipped authorization route. Deterministic
local signing, discovery, token, and JWKS seams are used; real SaaS-account behavior
remains Tier 3 and is not claimed here.

### RM.6 — Three-adapter CIMD route parity

The same HTTPS-shaped CIMD client is authorized through Fastify, Express, and
Hono. Each route proves resolver invocation, redirect continuation, and zero DCR
store writes; this is route parity rather than three redundant refresh lifecycles.

### RM.7 — Machine credential lifecycle

An A-bound credential uses `client_secret_basic` and `client_secret_post`, obtains
tokens through the shipped route, calls protected `/mcp`, rotates through its grace
window, and is disabled. Resource B shares the client store but cannot authenticate,
rotate, disable, mutate the row, or emit a B-side success audit.

### RM.8 — Cross-resource OAuth lifecycle

Two Fastify route sets share durable OAuth state. B rejects A consent, code,
refresh, and stored scopes without a success audit or state mutation; A retains the
legitimate lifecycle, and replay at A revokes A's successor.

### RM.9 — Gateway

The real API-key-gateway example completes pairing, token issuance, and an
official-SDK backend tool call. The backend credential remains server-side while
Origin and absolute-target guards run; documented backend authorization statuses
are relayed without exposing the credential.

### RM.10 — Store and service parity

Memory, persistent SQLite, and real MySQL each complete an OAuth lifecycle. The
selected MySQL rows cover real migration and concurrent rotation, while real Redis
covers a shared window and the error path consumed by the bridge's fail-open policy.
The release command rejects absent MySQL or Redis configuration before running rows.

## Harness helpers

The current shared helpers are:

| Helper | Purpose |
|---|---|
| `test/lib/adapter-flow.ts` | Shared authorize/token flow assertions for Fastify, Express, and Hono. |
| `test/lib/adapter-header-flow.ts` | Shared raw-header and duplicate-header assertions across adapters. |
| `test/lib/store-conformance.ts` | Single source for StorePort invariants across memory, sqlite, and mysql. |

Other integration and release checks live in their named `test/*.test.ts` or
`scripts/*.mjs` entrypoints; this document does not promise helper files that do
not exist.

## Tier 1 — CI tests

### T1.HF — adapter identity-rejection parity

Run before S2.

| # | Scenario | Assert |
|---|---|---|
| HF.1 | `IdentityPort` returns `{ ok: false }` on authorize | All adapters return HTTP 401 with RFC-shaped `{ error: "access_denied", error_description: ... }`. |
| HF.2 | `IdentityPort` throws `OAuthError("access_denied", 401)` | Same HTTP 401 body on Fastify, Express, and Hono. |
| HF.3 | Non-OAuth error thrown inside a handler | 500 with a top-level string error body, never a framework-specific envelope. |

### T1.TC — token-operation clock snapshots

| # | Scenario | Assert |
|---|---|---|
| TC.1 | Authorization-code exchange succeeds with a second clock read scripted invalid | Exactly one underlying read; code-consumption time, access JWT dates, refresh expiry, and success audit share the initial snapshot. |
| TC.2 | Refresh succeeds with a second clock read scripted invalid | Exactly one underlying read; rotation, successor expiry, access JWT dates, and success audit share the initial snapshot. Compensation reuses the same rotation timestamp. |
| TC.3 | Client credentials succeeds with a second clock read scripted invalid | Exactly one underlying read; secret-expiry decision, access JWT dates, and success audit share the initial snapshot. |
| TC.4 | Initial snapshot is non-canonical or a token TTL crosses the canonical upper bound | Direct use-case rejects before code consumption, refresh rotation, client-store lookup, signing, or audit. Bridge returns sanitized 500 `internal_error`. |

### T1.HB — Hono OAuth request-body bound

| # | Scenario | Assert |
|---|---|---|
| HB.1 | Valid real bodies | JSON and URL-encoded bodies are parsed through a real Hono route, while multipart remains unparsed: the normalized Bridge request has no multipart fields and the real registration path rejects it as `invalid_request`. A compact real DCR registration with maximal recognized field values (16-by-2,048-byte redirects plus 32-by-256-byte `grant_types`) serialized entirely with JSON `\uXXXX` escapes is accepted. A consent form with maximum permitted default scopes and identity ceiling is generated and successfully posted through Hono. |
| HB.2 | Header framing | Oversized, malformed, duplicate/coalesced, conflicting, or unsafe `Content-Length` returns fixed direct 413 before parsing; a valid small declared length cannot hide a larger body. |
| HB.3 | Streaming boundary | Missing-length/chunked actual `Request` streams pass at exactly 256 KiB and return 413 at one byte over; middleware stops pulling a demand-driven hostile stream after its crossing chunk, while one already-materialized 2 MiB host chunk is rejected without reaching a parser. Transport cancellation/draining is not asserted. |
| HB.4 | Route parity | `/oauth/register`, `/oauth/authorize/approve`, `/oauth/token`, and `/oauth/revoke` all return 413 for applicable over-cap bodies. |
| HB.5 | Side effects | An over-cap request makes zero Bridge-handler, limiter, store-write, and success-audit calls. |
| HB.6 | Parser failure | A malformed below-cap body preserves the existing fail-closed adapter behavior. |
| HB.7 | Framework siblings | Real Fastify and Express probes confirm the same shared 256 KiB budget on every built-in OAuth POST for JSON, URL-encoded, multipart, and unknown media. Their bounded catch-all/raw fallback passes unsupported below-cap input to Bridge only as non-object bytes, never as OAuth fields; over-cap input returns 413 before Bridge invocation. The Express probe also admits the 245,939-byte core-bound DCR and a consent-sized form. Express applies the same bounded parser chain to caller-owned pairing POST `/oauth/authorize`; Fastify preserves automatic form parsing there and clamps a caller-declared larger route limit while leaving unrelated routes and methods unchanged. |
| HB.8 | Caller-owned pairing POST | A custom Hono `POST /oauth/authorize` mounts exported `honoOAuthBodyLimit`; an oversized form is rejected before `parseBody` or pairing verification. |
| HB.9 | Runtime request metadata | For valid-length and missing-length streams, raw-Request own-property extensions survive Hono's reconstruction and remain visible to `clientIp`; no prototype/subclass/private-state preservation is claimed. |
| HB.10 | Failed streams | Under-cap streams that error before parsing return one sanitized direct 400, emit no raw error log, and perform no parser, Bridge, limiter, store, or success-audit work. |
| HB.11 | OAuth form occurrence parity | Raw URL-encoded requests with a repeated recognized member — including empty-first/value-last and value-first/empty-last — return direct 400 `invalid_request` on register, approve, token, and revoke through Fastify, Express, and Hono. The same routes reject duplicated or otherwise ambiguous `Content-Type` occurrences instead of dropping form provenance after a framework parser accepts the body. Fastify replaces an inherited last-wins exact form parser only inside the built-in OAuth plugin scope; the caller's parent parser remains active on unrelated routes. Each route reaches its existing limiter exactly once, then performs no field selection, grant routing, durable state, or endpoint audit. A single-member adjacent path stays green, and JSON DCR arrays remain valid. Semantic mutation removes the strict repeat/header guard; wiring mutation leaves the helper intact but disconnects each production route in turn. |

### T1.S0a — MySQL store and Redis/Valkey limiter

| # | Scenario | Assert |
|---|---|---|
| S0a.1 | Shared StorePort conformance against MySQL | Same suite passes for memory, sqlite, and mysql. |
| S0a.2 | MySQL async transaction failure | Original error propagates; rollback/release cleanup errors are swallowed; connection is released. |
| S0a.3 | Timestamp ordering through MySQL | 3-ms UTC timestamps preserve lexicographic ordering. |
| S0a.4 | Two Redis limiter instances share a key/window | Second instance observes the first's increments. |
| S0a.5 | Redis unavailable | Limiter fails open; auth flow continues. |
| S0a.6 | `/oauth/revoke` admission limiting | After the Fastify, Express, or Hono body boundary, each adapter reaches the same `Bridge.handleRevoke` guard with exactly `revoke:<trusted adapter IP or unknown>`. A denial is 429 before Bridge body normalization, token hashing, use-case, store, revocation, or audit work; a limiter throw proceeds. Hono's over-cap path remains 413 before the limiter. After the form-occurrence gate, admitted singleton unknown and already-revoked tokens remain RFC 7009 HTTP 200. |
| S0a.7 | MySQL 8.4 legacy subject-width migration | Starting from `VARCHAR(255)` on exactly the auth-code and refresh-token subject columns, migration widens both to `VARCHAR(384)` and is idempotent. A 331-character Entra `issuer|sub` survives authorization-code persistence, refresh persistence, and rotation with its exact bytes; the `(subject, client_id)` utf8mb4 index remains valid, including InnoDB's appended token-hash primary key. |
| S0a.8 | Clock-bound expiry collection | Each schema-ready reference store starts its scheduler after Bridge or a direct consumer binds the exact configured `ClockPort`; pre-readiness binding fails closed. Under divergent mocked host and Bridge time, one tick retains a consent JTI while the signed JWT remains valid to the Bridge, then collects it only after the bound clock passes expiry. SQLite-reopen and two-live-MySQL-instance regressions prove the durable sweep watermark rejects the original signed expiry after physical collection while admitting an unrelated future expiry. The scheduler is non-overlapping, retries after a fixed redacted failure, does not keep the process alive, and `close()` cancels pending work and waits for an active sweep. Semantic and real-Bridge wiring mutations fail, and the shared conformance row covers Memory, SQLite, and live MySQL. (`test/store-expiry-scheduler.test.ts`, `test/bridge.test.ts`, `test/lib/store-conformance.ts`, `test/store-conformance.test.ts`, `test/store-mysql.conformance.test.ts`) |

### T1.S1a — audit sinks

| # | Scenario | Assert |
|---|---|---|
| S1a.1 | Full authorize→token→refresh flow with JSONL audit | One valid JSON object per line; expected event sequence. (`test/audit-flow.test.ts`) |
| S1a.2 | No-secrets sweep over audit output | No raw auth code, access token, refresh token, consent token, client secret, private key, or pairing code appears. Asserted on the live-flow JSONL file and on synthetic per-event-name serialization through both sinks. |
| S1a.3 | `combineAudit(throwingSink, fileSink)` during a flow | Flow succeeds; file sink still writes; failure surfaces only as diagnostic output. (`test/audit-flow.test.ts`) |
| S1a.4 | `WebhookAudit` POST via injected transport stub | Body is the exact event JSON with merged headers; `redirect:"manual"`; a never-settling stub times out via `AbortSignal.timeout`; the sink never rejects and is at-most-once. |
| S1a.5 | `WebhookAudit("http://...")` and userinfo URLs | Constructor rejects non-https config and URLs carrying `user:pass@` userinfo. |
| S1a.6 | New v0.2 event names | Every new event name has a dedicated pure serialization test across both sinks. |
| S1a.7 | Sink stderr never leaks secrets or breaks fail-open | An IO/transport error carrying a Bearer token, a long opaque run, a known header value, or a credential-bearing query string (`?access_token=…`) is redacted before reaching stderr; a throwing JSONL stderr transport still cannot reject the audit write. (`test/audit-util.test.ts` + jsonl/webhook stderr-capture tests) |
| S1a.8 | JSONL final-path redirection and special files | On an `O_NOFOLLOW` host, a live/dangling/swap-to symlink writes zero bytes to its target; FIFO remains nonblocking; directory, socket, and device targets are rejected; the sink never rejects or logs the configured path/event payload. (`test/audit-jsonl-file.test.ts`, `test/audit-jsonl-file-security.test.ts`) |
| S1a.9 | JSONL rotation and descriptor-bound append | Existing regular files append; a missing target is `0600`; a rename-and-recreate rotation directs the next complete JSONL line to the replacement file. (`test/audit-jsonl-file.test.ts`, `test/audit-jsonl-file-security.test.ts`) |
| S1a.10 | JSONL mutation witnesses | Removing `O_NOFOLLOW` makes the symlink witness modify its victim; removing the descriptor regular-file check makes the device witness stop reporting a rejected target. |
| S1a.11 | JSONL short-write framing | A controlled first short write holds its suffix while a second event starts; the same sink instance does not issue the second event's write until the first line completes, and the resulting file has two parseable lines in order. A retry failure after a positive prefix rolls the fragment back before a later event writes. (`test/audit-jsonl-file-security.test.ts`) |
| S1a.12 | JSONL permanent-disable signal | An unverified partial-line rollback emits one fixed redacted stderr diagnostic and schedules the optional closed-reason `onDisable` hook exactly once on a detached turn after `writeAuthEvent` settles. Synchronous pre-await hook work therefore stays off the authentication promise path; a throwing or rejecting hook is contained. Later events do no file work and produce no duplicate signal. The factory forwards the option. Ordinary IO failures and verified rollback never call it. (`test/audit-jsonl-file-security.test.ts`, `test/audit-jsonl-file.test.ts`) |

Notes:

- **S1a.4 transport seam.** The webhook is https-only by construction, so a
  plain-http loopback server is rejected at build time and a self-signed
  loopback cert would need an out-of-dep undici dispatcher. The test drives the
  `fetchImpl` DI seam (the codebase's pattern, cf. Redis stubs) as the transport.
- **S1a.5 why userinfo is blocked.** Credentials belong in `headers`. A fetch
  error would otherwise echo the URL into stderr.

### T1.S1b — quickstart secrets and console pairing

| # | Scenario | Assert |
|---|---|---|
| S1b.1 | First boot with empty quickstart dir | Directory `0700`, secrets file `0600`, `.gitignore` with `*`, valid signing JWK and consent secret. |
| S1b.2 | Token survives restart | Mint token, close app, boot from same dir, old token still validates. |
| S1b.3 | POSIX secrets file is `0644` | Boot fails closed with `AuthConfigError` and chmod remediation. |
| S1b.4 | Corrupt or partial secrets file | Boot fails closed; no ephemeral fallback. |
| S1b.5 | Console pairing happy path | Code generated lazily, accepted once, authorize→token→`/mcp` succeeds. |
| S1b.6 | Pairing wrong attempts | Five wrong attempts invalidate the code independent of `RateLimitPort`. |
| S1b.7 | Pairing replay/expiry | Used or expired code cannot authorize. |
| S1b.8 | Example no longer uses dev stub | `examples/fastify-sqlite` boots zero-config and completes the protected MCP flow. (`test/e2e-pairing.test.ts`) |
| S1b.9 | Pairing code never in audit | The 12-char code (canonical and `XXXX-XXXX-XXXX`) appears in no `oauth.pairing.attempt` event; `reason` is always a short enum. (`test/identity-console-pairing.test.ts`) |
| S1b.10 | Rate-limit deny ≠ throw | A denying `RateLimitPort` blocks without bumping the attempt cap; a throwing limiter fails open. (`test/identity-console-pairing.test.ts`) |
| S1b.11 | Audit JSONL on a live pairing flow | `audit.jsonl` carries `oauth.pairing.attempt` plus the v0.1 authorize/token events; no raw pairing code, auth code, or access token. (`test/e2e-pairing.test.ts`) |

Notes:

- **S1b.10 deny-vs-throw.** The correct code still succeeds after a flood of
  denials — the deny path does not consume the attempt slot.

### T1.SQ — persistent SQLite state admission

| # | Scenario | Assert |
|---|---|---|
| SQ.1 | `:memory:` and ordinary private-directory paths | `:memory:` performs no filesystem work; a new path is `0600`; an existing owner `0600` database reopens and migrates. |
| SQ.2 | Runtime path grammar | Non-string, empty/blank, NUL, and case-insensitive `file:` inputs reject before any file/URI target is created or mutated. |
| SQ.3 | Directory boundary | Missing, symlink/junction, group/other-accessible, and unsafe-ancestry directories reject before database creation/migration; accepted system/sticky ancestry is covered. A deterministic policy row proves that an ancestor owned by another non-root account rejects even at `0755` or after a read-only snapshot; a root-owned immediate-directory probe covers UID mismatch when the runner is a non-root POSIX user. File-UID mismatch needs a privileged fixture and remains manual. |
| SQ.4 | Existing target boundary | `0644`, final/dangling symlink, directory, FIFO, socket/device where safe, and multi-link targets reject without chmod, byte, or schema mutation; FIFO proof runs in a bounded child process. |
| SQ.5 | Descriptor/path identity | A deterministic descriptor-vs-replaced-path mismatch rejects. POSIX `/dev/fd` probes pin descriptor cleanup after admission and initialization failures; cleanup is one bounded attempt and cannot guarantee success after an OS-level close error. |
| SQ.6 | Preseeded OAuth state | A chosen valid refresh family/token in an unsafe directory fails store boot before use: no bridge access token, successor, or success audit, and the hostile bytes/schema remain unchanged. The same fixture in a trusted private directory is operator-owned state and may reopen. |
| SQ.7 | Restart and store siblings | Existing SQLite authorization-code, refresh-family, stored-scope, replay, schema-migration, and restart rows remain green; Memory/MySQL behavior is unchanged. |
| SQ.8 | Packed artifact (manual release proof) | Produce/install the real tarball and run new-file, reopen, URI-rejection, and hostile-directory smokes through `mcp-sso/store/sqlite`; this is not a committed CI job. |
| SQ.9 | Platform contract | Ubuntu CI proves POSIX no-follow/UID/`0600`/directory controls. Windows-specific skips name unavailable primitives, but no Windows CI runner exists; Windows ACL/private-directory guarantees remain deployer-owned and must not be reported as CI-proven. |

### T1.S2a — core `allowedScopes` ceiling

| # | Scenario | Assert |
|---|---|---|
| S2a.1 | Identity has no `allowedScopes` | Existing authorize/token/refresh behavior unchanged. |
| S2a.2 | Identity has `allowedScopes` subset | Token scopes are the intersection of requested/default/prior scopes and the ceiling. |
| S2a.3 | Empty intersection | `access_denied` over the redirect channel, after redirect validation. |
| S2a.4 | Consent-token tampering | `approve` uses `allowed_scopes` from the verified consent token, never caller input. |
| S2a.5 | Prior grants | Existing grants cannot resurrect scopes outside the current ceiling. |
| S2a.5a | Corrupt or oversized prior grant | `approve` returns `invalid_grant` before consuming the consent JTI or writing an authorization code. |
| S2a.6 | Adapter plumbing | Fastify, Express, and Hono all pass the identity object through the bridge. |

### T1.S2b — Entra group mapping

| # | Scenario | Assert |
|---|---|---|
| S2b.1 | Boot config has display-name key | Boot rejects non-GUID mapping keys. |
| S2b.2 | Mapped groups plus base scopes | Returned `allowedScopes` is the contract-required union. |
| S2b.3 | Groups map to no scopes and no base | Fail closed with the Entra no-groups/no-scopes reason. |
| S2b.4 | Overage marker present | Fail closed; `_claim_sources` is never dereferenced. |
| S2b.5 | Existing Entra config without group auth | Behavior unchanged. |
| S2b.6 | Full authorize flow | Entra-derived ceiling enforced by the S2a core flow. |
| S2b.7 | Immutable Entra subject selection | The pure validator, explicit-key verifier, remote-JWKS factory, and redirect port all prefer exact usable `oid`, otherwise exact accepted `issuer|sub`; mutable-only identity is rejected. |
| S2b.8 | Entra allowlist normalization boundary | `oid` keeps trimmed, case-insensitive matching; issuer-namespaced `sub` matches byte-for-byte. Mutable username/email matches only when `allowMutableClaims === true`, case-insensitively but without whitespace trimming. |
| S2b.9 | Stored-DCR and legacy refresh compatibility | Two no-`oid` identities sharing a mutable username do not share accumulated scopes. A pre-upgrade mutable-key refresh family preserves that subject and receives the current sliding TTL on rotation; no migration is inferred. |

### T1.S3a — machine client provisioning

| # | Scenario | Assert |
|---|---|---|
| S3a.1 | Enable with non-stored DCR | Boot fails with `AuthConfigError`. |
| S3a.2 | Provision machine client | Returns `mcc_...` id and `mcs_...` secret once; store holds only a SHA-256 hash. |
| S3a.3 | Rotate secret | New secret works; old secret gets a bounded grace expiry; max two active secrets. |
| S3a.4 | Provision with invalid scope | Rejected before store write. |
| S3a.5 | Machine-shaped DCR request | `/oauth/register` returns `invalid_client_metadata`. |
| S3a.6 | Audit events | Provision/rotate events contain no secret and no hash. |

### T1.S3b — `client_credentials` grant

| # | Scenario | Assert |
|---|---|---|
| S3b.1 | `client_secret_basic` valid | Token response succeeds; protected `/mcp` accepts the access token. |
| S3b.2 | `client_secret_post` valid | Same success path. |
| S3b.3 | Wrong or expired secret | `invalid_client` 401; Basic attempt includes `WWW-Authenticate: Basic`. |
| S3b.4 | Omitted scope | Token gets the full allowed set. |
| S3b.5 | Requested scope outside allowed set | `invalid_scope`; no token minted. |
| S3b.6 | Resource mismatch | Token request fails. |
| S3b.7 | Response shape | No `refresh_token` member exists at all. |
| S3b.8 | User grant regression | Authorization-code and refresh flows unchanged. |

### T1.GG — stored-DCR grant-generation cutover (0.3.2)

| # | Scenario | Assert |
|---|---|---|
| GG.1 | Current-generation code and refresh family across reopen/restart | Exchange and refresh still succeed. |
| GG.2 | Old binary writes a null/missing-generation code after cutover | Current binary burns it and returns `invalid_grant`, for both an unknown and an existing stored client ID. |
| GG.3 | Old binary writes a null/missing-generation refresh family, or a successor inside an existing current family, after cutover | Current binary returns `invalid_grant` before consuming it or creating a successor. |
| GG.4 | Rotation caller substitutes generation | All three stores preserve the family generation from durable state. |
| GG.5 | Legacy/non-current or wrong-resource active refresh rows exist, including inside a current family | `findGrantedScopes` excludes their scopes. |
| GG.6 | Store lacks the generation or resource-binding capability in stored-DCR mode | Construction fails closed with `AuthConfigError`; stateless-DCR operation remains unchanged. CIMD alongside stored DCR uses the same cutover generation without enabling accumulation. |

### T1.RB — authorization-code resource binding

| # | Scenario | Assert |
|---|---|---|
| RB.1 | Code created under resource A is redeemed through resource B sharing the store | `invalid_grant`; no token response or success audit. |
| RB.2 | A redemption follows the rejected B attempt | A succeeds exactly once; replay through A fails. |
| RB.3 | Shared StorePort conformance | Memory, SQLite, and MySQL return `null` for B without consuming A's code; §12 records the implementation transaction/critical-section evidence. |
| RB.4 | Custom store ignores the resource predicate and returns A's record to B | The token use-case's returned-record check yields `invalid_grant`, no token response, zero refresh writes, and zero success audits. |
| RB.5 | Concurrently invoked A/B redemption | Shared observable behavior allows only the correctly bound A exchange to return the record; implementation inspection supplies the transaction/critical-section evidence rather than claiming the fixture proves every scheduler interleaving. |
| RB.6 | A consent token is submitted to bridge B, for Approve and Deny | Both fail directly as `invalid_consent` before redirect processing, JTI consumption, code storage, or success audit; bridge A can still approve once and replay then fails. |

### T1.S4a — Generic OIDC and Google preset

| # | Scenario | Assert |
|---|---|---|
| S4a.1 | Generic discovery issuer mismatch | Boot fails. |
| S4a.2 | Discovery endpoint non-https or redirects | Boot fails. |
| S4a.3 | Valid generic id_token claims | Pure validator accepts only exact issuer, expected audience, nonce, time window, and pinned alg. |
| S4a.4 | Multi-audience token | Rejected. |
| S4a.5 | Missing PKCE support | Boot fails unless an explicit loud override is set. |
| S4a.6 | Email allowlist with unverified email | Rejected. |
| S4a.7 | Google preset config | Issuer pinned to `https://accounts.google.com`; the `hd` claim (not email domain) controls hosted-domain matching. |

Google live sign-in is Tier 3, not CI.

### T1.S4b — GitHub identity port

| # | Scenario | Assert |
|---|---|---|
| S4b.1 | OAuth URL construction | Hardcoded GitHub authorize endpoint, state, PKCE S256, `user:email` scope. |
| S4b.2 | Token exchange request | Sends `Accept: application/json` and the client secret. |
| S4b.3 | User mapping | Subject is the numeric id string; login is not identity unless the mutable-claims opt-in is set. |
| S4b.4 | Email mapping | Primary verified email only; absence allowed. |
| S4b.5 | Allowlist reject | Fails closed before bridge token issuance. |

Real GitHub OAuth sign-in is Tier 3. CI uses pure mapping tests and a stubbed
transport only if the implementation exposes one without weakening the
production contract.

### T1.S5a — device-flow store and authorization endpoint

| # | Scenario | Assert |
|---|---|---|
| S5a.1 | Store conformance extension | Device-code invariants pass for memory, sqlite, and mysql if shipped. |
| S5a.2 | Request device authorization | Response has `device_code`, `user_code`, verification URIs, `expires_in`, `interval`. |
| S5a.3 | Stored record | Raw device code and user code are hashed, not stored. |
| S5a.4 | Poll before approval | Returns `authorization_pending`. |
| S5a.5 | Too-fast poll | Returns `slow_down`; persists interval +5. |
| S5a.6 | Expired code | Not found/consumed; sweep removes expired rows. |
| S5a.7 | Wrong-code attempt cap | Five wrong submissions per IP invalidate the path independently of the external limiter. |

### T1.S5b — device verification, approval, and token grant

| # | Scenario | Assert |
|---|---|---|
| S5b.1 | Browser enters code and approves | Polling succeeds; protected `/mcp` works with the issued access token. |
| S5b.2 | Browser denies | Token polling returns terminal `access_denied`. |
| S5b.3 | Approval replay | Device consent token and approved device code are single-use. |
| S5b.4 | `allowedScopes` ceiling | Approved scopes intersected with the S2a ceiling. |
| S5b.5 | Expired token path | Polling returns terminal `expired_token`. |
| S5b.6 | Refresh token issued | Device flow is a user grant: refresh/replay/revoke semantics match baseline. |

### T1.S6a — CIMD security primitives

The CIMD enforcement contract is
[§17.1](contracts/17-v0-2-feature-contracts.md#171-cimd--client-id-metadata-documents-the-ssrf-enforcement-contract);
the
security target is [`threat-model.md` row 13](threat-model.md). These rows are
its enforcement evidence.

| # | Scenario | Assert |
|---|---|---|
| S6a.1 | URL admission table | Rejects: non-https, malformed https, root path, query, fragment, userinfo, CRLF, controls, dot segments, localhost, trailing dot, denied ports, and IP literals — including dword, octal, and hex forms. |
| S6a.2 | IP blocklist table | At least one rejection for every enumerated IPv4/IPv6 CIDR; public allow cases pass. |
| S6a.3 | IPv4-embedding IPv6 | IPv4-mapped, NAT64, 6to4, and Teredo-style prefixes blocked wholesale. |
| S6a.4 | Guarded fetch all-records DNS | Any blocked A or AAAA record rejects the whole fetch. |
| S6a.5 | Pinned connect | Transport receives the validated IP; Host/SNI stay the original hostname. |
| S6a.6 | Redirect, cap, timeout | Redirects are not followed; explicit no-redirect evidence (`redirected === false` / hop count 0) asserted, never URL comparison alone; over-cap body rejects (not truncates); deadline aborts. |
| S6a.7 | Guard cannot be bypassed | Injected low-level transport sits below admission/DNS/IP/cap/timeout checks. |
| S6a.8 | Document validator | Exact `client_id` equality, required fields, auth method, forbidden secrets, private/symmetric key material in `jwks` rejected, redirect URI hygiene, grant/response constraints. |

### T1.S6b — CIMD integration and SSRF regression

| # | Scenario | Assert |
|---|---|---|
| S6b.1 | Boot config | **No whole `cimd.fetcher` config knob** (removed — §17.1.6 decision 5): the core constructs the default guarded fetcher from the `cimd` caps + `allowLoopback` derived solely from `dev.allowInsecureLocalhost`; only the below-guard `cimdTransport`/`cimdResolver` seams (never a whole `GuardedFetcher`, never a `BridgeConfig` field) inject in tests. |
| S6b.2 | Happy path | URL-shaped `client_id` fetches the doc, validates; authorize→token→`/mcp` succeeds. |
| S6b.3 | Generic client error | Every CIMD failure returns identical client-facing error text. |
| S6b.4 | Audit detail | `oauth.cimd.fetch` records the specific reason without leaking the document body or secrets. |
| S6b.5 | Redirect URI match | Exact match required; the loopback any-port exception is gated on a document declaring exact `application_type: "native"`, with `"web"` and absent both matching exactly. **IMPLEMENTED; FROZEN SUITE ACTIVE (D00-4.5.2).** |
| S6b.6 | Scope accumulation (CIMD deferred) | CIMD ids do NOT accumulate: a genuine CIMD authorization reports `priorScopes = []` and mints only the requested (ceiling-bounded) scopes in BOTH DCR modes; seed an active legacy URL-keyed refresh row with a broader scope and prove it is never unioned. Control: an opaque stored-DCR client still accumulates. (§17.1.6 decision 3.) |
| S6b.7 | Metadata flag | `client_id_metadata_document_supported` appears only when enabled. |
| S6b.8 | Cache (freshness) | Cache HIT reuses only a fresh validated document. The shared cache gives valid `s-maxage` priority over `max-age`, rejects `private`, `no-store`, `no-cache`, and `Vary: *`, and includes Age, valid Date apparent age, and observed response delay. It is bounded LRU, per Bridge, raw-client-id keyed, and serves direct-mode prepare plus upstream redirect resolution. |
| S6b.9 | SSRF negative suite | Encoded dot segments, IP-literal tricks, blocked DNS records, rebinding, redirect-to-blocked-host, over-cap body, slow endpoint, mismatched `client_id`, and `client_secret` doc all fail with identical client-facing text. |
| S6b.10 | Upstream-redirect CIMD | Doc resolved + validated ONCE at authorize, carried in the signed `cimd` flow claim, consumed at callback with **NO re-fetch**: inject a fetcher whose `fetch()` THROWS at callback and prove the CIMD flow still completes (carry-forward). Three-way dispatch: `HTTPS://` / `http://` / `ftp://`, and lowercase-`https://` while `cimd` is disabled ⇒ direct `invalid_client` (never a stateless fallback, never an IdP hop). Callback claim/mode/redirect matrix (row 5a) rejects a mismatch as `flow_cookie_invalid`; approve-time scheme gate rejects a legacy URL-shaped stateless token as `invalid_consent`. |

A happy path alone does not close S6b. The negative SSRF suite is the security
evidence.

### T1.S7a — examples

| # | Scenario | Assert |
|---|---|---|
| S7a.1 | Fastify example | Boots and completes authorize→token→protected `/mcp`. |
| S7a.2 | Express example | Same flow. |
| S7a.3 | Hono example | Same flow. |
| S7a.4 | API-key gateway example | Backend key read once at boot, injected only server-to-backend, never in client-visible traffic, token claims, or audit logs. |

## Tier 2 — packed-artifact release gate

Run after the source-tree gates, before tagging.

| # | Scenario | Assert |
|---|---|---|
| T2.1 | Source-tree gates | `pnpm run typecheck`, `pnpm run check:lines`, `pnpm run check:seams`, `pnpm test`, `pnpm run build` all green from a clean tree. |
| T2.2 | `npm pack --dry-run` | Tarball contains `dist`, README, LICENSE, and intended docs only. |
| T2.3 | Install packed artifact in a temp project | Public exports import successfully without source files. |
| T2.4 | Minimal metadata smoke from the installed package | Config + metadata endpoint works from the installed package. |
| T2.5 | Optional peer behavior | Importing core does not require fastify/express/hono/mysql/redis unless that adapter is imported. |
| T2.6 | Dependency ledger | Every new dependency or optional peer has version, publish date, and age recorded. |

**2026-07-28 receipt.** T2.1-T2.6 passed from clean commit
`e71a2bbaf6902f98502a788a8d1e4bfc604b9bbc`: 866 tests passed with zero
skipped; the tarball contained only `dist/`, `docs/`, `README.md`, `LICENSE`,
and `package.json`; a temporary install without optional peers imported the
eight peer-free public entry points, all 13 public entry points imported after
their declared optional peers were installed, and the installed root package
produced authorization-server and protected-resource metadata.

**v0.3.1 prepublication candidate input (2026-07-28).** Exact merged
implementation commit `d9b4f089dc46cf832ac598c5fce2401b095a2654`
passed typecheck, line, acceptance-seam, and dependency-policy checks; 886 local
tests and 910 hosted integration tests passed with zero skipped, followed by a
clean build and `npm pack --dry-run`. The 200-file dry-run artifact had only
`dist/`, `docs/`, `README.md`, `LICENSE`, and `package.json` at its root. That
input still declares package version 0.3.0 because the version bump is a
separate release commit. It is not evidence of a `v0.3.1` tag or npm
publication; the final versioned head, hosted CI and review, publish dry-run,
and installed-artifact smoke remain release gates.

**v0.3.2 prepublication candidate input (2026-07-28).** Exact merged
implementation commit `526ad2a2f1167ba7d905cb05cd3c44ce3a2c1d99`
contains the stored-DCR grant-generation cutover. Version candidate
`6b87d804084d899aa29942ae1348f9983ac79619` passed typecheck, line,
acceptance-seam, dependency-policy, process-guard, and CodeQL checks; 899 local
tests and 926 hosted tests with real MySQL and Redis passed with zero skipped,
followed by a clean build. Its 204-file dry-run artifact declared version
0.3.2 and contained only `dist/`, `docs/`, `README.md`, `LICENSE`, and
`package.json`. The documentation-status correction after that candidate must
pass the same exact-head gates and review before merge. This receipt is not
evidence of a `v0.3.2` tag or npm publication; the final versioned head,
publish workflow, and installed registry-artifact smoke remain release gates.

**v0.3.3 prepublication candidate input (2026-08-04).** The release-only
candidate based on exact merged implementation commit
`5725e77d26651f4c0a303554a3f0fd3bdf897df8` declares package version 0.3.3.
The clean source-tree suite passed 1,012 tests with nine platform or
release-selector skips and zero failures. The integration-enabled suite passed
1,051 tests with nine release-selector skips and zero failures against
disposable MySQL 8.4 and Redis 7.4 services; the executable release matrix then
reported all ten required rows passing with no required row skipped. The
210-file tarball contained only `dist/`, `docs/`, `README.md`, `LICENSE`, and
`package.json`, and its package manifest retained `jose` as the sole runtime
dependency. RM.1 installed that tarball and completed the generated-server
lifecycle through the installed executable, including the official-SDK
`ping`/`pong`, refresh rotation, replay-family rejection, and revocation. A
separate temporary consumer imported the root, Fastify, Express, and Hono entry
points and used the installed executable to scaffold the five documented
project files. This is prepublication evidence, not evidence of a `v0.3.3` tag,
npm publication, or GitHub Release.

**v0.3.4 prepublication candidate input (2026-08-14).** The release-only
candidate based on exact merged implementation commit
`b16de3bee8f35021aeb86f6c23ff5d8ea95a5408` declares package version 0.3.4.
The clean source-tree suite passed 1,214 tests with nine platform or
release-selector skips and zero failures. The integration-enabled suite passed
1,269 tests with nine release-selector skips and zero failures against
disposable MySQL 8.4 and Redis 7 services; the executable release matrix then
reported all ten required rows passing with no required row skipped. The
240-file dry-run tarball contained only `dist/`, `docs/`, `README.md`, `LICENSE`,
and `package.json` at its root, and its package manifest retained `jose` as the
sole runtime dependency. RM.1 installed the actual tarball and completed the
generated-server lifecycle through the installed executable, including the
official-SDK `ping`/`pong`, refresh rotation, replay-family rejection, and
revocation; all 13 public entry points imported. This is prepublication
evidence, not evidence of a `v0.3.4` tag, npm publication, or GitHub Release.

**v0.3.5 prepublication candidate input (2026-08-15).** The release-only
candidate based on exact merged implementation commit
`bfdd7b562cafce91c000c5d17c160aa289d5bee6` declares package version 0.3.5.
The clean source-tree suite passed 1,246 tests with nine platform or
release-selector skips and zero failures. The integration-enabled suite passed
1,301 tests with nine release-selector skips and zero failures against
disposable MySQL 8.4 and Redis 7 services; the executable release matrix then
reported all ten required rows passing with no required row skipped. The
242-file dry-run tarball contained only `dist/`, `docs/`, `README.md`, `LICENSE`,
and `package.json` at its root, and its package manifest retained `jose` as the
sole runtime dependency. RM.1 installed the actual tarball, exercised the
generated server through the installed executable, completed the official-SDK
`ping`/`pong`, refresh, replay-rejection, and revocation lifecycle, and imported
all 13 public entry points. This is prepublication evidence, not evidence of a
`v0.3.5` tag, npm publication, GitHub Release, or published-artifact conformance
claim.

### Release-authority gate

Before tagging, verify the `publish` GitHub Environment through the repository
API: the owner is a required reviewer, admin bypass is disabled, and the only
custom deployment branch policy is a tag pattern `v*.*.*`. A
`workflow_dispatch` run must execute the artifact dry-run and must not enter the
OIDC publish or GitHub Release jobs. For the real release, the tag must equal
`v${package.version}`; the build job produces one tarball and SHA-256 file, the
OIDC job publishes that exact digest-verified tarball without checkout,
dependency installation, or repository scripts, and the no-OIDC release job
runs only after publication succeeds.

## Tier 3 — manual live verification

Tier 3 proves provider/client compatibility. It must never be the only proof for
a security property.

| Area | Live target | Evidence to record |
|---|---|---|
| Captatum dogfood | Deployed Captatum using mcp-sso | Date, mcp-sso commit/package, Captatum commit, client rows, caveats. |
| Entra groups | Real tenant, mapped groups, overage/guest caveats | Date, sanitized tenant setup notes, pass/fail of mapped/no-map/overage paths. |
| Google identity | Real Google OAuth app | Stable subject observed; allowed/rejected allowlist cases; hosted-domain behavior if configured. |
| GitHub identity | Real GitHub OAuth app | Numeric id subject, verified primary email behavior, allowlist reject. |
| Device flow | Real terminal + browser | Request code, approve/deny, poll success/failure, protected `/mcp`. |
| CIMD | Owner-controlled HTTPS metadata URL | The clean-main rerun exercised guarded-fetcher deny legs. Claude Code 2.1.220 then completed CIMD authorization and protected calls through exact runtime commit `af2a61f` with Cloudflare Access, Entra, and Google. |
| MCP clients | curl, official MCP SDK, Claude Code, claude.ai, ChatGPT where available | Date, client version if known, exact caveat if any row is partial. |

README conformance rows can be upgraded only after the relevant Tier-3 evidence
exists.

### Tier 3 requirements

Live checks need operator-owned accounts and deployable URLs. Never put these
values in git. Record only dates, commits, provider/client versions, and
sanitized setup notes.

| Area | Needed before the run |
|---|---|
| Common | Node 24, corepack/pnpm, clean tree, current package commit, HTTPS issuer URL, redirect URL registered with the provider/client, audit log location, scratch browser profile or private window. |
| Release smoke | Temp dir outside the repo, packed tarball path, npm network access only when testing the published package, command transcript for import/metadata smoke. |
| Captatum dogfood | `~/project/smart-fetch` access, deploy credentials, target environment, production-like DB path, Cloudflare Access test identity, rollback plan, exact MCP clients to exercise. |
| Entra groups | Azure tenant, app registration, client secret, redirect URI, test users, group GUIDs for mapped and unmapped cases, scope mapping, owner-run plan for the overage case. |
| Google identity | Google Cloud project, OAuth consent screen, OAuth client id/secret, redirect URI, test account, allowlist values, optional Workspace hosted-domain account for `hd` testing. |
| GitHub identity | GitHub OAuth App, client id/secret, callback URL, test account with verified primary email, numeric user id for allowlist, mutable-login allowlist case if enabled. |
| Device flow | Terminal client session, browser session, identity source for the approving user, short TTL config for expiry checks, screenshots or transcript of approve/deny/poll. |
| CIMD | Owner-controlled HTTPS metadata-document URL, valid document, redirect URI under owner control, cache-control variants, confirmation the deployment uses the guarded fetcher. Negative SSRF proof stays Tier 1. |
| MCP clients | curl command, official MCP SDK version, Claude Code version, claude.ai test window, ChatGPT connector setup if available, per-client caveat field. |

Minimum evidence per live row:

1. Date and timezone.
2. mcp-sso commit or npm version.
3. Provider/client name and version when visible.
4. Sanitized config shape — never secrets.
5. Pass/fail for each scenario named in the Tier-3 row.
6. Exact caveat if any step was skipped, simulated, or only partially verified.
7. Protocol-accurate step names: a CIMD flow starts with an HTTPS `client_id`
   at authorize and does not call `/oauth/register`; only a DCR flow includes
   registration.

## Spec-release re-verification (completed 2026-08-02)

MANUAL maintainer receipt — not automated and not CI-enforced. Checked against:

- official stable release/tag
  [`2026-07-28`](https://github.com/modelcontextprotocol/modelcontextprotocol/releases/tag/2026-07-28),
  commit `5f5440bb26a62e2cf3440b92da5a667efa03b267`;
- dated [Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization),
  [Client Registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration),
  and [Key Changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
  pages; and
- the tagged source files under
  `docs/specification/2026-07-28/basic/authorization/` in the official
  `modelcontextprotocol/modelcontextprotocol` repository.

- [x] **(a) DCR deprecation wording.** Final text retains DCR as an optional
  `MAY` mechanism, marks it Deprecated, directs new implementations to CIMD,
  and retains DCR for backwards compatibility with authorization servers that
  do not support CIMD. The v0.3.2 shape — CIMD preferred, DCR retained for
  compatibility — is accurate.
- [x] **(b) CIMD normative level + draft revision.** Final text keeps CIMD at
  `SHOULD` and cites `draft-ietf-oauth-client-id-metadata-document-00`. The
  implementation was built against later hardening and proves the explicitly
  checked MCP-page requirements through capability advertisement in
  `src/metadata.ts`, exact document binding in `src/cimd/document.ts`, redirect
  binding through `src/cimd/registration.ts`, and the frozen
  `test/acceptance/cimd/` suites. The complete 44-statement draft `-00` mapping
  is now in [§16.1](contracts/16-spec-conformance-matrix.md#161-cimd-draft--00-requirement-matrix).
  D00-4.1.4 now restricts alternate `+json` media types to the `application/`
  tree. The shared CIMD cache now observes the applicable shared-cache
  directives, corrected `Age`/`Date` age, and bounded resident time. One
  confirmed runtime mismatch remains: the loopback port exception is applied
  without evaluating RFC 9700's native-app precondition — plus four unresolved
  test-evidence rows.
- [x] **(c) RFC 9207 `iss` + `application_type`.** Final text keeps
  authorization-server inclusion of `iss` at `SHOULD`, including error
  responses, with a signposted future `MUST`; a server that includes it `MUST`
  advertise `authorization_response_iss_parameter_supported: true`. MCP clients
  still `MUST` send an appropriate DCR `application_type`. v0.3.2 validates
  `"native"`/`"web"`, defaults omission to OIDC's `"web"`, and enforces stored
  per-type redirect policy. It advertises RFC 9207 support and emits `iss` on
  successful code responses, but `buildErrorRedirect` omits `iss` from
  redirected errors.
- [x] **(d) Record the outcome.** `docs/contracts.md`, normative references, the
  §9 bridge contract, §16 matrix, §17 CIMD citation, this receipt, and the
  contributor-facing status were updated.

**Verdict:** final checked, but MCP Authorization 2026-07-28 conformance remains
pending on three known items:

1. **RFC 9207 error responses.** `src/challenge.ts` builds
   `error`/`state`/`error_description` redirects without `iss`;
   `src/authorize.ts`, `src/adapters/http.ts`, and
   `src/adapters/upstream-flow-internals.ts` use that builder. Successful
   responses add `iss` in `src/authorize-internals.ts`, while AS metadata
   advertises support in `src/metadata.ts`.
2. **Scope hierarchies.** The final Authorization text says servers `MUST`
   account for hierarchies where a broader scope implies narrower scopes.
   `src/scopes.ts` `requireScope` currently performs exact array membership and
   has no hierarchy policy or proof.
3. **CIMD draft `-00` conformance.** The final artifact normatively references
   CIMD draft `-00`. The complete §16.1 mapping has **one confirmed runtime
   mismatch**, reproduced by probe: D00-4.5.2 — `cimdRedirectMatches`
   (`src/cimd/registration.ts:82-95`) applies RFC 9700's native-app-only
   loopback port exception without evaluating the client type, so a document
   declaring `application_type: "web"` still receives it.

   D00-4.1.4 is closed: alternate `+json` media types are restricted to the
   `application/` tree, with hostile direct and upstream resolution tests.
   Four rows also lack complete hostile or shipped-route evidence: symmetric
   client-auth declarations (D00-4.1.5), adapter route parity (D00-4.1, D00-5.1),
   and inert document-contained URLs (D00-6.5.2).

These are separate contract/runtime follow-ups. Counted individually they are
**three runtime defects** (RFC 9207 error responses, scope hierarchies, and the
CIMD native-app precondition)
plus **four CIMD test-evidence rows**. The conformance target must
not move from 2025-11-25 until every one of them is resolved and the resulting
implementation passes the full release gates.

**Closure note (2026-08-14):** item 1 above is superseded on this source branch.
The shared builder now requires bridge config, and core Deny, adapter-mapped
errors, and upstream callback rows 7/8/10/11 include its exact issuer while
direct errors remain unredirected. Symmetric client-auth declarations now have
direct and upstream hostile evidence. The six-cell shipped-adapter matrix now
proves direct and upstream resolution plus served metadata on all three
frameworks. Hostile document-contained URLs are inert through direct and
upstream callback-to-consent flows. The current remainder is **two runtime
defects** and **no unresolved CIMD test-evidence rows**; the target stays
2025-11-25.

**Scope closure note (2026-08-14):** item 2 above is also superseded on this
source branch. `createBridgeConfig` boot-validates and deeply freezes a bounded,
exact-resource implication graph; `requireScope` stays exact unless explicitly
passed that policy; and `RequestAuthorizer` passes it for transitive sufficiency
checks without adding implied strings to the token. The current remainder is
**one runtime defect** plus **four CIMD test-evidence rows**; the target stays
2025-11-25.

### Corrections after the 2026-08-02 receipt (append-only)

- **2026-08-14 final source-tree correction:** the dated verdict and incremental
  closure notes above are retained as historical evidence and superseded for
  current-source status. RFC 9207 error redirects carry the configured issuer;
  the bounded exact-resource implication graph closes scope hierarchy handling;
  and D00-4.5.2 validates and carries optional `application_type`, grants the
  loopback any-port exception only to exact `"native"`, and is pinned by its
  active frozen four-group suite. The source tree therefore targets MCP
  Authorization 2026-07-28 with no unresolved runtime or CIMD evidence row.
  Published v0.3.4 retains its earlier baseline.

## Done rules

Per build session:

1. Add or update the Tier-1 rows for that session.
2. Keep the baseline official MCP SDK flow green.
3. Run `pnpm run typecheck`, `pnpm run check:lines`, `pnpm run check:seams`,
   `pnpm test`, `pnpm run build`.
4. Push and confirm GitHub CI green.
5. Update roadmap memory with the commit SHA and any Tier-3 live status.

For the v0.3 release:

1. All Tier-1 rows for shipped features pass in CI.
2. Tier 2 packed-artifact gate passes.
3. Required Tier-3 rows for public README claims have dated evidence.
4. The finalized MCP Authorization spec re-read against
   [§16](contracts/16-spec-conformance-matrix.md) and
   [§17](contracts/17-v0-2-feature-contracts.md)
   before any v1.0 language is used.

## Status

The v0.3 feature rows already implemented on `main` are backed by the current
automated suite; rows for unshipped GitHub identity and device flow remain
future plans, not release claims. A 2026-07-26/27 patched, uncommitted checkout
based on `ee8994a` produced CIMD and refresh-replay observations, but its exact
dirty tree was not archived and those observations do not qualify as verified
rows under the minimum evidence contract. On
2026-07-28, an autonomous clean-main rerun at `e71a2bb` completed three
metadata/tokenless-challenge probes and DCR registrations, Cloudflare Access
path gating, public-CIMD resolution to authorization redirects on the Entra-
and Google-configured gateways, and the CIMD literal-IP, DNS-rebinding,
DNS-failure, non-200, content-type, size, and timeout deny legs.
The durable sanitized receipt is in
[`docs/live-verification.md`](live-verification.md#clean-main-rerun-receipt-2026-07-28).
At exact runtime commit `af2a61f`, Claude Code 2.1.220 then completed CIMD
authorization and protected `status` calls with Cloudflare Access, Entra, and
Google. A corrected refresh harness required and observed 200 responses for
A→B→C rotation, HTTP 400 `invalid_grant` for replayed A, and HTTP 400
`invalid_grant` for current C after family revocation. Retained client results
and all three audit logs contained zero backend-key matches.

The packed-artifact pre-tag smoke passed at exact clean-main commit `e71a2bb`.
The published `mcp-sso@0.3.0` artifact repeated the eight peer-free and all-13
with-peers import smokes, produced both metadata documents, and carried verified
registry signatures and attestations. The implementation was reviewed against `2026-07-28-RC`, and the official
stable artifact was manually checked on 2026-08-02. The published release keeps
the three-gap result in that dated receipt. This source branch closes RFC 9207
error redirects, scope-hierarchy handling, and the CIMD native-app policy. The
The source tree therefore targets MCP Authorization 2026-07-28 with no unresolved
runtime or CIMD evidence row. Version v0.3.5 packages that work without making a
published-artifact conformance claim; published v0.3.4 retains its earlier
baseline.
Historical Codex CLI success remains recorded, but installed Codex CLI 0.144.1
showed an RFC 9207 `iss` callback regression on 2026-07-28; current
compatibility awaits upstream resolution and retest.
