# Internal test catalog through 2026-08-21

This dated record preserves the internal test-group identifiers that were removed from the current release reference. Names such as `S4a` described implementation batches, not product capabilities. Use the current [release verification reference](../verification.md) to decide what must pass now.

## Tier 1 CI tests

### T1.HF: adapter identity-rejection parity

This group precedes S2.

| # | Scenario | Assert |
|---|---|---|
| HF.1 | `IdentityPort` returns `{ ok: false }` on authorize | All adapters return HTTP 401 with RFC-shaped `{ error: "access_denied", error_description: ... }`. |
| HF.2 | `IdentityPort` throws an `OAuthError` | Fastify, Express, and Hono preserve only allowlisted 401/403 status, fix code/description/audit reason, drop redirects, and map every other status to generic 500. |
| HF.3 | Non-OAuth error thrown inside a handler | 500 with a top-level string error body, never a framework-specific envelope. |

### T1.TC: token-operation clock snapshots

| # | Scenario | Assert |
|---|---|---|
| TC.1 | Authorization-code exchange succeeds with a second clock read scripted invalid | Exactly one underlying read. Code-consumption time, access JWT dates, refresh expiry, and success audit share the initial snapshot. |
| TC.2 | Refresh succeeds with a second clock read scripted invalid | Exactly one underlying read. Rotation, successor expiry, access JWT dates, and success audit share the initial snapshot. Compensation reuses the same rotation timestamp. |
| TC.3 | Client credentials succeeds with a second clock read scripted invalid | Exactly one underlying read. Secret-expiry decision, access JWT dates, and success audit share the initial snapshot. |
| TC.4 | Initial snapshot is non-canonical or a token TTL crosses the canonical upper bound | Direct use-case rejects before code consumption, refresh rotation, client-store lookup, signing, or audit. Bridge returns sanitized 500 `internal_error`. |

### T1.HB: Hono OAuth request-body bound

| # | Scenario | Assert |
|---|---|---|
| HB.1 | Valid real bodies | JSON and URL-encoded bodies are parsed through a real Hono route, while multipart remains unparsed: the normalized Bridge request has no multipart fields and the real registration path rejects it as `invalid_request`. A compact real DCR registration with maximal recognized field values (16-by-2,048-byte redirects plus 32-by-256-byte `grant_types`) serialized entirely with JSON `\uXXXX` escapes is accepted. A consent form with maximum permitted default scopes and identity ceiling is generated and successfully posted through Hono. |
| HB.2 | Header framing | Oversized, malformed, duplicate/coalesced, conflicting, or unsafe `Content-Length` returns fixed direct 413 before parsing. A valid small declared length cannot hide a larger body. |
| HB.3 | Streaming boundary | Missing-length/chunked actual `Request` streams pass at exactly 256 KiB and return 413 at one byte over. Middleware stops pulling a demand-driven hostile stream after its crossing chunk, while one already-materialized 2 MiB host chunk is rejected without reaching a parser. Transport cancellation/draining is not asserted. |
| HB.4 | Route parity | `POST /oauth/register`, `/oauth/authorize/approve`, `/oauth/token`, and `/oauth/revoke` all return 413 for applicable over-cap bodies. |
| HB.5 | Side effects | An over-cap request makes zero Bridge-handler, limiter, store-write, and success-audit calls. |
| HB.6 | Parser failure | A malformed below-cap body preserves the existing fail-closed adapter behavior. |
| HB.7 | Framework siblings | Real Fastify and Express probes confirm the same shared 256 KiB budget on every built-in OAuth POST for JSON, URL-encoded, multipart, and unknown media. Before field selection, Fastify, Express, and Hono admit a parsed body only for exactly one supported JSON or URL-encoded media essence. Unsupported, absent, or ambiguous media reach Bridge with no body even when an earlier application parser populated the framework body slot. Over-cap input owned by the adapter returns 413 before Bridge invocation. An earlier application parser still owns its byte accounting and error response. The Express probe also admits the 245,939-byte core-bound DCR and a consent-sized form. Express applies the same bounded parser chain to caller-owned pairing POST `/oauth/authorize`. Fastify preserves automatic form parsing there and clamps a caller-declared larger route limit while leaving unrelated routes and methods unchanged. |
| HB.8 | Caller-owned pairing POST | A custom Hono `POST /oauth/authorize` mounts exported `honoOAuthBodyLimit`. An oversized form is rejected before `parseBody` or pairing verification. |
| HB.9 | Runtime request metadata | For valid-length and missing-length streams, raw-Request own-property extensions survive Hono's reconstruction and remain visible to `clientIp`. No prototype/subclass/private-state preservation is claimed. |
| HB.10 | Failed streams | Under-cap streams that error before parsing return one sanitized direct 400, emit no raw error log, and perform no parser, Bridge, limiter, store, or success-audit work. |
| HB.11 | OAuth form occurrence parity | Raw URL-encoded requests with a repeated recognized member, including empty-first/value-last and value-first/empty-last, return direct 400 `invalid_request` on register, approve, token, and revoke through Fastify, Express, and Hono. The same routes reject duplicated or otherwise ambiguous `Content-Type` occurrences instead of dropping form provenance after a framework parser accepts the body. Fastify replaces an inherited last-wins exact form parser only inside the built-in OAuth plugin scope. The caller's parent parser remains active on unrelated routes. Each route reaches its existing limiter exactly once, then performs no field selection, grant routing, durable state, or endpoint audit. A single-member adjacent path stays green, and JSON DCR arrays remain valid. Semantic mutation removes the strict repeat/header guard. Wiring mutation leaves the helper intact but disconnects each production route in turn. |

### T1.S0a: MySQL store and Redis or Valkey limiter

| # | Scenario | Assert |
|---|---|---|
| S0a.1 | Shared StorePort conformance against MySQL | Same suite passes for memory, sqlite, and mysql. |
| S0a.2 | MySQL async transaction failure | Original error propagates. Rollback/release cleanup errors are swallowed. Connection is released. |
| S0a.3 | Timestamp ordering through MySQL | 3-ms UTC timestamps preserve lexicographic ordering. |
| S0a.4 | Two Redis limiter instances share a key/window | Second instance observes the first's increments. |
| S0a.5 | Redis unavailable | The Redis adapter rethrows the outage. Stored registration maps it to a direct 503 before body, durable-state, or audit work. Stateless registration and authorize/approve/token/revoke remain fail-open. (`test/stored-dcr-rate-limit.test.ts`, `test/bridge.test.ts`, and the three-adapter shared flow) |
| S0a.6 | `/oauth/revoke` admission limiting | After the Fastify, Express, or Hono body boundary, each adapter reaches the same `Bridge.handleRevoke` guard with exactly `revoke:<trusted adapter IP or unknown>`. A denial is 429 before Bridge body normalization, token hashing, use-case, store, revocation, or audit work. A limiter throw proceeds. Hono's over-cap path remains 413 before the limiter. After the form-occurrence gate, admitted singleton unknown and already-revoked tokens remain RFC 7009 HTTP 200. |
| S0a.7 | MySQL 8.4 legacy subject-width migration | Starting from `VARCHAR(255)` on exactly the auth-code and refresh-token subject columns, migration widens both to `VARCHAR(384)` and is idempotent. A 331-character Entra `issuer|sub` survives authorization-code persistence, refresh persistence, and rotation with its exact bytes. The `(subject, client_id)` utf8mb4 index remains valid, including InnoDB's appended token-hash primary key. |
| S0a.8 | Clock-bound expiry collection | Each schema-ready reference store starts its scheduler after Bridge or a direct consumer binds the exact configured `ClockPort`. Pre-readiness binding fails closed. Under divergent mocked host and Bridge time, one tick retains a consent JTI while the signed JWT remains valid to the Bridge, then collects it only after the bound clock passes expiry. SQLite-reopen and two-live-MySQL-instance regressions prove the durable sweep watermark rejects the original signed expiry after physical collection while admitting an unrelated future expiry. A live MySQL scheduler regression proves its five-minute replica horizon preserves authorization-code exchange and refresh rotation at the allowed slow-clock boundary. The scheduler is non-overlapping, retries after a fixed redacted failure, does not keep the process alive, and `close()` cancels pending work and waits for an active sweep. Semantic and real-Bridge wiring mutations fail, and the shared conformance row covers Memory, SQLite, and live MySQL. (`test/store-expiry-scheduler.test.ts`, `test/bridge.test.ts`, `test/lib/store-conformance.ts`, `test/store-conformance.test.ts`, `test/store-mysql.conformance.test.ts`) |

### T1.S1a: audit sinks

| # | Scenario | Assert |
|---|---|---|
| S1a.1 | Full authorize, token, and refresh flow with JSONL audit | One valid JSON object per line and the expected event sequence. (`test/audit-flow.test.ts`) |
| S1a.2 | No-secrets sweep over audit output | No raw auth code, access token, refresh token, consent token, client secret, private key, or pairing code appears. Asserted on the live-flow JSONL file and on synthetic per-event-name serialization through both sinks. |
| S1a.3 | `combineAudit(throwingSink, fileSink)` during a flow | Flow succeeds. File sink still writes. Failure surfaces only as diagnostic output. (`test/audit-flow.test.ts`) |
| S1a.4 | `WebhookAudit` POST via injected transport stub | Body is the exact event JSON with merged headers. `redirect:"manual"`. A never-settling stub times out via `AbortSignal.timeout`. The sink never rejects and is at-most-once. |
| S1a.5 | `WebhookAudit("http://...")` and userinfo URLs | Constructor rejects non-https config and URLs carrying `user:pass@` userinfo. |
| S1a.6 | New v0.2 event names | Every new event name has a dedicated pure serialization test across both sinks. |
| S1a.7 | Sink stderr never leaks secrets or breaks fail-open | An IO/transport error carrying a Bearer token, a long opaque run, a known header value, or a credential-bearing query string (`?access_token=…`) is redacted before reaching stderr. A throwing JSONL stderr transport still cannot reject the audit write. (`test/audit-util.test.ts` + jsonl/webhook stderr-capture tests) |
| S1a.8 | JSONL final-path redirection and special files | On an `O_NOFOLLOW` host, a live/dangling/swap-to symlink writes zero bytes to its target. FIFO remains nonblocking. Directory, socket, and device targets are rejected. The sink never rejects or logs the configured path/event payload. (`test/audit-jsonl-file.test.ts`, `test/audit-jsonl-file-security.test.ts`) |
| S1a.9 | JSONL rotation and descriptor-bound append | Existing regular files append. A missing target is `0600`. A rename-and-recreate rotation directs the next complete JSONL line to the replacement file. (`test/audit-jsonl-file.test.ts`, `test/audit-jsonl-file-security.test.ts`) |
| S1a.10 | JSONL mutation witnesses | Removing `O_NOFOLLOW` makes the symlink witness modify its victim. Removing the descriptor regular-file check makes the device witness stop reporting a rejected target. |
| S1a.11 | JSONL short-write framing | A controlled first short write holds its suffix while a second event starts. The same sink instance does not issue the second event's write until the first line completes, and the resulting file has two parseable lines in order. A retry failure after a positive prefix rolls the fragment back before a later event writes. (`test/audit-jsonl-file-security.test.ts`) |
| S1a.12 | JSONL permanent-disable signal | An unverified partial-line rollback emits one fixed redacted stderr diagnostic and schedules the optional closed-reason `onDisable` hook exactly once on a detached turn after `writeAuthEvent` settles. Synchronous pre-await hook work therefore stays off the authentication promise path. A throwing or rejecting hook is contained. Later events do no file work and produce no duplicate signal. The factory forwards the option. Ordinary IO failures and verified rollback never call it. (`test/audit-jsonl-file-security.test.ts`, `test/audit-jsonl-file.test.ts`) |

The S1a.4 test uses the injected `fetchImpl` transport. `WebhookAudit` rejects an HTTP loopback URL, and a self-signed loopback certificate would require an extra Undici dispatcher.

S1a.5 rejects URL userinfo because a fetch error can include the URL in stderr. Webhook credentials belong in `headers`.

### T1.S1b: quickstart secrets and console pairing

| # | Scenario | Assert |
|---|---|---|
| S1b.1 | First boot with empty quickstart dir | Directory `0700`, secrets file `0600`, `.gitignore` with `*`, valid signing JWK and consent secret. |
| S1b.2 | Token survives restart | Mint token, close app, boot from same dir, old token still validates. |
| S1b.3 | POSIX secrets file is `0644` | Boot fails closed with `AuthConfigError` and chmod remediation. |
| S1b.4 | Corrupt or partial secrets file | Boot fails closed. No ephemeral fallback. |
| S1b.5 | Console pairing happy path | The code is generated lazily and accepted once. Authorization, token exchange, and the protected `/mcp` call succeed. |
| S1b.6 | Pairing wrong attempts | Five wrong attempts invalidate the code independent of `RateLimitPort`. |
| S1b.7 | Pairing replay/expiry | Used or expired code cannot authorize. |
| S1b.8 | Example no longer uses dev stub | `examples/fastify-sqlite` boots zero-config and completes the protected MCP flow. (`test/e2e-pairing.test.ts`) |
| S1b.9 | Pairing code never in audit | The 12-char code (canonical and `XXXX-XXXX-XXXX`) appears in no `oauth.pairing.attempt` event. `reason` is always a short enum. (`test/identity-console-pairing.test.ts`) |
| S1b.10 | Rate-limit denial and exception | A denial from `RateLimitPort` blocks without increasing the attempt count. A thrown exception does not block pairing. (`test/identity-console-pairing.test.ts`) |
| S1b.11 | Audit JSONL on a live pairing flow | `audit.jsonl` carries `oauth.pairing.attempt` plus the v0.1 authorize/token events. No raw pairing code, auth code, or access token. (`test/e2e-pairing.test.ts`) |

In S1b.10, limiter denials do not consume pairing attempt slots. The correct pairing code still succeeds after repeated limiter denials.

### T1.SQ: persistent SQLite state admission

| # | Scenario | Assert |
|---|---|---|
| SQ.1 | `:memory:` and ordinary private-directory paths | `:memory:` performs no filesystem work. A new path is `0600`. An existing owner `0600` database reopens and migrates. |
| SQ.2 | Runtime path grammar | Non-string, empty/blank, NUL, and case-insensitive `file:` inputs reject before any file/URI target is created or mutated. |
| SQ.3 | Directory boundary | Missing, symlink/junction, group/other-accessible, and unsafe-ancestry directories reject before database creation/migration. Accepted system/sticky ancestry is covered. A deterministic policy row proves that an ancestor owned by another non-root account rejects even at `0755` or after a read-only snapshot. A root-owned immediate-directory probe covers UID mismatch when the runner is a non-root POSIX user. File-UID mismatch needs a privileged fixture and remains manual. |
| SQ.4 | Existing target boundary | `0644`, final/dangling symlink, directory, FIFO, socket/device where safe, and multi-link targets reject without chmod, byte, or schema mutation. FIFO proof runs in a bounded child process. |
| SQ.5 | Descriptor/path identity | A deterministic descriptor-vs-replaced-path mismatch rejects. POSIX `/dev/fd` probes pin descriptor cleanup after admission and initialization failures. Cleanup is one bounded attempt and cannot guarantee success after an OS-level close error. |
| SQ.6 | Preseeded OAuth state | A chosen valid refresh family/token in an unsafe directory fails store boot before use: no bridge access token, successor, or success audit, and the hostile bytes/schema remain unchanged. The same fixture in a trusted private directory is operator-owned state and may reopen. |
| SQ.7 | Restart and store siblings | Existing SQLite authorization-code, refresh-family, stored-scope, replay, schema-migration, and restart rows remain green. Memory/MySQL behavior is unchanged. |
| SQ.8 | Packed artifact (manual release proof) | Produce/install the real tarball and run new-file, reopen, URI-rejection, and hostile-directory smokes through `mcp-sso/store/sqlite`. This is not a committed CI job. |
| SQ.9 | Platform contract | Ubuntu CI proves POSIX no-follow/UID/`0600`/directory controls. Windows-specific skips name unavailable primitives, but no Windows CI runner exists. Windows ACL/private-directory guarantees remain deployer-owned and must not be reported as CI-proven. |
| SQ.10 | Windows permission-gap signal | Child-process wiring probes force the Windows branch and prove the first call among quickstart secrets, standalone `assertRealDir`, managed `ensureStateDir`, and persistent SQLite emits one shared, fixed, path-free warning per Node worker/runtime instance. Exact `:memory:`, POSIX use, and later calls in that instance stay silent, and a throwing warning transport cannot change the boot result. |

### T1.S2a: core `allowedScopes` ceiling

| # | Scenario | Assert |
|---|---|---|
| S2a.1 | Identity has no `allowedScopes` | Existing authorize/token/refresh behavior unchanged. |
| S2a.2 | Identity has `allowedScopes` subset | Token scopes are the intersection of requested/default/prior scopes and the ceiling. |
| S2a.3 | Empty intersection | `access_denied` over the redirect channel, after redirect validation. |
| S2a.4 | Consent-token tampering | `approve` uses `allowed_scopes` from the verified consent token, never caller input. |
| S2a.5 | Prior grants | Existing grants cannot resurrect scopes outside the current ceiling. |
| S2a.5a | Corrupt or oversized prior grant | `approve` returns `invalid_grant` before consuming the consent JTI or writing an authorization code. |
| S2a.6 | Adapter plumbing | Fastify, Express, and Hono all pass the identity object through the bridge. |

### T1.S2b: Entra group mapping

| # | Scenario | Assert |
|---|---|---|
| S2b.1 | Boot config has display-name key | Boot rejects non-GUID mapping keys. |
| S2b.2 | Mapped groups plus base scopes | Returned `allowedScopes` is the contract-required union. |
| S2b.3 | Groups map to no scopes and no base | Fail closed with the Entra no-groups/no-scopes reason. |
| S2b.4 | Overage marker present | Fail closed. `_claim_sources` is never dereferenced. |
| S2b.5 | Existing Entra config without group auth | Behavior unchanged. |
| S2b.6 | Full authorize flow | Entra-derived ceiling enforced by the S2a core flow. |
| S2b.7 | Immutable Entra subject selection | The pure validator, explicit-key verifier, remote-JWKS factory, and redirect port all prefer exact usable `oid`, otherwise exact accepted `issuer|sub`. Mutable-only identity is rejected. |
| S2b.8 | Entra allowlist normalization boundary | `oid` keeps trimmed, case-insensitive matching. Issuer-namespaced `sub` matches byte-for-byte. Mutable username/email matches only when `allowMutableClaims === true`, case-insensitively but without whitespace trimming. |
| S2b.9 | Stored DCR and legacy refresh compatibility | Two no-`oid` identities sharing a mutable username do not share accumulated scopes. A pre-upgrade mutable-key refresh family preserves that subject and receives the current sliding TTL on rotation. No migration is inferred. |

### T1.S3a: machine client provisioning

| # | Scenario | Assert |
|---|---|---|
| S3a.1 | Enable with non-stored DCR | Boot fails with `AuthConfigError`. |
| S3a.2 | Provision machine client | Returns `mcc_...` id and `mcs_...` secret once. Store holds only a SHA-256 hash. |
| S3a.3 | Rotate secret | New secret works. Old secret gets a bounded grace expiry. Max two active secrets. |
| S3a.4 | Provision with invalid scope | Rejected before store write. |
| S3a.5 | Machine-shaped DCR request | `POST /oauth/register` returns `invalid_client_metadata`. |
| S3a.6 | Audit events | Provision/rotate events contain no secret and no hash. |

### T1.S3b: `client_credentials` grant

| # | Scenario | Assert |
|---|---|---|
| S3b.1 | `client_secret_basic` valid | Token response succeeds. Protected `/mcp` accepts the access token. |
| S3b.2 | `client_secret_post` valid | Same success path. |
| S3b.3 | Wrong or expired secret | `invalid_client` 401. Basic attempt includes `WWW-Authenticate: Basic`. |
| S3b.4 | Omitted scope | Token gets the full allowed set. |
| S3b.5 | Requested scope outside allowed set | `invalid_scope`. No token minted. |
| S3b.6 | Resource mismatch | Token request fails. |
| S3b.7 | Response shape | No `refresh_token` member exists at all. |
| S3b.8 | User grant regression | Authorization-code and refresh flows unchanged. |

### T1.GG: stored DCR grant-generation cutover in 0.3.2

| # | Scenario | Assert |
|---|---|---|
| GG.1 | Current-generation code and refresh family across reopen/restart | Exchange and refresh still succeed. |
| GG.2 | Old binary writes a null/missing-generation code after cutover | Current binary burns it and returns `invalid_grant`, for both an unknown and an existing stored client ID. |
| GG.3 | Old binary writes a null/missing-generation refresh family, or a successor inside an existing current family, after cutover | Current binary returns `invalid_grant` before consuming it or creating a successor. |
| GG.4 | Rotation caller substitutes generation | All three stores preserve the family generation from durable state. |
| GG.5 | Legacy/non-current or wrong-resource active refresh rows exist, including inside a current family | `findGrantedScopes` excludes their scopes. |
| GG.6 | Store lacks the generation or resource-binding capability in stored DCR mode | Construction fails closed with `AuthConfigError`. Stateless DCR operation remains unchanged. CIMD alongside stored DCR uses the same cutover generation without enabling accumulation. |

### T1.RB: authorization-code resource binding

| # | Scenario | Assert |
|---|---|---|
| RB.1 | Code created under resource A is redeemed through resource B sharing the store | `invalid_grant`. No token response or success audit. |
| RB.2 | A redemption follows the rejected B attempt | A succeeds exactly once. Replay through A fails. |
| RB.3 | Shared StorePort conformance | Memory, SQLite, and MySQL return `null` for B without consuming A's code. §12 records the implementation transaction/critical-section evidence. |
| RB.4 | Custom store ignores the resource predicate and returns A's record to B | The token use-case's returned-record check yields `invalid_grant`, no token response, zero refresh writes, and zero success audits. |
| RB.5 | Concurrently invoked A/B redemption | Shared observable behavior allows only the correctly bound A exchange to return the record. Implementation inspection supplies the transaction/critical-section evidence rather than claiming the fixture proves every scheduler interleaving. |
| RB.6 | A consent token is submitted to bridge B, for Approve and Deny | Both fail directly as `invalid_consent` before redirect processing, JTI consumption, code storage, or success audit. Bridge A can still approve once and replay then fails. |

### T1.S4a: Generic OIDC and Google preset

| # | Scenario | Assert |
|---|---|---|
| S4a.1 | Generic discovery issuer mismatch | Boot fails. |
| S4a.2 | Discovery endpoint non-https or redirects | Boot fails. |
| S4a.3 | Valid generic id_token claims | Pure validator accepts only exact issuer, expected audience, nonce, time window, and pinned alg. |
| S4a.4 | Multi-audience token | Rejected. |
| S4a.5 | Missing PKCE support | Boot fails unless an explicit loud override is set. |
| S4a.6 | Email allowlist with unverified email | Rejected. |
| S4a.7 | Google preset config | Issuer pinned to `https://accounts.google.com`. The `hd` claim (not email domain) controls hosted-domain matching. |

Google live sign-in is Tier 3, not CI.

### T1.S4b: GitHub identity port (contract-only, never shipped as of 2026-08-21)

| # | Scenario | Assert |
|---|---|---|
| S4b.1 | OAuth URL construction | Hardcoded GitHub authorize endpoint, state, PKCE S256, `user:email` scope. |
| S4b.2 | Token exchange request | Sends `Accept: application/json` and the client secret. |
| S4b.3 | User mapping | Subject is the numeric id string. Login is not identity unless the mutable-claims opt-in is set. |
| S4b.4 | Email mapping | Primary verified email only. Absence allowed. |
| S4b.5 | Allowlist reject | Fails closed before bridge token issuance. |

Real GitHub OAuth sign-in is Tier 3. CI uses pure mapping tests and a stubbed transport only if the implementation exposes one without weakening the production contract.

### T1.S5a: device-flow store and authorization endpoint (contract-only, never shipped as of 2026-08-21)

| # | Scenario | Assert |
|---|---|---|
| S5a.1 | Store conformance extension | Device-code invariants pass for memory, sqlite, and mysql if shipped. |
| S5a.2 | Request device authorization | Response has `device_code`, `user_code`, verification URIs, `expires_in`, `interval`. |
| S5a.3 | Stored record | Raw device code and user code are hashed, not stored. |
| S5a.4 | Poll before approval | Returns `authorization_pending`. |
| S5a.5 | Too-fast poll | Returns `slow_down`. Persists interval +5. |
| S5a.6 | Expired code | Not found/consumed. Sweep removes expired rows. |
| S5a.7 | Wrong-code attempt cap | Five wrong submissions per IP invalidate the path independently of the external limiter. |

### T1.S5b: device verification, approval, and token grant (contract-only, never shipped as of 2026-08-21)

| # | Scenario | Assert |
|---|---|---|
| S5b.1 | Browser enters code and approves | Polling succeeds. Protected `/mcp` works with the issued access token. |
| S5b.2 | Browser denies | Token polling returns terminal `access_denied`. |
| S5b.3 | Approval replay | Device consent token and approved device code are single-use. |
| S5b.4 | `allowedScopes` ceiling | Approved scopes intersected with the S2a ceiling. |
| S5b.5 | Expired token path | Polling returns terminal `expired_token`. |
| S5b.6 | Refresh token issued | Device flow is a user grant: refresh/replay/revoke semantics match baseline. |

### T1.S6a: CIMD security controls

The CIMD enforcement contract is [§17.1](../contracts/17-v0-2-feature-contracts.md#171-cimd-client-id-metadata-documents-the-ssrf-enforcement-contract). The security target is [`threat-model.md` row 13](../threat-model.md). These rows are its enforcement evidence.

| # | Scenario | Assert |
|---|---|---|
| S6a.1 | URL admission table | Rejects non-HTTPS, malformed HTTPS, a root path, a query, a fragment, userinfo, CRLF, controls, dot segments, localhost, a trailing dot, denied ports, and IP literals, including dword, octal, and hexadecimal forms. |
| S6a.2 | IP blocklist table | At least one rejection for every enumerated IPv4/IPv6 CIDR. Public allow cases pass. |
| S6a.3 | IPv4-embedding IPv6 | IPv4-mapped, NAT64, 6to4, and Teredo-style prefixes blocked wholesale. |
| S6a.4 | Guarded fetch all-records DNS | Any blocked A or AAAA record rejects the whole fetch. |
| S6a.5 | Pinned connect | Transport receives the validated IP. Host/SNI stay the original hostname. |
| S6a.6 | Redirect, size, and timeout | The fetch does not follow redirects. The test checks `redirected === false` and a hop count of 0. A body over the size limit is rejected, not truncated. The deadline aborts the request. |
| S6a.7 | Guard cannot be bypassed | Injected low-level transport sits below admission/DNS/IP/cap/timeout checks. |
| S6a.8 | Document validator | Exact `client_id` equality, required fields, auth method, forbidden secrets, private/symmetric key material in `jwks` rejected, redirect URI hygiene, grant/response constraints. |

### T1.S6b: CIMD integration and SSRF regression

| # | Scenario | Assert |
|---|---|---|
| S6b.1 | Boot config | `BridgeConfig` has no `cimd.fetcher` field. The core constructs the guarded fetcher from the `cimd` limits and `allowLoopback`, which comes from `dev.allowInsecureLocalhost`. Tests inject `cimdTransport` or `cimdResolver` below the guard. |
| S6b.2 | Happy path | A URL-shaped `client_id` fetches and validates the document. Authorization, token exchange, and the protected `/mcp` call succeed. |
| S6b.3 | Generic client error | Every CIMD failure returns identical client-facing error text. |
| S6b.4 | Audit detail | `oauth.cimd.fetch` records the specific reason without leaking the document body or secrets. |
| S6b.5 | Redirect URI match | An exact match is required except when a registered loopback `http` entry has `application_type` set to `"native"` or absent. In that case, only the port may differ. The scheme, host, path, and query must match. An explicit `"web"` value requires an exact match. The active frozen suite covers Claude Code's published document, a declared native client, explicit web rejection, and narrow negative cases. |
| S6b.6 | Scope accumulation deferred for CIMD | A CIMD authorization reports `priorScopes = []` and mints only the requested scopes within the ceiling in both DCR modes. The test seeds an active legacy URL-keyed refresh row with a broader scope and confirms that the scope is not added. An opaque stored DCR client remains the positive control for scope accumulation. |
| S6b.7 | Metadata flag | `client_id_metadata_document_supported` appears only when enabled. |
| S6b.8 | Cache (freshness) | Cache HIT reuses only a fresh validated document. The shared cache gives valid `s-maxage` priority over `max-age`, rejects `private`, `no-store`, `no-cache`, and `Vary: *`, and includes Age, valid Date apparent age, and observed response delay. It is bounded LRU, per Bridge, raw-client-id keyed, and serves direct-mode prepare plus upstream redirect resolution. |
| S6b.9 | SSRF negative suite | Encoded dot segments, IP-literal tricks, blocked DNS records, rebinding, redirect-to-blocked-host, over-cap body, slow endpoint, mismatched `client_id`, and `client_secret` doc all fail with identical client-facing text. |
| S6b.10 | Upstream redirect with CIMD | The authorize request resolves and validates the document once. It carries the result in the signed `cimd` flow claim. The callback consumes that claim without fetching the document again. A callback fetcher that throws confirms this behavior. Uppercase `HTTPS://`, `http://`, and `ftp://` client IDs fail with direct `invalid_client`. A lowercase `https://` client ID does the same when CIMD is disabled. None of these requests fall through to stateless DCR or reach the IdP. A callback claim, mode, or redirect mismatch returns `flow_cookie_invalid`. The approve-time scheme check rejects a legacy URL-shaped stateless token as `invalid_consent`. |

A happy path alone does not close S6b. The negative SSRF suite is the security evidence.

### T1.S7a: examples

| # | Scenario | Assert |
|---|---|---|
| S7a.1 | Fastify example | Boots and completes authorization, token exchange, and a protected `/mcp` call. |
| S7a.2 | Express example | Same flow. |
| S7a.3 | Hono example | Same flow. |
| S7a.4 | API-key gateway example | Backend key read once at boot, injected only server-to-backend, never in client-visible traffic, token claims, or audit logs. |
