# 12. Store-conformance contract

Every `StorePort` implementation MUST satisfy these invariants — the
`store-conformance` suite asserts them against **both** `MemoryStore` and
`SqliteStore`, and `MysqlStore`, and any further downstream SQL adapter must pass the same suite. **Fix #3**
documents the one contract the source left implicit.

## 12.1 Records (secrets are SHA-256 hex digests; timestamps are UTC ISO 8601 with EXACTLY 3 ms digits)
```ts
interface AuthCodeRecord {
  codeHash: string; clientId: string; subject: string; redirectUri: string;
  resource: string; scopes: string[]; codeChallenge: string;
  codeChallengeMethod: "S256"; expiresAt: string;
  grantGeneration?: number | null;
}
interface RefreshTokenRecord {
  tokenHash: string; familyId: string; previousTokenHash: string | null;
  clientId: string; subject: string; scopes: string[]; expiresAt: string;
  grantGeneration?: number | null;
  resource?: string | null; // 0.4.0; new writes non-null
}
interface SaveAuthCodeInput {
  /* AuthCodeRecord fields; optional only for source compatibility with a
     pre-0.3.2 caller. Current API omission defaults to generation 1;
     explicit null and old SQL inserts are legacy. */
  grantGeneration?: number | null;
}
interface SaveRefreshTokenInput {
  tokenHash: string; familyId: string; previousTokenHash: string | null;
  clientId: string; subject: string; scopes: string[]; expiresAt: string;
  /* Same omission/null write semantics as SaveAuthCodeInput. */
  grantGeneration?: number | null;
  resource?: string | null; // 0.4.0; old writes are legacy
}
```
Inputs are validated: `assertSha256Hex` for every hash; `assertUtcIsoTimestamp`
for every timestamp — which **requires exactly 3 millisecond digits** (e.g.
`2026-07-03T13:00:00.000Z`), rejecting both no-ms and ≠3-digit forms. Rationale:
stores compare expiry strings **lexicographically** (SQLite `TEXT` / in-memory
string compare), and mixed precision inverts ordering (`"...00Z"` sorts after
`"...00.500Z"`, flipping an expired token to valid). `codeChallengeMethod ===
"S256"`; on rotation `next.previousTokenHash === tokenHash`. **`consumeConsentJti`
validates its `expiresAtIso` too** (addendum 10 — a known gap in the source, where
`jti` rows were written with an unvalidated timestamp; the library closes it).
The generation property remains optional in the public TypeScript record/input
shapes so a patch upgrade does not make an existing custom store fail to
compile. Reference stores always project it explicitly; the use-cases treat
`undefined` on a returned record exactly like legacy `null`, and stored-DCR
construction rejects a store without the generation capability marker.

## 12.2 Invariants the suite asserts
1. **Hashed, single-use auth codes:** `consumeAuthCode` deletes on read; a second
   consume returns `null`; an expired code returns `null`; raw codes never appear
   in storage. SQLite asserts the on-disk file contains no raw secret and has no
   content/body/cache tables (state is OAuth-only).
2. **Consent JTI single-use:** `consumeConsentJti` returns `true` once, `false` on
   replay (atomic insert-or-ignore). It also **rejects a `expiresAtIso` that is not
   a 3-ms UTC timestamp** (addendum 10 — the source left this unvalidated; the
   library closes the gap).
3. **Rotation + replay revokes the family:** rotating a token returns the consumed
   record; replaying it returns `null` and revokes the family; subsequent rotation
   of any token in that family returns `null`.
4. **Rotation backfill — fix #3 (the documented contract):** `rotateRefreshToken`
   fills `clientId`/`subject`/`scopes` on the **next** record from the
   **consumed** row, ignoring the caller-supplied values. The caller passes
   `clientId`/`subject`/`scopes` it does NOT trust (e.g. from the wire); the store
   authoritative-copies them from the row being consumed. Thus an attacker who
   supplies a stolen refresh token with a different `client_id`/`subject`/`scopes`
   cannot poison the next token — those fields always come from the stored record.
   (The use-case still independently enforces RFC 6749 §6 client binding and
   revokes on mismatch; the backfill is defense-in-depth at the store layer.)
5. **Family-validity sweep (addendum 8):** an expired refresh token still rotates
   to `null`; `sweepExpired(now)` deletes a refresh token (consumed OR unconsumed)
   ONLY when **no token in its family has `expires_at >= now`** (a `NOT EXISTS`
   family-member-still-valid check), and deletes ANY family left empty (not only
   revoked ones). **Boundary:** `expires_at >= now` counts as still-valid (the
   suite asserts the exact-boundary case so adapters cannot disagree). This retains a consumed predecessor while a successor rotated
   from it is still valid — a naive per-token expiry sweep would delete the
   predecessor at its own expiry and drop the **replay signal** while the successor
   is live (a replay-detection regression; the suite includes the
   successor-outlives-predecessor case). Expired auth codes and JTIs are swept by
   their own expiry. **Accepted boundary:** replay after the WHOLE family is past
   validity is undetected (the rows are GC'd by then).
6. **Idempotent close:** `close()` is callable more than once; any op after close
   throws `Store is closed`.
7. **Granted-scope derivation *(RC item (c))*:** `findGrantedScopes(subject,
   clientId, nowIso)` returns the union of `scopes` across refresh-token records
   for that `(subject, clientId)` that are unconsumed, in non-revoked families,
   and not expired at `nowIso`. It is a **read over existing records — there is no
   grant table**. Returns `[]` when no active token exists (a first authorization
   therefore grants exactly the requested scopes). **Registration provenance
   (§17.1.6 decision 3):** v0.2 refresh records carry NO registration provenance, so
   they are NOT eligible accumulation evidence for a CIMD authorization — the caller
   MUST NOT invoke `findGrantedScopes` for a scheme-shaped (`https://`/CIMD) client_id
   (accumulation runs only for opaque stored-DCR clients). A future CIMD-accumulation
   extension MUST add immutable mint-time provenance to the auth-code and
   refresh-family lineage, preserve it across rotation, filter this read by expected
   provenance, and treat absent/unknown provenance as ineligible — with an explicit
   legacy-row migration rule. Not part of v0.2. (This closes prior-grant resurrection
   by construction: a pre-CIMD stateless URL-keyed grant is never read into a CIMD
   authorization. Note it does NOT revoke already-issued legacy tokens — they keep
   their own scopes until expiry/revocation; enabling CIMD is not a retroactive
   re-validation of existing grants.)
8. **Token-hash preexistence (collision parity):** `rotateRefreshToken` whose
   `next.tokenHash` already exists returns `null` WITHOUT consuming the
   predecessor (the failed rotation is retryable — matches the SQL stores'
   check-before-update), and `saveRefreshToken` with an already-stored
   `tokenHash` **rejects** — it never silently overwrites. An overwrite would
   rebuild the row with `consumedAt: null`, resurrecting a consumed token and
   erasing the family's replay signal. Practically unreachable under SHA-256,
   but all reference stores must agree (parity by fixture — this invariant was
   previously asserted for MySQL only, and `MemoryStore` silently diverged).
9. **Post-rotation compensation:** after `rotateRefreshToken` succeeds, a
   response-preparation failure is compensated through
   `revokeRefreshTokenFamily(familyId, rotatedAtIso)` (§7.4). For that known
   family, the call leaves every member inactive; repeating it keeps the family
   inactive. The use-case reuses the rotation timestamp, so compensation does
   not introduce a second clock decision after the state mutation.
10. **Stored-DCR grant generation (0.3.2):**
    `STORED_DCR_GRANT_GENERATION` is the library-owned positive safe integer
    `1`; it is not deployer configuration and not a per-client policy version.
    New auth codes and refresh families issued while stored-DCR mode is active
    carry it. Stateless-DCR records use `null`. CIMD still does not accumulate
    scopes, but when it is enabled alongside stored DCR its grants carry the
    deployment cutover generation too.

    Reference SQL migrations add nullable `grant_generation` to
    `oauth_auth_codes`, `oauth_refresh_token_families`, and
    `oauth_refresh_tokens`. There is deliberately no non-null/default clause:
    an old binary using the previous explicit insert column list writes SQL
    `NULL`, making either a new family or a successor inserted into an existing
    current family unambiguously legacy after a rollback. Reference row
    projection maps missing/malformed values to legacy `null`.

    `consumeAuthCode(hash, now, expectedGeneration?)` always burns the selected
    code, but returns it only when unexpired and its generation equals a supplied
    expectation. `rotateRefreshToken(hash, next, now, expectedGeneration?)`
    compares both the family and token-row generations before replay handling,
    predecessor consumption, or successor insertion; rotation copies the stored
    token generation and ignores caller substitution.
    `findGrantedScopes(subject, clientId, now, expectedGeneration?)` filters by
    both generations. Thus an old binary
    cannot write a post-purge grant that a re-upgraded binary accepts or
    accumulates merely because the client ID currently exists.

    The use-cases repeat returned-record equality before token preparation.
    Stored-DCR mode requires the store capability marker
    `storedDcrGrantGeneration: 1`; an absent/different marker is a boot
    `AuthConfigError`, preventing a custom store that ignores the new optional
    parameters from failing open. A current-generation family survives ordinary
    process/store restarts.
11. **Resource lineage (0.4.0):**
    new refresh families and tokens store one canonical non-null resource.
    Rotation parses and generation-checks the family and token rows, then
    handles a consumed-token replay **before any resource comparison at all** —
    before the stored family/token equality check as well as before the optional
    request expectation. A consumed token is a replay whatever resource it
    carries. This ordering is load-bearing rather than stylistic: attested
    legacy binding stamps the family and the token being rotated, but NOT older
    consumed members of a pre-0.4 chain, which keep a null resource. Comparing
    stored equality first would make a replayed older predecessor fail that
    check and return early, so the theft would revoke nothing and the live
    family would stay usable. Stored equality is established after replay
    handling and still gates every non-replay path. Replay revokes
    that stored family even when the request names another configured resource
    and returns `null`/`invalid_grant`; it never becomes a retryable resource
    mismatch. For an unconsumed token, rotation compares the family row, token
    row, and request expectation before successor mutation, then copies the
    stored resource to the successor.
    `findGrantedScopes` includes the expected resource predicate alongside
    subject, client, time, and generation.
    An otherwise-valid unconsumed current lineage whose resource differs from
    the expectation returns the fieldless `{ status: "resource_mismatch" }`
    outcome without consuming the predecessor or inserting a successor; every
    other invalid lineage remains `null`. This typed result is what lets the
    use-case return `invalid_target` without a racy pre-read or exposing stored
    record fields.

    Reference SQL migrations add nullable `resource` columns to
    `oauth_refresh_token_families` and `oauth_refresh_tokens` with no database
    default, so an old binary's explicit insert remains legacy `NULL`.
    In singleton mode with a matching explicit `legacySingletonResource`
    attestation, rotation atomically binds a null family/token to the sole
    resource and a null active row may contribute prior scopes there. Without
    that attestation—or in multi-resource mode—a
    null/malformed/disagreeing lineage returns no rotation, contributes no
    scopes, and is never assigned the request value. This prevents a v0.3
    singleton A record from being inferred as B merely because the first v0.4
    process changed its singleton URL.
    The additive `resourceBinding: 1` marker is required for a custom store in
    multi-resource mode and whenever stored-DCR prior-scope accumulation is
    enabled, including singleton mode. The shared conformance suite owns
    memory, SQLite, and MySQL parity, including restart and old-binary insert
    fixtures.

    `assertResourceBindingStore` checks `resourceBinding: 1` in `Bridge`,
    `OAuthAuthorizationUseCase`, and `OAuthTokenUseCase` construction before
    any store or adapter side effect whenever the catalog is multi-resource or
    DCR is stored. The marker is not a lazy per-operation probe, and direct
    exported use-case construction does not bypass it.

    **Mixed-version cutover precondition:** before starting the first
    multi-resource process—or changing a singleton resource URL—the operator
    must drain every pre-0.4 token handler that can access the same store.
    After a resource-bound record has been written, rollback to a pre-0.4
    handler against that store is unsupported and unsafe: the old binary
    ignores the resource columns and can rotate a B-bound refresh token while
    minting its configured A audience. Nullable columns make old writes
    detectable by 0.4; they cannot make an already-running old binary enforce a
    field it does not know. A rollback requires an isolated pre-cutover store
    snapshot and must not receive any refresh or machine credential issued
    after activation. This is a deployment cutover gate, not a runtime claim
    that one process can discover another old process. The same drain applies
    to a separately configured `ClientStore`; §17.2 records the machine-token
    sibling.

## 12.3 Reference adapters
- `MemoryStore` (`/store/memory`) — in-process maps; dev/test only, labeled loud.
  Not HA; single-process.
- `SqliteStore` (`/store/sqlite`) — `node:sqlite` (built-in; no native dep),
  `:memory:` or file. STRICT tables, `BEGIN IMMEDIATE` transactions,
  `INSERT ... ON CONFLICT DO NOTHING` for consent JTIs. The schema migration is
  idempotent.
- `MysqlStore` (`/store/mysql`) — `mysql2` (optional peer dep; pooled). The first
  *async/pooled* reference adapter, so it is the binding example of addendum 13
  below: a pooled connection, `beginTransaction`/`commit`/`rollback` behind a
  begun-guard, `release()` in `finally` on every path. Timestamps are stored as
  `VARCHAR(24)` with a binary collation so expiry comparison is byte-lexicographic
  (identical semantics to SQLite `TEXT`, preserving the §12.1 3-ms ordering
  invariant — `DATETIME` would change comparison/tz semantics and is NOT used).
  Because a pool does NOT serialize writers the way `BEGIN IMMEDIATE` does,
  `rotateRefreshToken` takes a row lock via `SELECT ... FOR UPDATE` inside the
  transaction — without it, two concurrent rotations of the same token would both
  see `consumed_at IS NULL`, double-insert the successor, and break replay
  detection (§12.2 invariant 3). `INSERT IGNORE` substitutes for SQLite
  `ON CONFLICT DO NOTHING` on consent JTIs (the `ON DUPLICATE KEY UPDATE
  expires_at = expires_at` form reports `affectedRows=1` even on a no-op replay
  under MySQL 8.4, so it cannot distinguish first-use); family upserts use
  `ON DUPLICATE KEY UPDATE` without a row alias. The incoming revoke timestamp
  is repeated as a bound parameter rather than interpolated into SQL, while
  `COALESCE` preserves the first revocation timestamp.
  Transactions run at **`READ COMMITTED`** (`SET TRANSACTION ISOLATION LEVEL
  READ COMMITTED` — the next-transaction form, before `BEGIN`): under InnoDB's
  default `REPEATABLE READ`, range scans (`sweepExpired`'s family DELETE, the
  rotation `FOR UPDATE`) take next-key/gap locks that deadlock each other;
  `READ COMMITTED` disables gap locking. The next-transaction form scopes the
  isolation to that one transaction, so a caller-supplied shared pool
  (`new MysqlStore(appPool)`) does not inherit READ COMMITTED after `release()`. `sweepExpired` is a two-step SELECT-exact-dead-rows-then-DELETE-by-PK
  so a successor committed mid-sweep can never be swept. **Pool sizing is the
  deployer's responsibility** — `createMysqlStore(config)` accepts a `mysql2`
  `PoolOptions` object (or URI string), so `connectionLimit` is set there; provision
  it for peak refresh-rotation concurrency (the default is 10). **Pool ownership:**
  `createMysqlStore` owns the pool it creates (`close()` ends it); constructing
  `new MysqlStore(appPool)` with a caller-supplied shared pool leaves ownership — and
  the `close()` lifecycle — with the caller, so closing the store won't tear down a
  pool other components still use. Nullable-column migration is safe under
  concurrent replica startup: `ensureColumn` tolerates only MySQL
  `ER_DUP_FIELDNAME`, then re-reads `information_schema` and succeeds only when
  the raced column now exists; every other DDL error propagates. Two performance
  trade-offs are accepted as-is, both because the path is low-QPS OAuth state, not a
  hot loop: (1) `READ COMMITTED` is set per transaction (one extra ~1ms round-trip)
  because `mysql2`'s pool exposes no per-connection init hook to set it once; (2)
  statements use the text protocol (`query`) rather than prepared statements
  (`execute`), which do not support the `IN (?)` array expansion the two-step sweep
  relies on. Revisit either only if profiling flags it.

**Async-store transaction hygiene (addendum 13 — for any pooled/async adapter,
e.g. a MySQL-compatible or Postgres store):** acquire the connection → `begin` INSIDE the `try`
(behind a begun-guard) → `release` in `finally` on EVERY path, including a
`begin` throw; swallow cleanup errors from `rollback`/`release` so the original
error propagates. A `begin`-failure that leaks a connection otherwise exhausts the
pool = an auth outage. A pooled SQL adapter should also pin `READ COMMITTED`
isolation (gap-lock avoidance — see the `MysqlStore` note above) and fail-closed
assert strict mode (`STRICT_TRANS_TABLES` or `STRICT_ALL_TABLES` — either suffices for
InnoDB) + binary column collations at boot. (The in-tree
memory + sqlite adapters are synchronous, so this is forward guidance for async
adapters.)
