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
  clientId: string; subject: string; resource: string | null;
  scopes: string[]; expiresAt: string;
  grantGeneration?: number | null;
}
interface SaveAuthCodeInput {
  /* AuthCodeRecord fields; optional only for source compatibility with a
     pre-0.3.2 caller. Current API omission defaults to generation 1;
     explicit null and old SQL inserts are legacy. */
  grantGeneration?: number | null;
}
interface SaveRefreshTokenInput {
  tokenHash: string; familyId: string; previousTokenHash: string | null;
  clientId: string; subject: string; resource: string;
  scopes: string[]; expiresAt: string;
  /* Same omission/null write semantics as SaveAuthCodeInput. */
  grantGeneration?: number | null;
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

`resource` is the exact configured bridge resource string at authorization-code
issuance. New writes require a non-empty string and persist it both on the
family and on its token row. A returned `null` represents only an old durable
row whose migration-added column is absent, `NULL`, malformed, or blank; it is
never rebound from current configuration and fails refresh rotation closed.
The typed write port rejects a missing resource. For an untyped pre-resource
JavaScript call only, reference stores persist the reserved
`mcp-sso:unbound-refresh-resource` marker instead of guessing a bridge resource;
the marker is rejected by rotation before any mutation and cannot be supplied as
a normal write value.

**MySQL subject capacity.** OIDC `sub` may be 255 characters. For the Entra
no-`oid` key, the accepted v2 issuer is 75 characters for a 36-character tenant
identifier, so `issuer + "|" + sub` is `75 + 1 + 255 = 331` characters. The
`oauth_auth_codes.subject` and `oauth_refresh_tokens.subject` columns are therefore
`VARCHAR(384)`: narrow headroom above 331 without widening any other identifier.
The refresh lookup index remains `(subject, client_id)`, where `client_id` stays
`VARCHAR(255)`. Under `utf8mb4`, its worst-case key is
`(384 + 255) × 4 = 2556` bytes. InnoDB secondary-index records also carry this
table's `VARCHAR(64)` `token_hash` primary key, so the physical worst case is
`(384 + 255 + 64) × 4 = 2812` bytes, below the 3072-byte limit.

Fresh MySQL schemas use `VARCHAR(384)` for exactly those two subject columns.
Migration inspects and validates both columns before either ALTER: deployed `VARCHAR(255) NOT NULL`
columns are widened in place to `VARCHAR(384) NOT NULL`; an already sufficient
width is an idempotent no-op; an unexpected missing, nullable, non-`VARCHAR`, or
other undersized shape fails boot rather than being silently reinterpreted.
`client_id`, consent-JTI uniqueness, and every other column/index are unchanged.

## 12.2 Invariants the suite asserts
1. **Hashed, single-use, resource-bound auth codes:**
   `consumeAuthCode(codeHash, nowIso, expectedGeneration?, expectedResource?)`
   deletes an otherwise-selected code on read; a second consume returns `null`;
   an expired code returns `null`; raw codes never appear in storage. When
   `expectedResource` is supplied, the store compares it by exact equality to
   the stored `resource` string before deletion. A mismatch returns `null`
   without consuming the code. The shared suite asserts the observable behavior:
   a wrong-resource call returns `null`, the matching resource can then consume
   exactly once, and replay fails. SQLite asserts the on-disk file contains no raw secret and has no
   content/body/cache tables (state is OAuth-only).
2. **Consent JTI single-use and signed-expiry retention (0.3.3 correction):**
   `consumeConsentJti` returns `true` once and `false` on replay (atomic
   insert-or-ignore), independent of a replay caller supplying
   a different expiry. It rejects an `expiresAtIso` that is not a 3-ms UTC
   timestamp. The caller supplies the already-validated signed JWT expiry under
   §7.1; stores persist that exact value and do not derive or modify it.
   `sweepExpired(now)` MUST retain a JTI whose `expires_at >= now` and MAY delete
   it only when `expires_at < now`. The shared suite proves: consume with a
   future signed expiry, sweep before and exactly at it, replay remains false;
   sweep one millisecond after it permits a fresh insertion, directly proving
   collection rather than merely observing an already-expired rejection. This
   semantic rule is identical in Memory,
   SQLite, and MySQL. It does not turn process-local `MemoryStore` into durable
   storage: destroying that process or using an independent replica loses its
   map, while SQLite/MySQL retain the row through process replacement when the
   same persistent store is reopened.
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
   clientId, nowIso, expectedGeneration?, expectedResource?)` returns the union of `scopes` across refresh-token records
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

    `consumeAuthCode(hash, now, expectedGeneration?, expectedResource?)` burns a selected code whose
    resource predicate matched, but returns it only when unexpired and its
    generation equals a supplied expectation. A resource mismatch follows
    invariant 11 and does not consume; generation mismatch retains its burn
    behavior. Client, redirect, and PKCE mismatches occur after a returned record
    and therefore also retain their documented one-shot consumption behavior.
    `rotateRefreshToken(hash, next, now, expectedGeneration?)`
    compares both the family and token-row generations before replay handling,
    predecessor consumption, or successor insertion; rotation copies the stored
    token generation and ignores caller substitution.
    `findGrantedScopes(subject, clientId, now, expectedGeneration?, expectedResource?)`
    filters by both generations and, when a resource is supplied, requires the
    exact resource on both the token and family rows. Thus an old binary
    cannot write a post-purge grant that a re-upgraded binary accepts or
    accumulates merely because the client ID currently exists; nor can a
    legacy or resource-A refresh row contribute scopes to resource B.

    The use-cases repeat returned-record equality before token preparation.
    Stored-DCR mode requires the store capability markers
    `storedDcrGrantGeneration: 1` and `storedDcrResourceBinding: 1`; an
    absent/different marker is a boot `AuthConfigError`, preventing a custom
    store that ignores the new optional parameters from failing open. A
    current-generation family survives ordinary process/store restarts.

11. **Resource predicates (patch-compatible extensions):** the
    optional trailing `expectedResource` argument is supplied by
    `OAuthTokenUseCase` in every authorization-code exchange and refresh rotation.
    For codes, Memory checks it in the map critical section, SQLite checks it
    inside `BEGIN IMMEDIATE`, and MySQL checks it while holding the selected row
    `FOR UPDATE`; a mismatch commits no delete. For refreshes, the reference
    stores atomically reject a missing, malformed, or different family/token
    resource before replay handling, predecessor consumption, successor insertion,
    family revocation, signing, or success audit. A wrong-resource refresh returns
    `null` without mutation; a correctly bound request can still rotate once;
    replay still revokes the current family successor. The successor authoritative-
    copies the selected row's exact resource, and `saveRefreshToken` rejects an
    attempt to introduce a different or missing family resource. Comparison is
    exact string equality over stored resource strings.
    `findGrantedScopes` applies the same exact predicate to both active rows
    before returning their scopes.

    SQLite and MySQL migrations add nullable `resource` columns to both
    `oauth_refresh_token_families` and `oauth_refresh_tokens`; fresh schemas make
    both columns non-null. The nullable migration deliberately leaves old rows
    `NULL` rather than guessing from a current `BridgeConfig`. Thus a restart or
    resource cutover cannot silently rebind a legacy refresh family.

    The use-case repeats exact equality against `BridgeConfig.resource` after a
    returned record, so a custom/defective store that ignores either argument
    cannot cause a wrong-audience token, refresh write, or success audit. The
    extensions are source-compatible; custom stores must implement the predicates
    to satisfy conformance and preserve retry semantics.

    The shared conformance row proves that externally observable result across
    Memory, SQLite, and MySQL; it does not by itself prove every scheduler
    interleaving. Atomicity evidence comes from the implementations: Memory runs
    check and delete synchronously without an `await`, SQLite keeps both inside
    one transaction, and MySQL keeps both under `SELECT ... FOR UPDATE` until the
    transaction commits.

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
  detection (§12.2 invariant 3). Consent-JTI insertion uses plain `INSERT`:
  only `ER_DUP_ENTRY` means replay, while every other database error propagates.
  `INSERT IGNORE` is forbidden here because it also suppresses partition,
  foreign-key, truncation, and other failures as zero affected rows. Family upserts use
  `ON DUPLICATE KEY UPDATE` without a row alias. The incoming revoke timestamp
  is repeated as a bound parameter rather than interpolated into SQL, while
  `COALESCE` preserves the first revocation timestamp.
  At boot, `oauth_consent_jtis.jti` MUST be a non-null `VARCHAR(255)` or wider,
  `expires_at` MUST be a non-null `VARCHAR(24)` or wider, and JTI MUST have a
  full-column single-column PRIMARY or UNIQUE index. Every other unique index
  MUST also contain the full JTI column; otherwise a duplicate-key error could
  represent an unrelated constraint collision. `CREATE TABLE IF NOT EXISTS`
  does not repair a pre-created table, and
  the duplicate-key handler detects replay only when MySQL enforces uniqueness on the JTI
  itself. A composite unique index such as `(jti, expires_at)` is insufficient:
  it admits the same JTI with another expiry and therefore fails boot.
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
  relies on. Revisit either only if profiling flags it. The subject-width migration
  and index arithmetic are specified in §12.1; live MySQL 8.4 coverage starts from
  the deployed `VARCHAR(255)` columns, migrates them, persists a 331-character Entra
  subject through authorization and refresh rotation, and reruns migration to prove
  idempotence.

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

## 12.4 Persistent SQLite filesystem admission

`openSqliteStore(filename)` is the security boundary for a library-opened
SQLite database. `new SqliteStore(callerDatabaseSync)` remains public and
caller-owned: it wraps an already-open connection and makes no claim about the
connection's filesystem provenance, permissions, directory trust, or sidecars.

The exact string `:memory:` is accepted on every platform and performs no
filesystem check or write. Every other value is a persistent path. At runtime a
persistent path MUST be a primitive, non-blank string with no embedded NUL and
MUST NOT begin with `file:` in any ASCII case. SQLite URI syntax is deliberately
unsupported: `openSqliteStore` accepts ordinary filesystem path strings only,
does not parse URI query parameters, and never reinterprets a rejected URI as a
literal filename. This is a security-motivated compatibility change: the former
`file:` exception bypassed the file-permission control.

Before `DatabaseSync` is constructed, the immediate database directory MUST
already exist and MUST be a real directory, not a symlink or junction.
`openSqliteStore` never creates directories. On POSIX, the immediate directory
MUST be owned by the effective service user and have no group/other permission
bits. This protects the main database plus SQLite journal/WAL sidecars. Path
ancestry follows a stricter form of the scaffold trust model: every ancestor
directory owner MUST be either root or the effective service user (another
owner can chmod and replace an entry even when its current mode is read-only).
A trusted-owner group/other-writable ancestor is accepted only when it is
sticky and the next path entry is owned by the effective user; a symlink
ancestor is accepted only when its directory entry cannot be replaced by a
lower-privileged user, and its resolved destination ancestry is checked by the
same rule. The immediate database directory itself is never allowed to be a
symlink. This closes lower-privileged preseed and replacement, not attacks by
root or another process running as the same OS account.

Persistent-file admission is synchronous and precedes migrations or reads:

- A missing file is created with `O_RDWR | O_CREAT | O_EXCL | O_NONBLOCK` and,
  where available, `O_NOFOLLOW`, then set and verified as mode `0600`. A
  competing creator, symlink, or existing name fails closed; no existing path
  is truncated.
- An existing file is opened `O_RDWR | O_NONBLOCK` and, where available,
  `O_NOFOLLOW`. It is never chmodded. On POSIX it MUST be owned by the effective
  service user and have exact mode `0600`; remediation is an operator-owned
  `chmod 600` after verifying provenance.
- The admitted descriptor MUST identify a regular file with link count exactly
  one. A final symlink (including dangling), directory, FIFO, socket, device, or
  hard-linked target is rejected without migration, chmod, truncation,
  deletion, or other mutation.

The verified descriptor remains open while `DatabaseSync` opens the same path.
Before the descriptor is closed or any library migration/SQL read runs, a
no-follow path stat MUST still identify the same device/inode and a regular single-link file.
An identity mismatch closes both handles and fails boot. Node's `DatabaseSync`
accepts a path rather than a caller-owned descriptor, so this comparison cannot
make a same-account race impossible; the trusted-directory rule prevents a
lower-privileged process from replacing the entry during the remaining window.
All ordinary failure paths issue one bounded close for each descriptor/connection
created by the call; a cleanup error never replaces the fixed boot failure and
is not retried against a descriptor number the OS might already have reused.
Rejected paths are never deleted.

On POSIX, no-follow, ownership, exact `0600`, and directory-mode guarantees are
enforced. Node does not expose `O_NOFOLLOW`/`O_NONBLOCK` on Windows. There,
`openSqliteStore` uses no-follow `lstat` checks plus descriptor/path regular-file
and identity checks, exclusive creation, and the single-link rule, but makes no
claim that POSIX mode/UID checks enforce Windows ACL policy. The deployer MUST
place SQLite state in a private, deployer-controlled directory whose ACL denies
untrusted writers. No Windows ACL dependency is added.

Admission failures use the fixed `sqlite: unsafe persistent state:` prefix and
allowlisted reasons/remediation. They never include file contents, SQLite rows,
token material, or arbitrary thrown error text.
