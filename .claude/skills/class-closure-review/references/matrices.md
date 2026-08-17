# Matrices (mcp-sso)

Fill every applicable cell. `n/a` needs a one-line reason that
cites the **named behavior**, not the ticket. Classify `n/a`
immediately when that axis cannot be a sibling of this
behavior — do not open stores or schema to prove they are
irrelevant. An unmentioned cell that **is a sibling and
exists in the tree** is empty → FAIL. A surface that is not
in the tree (not in the checkout, or not in a pasted exact-head
excerpt) is `n/a`, not a finding. "Exists in the checkout"
alone does not occupy a cell.

These axes exist because hosted review kept finding them after
CLEAN local passes. They are the execution of AGENTS.md §7.2.

## M1 — Path and composition root

**When:** a guard, parser, budget, error wrapper, or any claim
about every request / no port error reaching the client.

Rows (every one that exists in the diff’s blast radius):

- Fastify / Express / Hono
- pairing (`skipAuthorize` and the pairing page)
- upstream callback
- register / approve / deny / token / revoke / `/mcp`
- throw vs `{ ok: false, reason }` vs getter / Proxy / capability
- each Port: Store, ClientStore, Identity, Clock, Audit,
  RateLimit, Fetcher

Columns:

- library (`src/`)
- `examples/fastify-sqlite`
- `examples/api-key-gateway`
- generated starter (`src/bin/templates.ts` / init output)
- scaffold / `mcp-sso init`

Wrapping only `find` while create / CAS / getters still throw
is one filled cell, not a closed class.

Store-call cells are Port **methods** on an already-open store.
The composition-root factory (`openSqliteStore`, MySQL open,
`new MemoryStore`) is **not** an M1 wrap sibling unless the
claim explicitly says store-*open* errors are sanitized. That
factory is an M4 cell: the guard must run **before** it. Do
not FAIL a closed wrap class because `boot` still calls
`openSqliteStore` after ack.

## M2 — Persistence and policy revalidation

**When:** allowlists, redirect matchers, schema, store instance
id, clocks, resource binding, or any policy already-issued
state must obey.

Rows: memory / SQLite / MySQL.

Columns: new entry; already-stored row; in-flight consent JWT
or pending grant; replica / copied file; case-variant object
name; inbound FK; outbound FK.

`prepare()` using a different matcher than `approve()` /
`deny()` is an empty stored / in-flight cell. A policy change
that does not revalidate stored native clients is FAIL.

Re-parsing stored slots, or re-applying grammar / loopback-
for-native, is **not** revalidation against the **new**
global policy. If the allowlist dropped a built-in (loopback,
hosted origin) and a stored registration still authorizes
that URI without a current-allowlist check, the stored-row
cell is empty.

## M3 — Leftover claim and status number

**When:** any guarantee changed, or a phase / count / current
status line moved.

Grep `never|always|cannot|enforced|rejected|only|must` on:

- the edited file
- `docs/contracts/03`, `09`, `10`, `15`, `16`, `17` (and any
  other numbered file the sentence still lives in)
- `docs/threat-model.md` residuals and field JSDoc
- `docs/verification.md` receipts (append below; recount C/U
  headlines)
- `AGENTS.md`, `CLAUDE.md`, `README.md`
- `docs/identity/*` and `docs/client-registration.md`
- `test/acceptance/phases.json` inventory vs “N files / M flags”

One leftover “ADDS to defaults” or “always 200” is FAIL.

## M4 — Guard before every side effect

**When:** a new boot, bind, ack, listen, or reject-at-start
guard.

Must run **before**:

- quickstart secret / key file create
- `openSqliteStore` / MySQL open
- migrate / DDL
- OIDC discovery fetch
- `listen` / bind
- success audit
- `consumeConsentJti`
- durable store write

“The throw exists” is not enough if it sits after `openStore`.

## M5 — Wire form and snapshot-once

**When:** redact, compare, or parse untrusted strings; config
or limiter read from accessors; duplicate headers / form
fields / `Authorization`.

Cells: raw; `+` form; percent-encoded; `encodeURIComponent`;
`Headers` vs `Map`; case-duplicate keys; Unicode whitespace;
constructor snapshot vs post-mutation transport value.

Read accessors **once**. A getter that returns stored-DCR here
and unsafe stateless later is FAIL.

Passing the live config object (`this.headers`, a Map, a
getter bag) into `fetchImpl` / transport is **not** a
snapshot. Snapshot means a copy taken **before** the
transport can normalize, replace, or delete keys. If
redaction or a later read uses the same object the
transport received, the snapshot-once cell is empty.

Fail closed: invalid enum must not become `"extend"`; a
non-callable limiter must not be “outage, allow”;
`commit !== "stored"` must not succeed; omitted `formBody`
must not skip the duplicate check.

## M6 — Schema exact-shape

**When:** admitting MySQL/SQLite/client tables, lockfile keys,
or “has unique X.”

Not enough: `UNIQUE` + column named `jti`. Also reject (or
contract as allowed):

- prefix / `SUB_PART`
- functional / expression keys
- competing uniques
- inbound and outbound FKs
- `BEFORE INSERT` rewrite triggers
- partitions
- extra NOT NULL / no-default columns
- `CHECK … NOT ENFORCED`
- case-variant names (`OAuth_Clients`)
- undersized types that revive a consumed value

`INSERT IGNORE` is not replay detection.

## M7 — Test bites the shipped function

Revert the **shipped** function (`walk`, `approveStored`,
`callPort` on `remove`), not the helper the test imports.

FAIL this matrix when the guarantee has **no** test, or the
named test would stay green if the shipped function were
reverted. Do not FAIL a closed class because a second call
site of the same wrapper lacks its own mutation — that is P3.

Also, when the claim needs them: success control; cache-hit /
stored path; all three loopback hosts on every gate; CI
`/tmp` vs macOS tmpdir for filesystem admits.
