# Verification design

The verification model separates deterministic implementation evidence from package evidence and live compatibility evidence. One green test cannot stand in for all three.

## Why the model has three tiers

Tier 1 proves behavior that CI can reproduce. It runs native TypeScript on Node's built-in test runner. Its tests use loopback servers, injected transports, fake resolvers, and explicit clocks. They do not depend on public networks, provider accounts, browser state, or real time delays.

Expiry tests use an injected `ClockPort` or an explicit test clock. Wall-clock sleeps are limited to sub-deadline transport behavior that cannot be modeled with a test clock. This keeps expiry evidence deterministic without removing the timing tests that exercise transport deadlines.

Tier 2 proves the package that users install. Source-tree tests can pass while the npm artifact omits an export, a generated file, or an optional peer. The packed-artifact checks install the tarball and call its public entry points.

Tier 3 proves compatibility with a named provider or client on a recorded version. CI cannot prove behavior in a real tenant or a signed-in desktop client. Live evidence therefore records the date, the exact mcp-sso version or commit, the external version when visible, and every skipped step.

Higher tiers do not replace lower tiers. A successful provider login does not replace deterministic security tests. A source-tree test does not prove that the npm tarball contains the tested code.

## Why Tier 1 requires a real flow

A unit test proves one function under its test inputs. OAuth failures often sit between functions: an adapter drops evidence, a store changes semantics, or a generated project omits wiring that the library supports.

The Tier 1 baseline crosses those boundaries. `test/e2e-mcp-sdk.test.ts` runs registration, authorization, token exchange, a protected `/mcp` call through the official MCP SDK, and refresh rotation. It proves replay-family revocation on one family, then revokes a second active family and confirms that its refresh token is refused. Store invariants use the shared conformance suite so Memory, SQLite, and MySQL receive the same tests.

A feature reaches implemented status only after its real-flow Tier 1 row is covered. Unit tests alone do not meet that bar. Every Tier 1 change keeps the official MCP SDK baseline green.

## Why the release matrix is separate

The full test suite is broad, but its test names do not show which shipped features have end-to-end evidence. `test/release-matrix.json` is an executable allowlist of release rows. `scripts/check-release-matrix.mjs` binds each row to an exact `### RM.N — <title>` section in [the release verification reference](verification.md).

Each row states the strongest evidence it has. Unit evidence stays unit evidence. One adapter route does not prove its siblings. The release command fails when a row lacks evidence, a selected test skips, a public export moves, or a shipped example disappears.

## Why some rows combine features

Most rows prove one deployable path. Combination rows exist where independent features can interfere without failing their own tests.

`RM.14` runs CIMD and stored DCR in one `Bridge`. The row proves that a CIMD client cannot inherit stored DCR grants and that an opaque client still accumulates its own grants.

`RM.15` crosses both DCR modes with CIMD enabled and disabled. The row proves that an HTTPS `client_id` either enters CIMD resolution or fails. It cannot fall through to DCR lookup.

`RM.16` runs the store conformance suites through the packed package export map. A contract that requires downstream stores to pass a suite is incomplete unless the published package exports that suite.

## Why live evidence stays separate

Provider and client behavior changes outside this repository. A live result is useful only with a date and an exact version. Keeping live receipts outside the deterministic matrix prevents an old provider run from reading as proof for the current source tree.
