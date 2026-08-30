# 19. Parity-fixture protocol

**What this protects and why.** How a second implementation of this contract set, in any language, proves it behaves exactly like the first, and how both stay equal after every contract change. The contract documents are prose. The tests in this repository are TypeScript. Neither is executable by another implementation. This section adds a corpus of language-neutral fixtures. Each fixture pins one contract clause that every implementation MUST pass. Without the corpus, a second implementation is a rewrite from memory. Two authorization servers maintained from memory drift apart in the fail-closed corners this contract set exists to hold.

The TypeScript package in this repository is the **reference implementation**. Any other implementation (the first planned one is in Go) is an **implementation**. The protocol does not privilege the reference implementation's *code*. It privileges the corpus, and the reference implementation must pass it like any other.

## 19.1 Definitions

- **Fixture.** One JSON document that states, for one contract clause: the configuration and pre-state, every injected value (clock, randomness, keys, recorded outbound HTTP), one inbound HTTP request, and the exact observable outcome (status, headers, body, audit events, store effects, outbound calls). Its shape is fixed by `fixtures/schema/fixture.schema.json`.
- **Corpus.** The set of all fixtures under `fixtures/`, versioned as one unit.
- **Runner.** Per-implementation code that loads a fixture, composes that implementation with the fixture's `given`, sends `when.request`, and compares the result with `then`. A runner contains no expectations of its own.
- **Profile.** A `portable` fixture pins OAuth behavior that every implementation shares. A `host` fixture pins the TypeScript reference envelope, including `BridgeConfig`, framework glue, or Node filesystem behavior. The profile is part of the fixture and is repeated in the `MANIFEST.json` coverage entry.
- **Parity.** An implementation is at parity with corpus version *V* when its runner passes every `frozen` `portable` fixture in *V* with zero skips. The TypeScript reference runner also runs every frozen `host` fixture. A host result never counts toward another implementation's parity claim.

## 19.2 What a fixture pins, and what makes it deterministic

A fixture is executable only if nothing in it depends on the machine that runs it. Therefore:

- **Clock.** `given.clock` is the single canonical timestamp for the run (UTC ISO 8601, exactly 3 ms digits, as §12.1). The implementation MUST take it through its clock port (§6.1). One fixture is one request. A flow (authorize → callback → token → refresh) is a chain of fixtures: each states its own `clock`, and the pre-state of each is the expected post-state of the one before it. Nothing sleeps, and no fixture depends on another having run in the same process.
- **Configuration.** `given.config` carries every JSON-representable required §5 field and every optional field the fixture uses. It never relies on a runner default. `given.keys.signingPrivate` supplies the required `signingPrivateJwk`: the runner reads that PEM and imports it as the §5 EC P-256 private key before it calls `createBridgeConfig`. For stored DCR, the runner supplies the required `ClientStore` port from `given.state`. These are port materializations, not configuration defaults. A missing required fixture field fails before the app starts.
- **Randomness.** `given.random.seed` feeds every generated value: PKCE verifiers, `state`, `nonce`, JTIs, token identifiers, and store instance ids. The seed is a non-empty UTF-8 string of at most 1,024 bytes. Its bytes are not normalized. Derive `key = SHA-256(ASCII("mcp-sso-fixture-random-v1") || 0x00 || UTF8(seed))`. Starting with counter zero, derive block `i = HMAC-SHA-256(key, uint64be(i))`, where `uint64be` is an unsigned eight-byte big-endian integer. Concatenate blocks into one byte stream. Each randomness-port call consumes the requested number of bytes from that stream and retains an unused block suffix for the next call. The counter never resets during one fixture. A runner rejects a non-positive or non-safe-integer byte count. An implementation MUST expose this seedable randomness port for fixture runs. Production randomness is unaffected.
- **Keys.** `given.keys` names PEM files under `fixtures/keys/`. The runner rejects an absolute path, a path outside that directory, a symlink, a non-regular file, or a malformed key before app composition. Fixture keys are test material only, generated for the corpus, never reused anywhere else.
- **Ports.** `given.identity.checks` and `given.rateLimit.checks` are complete ordered scripts for their ports. Each call must match the next check, and every check must be consumed. An unmatched call, an unconsumed check, or a call when the list is empty fails the fixture. `given.protectedResource` states the protected handler's required scope and success response. If the handler runs without a configured success response, the fixture fails. `given.state` supplies the Store and ClientStore pre-state. The audit port records events for `then.audit` and supplies no behavior.
- **Network.** `given.http` is the complete list of outbound exchanges the implementation may perform, including identity-provider token endpoints, JWKS documents, and CIMD documents. Each request matcher can match the method, URL, headers, and body. An outbound call that matches no exchange fails the fixture. `then.outbound` is the exact ordered list of calls that MUST have happened, including their method, URL, headers, and body. An empty list means none.
- **Secrets.** A fixture never carries a real credential. Client secrets, tokens, and signing material are corpus sentinels. Where the contract stores a digest (§12.1), the fixture states the digest of the sentinel.
- **Headers.** `when.request.headers` values are strings or arrays of strings. An array means distinct header occurrences on the wire, preserved as occurrences (the rule §8.4 relies on). A runner MUST NOT join or select among them.

Assertions use the following rules:

- A missing assertion member means that the fixture does not assert that observation. `{ "absent": true }` asserts that a named response header or request or response body is absent. `then.audit.absent` and `then.state.absent` provide the explicit selector forms for audit events and store rows. The runner distinguishes omission from asserted absence.
- `then.audit.events` is the exact ordered event list. `then.audit.absent` contains partial event selectors that MUST match no emitted event. Fields omitted from an event selector are wildcards. No event beyond `events` is permitted.
- `then.state.rows` is the exact post-request store snapshot by record kind. `then.state.absent` contains row selectors that MUST match no row. `then.state.allowExtraRows` is required and MUST be `false`. A fixture cannot silently accept extra rows.
- Header names in assertions are lowercase. `then.headers` and a `given.http` request matcher assert only the names they list. A listed `{ "absent": true }` header must not exist. Each `then.outbound` entry instead lists the exact outbound header-name set, so an extra outbound header fails the fixture. A single occurrence is a string and multiple occurrences are an ordered string array.
- A body matcher observes no bytes as absent. If the message's `Content-Type` essence is `application/json`, it parses the body as JSON and matches that value. Every other body is a UTF-8 string, and invalid UTF-8 fails the fixture. `equals` compares the complete observed value, `contains` accepts only a string target, and `schema` is JSON Schema 2020-12 applied to a parsed JSON body.
- A `matches` matcher uses the RE2 syntax accepted by Go's `regexp` package, with no flags. Matching uses UTF-8 string semantics and RE2 search semantics. Authors use `^` and `$` when they need a full-string assertion. A runner MUST reject a pattern outside that dialect instead of accepting an implementation-specific extension such as lookaround or a backreference.

Everything a fixture cannot pin this way is not a fixture (§19.7).

## 19.3 Corpus layout and identifiers

```
fixtures/
  schema/fixture.schema.json       the fixture shape (JSON Schema 2020-12)
  keys/                            corpus-only key material
  <NN>-<section-slug>/             one directory per numbered contract section
    <clause>-<slug>.json           one fixture per pinned clause instance
  MANIFEST.json                    corpus version, SHA-256 of every frozen fixture, profile-labelled clause coverage map
  CATALOGUE.md                     generated from MANIFEST.json: id, clause, what you get, receipt
  FREEZE-LOG.md                    every unfreeze, with its reason
```

`CATALOGUE.md` is the generated human index. It has one row per fixture and is readable without opening the JSON.

A fixture `id` is `<NN>-<section-slug>/<clause>-<slug>`, for example `08-resource-server-verifier/8.4-duplicate-authorization-fails-closed`. `contract.section` and `contract.clause` name the exact clause the fixture pins. The fixture quotes the clause text in `contract.quote` so the coverage gate (§19.4) detects a later rewording.

One clause may have many fixtures (one per input class the clause distinguishes). One fixture pins exactly one clause. Each coverage-map entry contains both the fixture id and its `portable` or `host` profile. Reports give separate counts for the two profiles.

## 19.4 Status, freezing, and the coverage gate

A fixture has one of three statuses:

- `draft` is written from the contract but not yet proven. A draft is not evidence. It becomes `frozen` only after the reference implementation's runner passes it unchanged. That run proves the fixture describes real behavior and not what the prose wishes.
- `frozen` is hash-locked in `MANIFEST.json` and carries a **receipt**. The fixture's `receipt` object names the implementation, version, commit, and run date. A fixture without a receipt cannot be frozen. A frozen fixture MUST NOT change without an entry in `FREEZE-LOG.md` that names the requiring contract change. Changing a frozen fixture without a contract change is a bug report against an implementation, never a specification change.
- `superseded` stays for history, points to its replacement in `supersededBy`, and is never run.

**Coverage gate.** Every normative statement in §05–§17 (MUST, MUST NOT, never, always, fails closed) MUST map to at least one `frozen` fixture id and profile. A normative sentence that lands without one fails the release gate the same way a release-matrix row without evidence does (`docs/verification-design.md`). `MANIFEST.json` contains the map and lists every uncovered clause. Only frozen portable entries satisfy portable parity coverage. A host entry can cover a TypeScript envelope rule, but it cannot make a shared OAuth rule look portable.

## 19.5 The change protocol extends §18

§18 orders a change as contract → threat model → code. With a corpus the order is:

1. Update the contract section.
2. Check the threat model and §12 invariants, as §18.
3. **Update or add the fixtures for the changed clause.** Mark them `draft`.
4. Change the reference implementation until the drafts pass. Freeze the passing drafts, then advance `MANIFEST.json` and the corpus version.
5. Every other implementation pins the new corpus version and changes until it passes. Until it does, its parity status shows the delta (§19.6).
6. Never weaken a fail-closed control to make a fixture pass, as §18 rule 4. If a fixture and a fail-closed rule conflict, the rule wins. Change the fixture, and record why in `FREEZE-LOG.md`.

A reference-implementation release MUST NOT ship a contract change without its frozen fixtures. An implementation release MUST state the corpus version it passes.

## 19.6 Divergence rule

When two implementations disagree on an input:

- The contract is explicit → the implementation that disagrees with it is wrong. Fix it. Add the fixture that would have caught it if none exists.
- The contract is silent or ambiguous → that is a contract gap, not a tie. Write the clause (§18 step 1), write the fixture, then fix whichever implementation the clause makes wrong. "Both are acceptable" is not an outcome. An authorization boundary with two acceptable behaviors has one undefined behavior.

Each implementation publishes a one-line parity status: corpus version passed, corpus version current, and the list of frozen fixtures it does not yet pass. An implementation MUST NOT describe itself as conformant to a contract section whose frozen fixtures it skips.

## 19.7 What fixtures do not cover

Fixtures are Tier 1 evidence in the sense of `docs/verification-design.md`. They do not replace:

- **Tier 2, packaging.** That the shipped artifact (npm tarball, container image, binary) contains and exports the tested behavior is proven per implementation, per artifact.
- **Tier 3, live compatibility.** That a named client on a recorded version completes a real flow against a real provider. The live client matrix runs against every implementation. Parity on the corpus is necessary for a compatibility claim, not sufficient.
- **Store conformance (§12).** The store invariants are behavioral and stay as an executable suite per implementation, driven by the §12 tables. They are listed in the coverage map so an implementation cannot claim parity while skipping a store section.
- **Official MCP conformance.** The MCP project's conformance suite (`@modelcontextprotocol/conformance`) publishes a frozen `server` and `client` requirement set per spec revision. For revision `2026-07-28`, the frozen set is anchored to `@modelcontextprotocol/conformance@0.2.0-alpha.10`. Its scored `server` list contains no OAuth resource-server scenario. Its authorization scenarios run under the `client` command and score the MCP client against controlled authorization and resource servers. It also has no authorization-server role. The corpus therefore excludes no §8, §9.1, or bridge scenario for this revision. If a later frozen requirement set scores server-side OAuth behavior, the corpus MUST omit only the exact overlapping scenario and record the suite version, scenario id, revision, and date in `MANIFEST.json`. An official client receipt does not prove this package's resource-server or authorization-server behavior. Section 16 records official receipts beside the self-declared matrix, never in place of it.

## 19.8 Slice order for a new implementation

A new implementation builds and proves one slice at a time. Each slice: extract fixtures from the reference tests and the contract clauses → the reference runner passes them → freeze → implement until the new runner passes. Code for a slice MUST NOT start before its fixtures are frozen.

1. §8 resource-server verifier, §9 protected-resource metadata, and the `WWW-Authenticate` challenge. This is the smallest slice that lets an implementation protect a `/mcp` route.
2. §9 bridge core with §7, §10, and §11: registration (DCR and CIMD), consent, PKCE, token exchange, refresh rotation, and revocation.
3. §17 identity flows in the order deployments need them: the upstream redirect flow, Entra, generic OIDC, then the remaining providers.
4. §12 stores against the conformance tables, §13 audit, and §14 error catalog. Every catalogued error is one fixture and is cheap to pin.
5. §16 conformance-matrix claims, re-asserted per implementation.

## 19.9 Threat-model notes

- **The corpus is a target.** An attacker who can edit a frozen fixture can make a fail-closed rule look satisfied. Review `MANIFEST.json` hashes and the freeze log like code. CI fails on a hash mismatch. The freeze log is append-only.
- **Fixtures must never leak.** No real hostname, tenant, client id, secret, or key from any deployment appears in a fixture. Corpus material is generated for the corpus.
- **Skips are failures.** A runner that skips a frozen fixture reports failure, as the store-conformance suite does. A skipped row is not evidence.

## 19.10 Delivery forms

The corpus is files plus one runner per implementation. This section requires no other form. Two later forms are compatible with it and are recorded so they are not designed twice:

- **A conformance client.** The frozen corpus walked by one tool against any implementation's URL, printing the catalogue with a pass mark per clause and a receipt line. It lets a third party verify a parity claim without reading either codebase. It is not required for parity and is not scheduled.
- **A misbehaving upstream.** For a gateway *in front of* an MCP server, the same catalogue idea points the other way: a backend that misbehaves on purpose with stalled, cut, or reset event streams, wrong media types, or malformed JSON-RPC shapes. That belongs to a gateway's own test suite, not to this corpus.

## 19.11 Bootstrap status

This section, the fixture schema, and one `draft` host fixture (`08-resource-server-verifier/8.4-duplicate-authorization-fails-closed`) exist. The fixture is host-profiled because its exact `WWW-Authenticate` assertion pins the reference implementation's origin-root protected-resource metadata location. Atesaki D1 uses a route-scoped path-inserted location and does not consume that fixture as portable evidence. No runner exists yet. The reference runner is the first implementation deliverable because nothing can be frozen until it runs. `MANIFEST.json` and `CATALOGUE.md` do not exist until the freeze machinery lands. The official MCP conformance suite has not yet been run against any shipped composition. Section 16 remains self-declared until it is. Until then no implementation may cite this section as evidence of parity or conformance.
