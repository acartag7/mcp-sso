# 10. Redirect-URI policy

## 10.0 The redirect-entry grammar (ONE definition, every consumer)

> **Status: implemented.** The shared predicate is enforced at all nine
> consumers below; the differential table remains historical evidence of the
> parser disagreement this section closed.
>
> **The implementation PR owes exactly this, and it is enumerable rather than
> "one negative test per rejected shape" left to judgment:**
>
> 1. A boot validator applying §10.0 to every `redirectAllowlist` entry —
>    under the §5 read-once/publication rule: the validator snapshots the
>    caller's array, validates THAT copy, and publishes the same frozen copy
>    it validated (never the caller's array), so a post-boot mutation or
>    accessor-backed entry cannot put an unvalidated value where request-time
>    reads look (the validate-vs-publish class). `redirectAllowlist` now follows
>    that rule. **And it is not the only array in the config:**
>    `scopeCatalog`, `defaultScopes` and `allowedOrigins` remain tracked by issue
>    #100 and are deliberately NOT silently fixed here. This obligation owns
>    `redirectAllowlist`; the other three are the same class, tracked by issue
>    #100, and are deliberately NOT silently fixed here. Consumer (5) covers the
>    direct-call path that bypasses boot entirely; this obligation covers the
>    array boot itself owns.
> 2. **Registration-time enforcement (the write side), in BOTH DCR modes:**
>    `registerClient` applies §10.0 to each `redirect_uris` entry BEFORE any
>    other effect, REJECTING any entry that is not already fully canonical —
>    the omitted-root-slash exemption is `redirectAllowlist`-only and does not
>    extend here, so nothing is folded on the client's behalf. Stateless mode
>    validates and echoes the entry unchanged (it persists nothing, but the
>    same endpoint must not accept and echo an entry the grammar forbids: one
>    grammar, every consumer includes the stateless sibling); stored mode
>    additionally persists it unchanged. Registered === echoed === presented,
>    byte for byte, which is what makes §10.2's raw comparison sound. The write side also enforces the **1..16 array
>    cardinality cap** (§9.2, bounding the authorize-time scan) and the
>    **stored client's §10.2 per-type
>    policy**: a `web` registration (the default when `application_type` is
>    omitted) rejects any non-`https` entry, and a `native` registration
>    rejects any non-loopback entry — at WRITE time, not first at authorize.
>    Without that, `http://localhost/cb` registers as `web` (passes the
>    allowlist and §10.0) and then §10.2 refuses it forever, and a
>    non-loopback https entry registers as `native` with the same outcome:
>    the exact register-but-never-authorize defect this obligation exists to
>    close, reachable through type policy instead of canonicality. The raw `redirect_uris` field crosses this boundary as
>    `unknown[]`, never pre-narrowed: `Bridge.handleRegister` hands the raw value
>    through and the §10.0 check rejects a non-string member, never filters it.
>    **Preserving raw members does NOT remove the read-once requirement, and
>    the two land together:** a getter- or Proxy-backed `redirectUris` passed straight
>    to `registerClient` can serve benign entries to the validator and
>    different, unvalidated entries to `ClientStore.save` and to the echoed
>    response. So `registerClient` **snapshots the array ONCE
>    (from one captured length and one read per index after the `Array.isArray`
>    check), validates THAT copy, and persists and echoes the SAME copy** — obligation 1's read-once rule
>    applied to the DCR boundary, with an accessor-backed regression test
>    (an array whose indices return a valid entry on first read and a
>    forbidden one afterwards must be REJECTED or must persist only what was
>    validated — never a mix). Sibling axis, checked: the adapter's own
>    `grant_types` follows the same snapshot discipline, and the §17.2
>    machine-shape rejection (§9.2) depends on seeing unfiltered members.
>    **Preserving the members is only half of it:** every `grant_types` member is a primitive
>    string or the registration is rejected `invalid_client_metadata`** (the
>    §9.2 error for malformed metadata), with `[7]` and `[null]` as witnesses.
>    Preserving a malformed member for inspection and then not inspecting it
>    is strictly worse than filtering it.
>    **The CONTAINER is checked before its members**, on both fields: a
>    present-but-non-array `grant_types` or `redirect_uris` is rejected
>    `invalid_client_metadata`, never coerced. This closes the earlier
>    `stringArray` collapse where every non-array became empty. Witnesses:
>    `grant_types: "client_credentials"`,
>    `grant_types: 7`, and `redirect_uris: "https://a.test/cb"` (the
>    same shape as the `allowedOrigins` substring-gate defect — a bare string where an array is
>    expected) all rejected. Absent remains valid for `grant_types` (it is
>    optional); `redirect_uris` absent is already `invalid_request` per §9.2.
>    **This coercion defect is a CLASS with FOUR members, not two.**
>    `Bridge.handleRegister` also reads `token_endpoint_auth_method` and
>    `application_type` through `formField` (`src/adapters/bridge.ts:114,116`;
>    `src/adapters/http.ts`), whose
>    `typeof value === "string" && value ? value : undefined` collapses a
>    number, `null`, an object, AND the empty string to `undefined`. The Bridge
>    therefore passes both fields raw to `registerClient`. The rule generalizes:
>    **a present DCR metadata field of the wrong type is
>    `invalid_client_metadata`, never coerced to `undefined`/`[]`/absent** —
>    for all four of `redirect_uris`, `grant_types`,
>    `token_endpoint_auth_method`, and `application_type`, each with `7`,
>    `""`, `null`, `{}` witnesses, each exercised through the Bridge per (c)
>    above. **One more incidental the removed `.filter()` was providing:** it
>    dropped EMPTY-STRING members too, so after the prescribed change
>    `grant_types: [""]` is a primitive string that passes the member check and
>    still reaches a gate that only asks `.includes("client_credentials")`.
>    Members must therefore be **non-empty** primitive strings, with `[""]` a
>    witness alongside `[7]` and `[null]`. (`redirect_uris: [""]` is already
>    covered — the empty string is an obligation-6 rejection row.)
>    `registerClient` REJECTS a non-canonical entry at registration,
>    not to store the normalized return: storing a value the client did not
>    send trades this defect for the twin described in §9.2. Write and read
>    guards must land together or the pair is worse than neither.
> 3. §10.2 applying §10.0 to every registered URI **it reads** (stored-state
>    sibling, below) — not only at registration. Covers records written before
>    this grammar existed or populated out-of-band.
> 4. `assertCimdRedirectUri` enforcing §10.0 rather than its own shape rules
>    (§17.1.5 rule 20, as amended there) — AND `projectCimdRegistration`
>    with one CIMD-specific note: **the omitted-root-slash exemption is
>    `redirectAllowlist`-only** (see "Canonical spelling" above), so it does
>    not apply here either — a CIMD `redirect_uris` entry must be
>    the full canonical `href` (`https://a.test/`, never `https://a.test`),
>    and the non-canonical spelling is rejected `document_invalid`. CIMD is
>    the sharpest case for that scoping: config gets a boot error naming the
>    canonical form and DCR gets a rejection at registration, but CIMD has NO
>    response channel at all, so EITHER projection choice for the
>    accepted-then-folded spelling breaks someone silently (project raw: the
>    §17.1.6 exact matcher can never match the canonical form a conforming
>    client presents; project canonical: a client presenting the exact string
>    published in its own document fails). Rejecting the non-canonical
>    spelling at document-validation time is the only choice that keeps
>    stored === published === presented as the same bytes — raw-equality
>    matching stays sound and the author learns at validation, not via a
>    silent authorize failure. The CIMD round-trip test covers both sides:
>    a document entry `https://a.test` is rejected `document_invalid`;
>    `https://a.test/` validates, projects verbatim, and matches a presented
>    `https://a.test/`.
> 5. `assertAllowedRedirectUri` applying §10.0 to every allowlist entry **it
>    reads** before matching (consumer (5) — the export-path sibling of 3;
>    rationale in the consumer list below). A non-conforming entry is refused
>    `invalid_redirect_uri`, never skipped and never matched.
> 6. **One rejection test per row of this closed list.** Two requirements on
>    HOW each row is tested, because without them the whole list is
>    tautological. Before §10.0, every entry-grammar witness below could "pass"
>    by rejecting with `redirect_uri is not allowed` (allowlist NON-MEMBERSHIP),
>    while accepting once the entry was actually placed:
>
>    - **(a0) EVERY row states its setup — rejections included.** The
>      per-consumer setup rule under obligation 7 covers positives only, which
>      left the rejection rows setup-free and therefore membership-gated.
>      Concretely: the DCR omitted-slash row (`https://a.test`) needs
>      `redirectAllowlist: ["https://a.test/"]` or it fails for
>      non-membership; the non-canonical PRESENTED rows need a registration of
>      `https://a.test/cb` (stored: plant the client; stateless: allowlist the
>      origin) or they fail the same way; the presented-fragment row needs its
>      origin reachable — or use a built-in host (`https://claude.ai/cb#frag`)
>      when zero config is the point. Spelled out for that row, the one most
>      likely to be written setup-free: *stored `web`* registers
>      `https://client.test/cb` and presents it with `#frag`; *stored `native`*
>      registers `http://127.0.0.1/cb` and presents that with `#frag`;
>      *stateless* puts `https://client.test/` on the allowlist. Before §10.0,
>      both matchers set `url.hash = ""` and accepted these requests; the tests
>      must fail if that normalize-then-match behavior returns.
>    - **(a) Defeat membership first.** For a matcher/export or stored-read
>      leg, the forbidden string MUST be placed as the allowlist/registered
>      entry under test (or the leg must be pinned to boot / the CIMD document
>      validator, where the entry IS the input). A witness that is merely
>      absent from the allowlist proves nothing about the grammar: probed —
>      `javascript:alert(1)`, `http://a.test/cb`, and
>      `https://client.test/cb#frag` all reject with "not allowed" when
>      unplaced, and all three ACCEPT when placed.
>    - **(b) Assert the REASON, not just the throw.** Each test asserts the
>      error identifies the grammar rule and names the offending entry —
>      never merely that an `OAuthError` was raised. (Rows whose subject is
>      not a single entry — a non-array `redirectAllowlist`, a 17-entry DCR
>      array — assert the field name and the rule instead; "names the
>      offending entry" is not literally satisfiable there.)
>    - **(c) Pin the PRODUCTION path for adapter-boundary rows.** The
>      container/member rows must be exercised through `Bridge.handleRegister`
>      with a raw JSON body, not against `registerClient` alone. The historical
>      bypass was adapter-only (`stringArray` collapsed the malformed container
>      before the core saw it), so a core-only unit test could stay green while
>      the production path remained open.
>
>    The rows. Each asserts the error names the offending ENTRY, **except the
>    field-level rows** — a non-array `redirectAllowlist`, a 17-entry DCR
>    array, and the four wrong-typed metadata fields have no single offending
>    entry to name, so those assert the FIELD name and the rule instead
>    (per (b) above; the blanket wording was not literally satisfiable):
>    `*`; any `*`-bearing entry — in the host
>    (`https://*.a.test/cb`) OR the path (`https://a.test/cb*`,
>    `https://a.test/*`; a host-star is WHATWG-canonical — verified — so the
>    test proves the `*` rule fires on its own, not via canonicality); a non-`http(s)`
>    scheme (`javascript:`, `data:`); userinfo (`https://u:p@a.test`) AND empty
>    userinfo (`https://@a.test`) AND **canonical** userinfo
>    (`https://u:p@a.test/` — its own `href`, so the test proves userinfo is
>    rejected by its own rule, not as a canonicality side effect); a query
>    delimiter — non-canonical (`https://a.test?`) AND canonical
>    (`https://a.test/?`, `https://a.test/cb?`); a fragment — including the
>    canonical trailing forms (`https://a.test/#`, `https://a.test/cb#`); a
>    percent-encoded C0 control or DEL (`https://a.test/cb%0A`, `%0D`, `%00`,
>    AND `%7F` — DEL is in the rule, so it gets its own witness; each
>    canonical, each rejected); a trailing-dot host (`https://a.test.` AND its
>    canonical spelling `https://a.test./`);
>    whitespace (leading/trailing/interior); a literal control character; a
>    backslash; a malformed percent-escape; a non-canonical origin
>    (`HTTPS://A.TEST`, `https://%65xample.com`, `https://a.test:443`, the
>    default-port fold `http://localhost:80`, and ALL THREE IPv4 variant
>    spellings the grammar text names — dword `https://2130706433`, hex
>    `https://0x7f.0.0.1`, octal `https://0177.0.0.1`); a
>    non-canonical exact-URI (`https://a.test:443/cb`, `https://a.test/x/../cb`,
>    `https://a.test/./cb`); an entry longer than 2048 UTF-8 bytes; the empty
>    string `""` AND a whitespace-only entry (degenerate emptiness gets its own
>    witnesses — an empty string is not a parse error to swallow, it is a
>    named rejection); an unparseable entry (`https://`, no host — `new URL`
>    throws, and the thrown case must map to the same named rejection, never
>    propagate) AND a **degenerate authority that PARSES**
>    (`https:///cb` — three slashes; WHATWG reads `cb` as the HOST and yields
>    `https://cb/`, verified, so this is not caught by the throw path and
>    needs its own witness); an entry with interior tab/CR/LF
>    (`https://a.test/c<TAB>b` — stripped by the parser, so only the raw
>    check sees it); a non-canonical IPv6 spelling
>    (`http://[0:0:0:0:0:0:0:1]/cb`, which folds to `http://[::1]/cb`); `http://a.test/cb` (http on a non-loopback host); a
>    non-string entry; a non-array `redirectAllowlist`; a **17-entry DCR
>    `redirect_uris` array** (the §9.2 cardinality cap gets its own boundary
>    witness — per-entry tests cannot catch an oversized array); a `web`
>    registration carrying `http://localhost/cb` AND a `native` registration
>    carrying a non-loopback https entry (the obligation-2 per-type write
>    guard, one witness per type); a PRESENTED `redirect_uri` carrying a
>    fragment (`https://client.test/cb#frag`) rejected at authorize in both
>    DCR modes (the reject-don't-strip rule under "The two matching
>    policies" — before §10.0 both matchers stripped and matched); a CIMD document entry
>    in omitted-slash form (`https://a.test` — rejected `document_invalid`
>    per obligation 4's CIMD tightening) AND a **DCR registration** in the
>    same form (rejected `invalid_redirect_uri`, per the exemption's
>    config-only scope — accepting it would create the twin that breaks the
>    registration-to-authorization round-trip under raw equality); and
>    **non-canonical PRESENTED
>    `redirect_uri`s against a canonical registration** — one witness per fold
>    WHATWG performs, because each collapsed into a false match before §10.0:
>    scheme case (`HTTPS://a.test/cb`), host case (`https://A.TEST/cb`),
>    default port (`https://a.test:443/cb`), dot segments
>    (`https://a.test/x/../cb`), and all of them at once
>    (`HTTPS://A.TEST:443/x/../cb`, verified to normalize to exactly
>    `https://a.test/cb` on Node 24). Each must be REFUSED against a
>    registration of `https://a.test/cb`, in both DCR modes — these are the
>    request-bytes-never-registered cases, and the `web` leg is where the
>    §10.2 exact-match policy lives.
> 7. **Positive tests** that the grammar does not over-reject. **Each case is
>    listed under the consumer it applies to** — this list must never say
>    "every consumer", because the consumers have DIFFERENT admissible sets:
>    the omitted-slash exemption is `redirectAllowlist`-only (obligations 2
>    and 4 reject it), emptiness is `redirectAllowlist`-only (DCR and CIMD
>    require 1..16 entries per §9.2 / §17.1.5 rule 19), and stored DCR
>    additionally partitions by `applicationType`. A positive case asserted
>    against the wrong consumer is a test that CANNOT pass without weakening a
>    rule. **Every case states its SETUP**, because the built-in defaults are
>    exactly `https://claude.ai`, `https://chatgpt.com`, `http://localhost`,
>    `http://127.0.0.1` — `a.test` is NOT among them, and stored DCR validates
>    registrations through the same global allowlist (§9.2), so any `a.test`
>    positive requires `redirectAllowlist: ["https://a.test/", …]` in config.
>    A positive case whose setup is unstated is not reproducible, and an
>    implementer will read the failure as a rule to weaken.
>    - *`redirectAllowlist` (boot)* — the entries ARE the setup: all four built-in defaults; the
>      omitted-slash forms `https://a.test`, `https://xn--80a.test` (punycode
>      — the ASCII form of the Cyrillic host above), `http://[::1]:9`; their
>      canonical spellings; `https://a.test/cb%2F..%2Fadmin` (canonical,
>      inert); **and an EMPTY array** (the built-in defaults cover the common
>      case — §10.0's "empty is valid" rule lives here and only here).
>    - *Stored DCR, `web`* (setup: `a.test` configured): `https://a.test/` and
>      `https://a.test/cb%2F..%2Fadmin` — https, canonical, 1..16 entries.
>      NOT `http://[::1]:9/` (web is https-only) and not an empty array.
>      `https://claude.ai/cb` also passes with an empty config allowlist.
>    - *Stored DCR, `native`* (setup: empty config allowlist suffices —
>      `localhost` and `127.0.0.1` are built-in; `[::1]` is NOT, so
>      `http://[::1]:9/` needs it configured): `http://127.0.0.1/cb`,
>      `http://localhost/cb`, and `http://[::1]:9/` — loopback, canonical.
>      NOT a non-loopback https entry (§10.2 native policy) and not an empty
>      array.
>    - *Stateless DCR*: the **§10.1 global-allowlist set — NOT the `web` set**.
>      Stateless mode persists no `applicationType`, so §9.2's
>      loopback-for-everyone policy applies and the per-type partition above
>      does not exist here. Positives split by SETUP, because the built-in
>      defaults are `claude.ai`, `chatgpt.com`, `localhost`, `127.0.0.1` and
>      nothing else — `a.test` is not among them:
>      *with an EMPTY config allowlist*, `https://claude.ai/cb` plus the
>      canonical loopback paths `http://localhost/cb`,
>      `http://localhost:54321/cb` (any port), `http://127.0.0.1:8080/cb` all
>      pass; *with `redirectAllowlist: ["https://a.test/"]`*, `https://a.test/`
>      passes too. Both verified on HEAD — and `https://a.test/` is REJECTED
>      under the empty-list setup, which is why the two are not one bullet. Borrowing the
>      https-only `web` set here would let an implementation reject the
>      primary native-client loopback path while passing this obligation.
>      §9.2 persists nothing but echoes the accepted entry unchanged.
>    - *CIMD document* (no config allowlist involved — rule 20's own
>      scheme/host rule governs, so no setup is needed):
>      `https://a.test/` plus a loopback `http://[::1]:9/` — canonical
>      spelling, 1..16 entries.
>    Plus a **round-trip** test per applicable consumer: a URI accepted at
>    registration is still accepted at authorize (obligations 2 and 3 agree).
> 8. A **differential test** exercising **all NINE consumers of the closed
>    list — nine legs, numbered to match the consumer list below, because an
>    earlier prose version of this sentence named seven and a skim-implementer
>    could build a seven-leg suite: (1) boot · (2) DCR write, both modes ·
>    (3) §10.2 stored read · (4) CIMD document · (5) exported matcher ·
>    (6) flow-cookie CIMD registration · (7) consent token at approve ·
>    (8) opaque flow-cookie params · (9) authorization-code record.** In
>    detail — boot config, the DCR registration write in BOTH modes (the
>    stateless leg asserts rejection AND that nothing forbidden is echoed;
>    the stored leg asserts rejection before persistence), the §10.2
>    stored-state READ,
>    CIMD document validation, the exported §10.1 matcher called DIRECTLY
>    with an entries array that never passed boot, the flow-cookie CIMD
>    consumption at callback, and the consent-token redirect at
>    `approve`: for each row of the table
>    below, every consumer agrees. The stored-read leg is exercised with
>    **pre-existing/out-of-band state** (a record placed directly in the
>    `ClientStore`, never through `registerClient`); the direct-call leg
>    passes the forbidden entry straight to `assertAllowedRedirectUri`; the
>    flow-cookie leg forges a validly-signed cookie whose carried
>    `CimdRegistration` holds the forbidden entry (modeling a pre-upgrade
>    in-flight cookie) and asserts the callback refuses it; the consent-token
>    leg mints a VALIDLY SIGNED consent token carrying the forbidden redirect
>    (modeling a token issued before the upgrade) and asserts `approve`
>    refuses it on BOTH the Deny and the Approve path, with a DIRECT error
>    rather than a redirect to the suspect value; the opaque-cookie leg
>    forges a signed cookie whose `params.redirect_uri` is forbidden and NO
>    `cimd` claim is present (so the CIMD gate returns early) and asserts
>    every callback error path refuses rather than redirecting to it; the
>    authorization-code leg stores a code record carrying a forbidden
>    `redirectUri` directly in the store and asserts the token endpoint
>    refuses `invalid_grant` even when the presented value matches those
>    bytes and PKCE verifies —
>    wiring the shared predicate into the entry boundaries while any
>    read-time consumer forgets its check must FAIL this test, or a legacy
>    record, a directly-supplied array, an in-flight cookie (CIMD or opaque),
>    a live consent token, or an unexpired authorization code carrying a
>    forbidden entry can still authorize. (The measured table has three
>    columns because the read guards did not exist on `40d9f58`; the
>    test covers nine.) That agreement is the property this section exists to
>    create, and without it the differential can silently return.

Everything below — the §10.1 global allowlist, the §10.2 per-client policy, and
the §17.1 CIMD document/matcher — decides against **this single grammar**. It is
stated first because the alternative has been demonstrated: three call sites
each inferred their own notion of a "valid entry" and disagreed on nearly every
non-obvious input, which is a **parser differential**, not a set of unrelated
bugs. Measured on `40d9f58`:

**Measurement protocol** (stated because the verdict depends on it — an
earlier version of this table gave one column with no protocol and was wrong
in two cells): each entry is placed in `redirectAllowlist` and probed twice —
**self** = present the entry string itself as the `redirect_uri`; **widens** =
present a DIFFERENT path on **that row's own canonical origin** (e.g.
`https://a.test/OTHER` for the `a.test` rows, but
`https://xn--80a.test/OTHER` for the Cyrillic row and
`https://example.com/OTHER` for the percent-encoded row — the probe follows
the origin the entry CANONICALIZES to, which is the whole point of those two
rows). "Widens"
is the origin-wide grant; "self" is whether the entry is a live redirect
target at all.

| entry | §10.1 self | §10.1 widens | CIMD matcher | CIMD doc validator |
| --- | --- | --- | --- | --- |
| `*` | reject | reject | **accept** | reject |
| `https://a.test/cb*` | **accept** | reject | **accept** | **accept** |
| `javascript:alert(1)` | **accept** | reject | **accept** | reject |
| `data:text/html,<script>1</script>` | **accept** | reject | **accept** | reject |
| `https://u:p@a.test` | reject | **accept** | **accept** | reject |
| `https://@a.test` | **accept** | **accept** | **accept** | reject |
| `https://a.test?` | **accept** | **accept** | **accept** | **accept** |
| `HTTPS://a.test/cb` | reject | reject | **accept** | **accept** |
| `https://a.test:443/cb` | reject | reject | **accept** | **accept** |
| `https://a.test/x/../cb` | reject | reject | **accept** | **accept** |
| `https://а.test` (Cyrillic `а`) | **accept** (as `xn--80a.test/`) | **accept** (as `xn--80a.test`) | **accept** | **accept** |
| `https://%65xample.com` | **accept** (as `example.com/`) | **accept** (as `example.com`) | **accept** | **accept** |
| `http://remote.test/cb` | **accept** | reject | **accept** | reject |

**The `javascript:` and `data:` rows were the sharpest reading of the measured
pre-§10.0 behavior:** the old §10.1 matcher had no scheme check and returned
true on exact normalized equality before any other rule, making those entries
live redirect targets when configured. The shared predicate now rejects them
before matching; the table remains the historical evidence for consumer (5).

**Definition.** A redirect entry — whether it comes from `redirectAllowlist`,
a stored `ClientRegistration.redirectUris`, or a CIMD document's
`redirect_uris` — is EXACTLY one of two forms, and nothing else:

- **Origin form** — `scheme "://" host [ ":" port ]`, with **nothing after the
  authority**: no path (or the single `/`), no query, no fragment, no userinfo.
- **Exact-URI form** — origin form followed by a path of **at least one
  non-root segment**: no query, no fragment, no userinfo.

**Classification is total and unambiguous:** the bare authority and the
root-slash spelling (`https://a.test`, `https://a.test/`) are BOTH origin form
— the root slash alone is never an exact-URI path, so no entry satisfies both
definitions. The first character after the authority decides: nothing or a
lone `/` ⇒ origin form; `/` followed by
at least one NON-EMPTY segment ⇒ exact-URI form. A path that is only slashes
(`https://a.test//`) is neither: it is canonical under WHATWG (verified —
`pathname === "//"`) but has no non-empty segment, so it satisfies neither
form and is **REJECTED**. Stating it explicitly because the two readings
disagree — the definition requires a non-root segment while "`/` followed by
anything" would admit it — and an empty-segment path is exactly the shape
that makes two matchers differ.

**Origin form is origin-wide ONLY in §10.1.** The same entry means something
narrower everywhere else, and the difference is security-relevant, so it is
stated rather than left to inference: under **§10.2** (both `web` and
`native`) and under the **§17.1.6 CIMD matcher**, a registered entry matches
by the per-type rule — path included — so an origin-form registration
authorizes only the origin ROOT path. Measured on HEAD: a `web` client
registered `https://app.test/` presenting `https://app.test/cb` is REFUSED
(`src/redirect.ts:86`), while the same entry in `redirectAllowlist` ALLOWS
it; a `native` client registered `http://127.0.0.1/` presenting
`http://127.0.0.1:54321/cb` is likewise refused (`src/redirect.ts:102`
compares `pathname`). A client or document that wants a callback path MUST
register exact-URI form.

**A canonical root callback is VALID and is not rejected.** Registering
`https://a.test/` is a legitimate choice — it authorizes exactly
`https://a.test/`, the origin root, and nothing else — so obligation 2 and
obligation 4 both ACCEPT it, and obligation 4's round-trip witness
(`https://a.test/` validates, projects verbatim, and matches a presented
`https://a.test/`) stands unchanged. What obligation 2 rejects is only the
**omitted-slash spelling** (`https://a.test`), and for the reason stated in
"Canonical spelling" — the twin it would create under raw equality, not
anything about origin form. There is no register-but-never-authorize record
here: a client registering the canonical root gets exactly the grant its
entry describes. The narrowing above is a statement about GRANT WIDTH — an
origin-form entry means origin-wide in §10.1 and root-only in §10.2/CIMD —
not a rejection rule. A deployer who wants
`https://a.test/` to match ONLY the root path cannot express that in origin
form and must accept that the root-slash spelling is origin-wide — stated
here because the two readings differ in grant width, which is exactly the
ambiguity class this grammar exists to remove.

**`http` is loopback-only, in the grammar itself:** the `http` scheme is
valid ONLY with host exactly `localhost`, `127.0.0.1`, or `[::1]`;
`http://prod.example.com/cb` is rejected at the entry boundary, not left for
per-consumer policy. This lifts the rule §10.2 (`web` ⇒ https) and §17.1.5
rule 20 (http ⇒ loopback) already apply into the shared grammar, so
stateless-mode §10.1 — which previously had no HTTPS floor of its own —
cannot be configured to send an authorization code over cleartext to a
non-loopback host.

**Canonical spelling is required in BOTH forms**, not just exact-URI form: the
raw entry MUST equal `new URL(entry).href`, with exactly one exemption — an
origin-form entry MAY omit the root slash WHATWG appends (`https://a.test` is
accepted for `https://a.test/`; nothing else is).

**The exemption is scoped to the §10.1 allowlist — deployer config AND the
built-in defaults — and to nothing else.** The built-ins are themselves
omitted-slash entries (`https://claude.ai`, `https://chatgpt.com`,
`http://localhost`, `http://127.0.0.1` — all four verified non-canonical: each
gains a root slash under `new URL(entry).href`), so the exemption must cover
them or obligation 1's "every built-in default is §10.0-valid" unit test
cannot pass. They are left in that spelling deliberately: it is the form
deployers read in the docs and copy into config, and §10.1 matches them
origin-wide either way (see below).** It is safe exactly there because a §10.1
origin-form entry matches **origin-wide**, never by raw equality against a
presented URI, so the two spellings cannot disagree about a match. **Boot does
NOT rewrite the entry**: the array published is byte-identical to the array
validated (obligation 1's read-once/publication rule — a separately normalized
copy would be an array boot never validated, which is the
validate-vs-publish class this repo has hit six times). The accepted
omitted-slash spelling is therefore stored and matched AS WRITTEN, and it
works because the §10.1 origin branch derives the origin from the parsed entry
rather than comparing its bytes — `https://a.test` and `https://a.test/` both
yield origin `https://a.test`, so the fold happens at COMPARISON time inside
the matcher, never at storage time. A rejection still names the canonical form
to paste back. On every OTHER surface the omitted-slash
form is **REJECTED**, not accepted-then-folded:

- **DCR `redirect_uris`** (obligation 2) — because §10.2 compares registered
  URIs by RAW equality. Accept-then-fold creates a twin: the client registers
  `https://a.test`, the server persists and echoes `https://a.test/`, and a
  client that re-presents its own original spelling fails a comparison that
  forbids normalizing the presented side. Rejecting at registration surfaces
  the fix once, at the moment the client can act on it, instead of as an
  authorize-time failure with no stated cause.
- **CIMD documents** (obligation 4) — same reason, and worse: CIMD has no
  registration response at all, so a fold is invisible to the client.

That leaves ONE spelling in play wherever raw equality decides, on both the
stored and presented sides, which is what makes the reject-don't-normalize
rule internally consistent. Without this rule on origin
form, `https://%65xample.com` is accepted, parses to `https://example.com`, and
is then granted **origin-wide** access to `example.com` under §10.1 — an entry
whose text names one host and whose effect names another, which is precisely
what "reject, don't normalize" exists to prevent. The same applies to
`HTTPS://EXAMPLE.com` and any other spelling WHATWG folds — including two
folds a deployer may not expect: WHATWG **strips the scheme's default port**
(`:80` on `http`, `:443` on `https`), so `http://localhost:80` is
non-canonical and rejected — write `http://localhost`; only a non-default port
survives (`http://localhost:8080`). And WHATWG **resolves alternative IPv4
spellings** — a dword/integer host (`https://2130706433`), hex labels
(`https://0x7f.0.0.1`), and octal labels all fold to `https://127.0.0.1/`
(verified, Node 24), so every one of them is non-canonical and rejected; the
canonical rule is what catches them, and the rejection list below names them so
an implementation checking parsed fields cannot miss the class §17.1.5 rule 6
enumerates for the CIMD client_id.

Two consequences of requiring canonical spelling, recorded so an implementer
does not "helpfully" relax either:

- A **Unicode homograph** entry (`https://а.test`, Cyrillic `а`) is REJECTED
  under §10.0 — it canonicalizes to `https://xn--80a.test/`, so it is
  non-canonical as written. Its punycode spelling (`https://xn--80a.test`) IS
  accepted: that is the entry's true identity, and the deployer wrote what
  they get. The pre-§10.0 matcher accepted the homograph entry and granted it
  `xn--80a.test` origin-wide; the shared grammar now rejects it before matching.
- An entry containing **percent-encoded path characters**
  (`https://a.test/cb%2F..%2Fadmin`) is ACCEPTED and is inert: canonical already,
  and it matches only its own literal self (verified — it matches neither
  `/admin` nor `/cb/../admin`). §10.0 governs entry SYNTAX, not path semantics;
  it grants nothing beyond the exact URI written.

In both forms: `scheme` is `https` or `http` (an allowlist — `javascript:`,
`data:`, `file:` and every other scheme are rejected, never enumerated as
exceptions); the raw entry contains no `*`, no whitespace (leading, trailing, or
interior), no control characters, no backslash, and no `%` that does not begin a
valid percent-triplet. The whitespace rule is checked on the RAW string for a
reason WHATWG makes concrete: it **strips** interior tab, CR, and LF outright
(`https://a.test/c\tb` parses to `https://a.test/cb` — verified), so a
parsed-field check cannot see them at all, and a canonicality check alone
would reject them only incidentally. Leading/trailing whitespace is likewise
trimmed before parsing.

Four more raw rules close the class of entries that are WHATWG-canonical yet
carry syntax the forms above forbid — each is a shape where `entry ===
new URL(entry).href` holds and a canonicality-only validator would therefore
accept what the form definitions reject:

- **No raw `?` or `#` code point anywhere in the entry**, independent of what
  the parser reports. `https://a.test/?`, `https://a.test/cb?`,
  `https://a.test/#`, and `https://a.test/cb#` are all their own `href`
  (verified, Node 24) and all parse to an EMPTY `search`/`hash` — so a
  parsed-field check classifies `https://a.test/?` as origin form and grants it
  **origin-wide** match under §10.1. An empty query is still a query. This is
  the same rule §17.1.5 rule 2 applies to the CIMD client_id, for the same
  reason.
- **No `@` anywhere before the path** — userinfo is rejected by an independent
  check, never as a side effect of canonicality: `https://u:p@a.test/` (with
  the trailing slash) IS canonical, so a validator relying on `entry !== href`
  to catch userinfo accepts it.
- **No percent-triplet whose decoded byte is a C0 control or DEL**
  (`%00`–`%1F`, `%7F`, any hex case): `https://a.test/cb%0A` is canonical
  (verified) and survives the literal-control-character rule above. Same
  decision as §17.1.5 rule 2's %-encoded CR/LF rejection — one verdict for the
  same bytes in both fields.
- **No trailing dot on the host**: `https://a.test./` is canonical under WHATWG
  (the dot is preserved, not folded — verified), but §17.1.5 rule 7 rejects a
  trailing-dot host for the CIMD client_id, and the same host string being a
  valid redirect entry and an invalid client_id is exactly the
  parser-differential class this section exists to kill — **for the same
  BYTES**. That qualifier is load-bearing: the two fields legitimately differ
  on Unicode-vs-punycode (§10.0 rejects `https://а.test` as non-canonical and
  accepts `https://xn--80a.test`, while §17.1.5's client_id rules treat the
  IDNA forms on their own terms), and that is a difference of INPUT
  normalization, not of host validity. The rule this row states is narrower:
  one host STRING must not be valid in one field and invalid in the other.

Percent-hex case is NOT folded: WHATWG preserves `%2f` and `%2F` alike (both
are their own `href`, verified), so both spellings are canonical and they are
**distinct entries** under the exact-string match — an entry written `%2f`
matches only a presented URI carrying `%2f`. This is deliberate: re-serializing
to force one case would be normalization, and the rule is reject-or-accept,
never rewrite.

**Duplicates and IPv6 spelling.** A `redirect_uris` array or
`redirectAllowlist` containing the SAME canonical entry twice is **valid** —
duplicates are inert under both origin-wide and raw-equality matching, and
rejecting them would fail a config that means exactly what it says. They do
count against the §9.2 cardinality cap (the cap bounds the scan, and a
duplicate costs a scan step like any other entry). An **IPv6 host** must be
in WHATWG canonical compressed form: `http://[::1]/cb` is canonical, while
`http://[0:0:0:0:0:0:0:1]/cb` folds to it and is therefore rejected
(verified) — the general canonicality rule already covers this, and it is
named here because IPv6 has more non-canonical spellings than any other host
form. **Custom/private-use schemes** (reverse-DNS native-app schemes like
`com.example.app:/cb`) are rejected by the closed `https`/`http` scheme list,
not by name — there is no per-scheme blocklist to keep current, and adding
support would be a contract amendment, never an implementation choice.

**Hard cap.** Every entry is length-checked on the RAW string BEFORE parsing:
an entry longer than **2048 UTF-8 bytes** is rejected — the same bound §17.1.5
rule 1 places on the CIMD client_id, applied for the same reason (hard caps on
every untrusted input, before the parser sees it). DCR `redirect_uris` arrays
are additionally capped at **1..16 entries** (§9.2 — same bound and rationale
as §17.1.5 rule 19: it limits the authorize-time exact-match scan).
`redirectAllowlist` has no entry-count cap, and that is a decision rather than
an omission: it is deployer-written boot configuration, validated once at boot,
and its size is not attacker-influenced.

**Every rule is checked on the RAW string before, or in addition to, any parsed
field.** WHATWG normalization erases the very syntax the decision depends on —
`new URL` drops empty userinfo (`https://@a.test` yields `username === ""`),
maps a bare `?` to `search === ""`, lowercases the scheme, strips the default
port, and resolves `..` segments. A validator reading only parsed fields is
therefore checking a different string than the one the deployer wrote and the
matcher later compares.

**The grammar has exactly NINE consumers, and this list is closed:**
(1) boot (`createBridgeConfig`) for `redirectAllowlist`; (2) the DCR
registration write in BOTH modes (§9.2 — entries must arrive already
canonical; stored persists them unchanged, stateless persists nothing and
echoes them unchanged, per obligation 2: the
same endpoint must not accept or echo what the grammar forbids); (3) the
stored-state READ at AUTHORIZE (§10.2 — the paragraph below; token
exchange never re-reads the registration on the authorization-code path,
which is precisely why consumer (9) exists); (4) CIMD document validation
(`assertCimdRedirectUri`, §17.1.5 rule 20); (5) the **exported §10.1 matcher
itself** (`assertAllowedRedirectUri`), which applies the predicate to each
allowlist entry it READS before matching; (6) the **flow-cookie CIMD
consumption at callback** (`parseCimdRegistrationClaim` + the §17.1.6
redirect match), which re-validates each carried `redirect_uris` entry —
the second stored-state sibling, detailed two paragraphs below; (7) the
**consent-token redirect at `approve`** (`OAuthAuthorizationUseCase.approve`,
`src/authorize.ts:193-234`), which re-validates `consent.redirectUri` after
verifying the token's signature and BEFORE using it — for the Deny redirect,
for the stored authorization code, and for the success redirect alike. (7) is
the third stored-state sibling and closes the same rolling-upgrade window as
(6): within `consentTokenTtlSeconds`, a consent token signed by `prepare()`
under the OLD grammar carries a redirect the new grammar rejects, and a valid
signature is not a grammar check — the token proves *we issued this*, never
*this entry is still valid*. A non-conforming carried redirect is refused
`invalid_redirect_uri` as a DIRECT error (never a redirect to the value under
suspicion — §9.3's untrusted-destination channel rule); (8) the **opaque
flow-cookie redirect at callback** (`claims.params.redirect_uri`,
read at `src/adapters/upstream-flow.ts:161`), which every callback error path
redirects to BEFORE `bridge.handleAuthorize` re-runs §10 — and there are FIVE
such sites, not two: rows 7/8 (IdP error) at `:176-177` and rows 10/11
(exchange-failed / identity_rejected) at `:182-185`. **The guard is placed
ONCE at extraction**, immediately after the value is read at `:161`, never
per-site, or the three later sites are missed — an opaque
pre-upgrade cookie carries no `cimd` claim, so consumer (6)'s gate returns
early (`assertCallbackCimdPolicy`, `src/adapters/upstream-flow-cimd.ts:79`)
and never inspects it; (9) the **authorization-code record at token
exchange** (`consumeValidCode`, `src/token.ts:208-218`), which snapshots and
re-validates `record.redirectUri` before comparison, PKCE, or token persistence.
This stops a code minted under the old grammar from minting access and refresh
tokens after the upgrade — §10.2's registration read does NOT cover this, because
the code path never re-reads the client registration.

**Why the list ends at nine, and how to re-derive it.** Consumers (3), (6),
(7), (8), and (9) are the places a redirect_uri **outlives the check that
admitted it**: the stored client record, the CIMD registration in the flow
cookie, the opaque params in the same cookie, the consent token, and the
authorization-code record. A signature or a store hit proves *we issued
this*, never *this is still valid* — so each re-validates on READ.

The membership test is mechanical: **can this value be read back after the
check that admitted it, by a process running the NEW grammar, without passing
that check again?** Both halves matter. "Readable later" alone is too wide —
the CIMD validated-success cache (`src/cimd/resolve.ts:90`,
`this.cache = new CimdSuccessCache()`) satisfies it and is deliberately NOT a
consumer: the cache is a private in-process LRU per resolver, so a process
running the new grammar starts EMPTY, and any process still holding a legacy
entry is by definition still running the old grammar. No upgrade state can
cross it, and a re-check on the hit path would guard nothing. Persistence or
signing is what lets a carrier outlive the CODE that admitted it; in-process
memoization does not.

When adding a carrier, state its window, because the LONGEST window in a given
deployment bounds how long a rolling upgrade stays exploitable — and which
carrier is longest is **deployment-dependent, not fixed**: a stored
`ClientRegistration` is unbounded (it persists until re-registered), while
`consentTokenTtlSeconds` / `authorizationCodeTtlSeconds` are validated only as
POSITIVE INTEGERS with no maximum (`validateTtl`, `src/config.ts:139-142`).
Only `flowTtlSeconds` carries a contract-imposed ceiling (600 s default,
≤ 3600). Typical defaults order them code ≈ consent (~300 s) < flow (600 s) <
stored record (unbounded), but an implementation must not rely on that
ordering. (5) exists
because the matcher is a
root export (`src/index.ts`): it is reachable with an entries array that
never passed boot — a consumer calling the helper directly, or (pre-#106) a
caller mutating the array after boot — so without its own read-side check the
one-grammar invariant holds only for arrays `createBridgeConfig` produced. A
non-conforming entry encountered at match time is refused
`invalid_redirect_uri` (fail closed and loud, the same rule as the §10.2 read
guard) — never silently skipped, which is the `"*"` defect this section
started from, and never matched. (6) exists because
`parseCimdRegistrationClaim` checks only types and cardinality, and the
§17.1.6 matcher returns true on `entry === presented` BEFORE any shape
check — so during a rolling upgrade, a still-valid cookie minted under the
old grammar carries a query-bearing or non-canonical entry that exact-matches
its way through the callback; updating document validation (4) alone does not
close that window. Every consumer applies the ONE
shared predicate — none re-derives the grammar from its own parsing. (1), (2),
and (4) reject at the boundary the entry enters; (3), (5), and (6) are
deliberately read-time re-checks of entries that entered before the grammar
existed, out-of-band, or through the public export — not a second grammar.

**Stored state is re-validated at READ, not only at write** (the entry-point
guard's stored-state sibling). A `ClientStore` can return records written before
this grammar existed, or populated out-of-band by a deployer — the registration
guard never saw them. Verified on `40d9f58`: a stored native record holding
`http://@127.0.0.1/cb` (empty userinfo, which §10.0 forbids) is **accepted** at
authorize by `assertRedirectAllowedForClient`. So §10.2 MUST apply §10.0 to each
registered URI it reads, and a record carrying a non-conforming entry is refused
`invalid_redirect_uri` rather than matched. The check is per-entry at match time,
not a migration: a store is not required to be rewritten, and a legacy record
simply stops authorizing until re-registered.

The same read-time rule covers the OTHER carrier of registered redirect URIs:
the **CIMD registration carried in the signed flow cookie** (§17.1.6 decision
1c). A cookie minted before this grammar was enforced carries a
`CimdRegistration` whose `redirect_uris` the §10.0-era validator never saw —
within `flowTtlSeconds` of an upgrade, exactly like a legacy store record.
When `handleCallback` consumes the carried registration, each of its
`redirect_uris` entries is re-checked against §10.0; a non-conforming entry
fails the row-5a matrix (direct 400, `flow_cookie_invalid` audit), so a
pre-upgrade in-flight cookie cannot grandfather an entry past the grammar.
This is consumer (6) of the closed list — it is load-bearing, not
belt-and-braces: `parseCimdRegistrationClaim` validates types and cardinality
only, and the §17.1.6 matcher's `entry === presented` fast path runs BEFORE
any shape check, so without this re-check an old cookie's exact-matching
forbidden entry sails through. The same "not a migration" stance applies: the
flow simply fails and the client re-authorizes.

**Why reject rather than normalize.** A non-canonical entry could be rewritten
to its canonical form instead of refused. It is refused because config should
mean what it says: silently rewriting `https://a.test:443/cb` leaves a manifest
whose text no longer describes the deployed policy, and the same rewrite applied
to an entry the deployer *intended* differently is an undetectable widening. The
error names the offending entry and shows its canonical form to paste back.

**Empty is valid — for `redirectAllowlist` ONLY.** An empty `redirectAllowlist`
is correct configuration (the built-in defaults below cover the common case);
only *entries* can be invalid, never emptiness. This does NOT generalize: DCR
`redirect_uris` and a CIMD document's array both require **1..16 entries**
(§9.2 / §17.1.5 rule 19), so emptiness there is a rejection. The obligation-7
positive list is partitioned per consumer for exactly this reason.

## The two matching policies

Two policies, by DCR mode. Both consume entries already valid per §10.0, and
share the core rule: **no allow-all (`"*"`), no unanchored prefix, userinfo
rejected.** On fragments there is no split left: **entries never contain one**
(§10.0 rejects a fragment, including a bare trailing `#`), and a **presented**
`redirect_uri` carrying a raw `#` is **REJECTED** `invalid_redirect_uri` — not
stripped. RFC 6749 §3.1.2 forbids a fragment in the redirection endpoint URI,
and CIMD's §17.1.3 rejects rather than strips — one verdict for the same shape
on every path. This supersedes the
earlier "hash stripped" wording; a stripped-then-matched fragment is exactly
the accept-what-was-never-registered behavior the exact-match rule exists to
prevent. The §10.0 obligation list owes a rejection test for a presented
`https://client.test/cb#frag` in both DCR modes. Shared
built-in defaults for MCP clients (these ADD to any config allowlist; a config
cannot remove them):

```
https://claude.ai        // Claude (web) custom connectors
https://chatgpt.com      // ChatGPT custom connectors
http://localhost         // native MCP clients — any port (RFC 8252 §7.3)
http://127.0.0.1         // numeric loopback variant
```

Two properties of this default set worth stating rather than leaving to
inference: **`http://[::1]` is deliberately NOT a default** — the §10.1 matcher
recognizes all three loopback hosts (`localhost`/`127.0.0.1`/`[::1]`) as
loopback, but an IPv6-literal callback only matches if the deployer adds
`http://[::1]` to `redirectAllowlist` explicitly (an IPv6-only loopback client
is rare enough that the default set stays minimal; the matcher capability is
already there). And the defaults are themselves §10.0-governed entries: they
are compile-time constants today, so the implementation owes a **unit test
asserting every `DEFAULT_ALLOWED_REDIRECT_ORIGINS` entry is §10.0-valid** —
the guard against a future edit adding a non-canonical or non-grammar default
that no boot validator would ever see.

## 10.1 Global allowlist (stateless-DCR mode) — `assertAllowedRedirectUri`
An entry matches if it is the exact redirect_uri, the exact ORIGIN
(`scheme://host[:port]`, no path) of the redirect_uri, or a **loopback origin**
(`localhost`/`127.0.0.1`/`[::1]`, same scheme, any port). A loopback entry
widens to any port only if it is an origin-only entry with no explicit port/path;
a port-scoped or path-specific loopback entry is NOT widened. Returns the
unchanged canonical URI.

This matcher is consumer (5) of the closed list: it applies the shared §10.0
predicate to each entry it reads BEFORE matching, refusing a non-conforming
entry `invalid_redirect_uri` rather than skipping or matching it. That is not
redundant with boot validation — the matcher is a root export
(`src/index.ts`) reachable with an entries array `createBridgeConfig` never
saw. A directly supplied non-conforming entry is rejected loudly rather than
silently skipped or matched.

Two consequences that make §10.0's raw-syntax rules load-bearing rather than
cosmetic:

- **Origin-form entries match origin-wide** (any path on that origin). That is
  the form's purpose, and it is exactly why the grammar forbids a query
  delimiter or empty userinfo inside it: `https://ok.test?` and
  `https://@ok.test` parse to an empty `search`/`username`, so a parsed-field
  check classifies them origin-only and grants that origin-wide match — while
  the text reads as something narrower.
- **Exact-URI entries match by RAW string equality** — the presented
  `redirect_uri` is compared byte-for-byte against the entry, with **no
  normalization of either side**. This is why the grammar requires canonical
  form: a non-canonical entry (`HTTPS://…`, `…:443/cb`, a `/x/../cb` dot
  segment, surrounding whitespace) matches **nothing**, so the deployer's
  configured callback fails at boot instead of at authorization.

  The presented `redirect_uri` MUST ITSELF BE §10.0-VALID: canonical
  spelling, no fragment (rejected, per "The two matching policies" above),
  no userinfo, http only on loopback. A non-canonical presented value is
  refused `invalid_redirect_uri` — never folded into a match. The **native
  loopback exception is unchanged and remains the only one**: RFC 8252 §7.3
  ports vary by design, so that branch compares scheme + hostname + pathname
  + search with the port ignored, on two values that are each already
  canonical.

## 10.2 Per-client policy (stored-DCR) — RC item (b)
At **authorize** in stored mode (the authorization-code token path never
re-reads the registration — verified: `src/token.ts`'s only `clientStore.find`
is on the `client_credentials` machine-client path, `token.ts:169`), the
client's registered `applicationType`
selects the rule (every registered URI it reads is first re-validated against
§10.0 — the stored-state read guard, obligation 3 there). The store's
TypeScript return type is not trusted at runtime: the authorization boundary
first snapshots the row through §6.4's
`parseAuthorizationClientRegistration`, and only exact `native`/`web`/`machine`
discriminants are recognized. A missing, undefined, null, blank, unknown, or
wrongly typed discriminant is `invalid_client`, never the native loopback
default. A recognized `machine` record is still rejected from this flow.

The upstream redirect leg applies the same stored-client parse and redirect
policy twice: before it creates the signed flow cookie, and again at callback
after cookie/state validation but before JTI consumption, every IdP-error or
missing-code early return, code exchange, consent signing, or callback success
audit. Thus a corrupted or replaced registration cannot inherit the native
loopback exception at initiation and cannot rely on a previously valid cookie
after initiation. Each decision uses the parser's fresh read-once snapshot.

- **`native`** → RFC 8252: the registered entry must be a §10.0-valid loopback
  URI (`localhost`/`127.0.0.1`/`[::1]`); the presented `redirect_uri` matches it
  on **scheme + hostname + pathname + search, with the port ignored** — never
  host-only. **The port-ignoring rule is scoped, and the three statements of
  it elsewhere must agree with this one:** §10.1 widens only a PORTLESS
  LOOPBACK ORIGIN entry (any port on that origin); stored-`native` and the
  §17.1.6 CIMD loopback-`http` case compare scheme+host+path+search with the
  port ignored — **for CIMD, PENDING (D00-4.5.2, §16.1): only when the
  validated document declares `application_type: "native"`; a `"web"` or
  absent declaration matches exactly (fail closed). Stored-`native` already
  carries its type, so only the CIMD leg is pending** —; and every `https`
  comparison stays exact raw equality WITH
  the port included (§17.1.5 rule 20's "port included" applies to that case,
  not to loopback `http`). A reader who takes any one of those sentences as
  the general rule derives a different matcher — which is why they are
  enumerated together here. "Origin" appears nowhere in this rule on purpose: the match tuple
  includes the path and query, exactly as §17.1.5 rule 20 and the shipped
  matcher (`src/redirect.ts:95-103`) define it, so a client registered for
  `http://127.0.0.1/cb` does not match a presented `http://127.0.0.1/other`.
  Only the port is elastic (lets CLI/desktop clients use ephemeral ports).
- **`web`** → `https` only, and the presented `redirect_uri` must equal a
  registered URI by **RAW string comparison** — no port widening, no origin
  wildcard, and **no normalization of the presented value** (RFC 6749
  §3.1.2.3 simple string comparison). A presented value that is not itself
  §10.0-valid is refused before any
  comparison.

This replaces the source's blanket loopback-for-everyone default in stored mode.
