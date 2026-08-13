# 17. v0.2 feature contracts (locked 2026-07-04)

> Written and reviewed **before implementation** (contract-first house rule,
> applied to the whole v0.2 batch at once because the features interact).
> Every open design question is resolved to an explicit decision here; deferred
> items are recorded as decisions too, with rationale. `docs/threat-model.md`
> carries the attacker analysis; `docs/authorization.md` carries the
> deployer-facing Gate 1/Gate 2 model. The initial spec facts were verified
> against primary sources on 2026-07-04 (IETF drafts/RFCs, IANA registries,
> modelcontextprotocol.io, vendor docs); final MCP 2026-07-28 facts were
> re-verified on 2026-08-02.

## 17.1 CIMD — Client ID Metadata Documents (the SSRF enforcement contract)

**Implementation hardening target: `draft-ietf-oauth-client-id-metadata-document-01`**
(2026-03-02). MCP Authorization 2025-11-25 and the final stable 2026-07-28
artifact both normatively reference draft **-00**. The implementation was built
against -01's additional SSRF, redirect, and response constraints. The final MCP
citation is `-00`; §16.1 now carries the complete 44-statement mapping. The
`+json` media-type mismatch and shared-cache directive handling are closed. One
confirmed runtime mismatch remains — the loopback port exception is applied
without RFC 9700's native-app precondition — plus four
unresolved test-evidence rows, so final CIMD draft conformance cannot yet be
claimed. §16.2 additionally records a
draft `-02`-only gap: the private-JWK denylist predates RFC 9964's `AKP` `priv`
member.

> **Draft `-02` (2026-07-06) review — performed 2026-07-10, recorded here
> 2026-07-16 (closes issue #58).** At that review, the implementation hardening
> target remained `-01`. Every normative change in `-02` is already satisfied by
> this contract **as written** — a property of the contract text, not of an
> implementation (CIMD has no runtime path until the S6 sessions ship code
> against this section): (1) `-02` §3's MUST — Client Identifier URLs
> compared using RFC 3986 §6.2.1 simple string comparison (`-02`'s
> changelog records this as a clarification, with the
> no-default-port-normalization example made explicit) — is carried by the
> raw-string identity rule below plus 17.1.3's exact
> character-for-character comparison; (2) the production loopback
> prohibition (`-02` §8.6) is carried by the loopback exception's binding
> to `dev.allowInsecureLocalhost`; (3) `-02` §8.6's MUST NOT on fetching
> document-contained URLs *that resolve to special-use IP addresses* is
> satisfied a fortiori — the contract forbids fetching ANY URL inside the
> document (17.1.3: `logo_uri` neither fetched nor displayed); (4) the
> periodic re-fetch SHOULD (`-02` §5) is carried by 17.1.4's cache clamp —
> re-fetch happens at the next authorize after cache expiry; 17.1.4's
> token/refresh/revoke no-re-fetch rule is about per-request fetching, not
> staleness; (5) the private-key-material MUST NOT (`-02` §4.1) is carried
> by 17.1.3's explicit rejection of private/symmetric key material in
> `jwks`, paired with the public-client-only profile; (6) `-02` §8.2's
> strengthened client-authentication language (an AS MUST authenticate a
> `private_key_jwt`-declaring client per RFC 7523) is satisfied vacuously —
> 17.1.3 rejects any document declaring a `token_endpoint_auth_method`
> other than absent/`"none"`. `-02` also renumbers sections. Unlabeled
> draft citations in this section remain in `-01` numbering; citations
> explicitly tagged `-02` are already re-pinned. The mapping for the next
> re-pin: §4.5 → §4.2 (redirect URL registration), §5 → §6 (AS metadata),
> §6.5 → §8.6 (SSRF), §6.6 → §8.7 (response size), §6.9 → §7.1
> (pre-registered + unregistered clients) — draft-section citations only
> (internal contract-set cross-references such as the §6.6 `FetcherPort`
> note are not draft citations). Re-pin to `-02` (or later) at the next
> §17.1 contract revision, re-pointing the citations then.

**Config (opt-in; absent ⇒ CIMD disabled and URL-shaped client_ids are
rejected with `invalid_client`, direct):**

```ts
cimd?: {
  enabled: true;
  // No `fetcher` knob — §17.1.6 decision 5; the core constructs the guarded
  // fetcher from these caps + allowLoopback (dev.allowInsecureLocalhost only).
  maxDocumentBytes?: number;    // default 5120 (the draft's recommended 5 KB cap)
  fetchTimeoutMs?: number;      // default 5000 — one wall-clock deadline, DNS→body
  cacheTtlCapSeconds?: number;  // default 3600; effectiveTtl=min(max-age,cap)−Age−elapsed (§17.1.6 dec 4)
  maxInFlight?: number;         // integer [1, 64], default 8 (global in-flight cap; §17.1.5 rule 21)
  maxWaitersPerFetch?: number;  // integer [1, 4096], default 256 — callers parked on ONE in-flight fetch
                                // (§17.1.6 decision 7). Total waiters ≤ maxInFlight × maxWaitersPerFetch.
}
```

**The guard is structural, not advisory (§17.1.6 decision 5).** `GuardedFetcher`
is a branded type (unique symbol brand) that ONLY `createGuardedFetcher()` can
produce. **The `cimd` config does NOT accept a deployer-supplied whole fetcher at
all** — the core constructs the guarded fetcher itself from the caps above, with
`allowLoopback` derived SOLELY from `dev.allowInsecureLocalhost` (a branded fetcher
still carries the profile it was built with, so accepting one would let
`createGuardedFetcher({allowLoopback:true})` reopen the prod loopback bypass — hence
no knob, per decision 5). Testability is preserved one layer down: below-guard
`cimdTransport?`/`cimdResolver?` deps on `BridgeDeps`/`UpstreamFlowDeps` (rule 14)
inject a low-level connect-to-validated-IP transport / resolver for tests, but the
guard pipeline — URL admission, blocklists, DNS validation, redirect refusal, caps —
always runs around whatever is injected and cannot be skipped, and these seams cannot
widen `allowLoopback` or the caps. (`FetcherPort` in §6.6 remains the generic boundary
description; CIMD requires the brand.)

Boot: invalid caps are an `AuthConfigError`. There is no `cimd.fetcher` field to
brand-check (decision 5 removed it); the runtime brand still gates any internal use of
`createGuardedFetcher()`'s result so the guard pipeline is provably attached. When
enabled, AS
metadata emits
`client_id_metadata_document_supported: true` (draft §5 MUST when supported).
The root-exposed `CimdResolver` keeps its enable gate, fetcher factory, cached
fetcher, validated profile fields, and internal fetcher-selection methods in ECMAScript `#private`
slots. They are absent from the compiled runtime object's own properties and
prototype, so same-process JavaScript cannot call, replace, or shadow a second
network-capable entry point or alter the gate used by `resolve()`. A public
read-only `enabled` projection exists only for boot wiring; shadowing it cannot
change `resolve()`'s private gate. Only the intended public resolver operations remain reachable.
Detection is by shape: a `client_id` starting with `https://` takes the CIMD
path (draft §6.9 — our generated ids `mcpdc_`/`mcc_` never collide).

**Raw-string identity rule (RFC 3986 §6.2.1; `-02` §3 MUST).** The presented
`client_id` string IS the client's identity, raw: the fetch target (17.1.2),
the document `client_id` comparison operand (17.1.3), the cache key (17.1.4),
and every stored/emitted identifier derived from it (the registration
`client_id` and audit fields) are the exact string the client presented — never
a parsed-and-re-serialized form. (A CIMD `client_id` is NOT a `findGrantedScopes`
key: scope accumulation never runs for a scheme-shaped client — §17.1.6 decision 3.) A WHATWG
re-serialization (`new URL(id).href`) drops an explicit `:443` and lowercases
the host, so a re-serialized operand would treat
`https://example.com:443/client` as equal to `https://example.com/client`,
defeating simple string comparison. The 17.1.1 parse exists for VALIDATION
(and to extract connection parameters — host for DNS/SNI, port); its output
is never a comparison operand, fetch target, cache key, or stored identifier.

**17.1.1 URL admission (pure function, unit-testable, runs before any DNS):**

1. Raw-string checks first — every check in this step runs on the RAW
   client_id string BEFORE `new URL()`: length ≤ 2048; no raw or
   percent-encoded CR/LF (`\r`, `\n`, `%0d`, `%0a` case-insensitive); no
   other control chars; raw `^https://` prefix check (addendum 11 pattern);
   and **dot-segment rejection**: split the raw path on `/` and reject any
   segment equal to `.` or `..` in literal OR percent-encoded form (`%2e`,
   `%2E`, and mixed — decode each segment once for this comparison only).
   This MUST happen pre-parse: the WHATWG parser *normalizes* both literal
   and percent-encoded dot segments away (`/a/%2e%2e/b` parses to pathname
   `/b`), so a post-parse `pathname` inspection can never see them. Unit
   tests MUST cover the literal, `%2e`, `%2E`, and mixed-case variants.
2. Parse (WHATWG). MUST: non-root path component (`pathname.length > 1` — the
   draft requires "a path component"; we read that as a real path,
   fail-closed). MUST NOT: fragment, userinfo. **Query strings are rejected**
   (draft says SHOULD NOT; we fail closed — stricter than spec, documented).
3. Host rules: IP-literal hosts rejected (v4 and v6 — beyond-spec hardening; a
   bare-IP "identity" defeats the hostname-display trust model). Note the
   WHATWG parser canonicalizes dword/octal/hex forms (`https://2130706433/`)
   to dotted-quad hostnames, so literal-encoding bypasses are caught by this
   same check. `localhost`, `*.localhost`, and trailing-dot hostnames rejected
   pre-DNS. Explicit ports allowed (draft MAY) but must pass the port denylist
   `{22, 25, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 6379, 9200,
   11211, 27017}`. (Rationale: the 17.1.2 IP blocklist is the SSRF security
   boundary; the port denylist is cross-protocol hardening — it keeps the
   fetcher from speaking HTTPS at well-known non-HTTP service ports — not a
   boundary of its own.)

**Loopback exception:** none in production. The draft (`-02` §8.6) permits a
development/testing AS that itself runs on a loopback address to fetch
client_ids resolving to the same loopback interface; we bind that to the
existing `dev.allowInsecureLocalhost` flag (which already boot-fails on
non-loopback origins — that flag carries the AS-side condition). Under the
flag, ONLY two checks relax, and only for a URL whose host is `localhost` or
`*.localhost`: (1) the 17.1.1 rejection of those hostnames — 17.1.1 stays a
pure pre-DNS function; under the flag it simply stops rejecting them — and
(2) the `127.0.0.0/8` + `::1/128` blocklist rows, enforced at 17.1.2's DNS
step, which additionally requires EVERY resolved A/AAAA record to be a
loopback address (the draft's resolves-to-the-AS's-own-loopback-interface
condition; a single non-loopback record rejects the whole fetch — the same
every-record rule as the rest of 17.1.2). A hostname outside
`localhost`/`*.localhost` gets NO relaxation: if its records resolve to
loopback they still reject — attacker-controlled DNS must not steer a dev AS
into itself. IP-literal hosts stay rejected (17.1.1). The raw `^https://`
requirement is NOT relaxed: 17.1.1 has no scheme carve-out, and admitting
http-loopback CIMD would be a §18 contract change, never an implementation
decision. Everything else in the pipeline still runs under the flag.

**17.1.2 Fetch enforcement (`createGuardedFetcher` — the reference
`FetcherPort`):**

- **Fetch target:** the URL fetched is the RAW presented `client_id` string
  (raw-string identity rule above). The admission parse extracts the
  connection parameters — the parsed host (case-normalized by the parse;
  hostname matching is case-insensitive, so this is the "original hostname"
  the DNS-pinning bullet names for DNS/SNI/certificate purposes) and the
  port — but the request is built from the presented string, never from a
  re-serialized URL.
- **DNS pinning:** resolve ALL A + AAAA records; EVERY resolved address must
  pass the blocklist (any hit rejects the whole fetch — multi-record attacks);
  connect to one validated resolved IP (family-consistent), with `Host` header
  and TLS SNI set to the original hostname, certificate verified against the
  original hostname. The hostname is NEVER re-resolved after validation
  (closes the rebinding TOCTOU; TTL-0 tricks are irrelevant under pinning).
- **Blocked ranges — IPv4** (IANA IPv4 Special-Purpose registry, complete,
  plus multicast): `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`,
  `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24` (entire block, including
  its sub-registrations and the globally-reachable PCP/TURN anycasts —
  fail-closed), `192.0.2.0/24`, `192.31.196.0/24`, `192.52.193.0/24`,
  `192.88.99.0/24`, `192.168.0.0/16`, `192.175.48.0/24`, `198.18.0.0/15`,
  `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4` (multicast — separate
  IANA registry, blocked explicitly), `240.0.0.0/4` (incl.
  `255.255.255.255/32`).
- **Blocked ranges — IPv6** (IANA IPv6 Special-Purpose registry, complete,
  plus multicast): `::/128`, `::1/128`, `::/96` (IPv4-compatible, deprecated),
  `::ffff:0:0/96` (IPv4-mapped), `64:ff9b::/96` + `64:ff9b:1::/48` (NAT64),
  `100::/64`, `100:0:0:1::/64`, `2001::/23` (the entire IETF-protocol block —
  covers Teredo `2001::/32`, benchmarking, AMT, AS112, ORCHID/ORCHIDv2, DRIP;
  no legitimate metadata host lives there), `2001:db8::/32`, `2002::/16`
  (6to4), `2620:4f:8000::/48`, `3fff::/20` (new documentation block, RFC
  9637), `5f00::/16` (SRv6, RFC 9602), `fc00::/7`, `fe80::/10`, `fec0::/10`
  (deprecated site-local), `ff00::/8` (multicast). Zone-scoped addresses
  (`%zone`) rejected outright.
- **Embedded IPv4:** every IPv4-embedding IPv6 form (IPv4-mapped,
  IPv4-compatible, both NAT64 prefixes, 6to4, Teredo) is **blocked wholesale
  by the list above** — no extraction-and-recheck step exists to get subtly
  wrong. Membership tests compare **parsed binary addresses**, never strings.
- **Redirects: refused.** Draft -01 MUST NOT follow; any 3xx is an error. The
  core additionally asserts that no redirect occurred and `status === 200`,
  so a fetcher that silently followed a redirect is detected and the result
  rejected. (Max hop count is therefore 0 by contract.) Redirect detection
  MUST rest on **explicit no-redirect evidence from the transport result** —
  the Fetch API's `redirected === false`, or an equivalent
  redirects-followed count of 0 — asserted by the core. A normalized-URL
  comparison alone is NOT sufficient evidence: a transport that silently
  followed a redirect from a non-canonical admitted `client_id` to its own
  canonical form (`https://Example.com:443/client` →
  `https://example.com/client`) reports a final URL identical to the
  requested URL's serialization, so that hop is invisible to URL comparison.
  The final-URL check (the transport-reported final URL against the WHATWG
  serialization of the fetch target — the **same serialization** on both
  sides) is kept as defense-in-depth on top of the explicit indicator.
  Neither check is an identity comparison: identity comparisons remain
  raw-string-only per the raw-string identity rule, and a legitimately
  admitted raw `client_id` carrying an explicit `:443` or a mixed-case host
  is NOT spuriously rejected by either check.
- **Response:** status 200 only (draft MUST); `Content-Type` must be
  `application/json` or an `application/<AS-defined>+json` suffix type — this is
  the draft's own rule, not our hardening: `-00` §4.1 permits a more specific
  content type "as long as the response is JSON **and conforms to
  `application/<AS-defined>+json`**". D00-4.1.4 is enforced by requiring the
  `application/` tree for every `+json` alternate. Body read with a streaming
  hard cap of
  `maxDocumentBytes` — exceeding it REJECTS (never truncates: truncated JSON
  must never parse "successfully"); unknown `Content-Encoding` rejected and
  decompressed output counted against the same cap (decompression bombs).
- **Timeout:** one `AbortController` deadline (`fetchTimeoutMs`, default
  5000 ms) spanning DNS, connect, TLS, headers, and body. The spec is silent
  on timeouts; this value is our own hardening, recorded as such.
- **Concurrency/DoS:** single-flight keyed by the RAW presented `client_id`
  string (raw-string identity rule — concurrent authorizes for the same
  client_id coalesce into one fetch; distinct raw strings never coalesce,
  even when they re-serialize identically); a global in-flight cap (default 8).
  Direct header-identity mode first applies the §6.7 outer
  `authorize:<ip>` budget before identity verification, then the resolver's
  `cimd:<ip>` budget before DNS/fetch. Upstream redirect mode retains its
  existing `upstream:<ip>` then `cimd:<ip>` budgets. Error
  responses are NOT cached (draft MUST NOT) — the rate-limit layer, not a
  negative cache, bounds refetch abuse.

**17.1.3 Document validation (pure function, unit-testable):**

- Strict `JSON.parse`; result must be a JSON object.
- `client_id` member MUST equal the RAW presented `client_id` string by
  **exact character-for-character comparison** (RFC 3986 §6.2.1 simple string
  comparison — no normalization, no case-folding, no trailing-slash
  equivalence; the raw-string identity rule — comparing against a
  parsed/re-serialized URL would let an explicit-`:443` or case-folded-host
  difference pass, and MUST reject instead).
- Required members (MCP profile): `client_id`, `client_name` (non-empty
  string, ≤ 256 chars — display data, HTML-escaped at render),
  `redirect_uris` (non-empty array).
- `token_endpoint_auth_method` MUST be absent or `"none"`. **v0.2 CIMD
  clients are public clients only** — the draft explicitly sanctions this
  profile restriction. `private_key_jwt` (confidential CIMD via published
  JWKS) is DEFERRED, together with 17.2's `private_key_jwt` — one future
  asymmetric-client-auth unit. `client_secret` /
  `client_secret_expires_at` present ⇒ reject (draft MUST NOT).
- **Private or symmetric key material rejects the document** (`-02` §4.1:
  "private key material MUST NOT be included ... only public keys ... are
  permitted" — enforced AS-side as a fail-closed conformance check, even
  though v0.2 never uses document keys). If a `jwks` member is present it
  MUST parse as a JWK Set — an object whose `keys` member is an array of
  objects; malformed ⇒ reject — and every key MUST be public-only: a key
  bearing any private or symmetric JOSE parameter (`d`, `p`, `q`, `dp`,
  `dq`, `qi`, `oth`, `k` — the complete registered RFC 7517/7518 set)
  rejects the whole document. Without this rule a nonconformant document
  would be accepted with the key material silently ignored. `jwks_uri` is a
  URL and is never fetched (17.1.4 / the no-second-fetch posture), so it
  cannot carry key material into the AS.
- `redirect_uris` entries: **§10.0-valid** (that grammar governs — not a
  restatement, and not a per-site re-derivation: the CIMD matcher previously
  accepted `*`, `javascript:`, and non-canonical entries that §10.1 refused).
  https entries exact-match at authorize (draft §4.5 / RFC 9700); loopback http
  matches RFC 8252 any-port **only for a document declaring
  `application_type: "native"`** — see the §17.1.6 decision-1 shared matcher for
  the canonical rule and its **PENDING (D00-4.5.2)** status. If present:
  `response_types` must include `"code"`; `grant_types` must be an array of
  non-empty strings that includes `"authorization_code"`. Additional grant
  declarations are accepted but do not enable any server grant handler.
- Unknown members ignored (the RFC 7591 registry allows extras). `logo_uri`
  is NOT fetched and NOT displayed in v0.2 (the draft requires
  prefetch-and-cache IF displayed; we sidestep the second fetch surface).
- **Named projection (§4.1, implementation pending):** the returned
  `CimdDocument` exposes only `client_id`, `client_name`, and `redirect_uris`;
  the parsed source object is not returned for a later spread or merge. Unknown
  members, including `__proto__` and `constructor`, remain ignored and cannot
  affect an output record's prototype. **Lifecycle note (§17.1.6 decision 1c):**
  the committed `CimdDocument` interface still exposes `raw` until the §4.1
  removal lands; until then S6b MUST project into the distinct `CimdRegistration`
  named type (`{ client_id, client_name, redirect_uris }`) at the fetch boundary
  **before** any caching or flow-cookie signing — a raw `CimdDocument` is never
  cached, signed, or passed as the `registration` option.

**17.1.4 Flow integration:**

- CIMD resolution runs in `prepare`, pre-validation (the fetched document IS
  the registration). Any failure — admission, DNS, blocklist, fetch, size,
  status, parse, validation — is a **direct** error (§9.3 channel) with ONE
  generic client-facing message ("client_id could not be resolved"): the error
  MUST NOT distinguish blocked-address from network-failure from invalid-
  document (**SSRF oracle prevention**). The specific reason goes to audit
  only (`oauth.cimd.fetch`, failure, reason code).
- The presented `redirect_uri` must exact-match a document entry (loopback
  any-port exception, native-declared documents only — §17.1.6 decision 1,
  **PENDING (D00-4.5.2)**). The consent page MUST present the client_id host and
  redirect host before the cosmetic name as the primary identity anchors, and
  SHOULD warn when every registered redirect is loopback (the MCP localhost-
  impersonation consideration). `client_name` renders second as explicitly
  self-reported, unverified display text; the copy directs the user to judge
  the hosts rather than implying that name verification failed.
- **Scope accumulation does NOT apply to CIMD clients in v0.2** (§17.1.6 decision 3):
  a CIMD authorization stands alone (`priorScopes = []`) in both DCR modes.
  Accumulation stays a stored-DCR opaque-client feature — deferred for CIMD because
  refresh records carry no registration provenance, so a pre-CIMD stateless grant for
  the same URL would silently resurrect. (The target AI clients request their full
  scope set up front, so the convenience is unused; a provenance-aware version is a
  future minor — §12 note.)
- Token/refresh/revoke: NO re-fetch; binding is the existing auth-code-record
  and refresh-record client checks (§9.4). Validated documents cache per the
  bounded shared-cache rules in rule 25 and §17.1.6 decision 4, keyed by the
  RAW presented `client_id` string (raw-string identity rule —
  `https://example.com/client` and `https://example.com:443/client` are
  distinct clients and distinct cache entries), in-memory per instance, bounded
  to a finite entry ceiling with LRU eviction (§17.1.6 decision 4); this SAME
  cache also serves the upstream-redirect authorize resolution (§17.1.6 decision
  1a); invalid/error results never cached.
- No new store records.

## 17.1.5 Precision amendments (S6 pre-implementation, 2026-07-22)

These close ambiguities and fail-open gaps found by the cross-family S6a spec
critique and confirmed by an adversarial amendment-verify pass (critics/verifiers:
GPT-5.6 Sol, Grok 4.5, GLM 5.2), each empirically re-verified on the project's
Node 24 runtime. They **TIGHTEN** the bullets above; where a rule here and a
bullet above differ, this subsection wins — **except for the §10.0
redirect-entry grammar, which governs every consumer including CIMD** (rule 20
is amended accordingly; a subsection-wins precedence over the shared grammar is
what let the CIMD matcher and §10.1 diverge in the first place). Every rule is fail-closed. No new
subsystem is introduced — these pin behavior the primitives already imply so the
S6a bake-off cannot diverge and review cannot discover. **This subsection is
contract text; the enforcement lands with the S6 code, not with this docs
change:** each S6a-scope rule is to be covered by a negative test in the frozen
S6a acceptance suite, and the flow rules (H) are to be implemented and tested in
S6b. **Status: those PRs have landed** — the S6a primitives, both frozen
acceptance suites, and the S6b flow integration are implemented, and §16 now
tracks CIMD as implemented, including the §10.0 amendment to rule 20.
A patched-checkout campaign subsequently observed real CIMD-first clients
across Cloudflare Access, Entra, and Google, but its exact dirty tree was not
archived and does not qualify as release evidence. On 2026-07-28, Claude Code
2.1.220 repeated CIMD authorization and protected tool calls through exact
runtime commit `af2a61f` with all three providers. The implementation was
reviewed against `2026-07-28-RC`; the official final artifact was then checked
on 2026-08-02 and retained CIMD at `SHOULD` with draft `-00`. §16.1 now maps all
44 normative statements: 24 `C` conformant plus one conformant disclosed caveat,
two reasoned deviations, 12 not applicable to the implemented public-client profile,
four with unresolved test evidence, and one confirmed runtime mismatch
(D00-4.5.2 native-app precondition).

**A. Admission input + raw pre-parse checks (tightens 17.1.1 step 1).**
1. The admission argument MUST be a primitive `string`, non-empty, and ≤ 2048
   **UTF-8 bytes** (`Buffer.byteLength(raw,"utf8")`); no type coercion. A
   non-string, empty, or over-length input rejects pre-parse.
2. Before `new URL()`, reject on the RAW string: any raw backslash `\` (WHATWG
   maps `\`→`/` on special schemes: `https://h/a\..\b` parses to pathname `/b`,
   invisible to a `/`-split — verified); any raw `?` (query delimiter, incl. a
   trailing `?` that parses to empty `search`); any raw `#` (fragment delimiter,
   incl. a trailing `#` that parses to empty `hash`); leading or trailing ASCII
   whitespace (WHATWG trims a trailing space — verified); any C0 control
   (U+0000–U+001F), DEL (U+007F), or raw/`%`-encoded CR/LF in all case variants.
   **Userinfo:** reject any `@` in the RAW AUTHORITY only — the substring after
   `https://` up to the first `/` (or end) — INCLUDING empty userinfo
   (`https://@h/c` parses to username `""`, host `h` — verified). A `@` in the
   PATH is a legal `pchar` and is allowed (`https://cdn.example/@scope/c.json`).
   No separate whole-string malformed-percent scan is required: a malformed
   escape in a path segment fails the rule-3 one-pass decode, and a malformed
   escape in the authority fails `new URL()` or the rule-6 raw-host check.
3. **Raw-path extraction (pins "split the raw path on `/`").** Because rule 2 has
   rejected raw `\`, authority `@`, `?`, `#`, and required a literal lowercase
   `^https://` prefix, the raw path is unambiguous: the substring beginning at the
   first `/` at or after index 8 (the char after `https://`). No such `/` ⇒ no
   path component ⇒ reject (17.1.1 step 2). Split that substring on `/`;
   percent-decode EACH segment exactly ONCE (a decode failure rejects; recursion
   is forbidden, so `%252e`→`%2e` is NOT a dot segment — verified); reject if a
   decoded segment equals `.` or `..`.

**B. Host checks run on the PARSED hostname (tightens 17.1.1 step 3).**
4. All host rules evaluate `url.hostname` AFTER `new URL()` (WHATWG canonicalizes
   dword/octal/hex and IDNA-narrows fullwidth digits to a dotted quad —
   `https://1．2．3．4/`→`1.2.3.4`, `https://2130706433/`→`127.0.0.1` — verified;
   caught by the IP-literal rule only when it runs on the parsed host).
5. **IP-literal rejection strips brackets first:** `new URL("https://[::1]/x")
   .hostname` returns `"[::1]"` WITH brackets and `net.isIP("[::1]")` returns 0
   (verified) — a naive `net.isIP(hostname)` admits every bracketed IPv6 literal.
   Rule: let `h` = hostname with one leading `[` and trailing `]` removed if both
   present; reject if `net.isIP(h) !== 0` OR the original hostname began with `[`.
6. **Non-ASCII / IDNA hostnames reject (deliberate v0.2 policy).** This is a
   chosen fail-closed policy, not a logical necessity: `new URL(
   "https://exämple.com/x").hostname` becomes `xn--exmple-cua.com` (verified),
   so admitting IDNA would force either a fetch target that differs from the raw
   identity or a punycode re-serialization as identity — both undesirable in v0.2.
   Rule: reject unless the **raw-authority host** is pure ASCII, equals
   `url.hostname` case-insensitively, AND contains no `xn--`-prefixed label — a
   pre-encoded IDNA A-label (e.g. `xn--exmple-cua.com`) is itself a punycode
   identity and is likewise deferred; without this an A-label host passes the
   pure-ASCII check and opens a homograph allow-path. Raw-authority-host extraction (validation
   only; never a fetch target/cache key/identity): after `https://`, take chars
   up to the first `/` or end = the authority; (authority `@` already rejected in
   rule 2); if it starts with `[`, the host is the substring through the matching
   `]`; else the host is the authority with an optional trailing `:port` removed
   at the LAST `:`. (IDNA/punycode CIMD identities are a §18 change, never a
   coder decision.)
7. **Trailing-dot and localhost matcher (pins the wording; restores the blanket
   rule).** FIRST, independently of any relaxation: reject ANY `url.hostname`
   ending in `.` (the blanket trailing-dot rejection of 17.1.1 step 3; the
   loopback exception does NOT relax it). THEN reject `localhost` and
   `*.localhost`: host equals `localhost`, or host ends with `.localhost` (so
   `notlocalhost` does NOT match; `a.b.localhost` does). The loopback exception
   relaxes exactly this localhost matcher and the loopback blocklist rows —
   nothing else.

**C. DNS resolution + blocklist membership (tightens 17.1.2 DNS pinning).**
8. Both A and AAAA are queried within the one deadline. An explicit no-data
   result for ONE family (`ENODATA`/`ENOTFOUND`) is permitted; any other resolver
   error rejects the whole fetch. The combined answer MUST contain ≥ 1 and ≤ 64
   addresses; **zero addresses rejects** (`[].every()` is `true` — verified — so
   an empty answer must never pass the blocklist or the loopback every-record
   check vacuously). More than 64 rejects.
9. Every returned address MUST be parseable and its parsed family MUST match the
   query record type; a whitespace/zoned/non-decimal/family-mismatched/otherwise
   unparseable record rejects the WHOLE fetch — records are never silently
   skipped (skipping a malformed record and passing the rest is the loopback
   fail-open in 17.1.1's exception).
10. **Blocklist engine is total on BOTH add and check.** Membership compares
    parsed binary addresses. If `net.BlockList` is used: (a) IPv6 subnets MUST be
    added with an explicit `"ipv6"` family — `addSubnet("::1",128)` THROWS
    `ERR_INVALID_ADDRESS` without it (verified); and (b) **every `check()` MUST
    pass the address family** — `check("::1")` returns `false` even after the
    subnet was added with family `"ipv6"`, while `check("::1","ipv6")` returns
    `true` (verified); omitting the family silently makes the ENTIRE IPv6
    blocklist inert (loopback, ULA, link-local, multicast, documentation all
    pass — a full IPv6 SSRF bypass). Use `check(addr, net.isIP(addr)===4?"ipv4":
    "ipv6")` with the per-record family from rule 9. Any error constructing the
    blocklist is a boot failure, never a caught-and-skipped range.

**D. Connection / transport (tightens 17.1.2 fetch enforcement).**
11. **Proxy env is forbidden.** The transport connects DIRECTLY to the validated
    IP and MUST NOT honor `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY` (any
    case) — a proxy re-resolves the hostname and defeats DNS pinning (SSRF
    bypass; threat rows 13/25).
12. **The deadline covers DNS with cancellation.** `dns.promises.resolve4/6` do
    not accept an `AbortSignal`, and a bare timer/race bounds only the caller
    while background resolution keeps running. Use a per-fetch
    `dns.promises.Resolver` (or an equivalently cancellable resolver seam) and
    call `.cancel()` at the shared `fetchTimeoutMs` deadline; the single-flight
    slot (H/24) is not released until resolution has settled or been cancelled,
    so a hanging resolver can neither exceed the deadline nor leak past the
    in-flight cap.
13. **Request + connection shape.** GET only; no body; no credentials/cookies; no
    `Authorization`/`Cookie`/`Proxy-Authorization`; only fixed allowlisted
    `Accept: application/json` and `Accept-Encoding: identity` headers. The HTTP
    request-target is **origin-form** (path + query) derived from the admitted
    URL — NEVER absolute-form to a directly-connected origin. The `Host` header
    is the parsed hostname, plus `:${url.port}` ONLY when `url.port !== ""` (a
    non-default explicit port survives WHATWG); a default-443 form carries no
    explicit port. TLS SNI and certificate verification use the parsed ASCII
    hostname with brackets/port stripped. The raw client_id string is carried
    separately as identity/evidence, never as the request-target.
14. **Injected transport seam (test-only, below the guard).** Its request is
    `{ connectIp, family, port, servername, hostHeader, requestTarget, signal,
    redirect:"manual" }` — `connectIp` is the already-validated address it MUST
    connect to (no DNS/proxy re-resolution). Its result is `{ status,
    redirected:boolean, finalUrl, headersDistinct, encodedBody }` where
    `headersDistinct` **preserves duplicate header occurrences** (Node's
    `IncomingMessage.headers` keeps only the first `Content-Type`, so a normalized
    map cannot satisfy rule 15's duplicate check — use `rawHeaders`/
    `headersDistinct`). The public guarded-fetch API accepts only the raw
    client_id; no generic `FetchInit` overrides.

**E. Response handling (tightens 17.1.2 response; supersedes its gzip allowance).**
15. A duplicate or multi-value `Content-Type` header rejects (an essence-ambiguous
    response is untrusted). Essence match is case-insensitive with parameters
    allowed: media type `application/json` or an `application/<AS-defined>+json`
    type (draft `-00` §4.1). D00-4.1.4 is enforced: non-`application` `+json`
    media types reject. (The duplicate-header and case-insensitivity clauses are
    implemented correctly.)
16. **Content-Encoding: identity only (v0.2).** The request sends
    `Accept-Encoding: identity`; ANY present `Content-Encoding` response header
    rejects — **including a bare `identity`; ONLY an ABSENT `Content-Encoding` is
    accepted** (examples that reject: `gzip`, `x-gzip`, `br`, `deflate`, `zstd`,
    `identity`, list-forms like `gzip, gzip`, and any unknown coding). This SUPERSEDES 17.1.2's gzip allowance: dropping
    compression eliminates the decompression-bomb class entirely rather than
    defending it (least machinery on a T3 SSRF boundary; a 5 KiB JSON document
    does not need compression). gzip interoperability, if a real metadata host
    ever requires it, is a documented §18 follow-up with its own streaming
    stream-and-abort defense — not v0.2. The single streaming cap therefore
    applies to wire bytes only: exceeding `maxDocumentBytes` REJECTS (never
    truncates).
17. Response header total size is bounded by Node's built-in
    `--max-http-header-size` default (~16 KiB) plus the one deadline; the built-in
    transport MUST NOT raise or disable that platform cap. An application-level
    header-byte counter is an accepted v0.2 residual (peak-memory only, no
    correctness impact) — documented, not enforced.

**F. Document validation typing + cardinality (tightens 17.1.3).**
18. The parsed root MUST be a non-null, non-array plain object
    (`typeof x==="object" && x!==null && !Array.isArray(x)`). Each member is
    type-checked before use: `client_id`/`client_name` MUST be strings,
    `redirect_uris` MUST be an array; a wrong JSON type rejects (never coerced).
19. `redirect_uris` length MUST be 1..16 (bounds the authorize-time exact-match
    linear scan). A `jwks` object's `keys` MUST be an array of plain objects
    (malformed rejects); no separate numeric keys-count cap is imposed — the
    5120-byte-default (≤ 64 KiB) body cap bounds the parse, and v0.2 never uses
    document keys, so the public-only per-key scan is the only obligation. JSON
    depth is bounded by the body cap; no separate depth limit.
20. **CIMD redirect hygiene uses a NEW pure validator, not the §10 exports.**
    *(AMENDED by §10.0 — read that first. The grammar there governs WHICH entries
    are valid, for CIMD exactly as for §10.1/§10.2, superseding this rule's
    looser shape rules wherever they differ: an https entry carrying a query or
    in non-canonical form is REJECTED under §10.0 even though the raw-shape rule
    below would admit it. What survives unchanged is the mechanical part — that
    CIMD needs its OWN pure per-URI error-mapping wrapper rather than reusing the
    §10 matcher exports, which require allowlist or stored-client context.
    `assertCimdRedirectUri` therefore stays,
    and becomes the CIMD-side enforcement OF §10.0 rather than a second grammar.
    The §17.1.5 "this subsection wins" precedence does NOT extend to the entry
    grammar.)*
    Neither `assertAllowedRedirectUri` (allowlist membership) nor
    `assertRedirectAllowedForClient` (stored-client context) is a pure per-URI
    error-mapping surface. `assertCimdRedirectUri(raw: unknown): void` supplies
    the CIMD `document_invalid` mapping over the same shared predicate; it is not
    a package export. Full edge class (enumerate before coding,
    per the identity-port lesson): argument MUST be a primitive non-empty string,
    no coercion; reject raw `\`, C0/DEL, CR/LF, malformed percent triplets, any
    userinfo (INCLUDING empty `@`), any fragment (INCLUDING a trailing `#`), and
    any `*` anywhere in the raw entry — host, path, or elsewhere (`https://a.test/cb*`
    is rejected here exactly as §10.0 rejects it; the earlier "in the host"
    scoping was narrower than the grammar and is superseded); accept `https:`
    with ANY host, or `http:` ONLY with host exactly
    `localhost`, `127.0.0.1`, or `[::1]` (the loopback restriction binds the
    `http:` case alone — the earlier "EITHER https: OR http: with host
    exactly…" phrasing read as if https also required loopback, contradicting
    the "Only the `http:` case is loopback" sentence below; this spelling and
    that sentence now say the same thing, and it is the same rule §10.0 now
    states grammar-wide) — **in each case only if the entry is
    also §10.0-valid** (canonical spelling, no query; this REPLACES the earlier
    "validated for shape only here" wording, which admitted queries and
    non-canonical forms). Matching at authorize is EXACT raw-string comparison,
    port included, with no normalization at match time — which is sound
    precisely because §10.0, once enforced, forces the stored entry into
    canonical form;
    raw-equality against a non-canonical entry is what made the two matchers
    disagree. Only the
    `http:` case is loopback. **PENDING (D00-4.5.2, §16.1):** RFC 9700 — which
    draft `-00` §4.5 delegates to — permits varying loopback ports only for
    **native apps**, and `application_type` is in the IANA client-metadata
    registry `-00` §4.1 imports, so the signal is available in a CIMD document.
    The shipped matcher receives no client type and applies the exception to
    every loopback registration, including one declaring `application_type:
    "web"`; the follow-up runtime PR carries the declared type into the
    projection and gates the exception on it.
    The authorize-time (S6b) loopback any-port match
    reuses the existing runtime semantics of src/redirect.ts:95-103 — scheme,
    hostname, pathname, and search equal; port ignored; fragment already rejected
    at validation — resolving the looser "origin" wording elsewhere.

**G. Config cap numeric domains (tightens the `cimd` config + boot + §5).**
21. The `cimd` config key MUST be enumerated in the canonical §5 `BridgeConfig`
    shape and in `KNOWN_CONFIG_KEYS` (§5 rejects every unenumerated key at boot,
    so the field is boot-rejected until listed). The concurrency bound is a named
    property `maxInFlight?`. Each cap has a closed integer domain; a non-integer,
    `NaN`, `Infinity`, or out-of-range value is an `AuthConfigError` at boot (an
    unbounded value defeats the very controls threat rows 13/25 describe):
    `maxDocumentBytes` ∈ [1024, 65536] (default 5120); `fetchTimeoutMs` ∈
    [1000, 30000] (default 5000); `cacheTtlCapSeconds` ∈ [60, 86400] (default
    3600); `maxInFlight` ∈ [1, 64] (default 8); `maxWaitersPerFetch` ∈ [1, 4096]
    (default 256 — §17.1.6 decision 7).

**H. Flow-integration items (enforced + tested in S6b; recorded here for the suite).**
22. **"URL-shaped" is mechanical.** A `client_id` matching raw scheme syntax
    `^[A-Za-z][A-Za-z0-9+.-]*://` is NEVER eligible for the stateless-DCR
    ephemeral-client fallback. Only a literal lowercase `https://` prefix enters
    CIMD admission; every other scheme-shaped value (including `HTTPS://`,
    `http://`, `ftp://`) is rejected `invalid_client` (direct). When CIMD is
    disabled/absent, a `https://`-shaped `client_id` is likewise rejected
    `invalid_client`, never treated as a stateless-DCR client.
23. For a CIMD `client_id`, `prepare`'s redirect validation is the document
    exact-match (loopback any-port per rule 20, native-declared documents only —
    §17.1.6 decision 1, **PENDING (D00-4.5.2)**), REPLACING §9.3 step 2's §10
    global-allowlist check for that client. Non-CIMD flows are unchanged.
24. Single-flight/overload: coalesce concurrent fetches for the same RAW
    client_id; a coalesced follower does NOT consume an in-flight slot. When
    `maxInFlight` distinct fetches are in flight, a new DISTINCT client_id fetch
    rejects with `CimdReason` **`overloaded`** (§17.1.6 decision 6; client-facing map
    = the decision-2 generic `invalid_client`), never queues unboundedly. A key's entry is removed
    on settle (success, error, or timeout/cancellation). Error/invalid results
    are never cached.
    **Followers are bounded too (§17.1.6 decision 7).** `maxInFlight` bounds
    concurrent OUTBOUND fetches; it does not bound how many inbound callers may
    park on ONE of them. A new `maxWaitersPerFetch` cap bounds that second
    quantity: when an in-flight entry already has `maxWaitersPerFetch` waiters, a
    further follower for that same client_id rejects `overloaded` (the SAME
    `CimdReason`, the same decision-2 generic — no new client-visible surface, no
    new oracle). Total concurrent waiting resolutions are therefore bounded above
    by `maxInFlight × (maxWaitersPerFetch + 1)` (the `+1` per entry is the
    initiating resolution; the cap counts FOLLOWERS only). This does NOT reverse the
    no-slot rule above: a follower still consumes no FETCH slot, so one popular
    client_id can never starve distinct client_ids out of `maxInFlight`.
25. Cache freshness (RFC 9111 shared-cache subset, in-memory per instance and
    keyed by raw client_id): cache metadata is reusable only when every relevant
    header has the expected runtime shape. `private`, `no-store`, `no-cache`, and
    `Vary: *` prevent reuse; malformed, duplicate, quoted, or unusable
    `Cache-Control`, `Age`, or `Date` values fail toward re-fetch. Valid
    `s-maxage` takes precedence over `max-age`; the selected lifetime must be at
    least 60 seconds and is bounded by `cacheTtlCapSeconds`. `Expires` is not a
    CIMD freshness source, so it never grants reuse. All freshness arithmetic is
    milliseconds: `apparentAge = max(0, responseTime − Date)`;
    `correctedInitialAge = max(apparentAge, Age + responseDelay)`; and absolute
    expiry is `responseTime + min(lifetime, cap) − correctedInitialAge`.
    Comparing the injected clock to that absolute expiry represents resident
    time without a second formula. A non-finite, backward, or otherwise invalid
    clock observation clears the temporal cache state and resets the observation
    point, so old entries cannot resurrect and later valid entries can cache.
    A stale entry is removed before re-fetch; a failed re-fetch never serves it.

## 17.1.6 S6b flow-integration amendments (decisions 1–6, 2026-07-23)

Resolves the S6b cross-family flow-integration critique (GPT-5.6 Sol / Grok / GLM)
against current `main` (post #85–#91). **Contract text; enforcement lands with the
S6b code + frozen suite.** Decision 1 is the owner-chosen "extend §17.11"
(2026-07-23): CIMD is a first-class client type in upstream-redirect mode
(Hosted-Claude + Entra target). These TIGHTEN §17.1.4, §17.1.5 H (22–25), and
extend §17.11; where a rule here differs, this subsection wins. Every rule is
fail-closed.

**Design stance (read first — this is the anti-over-scope boundary).** The
authorization decision for a CIMD client is made ONCE, at authorize, and carried
forward to the callback under the flow cookie's existing HS256 signature. The
validated CIMD registration handed to `bridge.handleAuthorize` at callback is
**orchestrator-resolved trusted state — the same trust category as `subject` and
`allowedScopes` already on that options object.** Its integrity source is the flow
cookie signature (`consentSigningSecret`) + the single-use `upf_` jti; **no
separate capability/brand/registry system is introduced.** An in-process caller
fabricating that field is at the same trust level as the library core — there is no
external attacker sink, and it is deliberately NOT defended with new machinery
(the §17.1 `GuardedFetcher` rationale applied honestly, and the boundary that keeps
this from becoming a descriptor-snapshot edifice). `prepare`'s redirect re-check
(1d) is the fail-closed defense-in-depth; the trust model and residuals below are
pinned so review VERIFIES conformance rather than re-deriving the threat model each
round.

**Decision 1 — CIMD in upstream-redirect mode (§17.11 extension).**

*Problem.* §17.11 calls `bridge.handleAuthorize` at **callback** (upstream-flow.ts:152)
from a synthetic request; `prepare` — where CIMD otherwise resolves — fires after
the IdP hop. `resolveAuthorizeRedirect` (upstream-flow.ts:99) validates
`redirect_uri` at authorize. For a CIMD id both are wrong as written, and
re-fetching at callback is a second fetch + a TOCTOU window + a late failure after
the user has already authenticated. Fix: resolve once at authorize, carry forward.

*Shared redirect matcher (used by 1a, 1d, and prepare).* CIMD redirect membership is
a **single NEW pure matcher** (not the §10 export functions, which strip fragments and
consult a stored client): an https registration entry matches by **exact raw-string**
`presented === registered` (rule 20 / the raw-string identity rule — no normalization
AT MATCH TIME, port included; sound because §10.0 already required the registered entry
to be canonical); a loopback `http` entry matches RFC 8252 **any-port** using the compare
semantics of `src/redirect.ts:95-103` (scheme, host, path, and search equal; port
ignored; fragment already rejected). It is NOT array `∈`/`includes` (that rejects a
legitimate any-port loopback redirect). Authorize (1a), the callback gate (1d), and
`prepare`'s re-check MUST call this SAME matcher.
**PENDING (D00-4.5.2, §16.1) — this rule is the canonical definition the other
any-port statements defer to, so the precondition is stated here once:** RFC 9700
permits varying the loopback port **only for native apps**, and `application_type`
is in the IANA client-metadata registry draft `-00` §4.1 imports. The any-port
branch therefore applies only when the validated document declares
`application_type: "native"`; a document declaring `"web"`, or omitting the
property, gets exact raw-string matching (fail closed). The shipped matcher does
not yet carry the type — follow-up runtime PR 2 threads it through the projection
and gates the branch on it.

*1a. Shape-first three-way dispatch; CIMD REPLACES §10 for CIMD ids.* Client_id
shape is classified identically at BOTH the authorize resolve (`upstream-flow.ts:99`)
and `prepare`'s `resolveRedirect` (`authorize.ts:188-196`) — the entry-guard and its
stored-state sibling: **(1)** a literal-lowercase-`https://` client_id (rule 22) with
`cimd` enabled → the CIMD path; **(2)** ANY other scheme-shaped value
(`^[A-Za-z][A-Za-z0-9+.-]*://`, including `HTTPS://`/`http://`/`ftp://`) AND a
lowercase-`https://` id while `cimd` is disabled → **direct `invalid_client`**, never
a stateless fallback and never an IdP hop; **(3)** an opaque non-scheme id → the
unchanged §10 path (and MUST carry no `cimd` claim, 1d). For branch (1) the CIMD path
REPLACES redirect validation — the stored-mode `store.find` "Unknown client_id"
miss MUST NOT fire (else every CIMD id dies on a stored-DCR deployment and
Hosted-Claude+Entra never works). Resolve the document through the **§17.1.4 success
cache** (raw-client-id-keyed) backed by the branded guarded fetcher — all §17.1.5
rules; under the `cimd:<ip>` rate-limit + single-flight + `maxInFlight` cap alongside
the existing `upstream:<ip>` guard; a cache hit resolves without a network fetch.
Validate the presented `redirect_uri` with the shared matcher against
`document.redirect_uris`. **This is at most one network fetch (cache miss); a
callback re-fetch is forbidden (1d).**

*1b. Anti-oracle ordering.* Resolve + redirect exact-match complete BEFORE
`Set-Cookie` / the IdP 302. Any failure ⇒ the decision-2 generic (`invalid_client`
401) and `oauth.cimd.fetch` (failure, reason); success ⇒ `oauth.cimd.fetch`
(success). The 4096-byte `Set-Cookie` oversize guard (upstream-flow.ts:104), for a
CIMD id, maps to the SAME generic `invalid_client` (never `invalid_request`) so it
is not a content oracle. The `oauth.cimd.fetch` **success** audit is emitted only
**after the oversize guard passes**: a resolution whose document is valid but whose
projected flow-cookie would exceed 4096 bytes is rejected as the generic
`invalid_client` and audited as a **failure** (reason `oversize`), never a success
event followed by a silent rejection — so the audit trail matches the actual outcome. Hosted-Claude-class registrations (a short URL + a few
redirects) serialize to ~1–2 KiB and fit comfortably. **Documented residual:**
because the validated projection rides the signed flow cookie, redirect-mode
effective document size is **cookie-bound (≤4096 serialized), not only
`maxDocumentBytes`-bound** — a document-*valid* registration with many or long
`redirect_uris` (still within rule 19 / `maxDocumentBytes`) can exceed the cookie
budget and then fails closed as `invalid_client`, whereas direct mode would accept
it. This is a deliberate least-machinery tradeoff (no compression, truncation, or
second store is added to enlarge the redirect-mode ceiling).

*1c. Carry the validated registration forward under signature.* Define a distinct
named projection type **`CimdRegistration = { client_id: string; client_name: string;
redirect_uris: readonly string[] }`** — `client_name` REQUIRED and non-empty per
§17.1.3; constructed by explicit named-field projection at the fetch boundary and the
flow-token-parse boundary; it is NOT the committed `CimdDocument` (which still exposes
`raw`, `guarded-fetcher.ts`/`document.ts`) — signing `fetchResult.document` directly
would leak attacker-controlled members into the cookie (§4.1). The flow JWT gains a
`cimd` claim carrying exactly a `CimdRegistration` (no key material), covered by the
existing HS256 signature + single-use jti. At callback, after the flow JWT is
verified, the orchestrator passes it as a **new named option
`registration?: CimdRegistration`** on `bridge.handleAuthorize`, threaded
`handleAuthorize → AuthorizeRequestInput → prepare` — optional, in the SAME trusted
category as `{subject, allowedScopes}`; **only `createUpstreamRedirectFlow` (after the
1d gate) may set it, and adapters/frameworks MUST NEVER bind it to any
client-controlled request field.** When it is present `prepare` uses it and **does
NOT re-fetch** — the decision is atomic at authorize and carried forward (no
post-authentication late fetch; no TOCTOU; the consent page shows exactly the
validated document). The consent renderer receives display-only CIMD fields on
`PreparedConsent` (client_id host, redirect host, `client_name` as unverified text —
threat row 17); only `cimd_verified` is copied into the consent JWT (decision 3).

*1d. Fail-closed consistency (a signed-claim schema check — NOT a capability
system).* Split across two seams (GLM): **(i)** `verifyFlowToken`
(`upstream-flow-internals.ts`) strict-parses the `cimd` claim SHAPE — object;
`client_id` a primitive string raw-equal to `params.client_id`; `redirect_uris` an
array length 1..16 of strings; `client_name` a **non-empty string ≤256** (matching
§17.1.3 — an absent/empty name is a shape a validated document could never produce);
projecting ONLY the named fields into a fresh `CimdRegistration` (never `Object.assign`
/ never reuse the lenient string-only `params` loop). A present-but-malformed claim
fails cookie verification ⇒ **callback row 3** (`invalid_request`, audit
`flow_cookie_invalid`), consistent with the other cookie-integrity failures.
**(ii) POLICY (new row 5a).** `handleCallback`, after the state match (row 5) and
BEFORE jti consumption / exchange / any redirect-channel response (rows 7/8/10/11),
enforces the **claim/mode matrix + redirect match**: a
literal-lowercase-`https://` client_id requires `cimd` enabled AND a present valid
`cimd` claim; a non-CIMD client_id MUST carry NO `cimd` claim; and
`params.redirect_uri` MUST match the claim's `redirect_uris` via the **shared
matcher**. Any violation ⇒ **direct 400 `invalid_request` with audit reason
`flow_cookie_invalid`** (new **row 5a**; `flow_cookie_invalid` is the audit reason, NOT
an OAuth code — same pattern as rows 3/4). This closes the
IdP-error/exchange/identity-reject branches redirecting to an unmatched
`params.redirect_uri` before `prepare` runs. **The no-fetch switch is
registration-PRESENCE, not "mode"** (`prepare` is shared by direct/header/pairing):
when a `registration` option is supplied `prepare` MUST NOT fetch; when it is absent
AND the client_id is a lowercase-`https://` CIMD id, `prepare` resolves through the
shared **§17.1.4 success cache** (at most one guarded fetch on a miss); an **opaque
non-scheme client_id never fetches** (three-way dispatch, 1a); the redirect
orchestrator MUST supply `registration` for every CIMD id. `prepare`'s defensive re-check
(`params.redirect_uri` matches `registration.redirect_uris`, shared matcher) is a
**PRE-validation check inside `resolveRedirect` that throws a DIRECT
`OAuthError(invalid_client)` — never a 302** (a failed re-check means the signed
cookie is internally inconsistent, so `params.redirect_uri` is untrusted). **Frozen
S6b test:** with `registration` supplied, inject a `cimdTransport`/`cimdResolver`
(1e) whose call throws; assert the callback→prepare path still completes for a CIMD id
— proving carry-forward, not re-fetch.

*1e. Direct/header mode + the below-guard test seam.* `prepare` fetches at prepare
and validates there (base S6b, when no `registration` is supplied). Only redirect
mode pre-resolves at authorize and carries forward. Because decision 5 makes the core
own fetcher construction (no deployer-supplied whole fetcher), the ONLY test-injection
surface is a **below-guard seam** enumerated on BOTH `BridgeDeps` and
`UpstreamFlowDeps` as optional `cimdTransport?` / `cimdResolver?` (the rule-14
transport/resolver seams, which cannot widen `allowLoopback` or the caps) — never a
`BridgeConfig` field, never a whole `GuardedFetcher`. Mode mutual-exclusion (§17.11
adapter wiring) unchanged.

*Trust model + residuals (pinned — review verifies these, does not re-derive):*
- The `cimd` registration on `handleAuthorize` options is orchestrator-resolved
  trusted state (integrity = flow-cookie signature), NOT a new deployer-facing
  trust boundary. No brand/capability system; in-process fabrication is the same
  trust level as the core (no external sink; undefended by design). `prepare`'s
  redirect re-check is defense-in-depth.
- *Residual (inherent, shared):* CIMD resolution runs at authorize BEFORE the user
  authenticates, so an unauthenticated caller can trigger one outbound guarded
  fetch to a blocklist-passing URL. Bounded by `cimd:<ip>` rate-limit +
  single-flight + `maxInFlight` + the SSRF guard; inherent to validating a redirect
  before the IdP hop; not eliminated.
- *Residual:* the flow JWT now integrity-covers `redirect_uris`, so a leaked
  `consentSigningSecret` elevates flow-JWT forgery to CIMD-registration
  substitution — same secret/trust §17.11 already assumes.

**Decision 2 — CimdError → one anti-oracle OAuth error (mapped at the resolution
boundary).** Every `CimdError` (all `CimdReason`s incl. decision-6 `overloaded`)
AND any unexpected throw in the CIMD resolution path ⇒ `invalid_client` 401, body
`{"error":"invalid_client","error_description":"client_id could not be resolved"}`,
mapped INSIDE the resolution boundary. **The two boundaries are named by file**
(they are the ONLY resolution sites): **(1)** `flow.handleAuthorize`'s authorize-time
resolve (`upstream-flow.ts:86`) — the map wraps resolve+match so a `CimdError` NEVER
reaches the `upstream-flow.ts:107-109` catch, which would return `internal_error` 500
(a channel distinguishable from the generic `invalid_client` 401 — reopening the
oracle); **(2)** `prepare`'s CIMD branch (direct-mode fetch, plus any redirect-mode
re-check that can throw). `bridge.handleAuthorize` is explicitly **NOT** a resolution
boundary in redirect mode. `mapCimdError` is an **exhaustive switch over `CimdReason`
plus a fail-closed default**; a non-`CimdError` throw (cache/clock/resolver wrapper)
maps to the same generic error AND audits one **fixed allowlisted reason
`fetch_failed`** — never the exception text (log-injection/leak). Reasons go to
`oauth.cimd.fetch` (failure) ONLY. The `cimd:<ip>` `RateLimitPort` denial is a
**pre-resolution direct 429** (`temporarily_unavailable`, the existing rate-limit
error) that is **OUTSIDE** this anti-oracle mapping (it is not a resolution outcome);
decision 2's map begins at URL admission / cache resolution and covers every
admission / DNS / blocklist / fetch / status / content-type / encoding / size /
timeout / document / redirect-match / overload failure. *Enforced property (no overclaim):* all CIMD
resolution **FAILURES** collapse to one client-visible **status + headers + OAuth
code + description** — closing the SSRF content/reachability oracle. (A **success**
necessarily proceeds to the normal authorize response — Set-Cookie + IdP 302 — and is
not claimed indistinguishable.) Response **timing is NOT equalized** (block ≈ instant,
timeout ≈ `fetchTimeoutMs`, success slowest) and remains a bounded residual side
channel, bounded by rate-limit + single-flight + `maxInFlight` + DNS-pinning +
blocklist + the deadline. The earlier "matches unknown-stored-client" parity wording
is DROPPED (that sibling uses description "Unknown client_id" — authorize.ts:192 /
upstream-flow.ts:176 — so parity is not claimed).

**Decision 3 — consent provenance; scope accumulation is stored-DCR-opaque-only
(CIMD accumulation DEFERRED).** `ConsentRequestClaims` (crypto.ts:19-34) gains
`cimdVerified?: true`, minted into the consent JWT as `cimd_verified: true` ONLY when
`prepare` established the CIMD registration by genuine validation this flow (direct:
its own validated fetch/cache result — a cache HIT counts, no network fetch; redirect:
the carried-forward validated registration, 1c). `signConsentToken` OMITS the claim
when absent/false (never `cimd_verified:false`); strict `payload.cimd_verified === true`
is the sole true path; any present non-`true` value INVALIDATES the token (fail-closed).
**This claim proves the provenance of the CURRENT authorization flow ONLY; it does NOT
establish the provenance of any existing refresh-token record, and is NEVER a
scope-accumulation entitlement.**

*Scope accumulation stays a stored-DCR opaque-client feature; every CIMD client stands
alone in v0.2.* The core MAY call `findGrantedScopes(subject, clientId, now, generation, resource)` ONLY for
an opaque client resolved through `ClientStore` in stored-DCR mode. For **every
scheme-shaped (`https://`) `client_id`, in BOTH stateless and stored mode**,
`priorScopes` MUST be `[]` and the code is minted from the current request's scopes
only (still bounded by the identity `allowedScopes` ceiling). The gate is fail-closed
on the **NEGATIVE class** — accumulation runs iff `dcr.mode === "stored" && NOT
scheme-shaped(clientId)` (the same canonical classifier rule 22 uses), **NEVER keyed on
`clientId.startsWith("https://")` and NEVER on `cimd_verified`** — so a missing or
mis-propagated `cimdVerified` value can never enable a grant-store read. Both sites:
prepare-time (authorize.ts:124) and approve-time (authorize.ts:158).
The stored-DCR lookup supplies the exact configured resource and only accepts rows
whose token and family carry that same string, so pre-resource and cross-resource
refresh records cannot become scope-accumulation entitlement.

*Why deferred, not built (design-for-eventual-shape, build-minimal):* the current
refresh records (§12) carry no registration provenance, so a CIMD authorization cannot
safely union prior rows — a pre-CIMD stateless URL-keyed grant would silently resurrect
into a new document-bound CIMD grant. Doing it correctly needs immutable mint-time
registration provenance propagated through auth-code → token exchange → refresh-family
creation → rotation across all three stores, plus a legacy-row migration/default rule
(see the §12 note) — real security-core machinery for a re-authorization *convenience*
that the target AI clients (Claude, Cursor, VS Code — which request their full scope set
up front) do not use. It is a future-minor extension gated on real demand, never
inferred from the current flow's `cimd_verified` bit.

*Approve-time scheme/claim consistency gate (stored-state sibling of rule 22 — KEPT,
decoupled from accumulation).* Immediately after `verifyConsentToken` (authorize.ts:142)
and BEFORE the `approved !== true` deny branch (authorize.ts:145-149, which 302s to the
token's `redirectUri`), before any token-claim audit or `consumeConsentJti`
(authorize.ts:153): a lowercase-`https://` client_id is valid only when `cimd` is enabled
AND `cimd_verified === true`; any other scheme-shaped client_id, or `cimd_verified:true`
on a non-CIMD-shaped id, is invalid ⇒ **direct `invalid_consent`**, no code or state
change (so a legacy URL-shaped stateless consent token cannot be redeemed at all). This
is a validity check only — it is NOT an accumulation decision.

*Sibling reversals (S6b updates in lockstep):* §6.3, §9.3 step 5 + the approve "mint the
code with the accumulated scopes" bullet, §11, the §16 conformance-matrix row, and
§17.1.4 all state accumulation = **stored-DCR opaque clients only; CIMD clients stand
alone**; every "CIMD accumulates in either mode" claim is removed. The §7 `cimd_verified`
claim stays for the consistency gate + audit. Frozen suite: seed an active legacy
URL-keyed refresh row with a broader scope and prove a genuine CIMD authorization (BOTH
modes) reports `priorScopes = []` and mints only the requested, ceiling-bounded scopes; a
control case proves an opaque stored-DCR client still accumulates.

**Decision 4 — CimdFetchResult minimal cache view; shared-cache freshness (the
success cache serves BOTH modes).** The raw-client-id-keyed validated-success cache
(§17.1.4) is used at **both** direct-mode `prepare` AND upstream-redirect authorize
(1a) — NOT direct-mode-only. Redirect mode is the only mode that resolves
attacker-selected CIMD URLs BEFORE authentication, so without a cross-request cache an
unauthenticated caller sending sequential authorize requests for one valid CIMD id
would drive an unbounded series of outbound fetches (single-flight coalesces only
CONCURRENT requests; `maxInFlight` caps only concurrency; the rate limiter is optional
+ fail-open). Carrying the doc through one flow prevents a callback re-fetch; the
cache collapses repeated same-id fetches to one per freshness window **for cacheable
responses only** — a deliberately non-cacheable response (including `private`,
`no-store`, `no-cache`, `Vary: *`, absent or malformed freshness metadata, old or
skewed `Date`, and short/zero selected lifetime) is re-fetched on each request.
The guarded fetcher's global in-flight cap, timeout, response-size cap, optional
`cimd:<ip>` limiter, cache lifetime cap, and deployment egress policy bound but do
not eliminate that residual. `CimdFetchResult` carries only an explicit-validity
marker plus the `Cache-Control`, `Age`, `Date`, and `Vary` occurrences extracted
from `headersDistinct`; `Expires` is intentionally not carried or honoured.
Error/invalid results carry no cache view and are never cached. `t0Ms` is captured
before guarded fetch and `t1Ms` after body validation; their millisecond difference
is conservative response delay. The shared-cache rule is exact: `s-maxage` wins,
`private`/`no-store`/`no-cache`/`Vary:*` refuse reuse, and corrected initial age is
`max(max(0, t1Ms − Date), Age * 1000 + (t1Ms − t0Ms))`. Absolute expiry represents
resident time at read. The cache clears entries and resets its observation point on
a backward/non-finite injected-clock reading; this fails closed without retaining a
spurious future timestamp. The cache remains bounded LRU (default 256 entries).

**Decision 5 — loopback derives from the dev flag; the core owns fetcher
construction (least machinery).** `allowLoopback` is **never a `cimd` config field**
(confirmed absent from `config.ts`); its effective value derives SOLELY from the
already-validated `dev.allowInsecureLocalhost === true`. The core CONSTRUCTS the
branded guarded fetcher itself from the validated `cimd` cap profile (rule-21
domains) + `allowLoopback` from the dev flag. A deployer-supplied **whole
`cimd.fetcher` is not a production config knob** — test injection uses the
`transport`/`resolver` seams (rule 14, already below the guard), which cannot widen
`allowLoopback` or the caps. This closes the prod loopback bypass
(`createGuardedFetcher({allowLoopback:true})` injected where
`dev.allowInsecureLocalhost` is off) by removing the injection point rather than
adding a profile-equality checker. **This amendment EDITS (not merely supersedes) the
canonical config in the SAME commit** — the `fetcher?: GuardedFetcher` field and its
brand-verification paragraph are deleted from §5 `BridgeConfig.cimd` and from §17.1
(a "supersedes" note is insufficient because §5 is the canonical configuration
contract: leaving the snippet live lets S6b keep the injection point). `createGuardedFetcher`
remains the primitive/test factory but its whole result is NEVER accepted by
`BridgeConfig`. #90 already closed the prototype/inherited-option and unknown-key
vectors on the constructed fetcher's own options. *Residual (documented, not a gap):*
a production custom egress (e.g. a pinned corporate egress IP) has no v0.2 config knob
— consistent with rule 11 forbidding proxy env; it is a §18 follow-up if a real
deployment ever needs it, never a re-added whole-fetcher knob.

**Decision 6 — overload reason code (exhaustive mapper).** `CimdReason` (errors.ts)
gains `overloaded` for the rule-24 in-flight-cap rejection (a DISTINCT-client fetch
while `maxInFlight` distinct fetches are already in flight); **rule 24's "rejects
(generic error)" text is amended to name reason `overloaded`.** Audited to
`oauth.cimd.fetch` as `overloaded`; client-facing mapping is the decision-2 generic.
`overloaded` is simply added to `CimdReason` (rule 24 previously named no reason).
Covered by `mapCimdError`'s exhaustive switch
+ fail-closed default (decision 2), which a frozen test forces down the default path
with an unknown reason.

**Threat-model additions** (see [`threat-model.md`](../threat-model.md) — CIMD ×
upstream-redirect row): (1) approve-then-swap CLOSED (validate-once + carry-forward);
(2) unauthenticated outbound-fetch-at-authorize RESIDUAL; (3) `consentSigningSecret`
value elevation RESIDUAL; (4) resolution-timing side channel RESIDUAL.

### Decision 7 — bound the WAITERS on a single in-flight fetch (2026-07-25)

*Amends rule 24. Contract text; enforcement lands with its own frozen row + code.*

**The gap.** `maxInFlight` bounds concurrent outbound fetches. Single-flight
then collapses N concurrent requests for one raw `client_id` into ONE fetch —
correct, and rule 24 deliberately exempts followers from consuming a fetch slot
so a popular client cannot starve distinct client_ids. But the follower
REQUESTS still exist: each holds a socket, a promise chain, and a closure for up
to `fetchTimeoutMs` (≤ 30 s). Nothing bounded that count. Measured on the S6b
implementation: **10 000 concurrent same-id resolutions ⇒ 1 fetch, 0 settled,
~15.4 MB retained**, driven by an UNAUTHENTICATED caller (CIMD resolution runs
at upstream-authorize step 3a, before any IdP redirect). The only existing
defence is the `cimd:<ip>` limiter, which is OPTIONAL and FAIL-OPEN
(`noopRateLimit` returns `true`), so a default deployment has no bound at all.
This is the CWE-770 shape (allocation of resources without limits) on an
anonymous path.

**The rule.** A new `cimd.maxWaitersPerFetch` cap bounds callers parked on one
in-flight entry:

1. Domain `[1, 4096]`, default **256**, validated with the other caps (rule 21 —
   non-integer / out-of-domain / `NaN` ⇒ `AuthConfigError` at boot).
2. When an in-flight entry already has `maxWaitersPerFetch` waiters, a further
   follower for that SAME client_id rejects `CimdError("overloaded")` — the
   existing reason (decision 6), the existing decision-2 generic
   `invalid_client`. **No new client-visible surface and no new oracle:** an
   over-cap follower is byte-identical to every other resolution failure.
3. Audited `oauth.cimd.fetch` failure, reason `overloaded`, like any other.
4. Rule 24's no-slot rule is UNCHANGED: a follower still consumes no FETCH slot.
   Decision 7 bounds a different quantity. Both properties hold together.
5. Total concurrent waiting resolutions are bounded above by
   **`maxInFlight × (maxWaitersPerFetch + 1)`** — the `+1` is the INITIATING
   resolution, which also waits on its own fetch. Default
   `8 × (256 + 1) = 2056`, ≈ 3 MB at the measured ~1.5 KB/waiter. The cap counts
   FOLLOWERS only; the leader is never rejected by it. This composed number is
   the statement a deployer can hand to a security review, so it is stated
   exactly rather than rounded.

**Why 256 and not lower.** The cap must not break a legitimate thundering herd —
e.g. a workforce opening an MCP client at the start of a shift, all naming the
same `client_id` against a cold cache. 256 same-id waiters is far above that
pattern while still bounding the surface. It is a CEILING, not a throttle:
per-tenant shaping remains the deployer's `RateLimitPort`.

**Threat-model delta.** Residual (2) above narrows: the unauthenticated
outbound-fetch surface remains, but its memory/connection amplification is now
bounded rather than open-ended.

## 17.2 `client_credentials` grant (MCP extension `io.modelcontextprotocol/oauth-client-credentials`)

> **SHIPPED.** S3a (PR #16, `0589ed3`) shipped the machine-client records +
> out-of-band provisioning/rotation primitives + the timing-safe `verify` and
> the boot/config/DCR/redirect guards. S3b ships the `/oauth/token` grant itself:
> `client_secret_basic` + `client_secret_post` client auth, the
> `MachineTokenResponse` split, the `client_credentials`-aware RFC 8414 metadata,
> and the `oauth.token.client_credentials` audit event.

The extension (ext-auth repo, status Draft) requires OAuth 2.1-shaped client
authentication and states outright: *"Dynamic Client Registration is not used
in this flow."* Decisions:

- **Stored-DCR mode only**, and machine clients are **provisioned
  out-of-band, never via `/oauth/register`**: the open registration endpoint
  MUST reject any request naming `token_endpoint_auth_method` other than
  `"none"` or a `grant_types` containing `client_credentials`
  (`invalid_client_metadata`). Otherwise anyone on the internet could mint
  themselves a secret. Config: `clientCredentials?: { enabled: boolean }`;
  boot `AuthConfigError` if enabled with `dcr.mode !== "stored"`.
- **Provisioning API (library functions, not endpoints).** The provisioning
  use-cases take a deps object — `{ store, catalog, resource, clock, audit }` — so they
  can validate `allowedScopes` against `scopeCatalog` (item below), stamp
  epochs, bind a credential to the configured resource, and emit audit without
  hidden globals (same deps-first shape as `registerClient`). `catalog` is
  `config.scopeCatalog` and `resource` is the exact `config.resource` string.
  `resource` is a newly required public `MachineClientDeps` property, so an
  upgrading TypeScript lifecycle caller must add it. For the store API's patch
  compatibility, `MachineClientDeps.store` remains typed as `ClientStore`; each
  lifecycle mutation requires the additive `MachineClientStore` methods at
  runtime and fails before credential generation or mutation when they are
  absent. Its raw value is accepted only when it is eligible for
  `BridgeConfig.resource`: HTTPS, or HTTP on `localhost`, `127.0.0.1`, or
  `[::1]` for a matching `dev.allowInsecureLocalhost` bridge. A remote HTTP,
  blank, or malformed value is `invalid_request` before secret generation,
  mutation, or success audit.
  - `provisionMachineClient(deps, { name?, allowedScopes, secretTtlSeconds? })`
    → `{ clientId, clientSecret }`. `clientId` = `mcc_<random>` — the prefix is
    enforced, giving a namespace disjoint from human subjects and from `mcpdc_`
    ids (RFC 9700 §4.15.1: the AS MUST let the RS distinguish machine tokens
    from user tokens; here `sub` starting `mcc_` ⇔ machine — made sound in
    BOTH directions by `prepare` rejecting any user-grant subject that starts
    with `mcc_` (§9.3 direct-error list) AND by the token grant handlers
    (code-exchange and refresh) rejecting a stored record whose subject is in
    the reserved namespace with `invalid_grant` BEFORE any side effect — the
    exchange saves no refresh token and audits no success (the single-use
    code is burned); the refresh path revokes the legacy family outright so
    it stops rotating — so neither a live IdP-supplied subject nor a legacy
    stored grant from a pre-guard deployment can impersonate the machine
    namespace, and the audit/refresh ledger reflects only real issuance —
    THIRD enforcement point: machine access tokens mint a
    `gty: "client_credentials"` marker claim, and `verifyAccessToken`
    classifies a verified token as `credentialKind: "machine"` ONLY with an
    `mcc_` `sub`, `sub == client_id` (RFC 9068 §2.2), AND that marker. An
    `mcc_` `sub` or any present `gty` enters the machine branch; a
    partial/conflicting triad or a `gty` other than the exact string
    `"client_credentials"` is `invalid_token`, never an interactive fallback.
    An `mcc_` `client_id` alone is not a marker because opaque stateless client
    IDs are client-selected. Tokens with no machine signal return
    `credentialKind: "interactive"`. The full triad is required because
    stateless-DCR clients choose their own `client_id`, so `sub == client_id` alone could be
    satisfied by a pre-guard human token; the marker cannot, since only the
    machine grant mints it and the grant first ships in the SAME release as
    the marker (no legitimate unmarked machine token can exist from any
    published version — and any from pre-release `main` expires within
    `accessTokenTtlSeconds`). `VerifiedAccessToken`, `AuthorizedSubject`, and
    `RequestAuthResult` expose the verifier-produced kind; downstream code
    MUST NOT decode the JWT or infer from a prefix. The secret is
    returned ONCE and never retrievable. `allowedScopes` MUST be a non-empty
    subset of `catalog` (each entry a single RFC 6749 scope token; unknown or
    malformed ⇒ `invalid_scope`) — the per-client ceiling is fixed at
    provisioning, so a later catalog narrowing cannot silently widen a machine
    client. `secretTtlSeconds?` (positive integer), when given, sets the
    provisioned secret's `expiresAtEpoch = now + ttl` (a bounded-lifetime
    first secret); omitted ⇒ the secret is live until rotated. A TTL whose
    derived expiry is not a non-negative safe integer is `invalid_request`
    before client-id/secret generation, `createMachineClient`, or a success
    audit. A blank or malformed deps resource is `invalid_request` before a
    credential is generated or a row/audit is written.
  - `rotateMachineClientSecret(deps, clientId, { graceSeconds = 86400 })` →
    `VersionedRotatedSecret { clientSecret, version }` (see Rotation below).
    The published v0.3.0 `RotatedSecret { clientSecret }` remains its base type
    for patch source compatibility.
  - `disableMachineClient(deps, clientId)` →
    `{ clientId, disabledAtEpoch, version }`. It atomically replaces an active
    record with a hash-free tombstone and its durable audit. Existing access
    tokens remain valid only until their ordinary access-token expiry.
  - `verifyMachineClientSecret(deps, clientId, presentedSecret)` → `boolean`:
    the timing-safe comparison primitive the token endpoint (§9.4
    client_credentials grant, S3b) composes into client authentication. Finds
    and parses the machine client through
    `parseMachineClientRegistration(value, clientId, nowEpoch)`, requires its
    resource to be exactly equal to `deps.resource`, SHA-256s the presented
    secret, and constant-time compares it against each **unexpired** stored hash
    (expired entries skipped). Non-machine, unknown, malformed, or
    lookup-key-mismatched, resource-less, malformed-resource, or
    wrong-resource records ⇒ `false` (the grant maps the boolean to
    `invalid_client`). A rejected `ClientStore.find` remains a store error; this
    function does not convert store I/O failure into an authentication result.
- **`MachineClientStore` extension:** `applicationType` gains `"machine"`;
  the v0.3.0 `MachineClientRegistration` name/shape and
  `ClientStore.save(ClientRegistration)` signature remain public and
  source-compatible as legacy input. New writes use the separately named
  `VersionedMachineClientRegistration` union;
  active machine records carry `status: "active"`, a positive monotonic
  `version`, the exact uncanonicalized `resource` supplied at provisioning,
  `allowedScopes: string[]` (validated ⊆ `scopeCatalog` at wiring), and one or
  two `{ hash, createdAtEpoch, expiresAtEpoch? }` secrets. Disabled tombstones
  preserve that `resource`, carry `status: "disabled"`, a disable epoch, and no
  secrets.
  `redirectUris` MUST be `[]`; machine clients are rejected at
  `/oauth/authorize` and MUST be rejected at any future device endpoints
  (`invalid_client`). Lifecycle functions never write a machine row through
  the compatibility `ClientStore.save` method.
  `createMachineClient(client, audit)` and
  `compareAndSwapMachineClient(expectedVersion, client, audit)` commit the row
  and durable metadata-only lifecycle audit in one backend transaction or
  commit neither; `false` is a no-write collision/conflict. New records start
  at version 1. The public legacy v0.3.0 type remains source-compatible for
  reads, but a resource-less row cannot authenticate, rotate, or disable and
  requires reprovisioning. A resource-bearing row with no `status` or `version`
  is active version 0; `expectedVersion: 0` matches only that shape, and its
  first successful mutation writes version 1. A partial marker, malformed full
  record, wrong resource, or version overflow fails closed before mutation.
- **Secret contract:** `mcs_` + base64url(32 CSPRNG bytes) — 256-bit,
  clearing RFC 6749 §10.10 (≥2⁻¹²⁸ MUST) and RFC 6819 §5.1.4.2.2. Stored as
  **unsalted SHA-256 hex only**: RFC 6819 §5.1.4.1.3 conditions salting/work
  factors on LOW-entropy credentials (user passwords); for a 256-bit random
  secret SHA-256 is sufficient, keeps the hot path cheap (bcrypt on the token
  endpoint is a DoS lever), and keeps `jose` the only dep. Digest comparison
  is constant-time.
- **Token-endpoint auth:** support BOTH `client_secret_basic` (RFC 6749 §2.3.1
  MUST — including the percent-decode-after-Basic-split quirk; our base64url
  alphabet makes encoding a no-op but we decode anyway) and
  `client_secret_post` (OAuth 2.1 §2.4.1 MUST — the two specs flipped the
  mandatory method; the MCP extension names `client_secret_basic`). A request
  presenting BOTH a `Basic` header and a body `client_secret` uses two auth
  methods and is rejected (`invalid_client`, RFC 6749 §2.3).
  `Bridge.handleToken` reads normalized headers through `readHeader`; an
  array-valued header or more than one case-insensitive `Authorization` key is
  `invalid_client` before body authentication is considered, so ambiguity never
  degrades to an absent header and `client_secret_post`. If any ambiguous value
  names the case-insensitive Basic scheme — including a bare malformed `Basic`,
  but not a `BasicX` prefix — `Bridge.handleToken` still returns the Basic
  challenge. For `client_credentials`, it attempts the
  `oauth.token.client_credentials` failure audit before rejecting, without
  reading the client store; a synchronous or rejected audit write cannot replace
  that `invalid_client` response. Fastify/Express `headersFromDistinct`
  preserves the raw occurrence count; Fetch/Hono `readHeader` rejects the
  comma-coalesced form before `Bridge.handleToken` dispatches a grant. Advertise
  `token_endpoint_auth_methods_supported:
  ["none","client_secret_basic","client_secret_post"]` and
  `grant_types_supported` += `client_credentials` (RFC 8414's default omits
  it) — but ONLY when `clientCredentials.enabled` (a disabled grant is never
  advertised, so discovery cannot steer a client to a surface the bridge would
  reject with `unsupported_grant_type`; `"none"` is always advertised for the
  PKCE user grants). `private_key_jwt` (RFC 7523; the extension's RECOMMENDED
  method) is DEFERRED with 17.1's confidential-CIMD — recorded, not forgotten;
  the secret-based path is extension-compliant.
- **Grant semantics:** authenticate the client (failure ⇒ `invalid_client`
  401, `WWW-Authenticate: Basic` when Basic was attempted); `scope` validated
  against BOTH the client's `allowedScopes` ceiling AND the live `scopeCatalog`
  (a scope outside either ⇒ `invalid_scope`); omitted ⇒ the full allowed set
  (RFC 6749 §3.3 default). The catalog check matches the user-grant fail-closed
  gate (`normalizeScopes`): a scope removed from the catalog AFTER a machine
  client was provisioned is never minted — the persisted ceiling is not the
  whole truth, so drift surfaces as `invalid_scope` until the client is
  re-provisioned (the same discipline a drifted user refresh token imposes).
  The stored ceiling is itself validated at grant time — a non-empty array of
  scope tokens. Authentication and scope resolution use one fresh snapshot
  returned by `parseMachineClientRegistration(value, clientId, nowEpoch)`, so
  a custom/migrated store returning a malformed, resource-less, wrong-resource,
  over-active, or differently keyed row fails closed as `invalid_client` (never
  an empty-scope token or a token for the embedded wrong client). The parser also enforces the `mcc_`
  prefix — the RS's machine-vs-user distinguishability signal (RFC 9700
  §4.15.1) — before the record reaches token signing.
  `resource` if present MUST equal `config.resource` (`invalid_target`). Mint
  an access token with `sub = client_id`
  (RFC 9068 §2.2) and the existing `client_id` claim; **NO refresh token**
  (RFC 6749 §4.4.3 SHOULD NOT — the client holds a durable credential; a
  refresh token is a second bearer secret with zero benefit). **This requires
  splitting the §9.4 response type**, whose current `TokenResponse` makes
  `refresh_token` required: the implementation defines `UserTokenResponse`
  (today's shape, refresh_token required — authorization-code, refresh, and
  device grants) and `MachineTokenResponse { access_token, token_type:
  "Bearer", expires_in, scope }` — no `refresh_token` member at all, not an
  optional one, so an accidental `refresh_token: undefined` is
  unrepresentable. The token endpoint returns one or the other by grant type.
- **Rotation:** `rotateMachineClientSecret(deps, clientId, { graceSeconds =
  86400 })` — adds the new secret (live, no `expiresAtEpoch`), expires the
  currently-live secret at `now + grace` (the two-active-secrets overlap
  pattern, per Okta/Entra practice; RFC 7592 is Experimental and
  hard-cutover, not used). Patch releases preserve the published
  `DEFAULT_ROTATION_GRACE_SECONDS` of 86,400 seconds; the hard
  `MAX_ROTATION_GRACE_SECONDS` is also 86,400 seconds. Deployments that need a
  shorter overlap pass it explicitly. A non-positive,
  non-integer, above-maximum, or unsafe derived grace is `invalid_request`
  before secret generation, CAS, or a success audit. The record's `secrets`
  array is then **exactly**
  the permitted active set: the new live secret plus at most one grace secret
  (the latest-expiring); any older/expired (`expiresAtEpoch ≤ now`) entry is
  dropped so the array never exceeds two unexpired hashes. So a rotation from
  a single-secret record yields `[{old, expiresAt=now+grace}, {new}]`; a
  second rotation before the first grace elapses supersedes the prior grace
  secret (its overlap is cut) to hold the two-active cap. The stored row is
  parsed and bound to the requested key and configured resource before secret
  generation or `save`; unknown, non-machine, malformed, resource-less,
  wrong-resource, or key-mismatched records ⇒ `invalid_client`. Verification
  accepts any unexpired stored hash.
- **Audit:** `oauth.token.client_credentials`, `oauth.client.provision`,
  `oauth.client.rotate_secret`, `oauth.client.disable` — clientId/scopes/resource
  metadata only; never a secret or a secret hash. Each lifecycle success audit
  is durable in the same `MachineClientStore` transaction as its row mutation.
  The ordinary `AuditPort` copy is best-effort and cannot turn a committed,
  one-time secret into an error response.
- The MCP `initialize`-handshake extension advertisement
  (`capabilities.extensions`) is the host app's/example's concern, not the
  bridge's.
- **Concurrency:** a rotation reads a fully parsed, key-bound active snapshot,
  derives version `n + 1`, and submits one CAS with expected version `n`.
  Exactly one same-version competitor can commit and return its raw secret;
  losers receive a conflict before any secret is returned. Provision, rotate,
  and disable commit their required durable audit in that same mutation.
  `client_credentials` issuance remains stateless: it reads the record, signs a
  JWT with no server-side token write, and returns no refresh token.

## 17.3 Device authorization grant (RFC 8628)

> **CONTRACT ONLY — NOT IMPLEMENTED.** No device endpoint, device-code store
> record, approval surface, polling limiter, or metadata advertisement ships.
> The public audit type reserves the three §17.3 event names
> (`oauth.device.authorization`, `oauth.device.approve`, and
> `oauth.token.device_code`), but no runtime emits them. Everything below
> specifies a future implementation.

Honest scope note: RFC 8628 is in neither the MCP core spec nor any official
MCP extension (SEP-2059 was closed unadopted). This contract targets the
owner's non-MCP-shaped clients (CLI over SSH, sandboxed CI agents) as standard
OAuth, discoverable via RFC 8414 metadata; MCP clients would not discover it
via the MCP spec.

- **Endpoint:** `POST ${issuer}/oauth/device_authorization` (behind
  `RateLimitPort`, key `device:<ip>`). Request: `client_id` required
  (stateless: any non-empty; stored: must exist and not be `machine`; CIMD
  URL ids allowed — the document is fetched/validated per 17.1), `scope`
  optional (§11 normalization), `resource` optional (must equal
  `config.resource`). Duplicate parameters rejected (§3.1 MUST NOT).
- **Response** (200, `application/json`, `cache-control: no-store`):
  `device_code`, `user_code`, `verification_uri` = `${issuer}/oauth/device`,
  `verification_uri_complete` = `${issuer}/oauth/device?user_code=XXXX-XXXX`,
  `expires_in` = `deviceCodeTtlSeconds` (config, default **600**), `interval`
  = **5**.
- **`user_code`:** 8 chars from the RFC 8628 §6.1 base-20 set
  `BCDFGHJKLMNPQRSTVWXZ` (~34.5 bits), displayed `XXXX-XXXX`; CSPRNG with
  rejection sampling. Input canonicalization per §6.1: uppercase, strip every
  character outside the charset, then compare. Stored as
  `sha256(canonical)`.
- **`device_code`:** `dc_` + base64url(32 bytes) (§5.2 "very high entropy"),
  stored hashed, treated as a bearer secret.
- **Brute force (§5.1 budget):** 34.5 bits × 600 s TTL × a built-in
  **in-process** per-IP cap of 5 wrong `user_code` submissions per 10 minutes
  (deliberately NOT dependent on the deployer wiring `RateLimitPort`; the
  port hook `device-verify:<ip>` adds defense-in-depth) ≈ the RFC's 2⁻³²
  target. The in-process limiter is per-instance; multi-instance deployments
  get the residual noted in the threat model.
- **Store additions (`StorePort`, conformance-suite invariants):**
  `DeviceCodeRecord { deviceCodeHash, userCodeHash, clientId, scopes,
  resource, status: "pending"|"approved"|"denied", subject: string|null,
  approvedScopes: string[]|null, intervalSeconds, lastPolledAt: string|null,
  expiresAt }` with methods: `saveDeviceCode`,
  `findDeviceCodeByUserCodeHash` (pending + unexpired only),
  `pollDeviceCode(hash, nowIso)` (atomic: stamps `lastPolledAt`; polls faster
  than `intervalSeconds` return a too-fast marker AND bump the stored
  interval +5 — server-side mirror of the client's `slow_down` MUST),
  `resolveDeviceCode(userCodeHash, {status, subject, approvedScopes}, nowIso)`
  (CAS `pending`→`approved`/`denied`), `consumeApprovedDeviceCode(hash,
  nowIso)` (single-use delete-on-read for token issuance), and `sweepExpired`
  extended to device codes. Timestamps follow §12.1 (3-ms rule).
- **Verification UI (adapter):** `GET /oauth/device` renders enter-the-code
  first (prefilled from `user_code` query for the `_complete` variant); on a
  canonicalized match, identity resolution runs (the SAME `IdentityPort`
  machinery as authorize), then the existing consent page in a device variant:
  it MUST echo the `user_code` and say the user is authorizing a device they
  should confirm is theirs (§5.4 remote-phishing mitigation), show client
  info + requested scopes + Approve/Deny, and end on "return to your device"
  (no redirect). **This is a distinct consent surface, not a reuse of §7.1's
  token** — the §7.1 `ConsentRequestClaims` requires `redirectUri` and
  `approve()` always resolves to a redirect, which the device flow has none
  of. Contract: a separate `DeviceConsentClaims` token — HS256 with the same
  consent secret but a DISTINCT pinned audience `"mcp-sso/device-consent"`
  (so the two token kinds can never validate on each other's surface),
  claims `{ userCodeHash, clientId, scopes, allowedScopes?, subject, jti,
  iat, exp }` — and a separate `approveDevice({ deviceConsentToken,
  approved?, origin? })` use-case returning `{ decision: "approved" |
  "denied" }` with no redirect member. It shares the Origin/CSRF rule and the
  single-use-JTI store primitive (`consumeConsentJti`) with §9.3. The §17.4
  group ceiling applies here exactly as at authorize.
- **Token endpoint:** `grant_type=urn:ietf:params:oauth:grant-type:device_code`
  + `device_code` + `client_id` (must match the record; mismatch ⇒
  `invalid_grant`). Error state machine, all HTTP 400 §5.2-shaped:
  `authorization_pending` (pending), `slow_down` (poll arrived before the
  current interval elapsed; interval grows +5 persistently),
  `access_denied` (denied — terminal; record deleted on delivery),
  `expired_token` (expired — terminal). Success: `consumeApprovedDeviceCode`
  (single-use) → mint access + refresh tokens (new family) with
  `approvedScopes` — this IS a user grant, so refresh tokens apply, unlike
  17.2.
- **Metadata:** `device_authorization_endpoint` + `grant_types_supported` +=
  the device URN.
- **Audit:** `oauth.device.authorization`, `oauth.device.approve`
  (approved/denied), `oauth.token.device_code`.

## 17.4 Entra group-based authorization (Gate 2 becomes a scope ceiling)

> **SHIPPED S2a — IdP-agnostic `allowedScopes` ceiling plumbing (core).** The
> scope-ceiling *engine* is implemented and shipped: `IdentityClaims.allowedScopes?`,
> `Bridge.resolveIdentity(identity, input, ip?)` (replaces the `resolveSubject`
> helper and emits `identity.verify` — implemented as a Bridge method rather than
> the http.ts free function, so all three adapters share one DRY emission path),
> `Bridge.handleAuthorize(req, { subject, allowedScopes? })`
> (bare-string form removed), `AuthorizeRequestInput.allowedScopes?`,
> `ConsentRequestClaims.allowedScopes?` carried as the consent-JWT `allowed_scopes`
> claim, `prepare` narrows requested/default scopes by intersection (empty ⇒
> `access_denied` on the redirect channel), and `approve` re-intersects
> `union(requested, priorScopes)` against the ceiling read from the *verified
> consent token* (prior grants cannot resurrect a since-removed-group scope).
> Refresh is not re-checked. **No shipped identity port sets `allowedScopes`
> except Entra (see below), so v0.1 behavior is unchanged unless a port supplies
> a ceiling.**
>
> **SHIPPED S2b — the Entra group→scope *producer*.** `EntraConfig.groupAuthorization`
> (`mapping: Record<GUID, string[]>` + `baseScopes?`) ships in
> `src/identity/entra-groups.ts` (pure, JWKS-free, unit-testable) wired into
> `src/identity/entra.ts`. GUID-only mapping keys, non-empty scope values, and
> duplicate (case-insensitive) keys are boot-rejected (`AuthConfigError`); the
> mapped/base ⊆ `scopeCatalog` subset check runs at
> `createEntraIdentity(config, { scopeCatalog })` — the construction-time
> junction where both the Entra mapping and the bridge catalog are in scope (the
> shipped `registerOAuthRoutes` takes an opaque `IdentityPort` and does not see
> the EntraConfig; S2a kept the engine IdP-agnostic, so the port-construction
> call is the honest, enforceable junction — one extra arg). The verified
> `groups` claim is unioned with `baseScopes` into the ceiling; overage (`groups`
> absent + `_claim_names.groups` or `hasgroups`) fails closed with
> `entra_groups_overage` and `_claim_sources` is NEVER dereferenced; no groups +
> empty `baseScopes` fails with `entra_no_groups`. Reasons flow through
> `Bridge.resolveIdentity`'s `identity.verify` emission (S2a). Gates green
> (typecheck · lines · 244/244 test · build). The
> `createEntraRedirectIdentity` → `resolveGroupCeiling` path was subsequently
> observed for member, no-group/no-mapped-group, overage, allowlist, and
> guest/B2B outcomes on an unarchived patched checkout; those deny/ceiling
> observations do not qualify as verified rows. The clean-runtime CIMD happy
> path was repeated at `af2a61f` on 2026-07-28, while the deny/ceiling sweep
> remains pending.

Entra-specific by design (the owner's real deployment; do not generalize
prematurely). Facts verified against Microsoft Learn 2026-07-04: JWT group
claims cap at **200 groups**, beyond which the claim is **omitted** and
`_claim_names`/`_claim_sources` overage markers appear instead; group
**object IDs are the only universally available, immutable, collision-safe
form** (display names are a documented spoof vector — any user can create a
duplicate-named group); the `_claim_sources` endpoint URL is legacy Azure AD
Graph and Microsoft says not to rely on it.

**Config (on `EntraConfig`):**

```ts
groupAuthorization?: {
  mapping: Record<string, string[]>; // Entra group OBJECT ID (GUID) → scopes
  baseScopes?: string[];             // scopes every authenticated subject gets; default []
}
```

- **Shipped-example env surface (shipped).**
  `ENTRA_GROUP_AUTHORIZATION_JSON`, when present, is parsed as the complete
  `groupAuthorization` object above and passed unchanged to
  `createEntraRedirectIdentity` by both shipped example composition roots.
  Absence preserves the existing no-ceiling behavior. A present blank value,
  invalid JSON, or any value that fails `assertGroupAuthorizationMapping`
  rejects example boot before state-directory creation; it never degrades to
  an absent ceiling. The JSON form is the only env grammar: it avoids a second
  delimiter parser for the GUID-to-scope mapping.
- Boot validation (shipped S2b, `assertGroupAuthorizationMapping`): every
  `mapping` key must be GUID-shaped (display names rejected — fail-closed
  against the documented spoofing vector; case-insensitive, duplicate keys
  rejected), scope values non-empty AND each a single RFC 6749 scope token
  (`isScopeToken` / `SCOPE_TOKEN_RE` from `scopes.ts` — a whitespace/quote/
  control-bearing value is rejected so it cannot corrupt the space-joined
  `allowed_scopes` JWT round-trip; the boot-layer instance the PR #8 sweep left
  open). The mapped/base ⊆ `scopeCatalog` subset check runs at
  `createEntraIdentity(config, { scopeCatalog })` — the composition root where
  both the Entra mapping and the bridge catalog are in scope. (The original
  wording pointed at `registerOAuthRoutes`; the shipped S2a adapter takes an
  opaque `IdentityPort` and does not see the `EntraConfig`, so port construction
  is the honest, enforceable junction. A mapped scope absent from the catalog can
  never be granted anyway — the engine intersects against catalog-validated
  requested scopes — so the subset check is a deployer foot gun guard surfacing
  misconfiguration loudly at boot, not a security boundary. The separate
  `scopeCatalog`/`defaultScopes` entry shape-validation is a tracked backlog
  item, NOT bundled here.)
- **Combination model: UNION.** A subject's scope ceiling
  `allowedScopes = baseScopes ∪ ⋃ mapping[g]` over every group GUID `g` in
  the verified `groups` claim that has a mapping entry. No tier precedence,
  no highest-wins — union is order-independent and matches how directory
  membership composes. The verified GUID is a dynamic lookup key (§4.1): only
  an own mapping entry or equivalent `Map` entry contributes scopes. An
  inherited entry is unmapped and contributes nothing; if no mapped group and
  no `baseScopes` remain, the existing `entra_no_mapped_groups` failure applies.
- **Overage = fail closed.** `groups` absent + (`_claim_names.groups` or
  `hasgroups`) present ⇒ `verify()` fails with reason
  `entra_groups_overage`. The `_claim_sources` URL is NEVER dereferenced — a
  URL inside a token is data, not instructions. Documented remediation:
  configure the app registration with **"Groups assigned to the
  application"** (`groupMembershipClaims: "ApplicationGroup"`) — caveats
  recorded: requires Entra P1, direct membership only, no nesting — or reduce
  group sprawl.
- **No usable groups ⇒ fail closed with a reason that names the likely knob.**
  No `groups` claim at all (not configured in the app manifest, or the user is
  in zero groups) + empty `baseScopes` ⇒ `entra_no_groups` (likely a
  `groupMembershipClaims` misconfiguration). A `groups` claim IS present but
  every group is unmapped + empty `baseScopes` ⇒ `entra_no_mapped_groups` (a
  deployer *mapping* gap, not a manifest problem — the distinct reason points
  the operator at `groupAuthorization.mapping` rather than the Entra app
  manifest; audit fidelity for a product whose wedge is auditable execution).
  Both are entitled-to-nothing and fail closed; non-empty `baseScopes` resolves
  to the baseline ceiling instead. Nested groups: the `SecurityGroup` claim is
  transitive; `ApplicationGroup` is direct-only (deployer caveat in
  `docs/authorization.md`).
- **Graph API fallback: DEFERRED (explicit decision).** The designed
  extension point is `POST /users/{oid}/checkMemberGroups` (≤20 group IDs per
  call — allowlist-shaped, transitive, app-only permissions
  `GroupMember.Read.All` + `User.ReadBasic.All`), but it puts an outbound
  Microsoft Graph call inside the auth path (availability + latency), needs
  admin consent and a confidential Entra client, and `ApplicationGroup`
  filtering already solves overage for the mapping use case. Revisit on real
  deployment demand. (Microsoft's first-line recommendation — App Roles via
  the `roles` claim, which never overflows — is recorded as a backlog
  alternative, not v0.2.)
- **Plumbing (explicit signature changes — the ceiling must travel the whole
  path, not live as a local Entra patch).** Today the adapters reduce identity
  to a bare subject string (`resolveSubject(): Promise<string>` in
  `adapters/http.ts`), `Bridge.handleAuthorize(req, subject)` takes only the
  string, and `ConsentRequestClaims` has no ceiling field. The contract
  changes every hop:
  1. `IdentityClaims` gains optional `allowedScopes?: string[]` (set by the
     Entra port from the group mapping; any future port may set it).
  2. `resolveSubject` is REPLACED by `resolveIdentity(identity, input):
     Promise<{ subject: string; allowedScopes?: string[] }>` — same
     fail-closed `access_denied` behavior, richer return. (Internal adapter
     helper; not a public export — no compat shim needed.)
  3. `Bridge.handleAuthorize(req, identity: { subject; allowedScopes? })` —
     the bare-string form is removed in the same release.
  4. `AuthorizeRequestInput` gains `allowedScopes?: string[]`.
  5. `ConsentRequestClaims` gains `allowedScopes?: string[]`, carried in the
     consent JWT as an `allowed_scopes` claim (§7.1 shape extended), so
     `approve` re-intersects from the *verified token*, not from anything
     client-resupplied.
  6. The device-approval path (§17.3 `DeviceConsentClaims`) carries the same
     field the same way.
- **Core enforcement (IdP-agnostic):** with the ceiling present,
  `prepare` (and the device-flow approval) **narrows by intersection** with
  the ceiling — RFC 6749 permits granting fewer scopes than requested, and
  the token response `scope` + consent page reflect the narrowed set (this is
  not fail-open: the un-entitled scope is never granted; rejecting outright
  would only worsen interop since MCP clients cannot know what to request).
  An EMPTY intersection ⇒ `access_denied` (redirect channel). The ceiling is
  embedded in the consent-token claims, and `approve` re-intersects
  `union(requested, priorScopes)` against it — accumulated prior grants must
  not resurrect scopes a since-removed group granted. `defaultScopes` pass
  through the same intersection.
- **Refresh is NOT re-checked** (no identity at refresh): group revocation
  takes effect at the next full authorize. Residual risk documented in the
  threat model; deployers needing faster revocation shorten
  `refreshTokenTtlSeconds` or revoke families.
- Guest (B2B) behavior was observed with a real invited guest whose mapped group
  membership produced the expected ceiling, but that patched checkout's exact
  tree was not archived. The observation does not satisfy the release-evidence
  contract or support a current live claim for every Entra tenant
  configuration.
- **Audit:** event `identity.verify` (emitted by `Bridge.resolveIdentity`,
  S2a; success/failure + reason) carries the Entra reasons
  `entra_groups_overage`, `entra_no_groups`, and `entra_no_mapped_groups` —
  failed-login evidence for enterprises.

## 17.5 Console-pairing identity (zero-IdP setup)

> **SHIPPED S1b** (`src/identity/console-pairing.ts`, subpath
> `./identity/console-pairing`; the example's `DEV_STUB_SUBJECT` dev bypass is
> deleted — a real gate replaces no-gate). The framework-free authorize
> orchestration is `handlePairingAuthorize` (`src/adapters/pairing-flow.ts`),
> mounted via the adapters' `skipAuthorize` option; `beginSession()` generates +
> prints the code lazily (one active code per process, reused while live), and
> `verify({ code, nonce, ip? })` does the timing-safe check + emits
> `oauth.pairing.attempt`. The code is NEVER audited — it is 12 chars, below the
> 32-char redactor in `src/audit/util.ts`, so the event's `reason` is always an
> enum literal (asserted in `test/identity-console-pairing.test.ts`).

`createConsolePairingIdentity({ subject = "console-operator",
codeTtlSeconds = 600, maxAttempts = 5, output = stderr })` — an
`IdentityPort` for single-operator deployments: a one-time code is printed to
the server console and pasted at the consent step. **Replaces the example's
`DEV_STUB_SUBJECT` outright** (the stub is deleted when this ships — a real
gate replaces no-gate).

- **Code:** 12 chars from the base-20 set `BCDFGHJKLMNPQRSTVWXZ`, displayed
  `XXXX-XXXX-XXXX` (~51.9 bits — deliberately above RFC 8628's 34.5-bit
  example because this code is the ENTIRE identity gate, not a secondary
  confirmation). CSPRNG rejection sampling; input canonicalization as 17.3;
  timing-safe comparison.
- **Lifecycle:** generated lazily when a pairing-needed authorize arrives
  (never at boot — no stale scrollback codes), printed to stderr with
  timestamp and expiry; ONE active code per process; single-use (consumed on
  success); invalidated by expiry (600 s) or by `maxAttempts` (5) wrong
  submissions, after which the next request prints a fresh code. **Never
  persisted** — process-memory only; restart = clean slate (fail-closed).
- **Session binding:** the code is single-use and bound to the pairing *session*
  (a random nonce in the form) and to the operator who pastes it — not to the
  specific OAuth request parameters (`client_id`, `redirect_uri`, `scope`, …),
  which round-trip through the form. Those parameters are re-displayed on the
  consent page before the grant is minted, so the operator sees and approves the
  resource + scopes at consent time. An attacker who triggers a code onto the
  operator's console gains nothing without the printed code; only the operator
  pasting it completes the flow.
- **Authorize-parameter ambiguity:** `handlePairingAuthorize` applies the same
  pure RFC 6749 §3.1 occurrence guard and canonical singleton-key definition
  as `Bridge.handleAuthorize` and §17.11 upstream authorize. If any of
  `response_type`, `client_id`, `redirect_uri`, `code_challenge`,
  `code_challenge_method`, `scope`, or `state` has more than one nonempty
  occurrence in the normalized authorize query, it returns direct 400 `invalid_request` with
  no `Location`. This check runs before selecting any OAuth value and before
  `beginSession`, pairing-code output, `verify`, hidden-field rendering,
  `bridge.handleAuthorize`, consent preparation/rendering, store mutation, or
  success audit. The generated pairing form round-trips one snapshotted value
  per key; duplicate form-body handling remains an adapter-body contract, not a
  guarantee of this query-occurrence guard. Single-valued GET and POST pairing
  flows are unchanged.
- **Rate limiting:** the attempt cap is built-in and in-process — it cannot be
  misconfigured away; the `RateLimitPort` hook (`pairing:<ip>`) adds
  defense-in-depth.
- **Trust boundary (threat model):** whoever can read the process's stderr IS
  the operator. Log pipelines (docker logs, CloudWatch, Loki) EXTEND that
  boundary — codes land in them; TTL + single-use + attempt cap bound but do
  not eliminate the exposure. **Deployment envelope: single-operator/personal
  deployments with operator-private console output + LOOPBACK binding.** A host
  example binds the pairing authorize surface to `127.0.0.1` by default
  (`defaultListenHost`); a non-loopback bind (or tunneling the loopback
  listener publicly) exposes the surface + the attempt budget to the network and
  is an explicit envelope breach — public/networked deployments must use a real
  IdP port (Cloudflare Access, etc.), not pairing. The printed banner and docs
  say exactly this.
- Audit: `oauth.pairing.attempt` (success/failure — brute-force evidence).

## 17.6 `GenericOidcIdentity` + Google preset + dedicated GitHub port

> **SHIPPED S4a (generic + Google):** `createGenericOidcIdentity` +
> `createGenericOidcRedirectIdentity`, and the Google preset
> (`createGoogleIdentity` + `createGoogleRedirectIdentity`), ship as
> `RedirectIdentityPort`s consumed by the §17.11 orchestrator. They are
> unit/flow-verified only (synthetic RS256/ES256 id_tokens through the real
> `validateGenericOidcIdToken`/`validateGoogleIdToken` → bridge path). Google
> was subsequently live-verified, including the hosted-domain deny path, and
> its CIMD happy path was repeated at exact runtime commit `af2a61f` on
> 2026-07-28. A second non-Google generic-OIDC issuer remains pending. The
> dedicated GitHub port stays 🔒 locked (its own port — no OIDC
> discovery, no id_token; identity via the REST API). Setup guides:
> [`docs/identity/generic-oidc.md`](../identity/generic-oidc.md),
> [`docs/identity/google.md`](../identity/google.md).

**`createGenericOidcIdentity(config)`** — the missing generic port:

- Config: `issuer` (https, the exact-match anchor), `clientId`,
  `clientSecret?`, `redirectUri`, `endpoints: "discover" |
  { authorizationEndpoint, tokenEndpoint, jwksUri }` (manual mode — zero
  boot-time fetching), `scopes?` (default `openid profile email`),
  `subjectAllowlist?` (matches `sub`), `allowEmailAllowlist?` (opt-in; only
  matches when `email_verified === true`).
- **Discovery** (`endpoints: "discover"`): fetched ONCE at boot from
  `${issuer}/.well-known/openid-configuration`; the document's `issuer` MUST
  exactly equal the configured issuer (OIDC Discovery §4.3; RFC 8414 §3.3:
  "MUST NOT be used" on mismatch — boot failure); all endpoints + `jwks_uri`
  MUST pass the raw `^https://` check (addendum 11). Discovery/JWKS fetches
  use plain https (NOT the 17.1 SSRF guard): the issuer is deployer-trusted
  config, and enterprise IdPs legitimately live on private networks —
  documented rationale. Redirects on the discovery fetch: not followed
  (fail closed).
- **id_token validation:** `iss` exact-match; `aud` must contain `clientId`
  and multiple-audience tokens are rejected outright (a single-element
  `[clientId]` array is accepted; an array with any second audience is
  rejected before the contains-check — fail-closed simplification of OIDC
  Core §3.1.3.7; the check lives in the pure validator, NOT jose's
  `audience` option, which accepts multi-audience tokens); `exp` **and**
  `iat` presence required (OIDC Core §2 mandates `iat`; jose validates
  `exp`/`nbf` against the clock but does **not** validate `iat`'s value, so
  the pure validator asserts both claims' *presence* — a deliberate tightening
  over the Entra `exp`-only check; the Entra public API is unchanged. A
  far-future `iat` is **not** separately rejected: `exp` bounds the token's
  lifetime, and rejecting `iat`-ahead-of-now would break legit issuers with
  clock skew — accepting it gives an attacker who can already sign nothing
  beyond what `exp` already grants);
  algorithms pinned to `{RS256, ES256}` ∩ the provider's advertised
  `id_token_signing_alg_values_supported` — a **missing** advertised set
  defaults to `{RS256, ES256}` (don't over-reject providers that omit the
  metadata), but a **present** set with an empty intersection boot-FAILS
  (no usable alg); **nonce always sent, always verified** (once sent, OIDC
  Core makes the claim mandatory — missing/mismatch is a hard failure);
  `at_hash` validated when present **in the code flow** (the access_token is
  available). Subject = `sub`, canonicalized to `${issuer}|${sub}` as the bridge
  subject string — the bridge keys granted scopes by the subject string, so an
  opaque `sub` that collides across issuers (e.g. a stored-DCR store reused after
  changing issuers) must not inherit another issuer's grants. (Entra `oid` / CF
  `sub` are globally-unique GUID/UUID; a generic `sub` is not, hence the issuer
  namespace. The optional `subjectAllowlist` matches the raw `sub` claim.) Email is a display
  attribute, never the identity key.
  - **`at_hash` header-mode residual:** when a raw id_token is verified
    standalone with no `access_token` (header mode), `at_hash` — if present
    — is **skipped**, not rejected: there is no access_token to hash it
    against. This is the same residual class as the header-mode nonce
    (threat-model row 12): the fronting proxy owns the access_token binding.
    Never computed against `undefined`.
- **PKCE:** always S256. If discovery omits `code_challenge_methods_supported`
  (per RFC 8414 that means no PKCE support), boot FAILS unless the deployer
  sets `allowProviderWithoutPkce: true` (state + nonce + client secret still
  bind the flow; the flag is loud).
- **Token-endpoint client auth (confidential clients):** the secret is sent by the
  method resolved from discovery `token_endpoint_auth_methods_supported` —
  `client_secret_post` when supported (else `client_secret_basic`), boot-failing if
  neither is advertised for a confidential client. Omitting the field defaults to
  `client_secret_basic` (OIDC Discovery §3). A deployer may force either via
  `tokenEndpointAuthMethod`. Public clients (no secret) are unaffected (PKCE only).
- **Google preset** (`createGoogleIdentity`): the generic port pinned to
  `https://accounts.google.com` + discovery; `clientSecret` REQUIRED
  (Google's advertised token auth methods are secret-based only; its docs'
  newer "Optional" marking is unverified — we treat it as required);
  subject = `sub` per Google's own don't-key-on-email guidance; optional
  `hostedDomain` validated against the **`hd` claim** (Google: check the
  claim, never the email's domain); email surfaced only when
  `email_verified === true`. `iss` accepted ONLY as
  `https://accounts.google.com` (the schemeless legacy variant is rejected;
  if live verification ever hits it, any allowance will be an explicit,
  documented Google-only quirk).
- **GitHub = its own dedicated port** (`createGitHubIdentity`), NOT a preset:
  GitHub OAuth Apps have **no OIDC discovery document (404, verified) and no
  id_token** — identity comes from the REST API, so forcing it through the
  generic port would mean a degenerate bespoke branch inside it. Contract:
  hardcoded `https://github.com/login/oauth/{authorize,access_token}`;
  `Accept: application/json` on the token exchange (default response is
  form-encoded); `state` required; PKCE S256 sent (supported since
  2025-07-14; optional) AND `client_secret` always required; scope
  `user:email` only; identity: `GET https://api.github.com/user` → subject =
  the **numeric `id`** as a string (stable; `login` is mutable), email from
  `GET /user/emails` filtered to `primary && verified` (else no email
  attribute). Allowlist matches the numeric id by default; matching `login`
  requires the mutable-claims opt-in (mirrors Entra's `allowMutableClaims`).
  The upstream GitHub token is discarded after the identity calls (the bridge
  mints its own tokens), so OAuth Apps suffice; GitHub Apps work identically
  if the deployer prefers.
- **Entra refactor:** the public `identity/entra` API is UNCHANGED in v0.2;
  sharing internals with the generic port is permitted as an implementation
  detail, not required.
- **Verification + guides (decided, not deferred):** every new port/preset
  ships with (1) exported pure claim-validation functions unit-tested without
  network, (2) a manual live checklist at the top of the file (Entra
  pattern: register → sign in → claims validated → allowlist negative test →
  bridge mints its own token), (3) a README conformance row only after a real
  live pass. Setup guides are **human-facing docs written to be
  agent-executable** (exact console paths and field names —
  `docs/identity/{github,google,entra}.md`); a scripted/agentic setup flow is
  explicitly out of v0.2 scope (provider UIs churn; an agent can follow the
  docs).
- Export map additions: `./identity/generic-oidc`, `./identity/google`,
  `./identity/github`, `./identity/console-pairing`.

## 17.7 Audit reference sinks + event coverage

> **SHIPPED S1a** (`src/audit/jsonl-file.ts`, `src/audit/webhook.ts`,
> `src/audit/combine.ts`; exported from the root entry per §15). The 9 event
> names and `ip` field are in `src/ports/audit.ts`. The use-cases that *emit* the
> new names land with their features (S2 identity.verify, S3 client_credentials,
> S5 device, S6 cimd); the sinks + type are stable now so later sessions only
> call `writeAuthEvent`. Fail-open verified: each sink's `writeAuthEvent` never
> rejects, and `combineAudit` survives any subset of sinks rejecting.

- **Decision: no new port.** `AuditPort` IS the sink boundary; a second
  `AuditSinkPort` would be indirection with no gain. v0.2 ships reference
  implementations:
  - `JsonlFileAudit(filePath)` — one `JSON.stringify`d event per line
    (JSON encoding escapes newlines ⇒ log-injection-safe by construction),
    file created `0600`. On hosts exposing Node's `O_NOFOLLOW`, every append
    opens the final path with `O_APPEND | O_CREAT | O_NONBLOCK | O_NOFOLLOW`,
    checks `fstat().isFile()` on that descriptor, then writes the complete
    encoded line through it. Concurrent calls to one sink instance are
    serialized, so short OS writes cannot splice that instance's records. A
    retry failure after a positive prefix rolls back only a verified descriptor
    tail; if that rollback cannot be verified, the instance drops later events
    rather than append another record to the fragment.
    Thus a live or dangling symlink, FIFO, socket,
    device, and directory are rejected without writing through the configured
    path; the sink reports a redacted failure and remains fail-open. It does not
    rotate files itself, but opening per event preserves logrotate's
    rename-and-recreate pattern. If `O_NOFOLLOW` is unavailable (notably on
    Windows Node builds), the sink safely drops the event with a fixed diagnostic
    instead of falling back to a raceable path check. Hard-linked regular files
    are an explicit deployer/host hard-link-policy residual, not rejected by
    this reference sink; changing that needs a separate contract decision.
    Separate sink instances or processes writing one path are not coordinated:
    deployments needing cross-process JSONL framing must designate one writer
    or provide their own coordination.
  - `WebhookAudit(url, { timeoutMs = 5000, headers?, fetchImpl? })` — per-event
    POST, https required (raw prefix check), userinfo (`user:pass@`) rejected at
    construction (credentials belong in `headers`; a fetch error would otherwise
    echo the URL), redirects not followed, at-most-once (no retry). Deliberately
    NOT behind the 17.1 SSRF guard: the URL is static deployer config (trusted),
    and SIEM collectors legitimately live on private networks — documented
    rationale. `fetchImpl` is an optional DI seam (defaults to the global
    `fetch`) for test-injecting the transport without an https server; not a
    deployer-facing knob. Error messages reaching stderr are redacted
    (`src/audit/util.ts`) and the configured header values and URL query-string
    params scrubbed — a transport that echoes request headers, the URL, or a
    credential-bearing query (`?access_token=…`) into an Error.message cannot
    leak them.
  - `combineAudit(...sinks)` — fan-out; one sink's failure never stops the
    others.
- **Failure policy:** an audit-write failure NEVER blocks the auth operation
  (matches `RateLimitPort`'s advisory posture — audit is evidence, not a
  gate); failures surface on stderr. Residual (threat model): audit loss under
  sink outage — deployers with hard evidence requirements should use the file
  sink + a log shipper.
- **New `AuthAuditEventName` values:** `identity.verify`,
  `oauth.pairing.attempt`, `oauth.device.authorization`,
  `oauth.device.approve`, `oauth.token.device_code`,
  `oauth.token.client_credentials`, `oauth.client.provision`,
  `oauth.client.rotate_secret`, `oauth.cimd.fetch`. `AuthAuditEvent` gains
  optional `ip?: string` (adapter-populated; personal data — noted in docs).
  The §13 metadata-only rule is unchanged and the no-secrets serialization
  test extends to every new event.
- **Retention: documentation guidance, not a library mechanism.** The library
  emits; the deployer retains (compliance frameworks set their own periods).

## 17.8 Quickstart secret persistence (auto-keygen)

> **SHIPPED S1b** (`src/quickstart.ts`, root-exported). The standalone
> `examples/fastify-sqlite` boots zero-config via
> `loadOrCreateQuickstartSecrets`; the env-var path (`configFromEnv`) remains for
> production. POSIX permission check, `O_EXCL` create, `0700`/`0600`, and the
> `.gitignore` are all asserted in `test/quickstart.test.ts` (rows S1b.1–S1b.4);
> no ephemeral fallback under any failure mode.

`loadOrCreateQuickstartSecrets({ dir = "./.mcp-sso" })` →
`{ signingPrivateJwk, consentSigningSecret }`:

- If `${dir}/secrets.json` exists: load, validate shape (§5 boot checks), and
  on POSIX **reject group/other-readable files** (`mode & 0o077` ⇒ boot error
  with the exact `chmod 600` remediation; the check is skipped on Windows,
  documented). If absent: generate (EC P-256 keypair via jose; consent secret
  = base64url(48 bytes)), `mkdir` `0700`, write `0600` with `O_EXCL`, and
  write `${dir}/.gitignore` containing `*` so the directory can never be
  committed.
- **Fail-closed:** unwritable directory, partial write, bad permissions, or
  an unparseable file is a boot `AuthConfigError`. NEVER fall back to
  ephemeral in-memory keys — silent key rotation on restart would invalidate
  every outstanding token while masking the misconfiguration.
- Env-var configuration remains the primary production path; this is the
  zero-setup path (same audience as 17.5). Threat-model entry: plaintext key
  material on disk, boundary = the OS user account; production belongs in
  env/secret managers. (`npx mcp-sso init` is now implemented — §15 "Init CLI" —
  scaffolding a server that uses this helper; the function remains the contract.)
- **Filesystem-trust bar (the quickstart reference — every state-dir code path
  meets this):** writes are `0600` (files) / `0700` (dirs) with `O_EXCL` for
  create-don't-clobber; reads of trusted content go through `open(O_NOFOLLOW |
  O_NONBLOCK)` + `fstat` + read-fd (atomic: refuses a symlink, won't hang on a
  FIFO/special file, no lstat→readFile race) + a perm check (`mode & 0o077`
  fails closed, POSIX); a pre-existing dir is `assertRealDir`'d (reject symlink
  + group/other-accessible mode); the `.gitignore` is the managed `*\n` (write
  into a dir we created, require exact in a pre-existing one).
- **Parity rule:** EVERY code path that creates or reads the state dir —
  `loadOrCreateQuickstartSecrets`, the example's Cloudflare Access branch
  (`ensureStateDir`), and the sqlite store ([§12.4](12-store-conformance-contract.md#124-persistent-sqlite-filesystem-admission)) —
  meets the applicable bar. SQLite additionally requires an already-existing,
  private, effective-user-owned immediate directory; descriptor-first
  exclusive/no-follow/nonblocking admission; regular-file, `0600`, ownership,
  identity, and single-link checks before migration. A control fixed in one
  path MUST be applied to every sibling
  that touches the same resource (the "sweep for sibling instances" discipline
  — global CLAUDE.md). `JsonlFileAudit` is an operator-configured audit
  destination, not state-dir storage; its deliberately narrower final-target
  control and parent-directory residual are §17.7 and threat-model row 24.

## 17.9 Worked-example design notes (v0.2 examples)

- Express + Hono equivalents of `examples/fastify-sqlite` — execution only,
  no new contract surface. Examples use console pairing (17.5) or a real IdP;
  the `DEV_STUB_SUBJECT` pattern is removed.
- **API-key-gateway example** (mcp-sso as the SSO front door for a backend
  that only accepts a static API key): the backend key lives in an env var
  (`BACKEND_API_KEY`), read once at boot into a closure — never logged, never
  audited, never placed in token claims, and never injected into any response
  the gateway itself generates; it is injected server-side on the proxied backend
  call only after `RequestAuthorizer` accepts the bridge-minted token. Missing
  key = boot failure. Secret-manager integration is out of scope for the example
  but the read is isolated behind a single `getBackendCredential()` swap point.
  **Boundary (transparent proxy):** the gateway forwards backend response bodies
  verbatim, so it cannot prevent a *backend that itself echoes the injected
  credential* from exposing it — a backend MUST never reflect its received
  `Authorization`. The gateway's guarantee is that it does not introduce the key
  into any client-visible surface; the trusted backend must not either.

## 17.10 distributed `RateLimitPort` (Redis/Valkey) — shipped v0.1.2

> Implemented at `src/rate-limit/redis.ts` (subpath `./rate-limit/redis`); `ioredis`
> is an optional peer dep. Retained under §17 (contracts) as the locked spec for the
> shipped adapter, not a forward-looking v0.2 contract.

Scope confirmed earlier (roadmap): a Redis/Valkey-backed `RateLimitPort`
ONLY — not a Redis `StorePort`. Contract: fixed-window counter per key — one Lua
script does atomic `INCR` + `EXPIRE`-on-first-increment (the TTL is set exactly
once per window, on `n == 1`; never reset mid-window). Config
`{ windowSeconds: number, limit: number, keyPrefix?: string }` (`keyPrefix`
defaults to `mcp-sso:rl:` so a shared Redis is namespaced; it MUST NOT collide
with a non-string key, which would degrade to fail-open). Constructor validates
both `windowSeconds` and `limit` as positive integers (fail-closed on misconfig).
Keys are as in §6.7 (`register:<ip>` etc.). Failure semantics are UNCHANGED from
§6.7: `check()` THROWS on Redis error, so the bridge `guard()` fails OPEN
(availability over advisory defense). Client library enters as an optional peer
dep through the §15 ledger process (ordinary 15-day rule or verified published-
advisory exception). The hot path runs the script via
`EVALSHA` (Redis caches compiled scripts by SHA1 after the first call, so only the
hash crosses the wire); on `NOSCRIPT` (Redis restart or `SCRIPT FLUSH`) it falls
back to `EVAL`, which re-loads the script for next time. Atomicity and fail-open
are identical either way.

## 17.11 Upstream redirect-leg orchestrator (locked 2026-07-06)

The framework-free orchestrator for **redirect-based upstream IdPs** — the
`pairing-flow.ts`-style sibling that turns the shipped Entra *primitives*
(`getAuthorizationUrl`, `exchangeCodeForToken`, `verify` — §6.5) into a mounted
flow: GET `/oauth/authorize` → persist flow state → 302 to the IdP → callback →
validate → exchange → verify → `bridge.handleAuthorize` → consent page. Before
this orchestrator shipped, deployers had to hand-write that high-risk dance
(state CSRF binding, nonce/id_token replay, callback validation). Historical
live verification has now exercised Cloudflare Access, Entra, and Google
browser legs. The contract-only GitHub port remains future work.

**Port surface — `RedirectIdentityPort` (new, in `ports/identity.ts`):**

```ts
interface RedirectIdentityPort {
  /** The exact redirect URI registered at the IdP. Boot-asserted equal to
   *  issuerOrigin(config) + callbackPath — the callback is served by the same
   *  app at the issuer origin, and a mismatch is silent breakage at the IdP. */
  redirectUri: string;
  buildAuthorizationUrl(req: {
    state: string; nonce: string;
    codeChallenge: string; codeChallengeMethod: "S256";
  }): string;
  /** Exchange the code and verify the resulting identity. MUST bind the
   *  id_token to `nonce` when the provider issues id_tokens (OIDC); a provider
   *  with no id_token (the §17.6 GitHub port) verifies identity via its REST
   *  calls and reports through the same result type — that gap is documented
   *  per-port, never silent. */
  exchangeAndVerify(args: {
    code: string; codeVerifier: string; nonce: string;
  }): Promise<RedirectExchangeResult>;
}

type RedirectExchangeResult =
  | { ok: true; identity: IdentityClaims }
  /** Transport/protocol failure — non-200, timeout, malformed body, missing
   *  id_token (for a provider that issues them). No identity decision made. */
  | { ok: false; kind: "exchange_failed"; reason: string }
  /** Verified-context denial — bad iss/aud/tid/nonce, allowlist, group
   *  rejection. An identity decision WAS made: the user is refused. */
  | { ok: false; kind: "identity_rejected"; reason: string };
```

A **throw** from `exchangeAndVerify` is always classified `exchange_failed`
(unexpected infrastructure failure — one deterministic rule, so the two
failure channels below can never depend on which exception a port happened to
raise); `identity_rejected` exists only as an explicit returned value.

The **orchestrator** (not the port) generates `state`, `nonce`, and the PKCE
verifier/challenge — uniform CSPRNG entropy guarantees, 32 random bytes
base64url each. Entra ships `createEntraRedirectIdentity(config, opts?)`
(subpath `./identity/entra`) wrapping the existing primitives — the current
`EntraIdentity` API is unchanged. Its default token-endpoint transport is the
global `fetch` against the hardcoded `https://login.microsoftonline.com`
endpoint with a 10 s `AbortSignal.timeout` deadline (deployer-trusted endpoint,
deliberately NOT the §17.1 SSRF guard — same rationale as §17.6 discovery); the
transport stays injectable for tests. It requests upstream scope
`openid profile email` exactly — **no `offline_access`**: the bridge discards
the upstream token response, so requesting a long-lived upstream refresh token
it will never use violates least-grant.

**Factory — `createUpstreamRedirectFlow` (new, `src/adapters/upstream-flow.ts`,
root-exported like `handlePairingAuthorize`):**

```ts
createUpstreamRedirectFlow({
  bridge: Bridge;
  identity: RedirectIdentityPort;
  store: StorePort;           // REQUIRED — the SAME instance the Bridge uses
  clock: ClockPort;           // REQUIRED — the same instance the Bridge uses
  audit: AuditPort;           // REQUIRED — the Bridge's sink (pass noopAudit only deliberately)
  rateLimit?: RateLimitPort;  // default noopRateLimit — mirrors BridgeDeps exactly
  callbackPath?: string;      // default "/oauth/callback"
  flowTtlSeconds?: number;    // default 600
  // Below-guard test seams ONLY (§17.1.6 decisions 1e/5) — never a whole GuardedFetcher,
  // never a BridgeConfig field; cannot widen allowLoopback or the caps:
  cimdTransport?: CimdTransport;   // optional low-level connect-to-validated-IP transport
  cimdResolver?: DnsResolver;      // optional DNS resolver seam (the guarded-fetcher DnsResolver type)
}) → UpstreamRedirectFlow    // { handleAuthorize(req), handleCallback(req), callbackPath }
```

The flow's mandatory controls (the `upstream:<ip>` rate-limit guard, the
single-use jti via `consumeConsentJti`, `ClockPort` time for the flow JWT, and
the `oauth.upstream.callback` emission) need these ports **explicitly**: the
`Bridge` deliberately keeps its own deps private (only `config` is public, which
also supplies `consentSigningSecret`/`issuer` here), and this contract adds NO
new Bridge surface. The composition root already holds `BridgeDeps` — it passes
the same instances to both, and the factory's required/optional split
**mirrors `BridgeDeps` exactly** (`store`/`clock`/`audit` required,
`rateLimit` optional defaulting to no-op): `store` because flow jti rows must
live in the same store as the consent JTIs (`sweepExpired` coverage +
multi-replica replay scope), and `clock`/`audit` because making them
defaultable would let a forgotten argument silently split time and evidence
between a bridge and its flow — omitting audit must be a visible, deliberate
`noopAudit` at the call site, never an accident.

Boot validation (all `AuthConfigError`, fail-closed): `callbackPath` is a
**plain pathname** — starts with `/`; contains no `?`, `#`, `%`, `\`,
whitespace, or control characters (framework routes match by pathname, so a
query-bearing "path" would register a route the real callback request never
hits; percent-encoding and backslashes have no business in a configured route
and are rejected outright rather than decoded); has no empty (`//`) or dot
(`.`/`..`) segments; and `new URL(issuerOrigin + callbackPath).pathname` MUST
equal the configured string exactly. The character checks run on the RAW
string BEFORE any URL parsing (the §17.1 dot-segment lesson: WHATWG parsers
normalize `/%2e%2e/` away, so a post-parse check cannot see it), and the
normalized-equality check catches whatever survives — otherwise a path like
`/foo/%2e%2e/oauth/token` registers one route while browsers deliver the
callback to a reserved one. The reserved-route comparison runs on this
validated literal, which the checks above make identical to its normalized
form. `callbackPath` must be none of the reserved routes (`/oauth/authorize`, `/oauth/authorize/approve`,
`/oauth/token`, `/oauth/register`, `/oauth/revoke`, `/oauth/jwks`, anything
under `/.well-known/`, or the resource path); `identity.redirectUri` contains
no query or fragment and `=== issuerOrigin(config) + callbackPath` exactly;
`flowTtlSeconds` is a positive integer ≤ 3600. Both handlers are GET-only and
speak `NormRequest`/`NormResponse` (§9.6) — no new runtime deps (jose + core).

**Cross-redirect state: a signed flow cookie (DECIDED — not StorePort
records).** The flow context crosses the redirect as an HS256-signed JWT in a
cookie, single-used through the existing consent-JTI registry:

- *Why a cookie is required regardless:* binding the callback to the browser
  that initiated the flow (login-CSRF/session-fixation defense, and the
  same-browser guarantee below) needs a **browser-held secret**. Server-side
  records keyed by `state` cannot provide that — anyone who obtains a callback
  URL could complete the flow in a victim's browser. Given the cookie is
  mandatory, a parallel StorePort record (new methods + conformance rows +
  three store migrations) would duplicate state the cookie carries statelessly.
- *Single-use without new store surface:* the flow JWT's `jti` (prefix `upf_`,
  32 random bytes base64url — namespaced so it can never collide with consent
  JTIs) is consumed via the shipped `consumeConsentJti(jti, expiresAtIso)`
  (§12: true on first use, false on replay; swept by `sweepExpired`).
  Multi-replica deployments on a shared store (mysql) get cross-replica replay
  detection for free; the per-process memory store detects replay per instance
  only (same residual class as consent JTIs — threat model).
- A store failure during consumption propagates as a direct 500 per §9.5
  (consistent with `handleApprove`) — never fail-open.

**Flow JWT (the cookie value):** header `{alg:"HS256", typ:"JWT"}`; claims
`iss`=issuer, `aud`=**`"mcp-sso/upstream-flow" + callbackPath`** (see
"flow-instance binding" below), `jti` (`upf_…`, single-use),
*(suite-faithfulness rule, added 2026-07-26, scope clarified same day: a
FROZEN acceptance test must never import or hardcode an **implementation
constant** — a value the contract does not specify, which can therefore
change without a contract amendment. It MAY (and, where the contract pins an
exact value, MUST) assert what the CONTRACT specifies. Two consequences,
one per suite: `s6b-redirect.test.ts` predates the per-flow binding and pins
only behavior §17.11 owned then, so it observes the audience once through
the public seam — mint a cookie via `handleAuthorize`, decode, reuse — and
survives audience amendments unchanged. `flow-instance-binding.test.ts` is
the frozen suite FOR the per-flow amendment: §17.11 contracts
`aud === "mcp-sso/upstream-flow" + callbackPath` exactly, so that suite
derives the expected audience from the contracted formula and asserts it —
behavior-only assertions there would pass an implementation that keeps the
deployment-wide audience and adds a side claim, violating the locked
contract. Deriving from the contract's own text is pinning the contract;
importing `FLOW_AUDIENCE` from
`src/adapters/upstream-flow-internals.ts` — what the original
`s6b-redirect.test.ts` did, forcing a frozen edit for a contract-legitimate
change — is pinning the implementation, and the `check:seams` CI gate now
rejects it.)*
`iat`, `exp`=`iat`+`flowTtlSeconds`, `state` (upstream state, 32B base64url),
`nonce` (32B base64url), `code_verifier` (the **upstream** PKCE verifier, RFC
7636 43-char base64url), and `params` — the round-tripped client OAuth params,
exactly the `OAUTH_PARAM_KEYS` set (`response_type`, `client_id`,
`redirect_uri`, `code_challenge`, `code_challenge_method`, `resource`, `scope`,
`state`; string values only, absent keys omitted), plus (§17.1.6 decision 1c) an
optional **`cimd`** claim carrying exactly a `CimdRegistration`
(`{ client_id, client_name, redirect_uris }`) — present ONLY for a CIMD-path
authorize, absent for opaque clients, covered by the same HS256 signature and
strict-parsed at callback row 3 (1d). Verified with
`algorithms: ["HS256"]`, pinned `iss`+`aud`, clock from `ClockPort`.

**Flow-instance binding (amended — the `aud` is per-flow, not deployment-wide).**
The audience is `"mcp-sso/upstream-flow" + callbackPath` (e.g.
`mcp-sso/upstream-flow/oauth/callback`), so each flow accepts only cookies it
minted. `callbackPath` is the binding value because it is already required to be
unique per mounted flow and is boot-validated (`assertCallbackPath`) into a
canonical, non-forgeable literal; no new config knob is introduced. A cookie
whose `aud` does not match the callback's own value fails `jwtVerify` and is
reported as the existing **row 3** `flow_cookie_invalid` — no new failure row,
no new error code.

*Why:* the audience was previously the deployment-wide constant
`"mcp-sso/upstream-flow"`, carrying no callback path, provider id, or per-flow
identity, so **every flow built from one signing secret accepted every other
flow's cookies**. A deployment mounting two flows under one issuer (two IdPs)
could therefore have a cookie minted for the intended IdP redeemed through a
different configured one — an authentication-provider **confused deputy**.
Reproduced before the fix: flow B's callback returned 302 while calling IdP B's
`exchangeAndVerify` with flow **A's** PKCE verifier and nonce, and accepting A's
carried CIMD registration. The initiating request is unauthenticated (CIMD
resolution runs at authorize step 3a, before any IdP redirect), so a remote
caller can start flow A and reuse its state/challenge against IdP B. The shipped
adapters mount a single flow — hence MEDIUM, not HIGH — but the exported factory
does not prevent the multi-flow topology and nothing documented it as
unsupported. Binding is preferred over forbidding the topology: two IdPs under
one issuer is a shape a deployer may legitimately want.

*Compatibility:* this changes the flow-token claim shape. Flow cookies are
short-lived (`flowTtlSeconds`, default 600 s) and only ever in flight during a
login, so an in-flight cookie minted before an upgrade fails row 3 and the user
retries — no persistent state is invalidated.
**Signing key: `consentSigningSecret`** (decided): one deployment secret that
already crosses replicas; cross-type replay is impossible because both
verifiers pin distinct `aud` values (`mcp-sso/consent` vs
`mcp-sso/upstream-flow`), and a hypothetical flow-JWT forgery is strictly
weaker than the consent-token forgery the same secret already implies (a flow
token asserts no subject — identity still comes from the IdP exchange). The
§7 HS256/ES256 key separation is unchanged. The JWT is signed, **not
encrypted**: the browser's owner can read their own in-flight params and PKCE
verifier; the verifier's only power is redeeming the code bound to this same
browser's flow. Naming note: `state`/`nonce`/`code_verifier` here are the
**upstream (bridge→IdP) leg's** values; the *client's* `state` and
`code_challenge` ride untouched inside `params` (two independent PKCE pairs —
see below).

**Cookie profile (this library sets its FIRST cookie here — threat-model row 4
amended accordingly).** Decided at boot from the issuer origin scheme:

- https issuer: name **`__Host-mcp-sso-upstream`**, attributes
  `Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=<flowTtlSeconds>`. Per the
  `__Host-` prefix rules (RFC 6265bis): `Path` MUST be exactly `/`, `Secure`
  MUST be present, and the `Domain` attribute MUST NOT be set — on the
  clearing `Set-Cookie` too, or browsers treat it as a different cookie.
- http loopback issuer (legal only under §5 `dev.allowInsecureLocalhost`):
  name `mcp-sso-upstream`, same attributes minus `Secure` (the `__Host-`
  prefix requires `Secure`); still no `Domain`, still `Path=/`.

`SameSite=Lax` is load-bearing: the callback is a top-level cross-site GET
navigation from the IdP, which Lax permits while still blocking cross-site
subresource/POST delivery — this is also why the flow **locks the query
response mode** (`response_mode=query` for Entra; a form_post-style callback
would arrive cookieless under Lax and MUST NOT be used). `HttpOnly` keeps the
PKCE verifier out of script reach. The cookie is cleared (`Max-Age=0`, same
attributes) on every callback response that had a readable cookie — success or
failure. Every upstream response that sets or clears this credential-bearing
flow cookie also carries `Cache-Control: no-store`; the framework-free response
helpers add the directive before Fastify, Express, or Hono maps the response.
Callback response construction and cookie clearing are authoritative over
callback-owned audit writes: a custom `AuditPort` synchronous throw or
asynchronous rejection cannot suppress or replace the response or its headers.
One flow per browser: a second authorize overwrites the cookie
(last-writer-wins); the superseded flow's callback then fails the state match
(direct 400). If the serialized `Set-Cookie` value would exceed **4096 bytes**,
`handleAuthorize` fails direct `invalid_request` (oversized client params) — EXCEPT
when this authorize took the CIMD path (§17.1.6 decision 1b), where oversize maps to
the decision-2 generic `invalid_client` so document size is not a content oracle.

**`flow.handleAuthorize(req)` (GET `/oauth/authorize`):**

1. `RateLimitPort` guard, key **`upstream:<ip>`** (extends the §6.7 key set;
   same advisory posture — `false` ⇒ 429, thrown ⇒ fail-open). Rationale: each
   initiated flow authorizes at most one outbound token-endpoint call at the
   callback, so limiting initiation bounds exchange amplification.
2. Any singleton authorize parameter with **more than one nonempty occurrence** (array-valued
   in `NormRequest.query`) ⇒ **direct 400 `invalid_request`** before any
   cookie is set — RFC 6749 §3.1 forbids repeated request parameters, and
   silently picking first/last would make parameter-pollution behavior
   adapter-dependent.

The singleton-key set and its pure duplicate-finding helper are shared with direct
`Bridge.handleAuthorize` and `handlePairingAuthorize`; this upstream path keeps
the same step-2 response and ordering while eliminating per-entry-point key-list
drift.
RFC 8707 permits repeated `resource` indicators. Identical nonempty indicators
collapse to one target. Multiple distinct indicators remain unsupported in this
single-resource release and reach the existing post-validation `invalid_target`
channel; they are not classified as an RFC 6749 duplicate.
3. `client_id` present and `redirect_uri` **mode-appropriately validated**
   (§17.1.6 decision 1a): for a literal-lowercase-`https://` CIMD id with `cimd`
   enabled, the CIMD document match (shape-first, BEFORE any `store.find`);
   for an opaque non-scheme id, §10; any other scheme-shaped value ⇒ direct
   `invalid_client`. Else **direct 4xx** (§9.3 pre-validation; `invalid_request`
   / `invalid_redirect_uri` / `invalid_client`). No other param is validated
   here (DECIDED): `prepare` (§9.3) stays the single source of truth for
   `response_type`/scope/PKCE validation — a malformed request costs one IdP
   round-trip and then errors on the proper §9.3 channel, instead of this leg
   growing a drift-prone duplicate validator.
4. Generate `state`/`nonce`/verifier+challenge, sign the flow JWT, `Set-Cookie`,
   and 302 to `identity.buildAuthorizationUrl(...)`, with
   `Cache-Control: no-store` on that cookie-setting response. Nothing is
   persisted server-side at this step; an abandoned flow is just an expired
   cookie.

**`flow.handleCallback(req)` (GET `callbackPath`) — validation order and
failure table.** The redirect channel becomes available only because the
`redirect_uri` inside the *verified* flow JWT already passed **mode-appropriate
validation** (§10 for opaque ids, the CIMD document match for CIMD ids — §17.1.6
decision 1) at authorize time; any failure to establish that context is a
**direct 4xx, never a redirect**:

| # | Condition | Channel | Error / audit reason |
|---|---|---|---|
| 1 | `state`/`code`/`error`/`error_description` present more than once (RFC 6749 §3.1 — no first/last picking) | direct 400 `invalid_request` | `duplicate_params` |
| 2 | flow cookie absent | direct 400 `invalid_request` | `flow_cookie_missing` |
| 3 | flow JWT signature/`iss`/`aud` invalid | direct 400 `invalid_request` | `flow_cookie_invalid` |
| 4 | flow JWT expired | direct 400 `invalid_request` | `flow_expired` |
| 5 | `state` query param absent or ≠ JWT `state` (timing-safe compare; length mismatch fails) | direct 400 `invalid_request` | `state_mismatch` |
| 5a | **(§17.1.6 decision 1d, POLICY)** CIMD claim/mode/redirect inconsistency — for a lowercase-`https://` client_id: `cimd` disabled, or an **absent** `cimd` claim, or `params.redirect_uri` not matching the claim's `redirect_uris` (shared matcher); or a non-CIMD client_id carrying a `cimd` claim. (A present-but-**malformed** claim already failed cookie verification at row 3.) Checked AFTER state match, BEFORE jti consumption / exchange / any redirect-channel row | direct 400 `invalid_request` | `flow_cookie_invalid` |
| 6 | `jti` already consumed (callback replay) | direct 400 `invalid_request` | `flow_replayed` |
| 7 | IdP `error` param ∈ `access_denied`/`consent_required`/`interaction_required`/`login_required` | **302 redirect** `access_denied` | `upstream_denied` |
| 8 | IdP `error` param = anything else | **302 redirect** `server_error` | `upstream_error` |
| 9 | no `code` param (and no `error`) | direct 400 `invalid_request` | `missing_code` |
| 10 | `exchangeAndVerify` returns `kind: "exchange_failed"` **or throws** (non-200, timeout, malformed body, missing id_token from an id_token-issuing provider) | **302 redirect** `server_error` | `exchange_failed` |
| 11 | `exchangeAndVerify` returns `kind: "identity_rejected"` (id_token invalid, nonce mismatch, tid/allowlist/group rejection) | **302 redirect** `access_denied` | `identity_rejected` (detail in `identity.verify`) |
| 12 | `bridge.handleAuthorize` errors | its own §9.3 channels | unchanged |
| 13 | success | 200 consent page | — |

Rows 1 and 2 return without a clear only when no readable flow cookie exists;
row 1 also clears when a cookie was present. Every callback exit that clears a
readable cookie — duplicate-parameter, invalid-cookie/expiry/state/CIMD policy,
replay/store, upstream denial/error, missing-code, exchange/identity, bridge,
or unexpected callback failures, plus successful consent rendering — carries
`Cache-Control: no-store` alongside the unchanged clearing `Set-Cookie` header.
The initial-clock failure has no trustworthy timestamp and therefore emits no
audit event, but it still returns that clear plus `no-store` when a cookie was
readable. Missing-cookie behavior remains the intentional exception: row 2
attempts its callback audit but sends no clearing cookie.

The `jti` is consumed at step 6 — before the IdP `error` branch and before the
exchange — so a callback URL is single-use as a whole and a replay can never
trigger a second outbound exchange. Redirect-channel errors carry **fixed**
`error_description` strings ("upstream identity provider denied the request",
"upstream identity provider error", "upstream identity verification failed");
the IdP's own `error`/`error_description` values are **attacker-influenceable
query params and are never echoed** into the redirect, response body, or logs.
The final redirect's `state` is the *client's* state from the verified
`params`, never attacker input. An RFC 9207 `iss` param on the upstream
callback is not validated in this release (DECIDED): mix-up defense applies to
clients talking to multiple ASes; a flow instance has exactly ONE upstream IdP,
and state+nonce+PKCE bind the callback to it. Revisit at §17.6 (S4a) if a
generic deployment ever configures interchangeable upstreams.

**§9.3 extension (explicit deviation):** §9.3 routes identity failure as a
direct 401 because it normally occurs *pre*-validation. On this flow the
identity outcome arrives *after* the `redirect_uri` was **mode-appropriately
validated** (§10 for opaque ids, the CIMD document match for CIMD ids — §17.1.6
decision 1) and integrity-protected, so a verified-context identity rejection
(row 11) uses the **redirect channel with `access_denied`** — the clean RFC 6749
§4.1.2.1 answer an MCP client can render ("denied") — while every
flow-binding/integrity failure (rows 1–6 incl. 5a, 9) stays direct. Threat row
5's invariant holds: a redirect is only ever issued to a **validated** URI (§10
or the CIMD document match). §14's redirect-vs-direct note is amended to match.

**Upstream PKCE (bridge→IdP leg): REQUIRED.** The orchestrator always generates
a verifier/challenge pair and always passes the challenge to
`buildAuthorizationUrl` (S256 only). This is the **second, independent** PKCE
pair in the system: the *client's* pair (client ↔ bridge, verified by the
bridge at `/oauth/token` — §7.5) rides opaquely in `params`; the *upstream*
pair (bridge ↔ IdP, verifier in the flow cookie) binds the IdP's code to this
browser's flow — an injected/stolen code cannot be redeemed inside a foreign
flow because the exchange presents the wrong verifier. `nonce` provides the
same binding at the id_token layer. A provider that cannot accept PKCE may
ignore the challenge only under §17.6's loud opt-out
(`allowProviderWithoutPkce`); Entra supports it unconditionally.

**Same-browser binding (the confused-deputy closure — REQUIRED).** §7.1's
consent token is only as strong as the path that delivers it: the consent page
(carrying the single-use consent token) MUST be returned **only as the direct
HTTP response to the callback request that presented a valid flow cookie** —
never via a second redirect, an intermediate retrievable URL, or any other
channel. Chain: the flow cookie binds initiate→callback to one browser; the
consent token binds callback→approve within that browser (Origin check +
single-use JTI, §9.3); both hops are single-use. This closes the
session-binding residual: the browser that approves consent is
cryptographically the browser that just authenticated at the IdP.

**Upstream token handling (existing rule, restated as binding here):** the
id_token is verified and then discarded; any `access_token`/`refresh_token` in
the IdP's token response is **discarded immediately — never stored, logged,
audited, forwarded, or placed in the flow cookie**. The bridge mints its own
audience-bound tokens (§1). The verified identity — including any
`allowedScopes` ceiling a port derives (Entra groups, §17.4) — is handed to
`bridge.handleAuthorize(synthetic, { subject, allowedScopes?, registration? })`
with the synthetic request's `query` reconstructed from the verified `params`
(pairing-flow precedent), so the §17.4 ceiling plumbing applies unchanged. For a
CIMD id, `registration` = the verified flow JWT's `cimd` claim (§17.1.6 decisions
1c/1d), so `prepare` consumes it and does not re-fetch.

**Audit.** One new event name: **`oauth.upstream.callback`** (added to §13 and
`AuthAuditEventName` at implementation) — best-effort submitted on **every**
callback outcome for which the callback established a trustworthy timestamp,
with `status` success/failure and `reason` from the fixed enum in the failure
table; optional `clientId` (from `params`) and `ip`. `identity.verify` is
best-effort submitted whenever an identity **decision was reached** — `ok: true`
(success) and `kind: "identity_rejected"` (failure, with the port's reason) —
with the same event metadata as `Bridge.resolveIdentity`'s emission (S2a);
`exchange_failed` reaches no identity decision, so it emits only the
`oauth.upstream.callback` failure, never a spurious `identity.verify`. Whether
the implementation routes through `resolveIdentity` internally or emits
directly is an implementation choice; the observable events are identical. The authorize
(redirect-out) leg is deliberately not audited: it carries no identity, and the
flow is evidenced at the callback (an abandoned flow is an expired cookie the
server never sees — a documented, trivial blind spot of the cookie decision).
Both callback-owned event types use one fail-open boundary. A working sink
receives the complete event metadata described above; a custom sink that throws
synchronously or rejects asynchronously loses evidence but cannot replace or
reject the OAuth response, including its clearing
`Set-Cookie` and `Cache-Control: no-store` headers.
**Never logged or audited, anywhere:** `state`, `nonce`, `code`, id_tokens,
upstream tokens, the PKCE verifiers, or the flow cookie value — audit carries
enum reasons and metadata only (§13).

**Adapter wiring.** `FastifyAdapterOptions`/`ExpressAdapterOptions`/
`HonoAdapterOptions` gain `upstream?: UpstreamRedirectFlow`. When set: GET
`/oauth/authorize` → `upstream.handleAuthorize`, GET `upstream.callbackPath` →
`upstream.handleCallback`; all other routes unchanged. Exactly one authorize
mode per adapter instance — `upstream` is mutually exclusive with `identity`/
`identityHeader` (header-driven) and with `skipAuthorize` (pairing); any
combination throws at registration (fail-closed, mirrors the existing
`skipAuthorize` guard). The example's `buildExample` gains an Entra-redirect
branch (env-selected, e.g. `ENTRA_TENANT_ID`/`ENTRA_CLIENT_ID`/
`ENTRA_REDIRECT_URI`) alongside the CF and pairing branches;
`defaultListenHost` maps it to `0.0.0.0` (CF-class network deployment — the
real IdP is the gate, unlike pairing's loopback envelope).

**Deployment envelope / callback exposure (§17.5-style guidance):** this flow
is *designed* for network exposure — the upstream IdP (plus Gate 1, Entra app
assignment/Conditional Access) is the authentication gate. The callback URL
registered at the IdP MUST be the public https `issuerOrigin + callbackPath`
(Entra itself refuses plain-http redirect URIs off-loopback); http is legal
only on loopback under the §5 dev flag, where the cookie drops `Secure`/
`__Host-`. The docs state the failure path exactly: a redirect-URI mismatch
surfaces as the IdP's own error page (never a bridge redirect), and the §10
allowlist still governs the *client-facing* redirect leg independently.

**Alternatives considered (recorded, rejected):**

- **StorePort flow records** — rejected as the state carrier: browser binding
  needs a cookie regardless (above), and records would add store surface
  (methods, conformance rows, three adapters) to duplicate what the signed
  cookie carries statelessly. Single-use still uses the store (JTI registry) —
  the one property a cookie cannot self-enforce.
- **Fronting with oauth2-proxy feeding the header-driven authorize** — rejected
  as the recommended posture: default proxy-injected headers are NETWORK trust
  (the CF port verifies a *signed* assertion; oauth2-proxy's default headers
  are not signed), a forwarded upstream id_token breaks nonce binding (the
  bridge did not mint the nonce), and `/oauth/register`+`/oauth/token`+
  `/.well-known/*` would need skip-auth carve-outs where an over-broad regex
  is an auth bypass. Kept as comparison material, not a supported recipe.

**Out of scope (this contract):** the generic-OIDC port itself (§17.6, S4a —
it will *implement* `RedirectIdentityPort`), any change to the Entra
primitives' behavior, `client_credentials`/device flow (§17.2/§17.3), IdP
logout/re-auth prompting (`prompt`/`login_hint` passthrough), and multiple
simultaneous upstream IdPs on one bridge instance (exactly one
`RedirectIdentityPort` per flow/adapter).

**ID-JAG adjacency (recorded 2026-07-10; posture: TRACK).** The MCP
Enterprise-Managed Authorization extension (Stable 2026-06-18,
modelcontextprotocol/ext-auth) defines ID-JAG — the Identity Assertion JWT
Authorization Grant (draft-ietf-oauth-identity-assertion-authz-grant,
WG-adopted, pre-WGLC; informally "Cross-App Access"): the client obtains an
IdP-issued assertion via RFC 8693 token exchange and redeems it at the MCP AS
under RFC 7523 jwt-bearer; the AS validates it against the IdP's JWKS and
mints an audience-restricted token, advertising
`urn:ietf:params:oauth:grant-profile:id-jag` in
`authorization_grant_profiles_supported`. This is the spec-native sibling of
this section's flow for ENTERPRISE-MANAGED clients: it replaces the
interactive browser leg + consent page with IdP-admin policy, and requires
client-side token exchange plus IdP-side issuance — as of 2026-07-10 the only
end-to-end MCP deployment is Claude EMA beta / VS Code Preview on Okta Early
Access (protocol-level ID-JAG issuance elsewhere is pre-GA: Athenz beta,
Keycloak in progress); no IdP this library's deployments use (Entra,
Cloudflare Access — nor the other shipped ports, Google/generic OIDC) issues
ID-JAGs. It does NOT replace the AS itself (assertion validation,
audience-bound minting, refresh rotation, and audit land HERE if adopted),
the RS verifier, registration (§17.1/§9.2), client_credentials (§17.2),
pairing (§17.5), or the gateway pattern. No contract change now. Escalation
triggers, recorded here so this contract stays self-contained: an IdP this
library's deployments use begins issuing ID-JAGs, or a real client requests
`urn:ietf:params:oauth:grant-profile:id-jag`. Any future id-jag leg is a NEW
§17.x contract through the §18 protocol, never an amendment to this
section's flow.
