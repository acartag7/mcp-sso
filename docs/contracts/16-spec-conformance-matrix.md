# 16. Spec-conformance matrix

| Requirement | Status | Where |
|---|---|---|
| RFC 9728 PRM (root) | ✅ v0.1 | §9.1 |
| RFC 9728 PRM (path-inserted) | ✅ v0.1 *(fix #2)* | §9.1 |
| `WWW-Authenticate: … resource_metadata=…, scope=…` (401) | ✅ v0.1 *(fix #1)* | §8.2 |
| `insufficient_scope` 403 step-up | ✅ exact-scope check; ⚠️ MCP 2026-07-28 additionally requires servers to account for scope hierarchies, which the current flat `requireScope` helper does not model | §8.3, §11 |
| RFC 8414 AS metadata | ✅ v0.1 | §9.1 |
| RFC 7591 DCR (stateless) | ✅ implemented as a deprecated compatibility path; MCP 2026-07-28 retains DCR as `MAY` | §9.2 |
| Stored-client DCR + `application_type` | ✅ server behavior aligns: raw values are validated, omission defaults to `"web"`, and stored per-type redirect policy is enforced. The final MCP `MUST` to send an appropriate value applies to clients | §9.2, §10.2 |
| Redirect-entry grammar §10.0 (all nine consumers) | ✅ implemented — the nine-leg differential test passes across every consumer | §10.0, §10.1, §10.2, §17.1.5 rule 20, §17.1.6 dec 1c |
| PKCE S256 (timing-safe) | ✅ v0.1 | §7.5 |
| RFC 8707 audience fail-closed | ✅ v0.1 | §7.2 |
| RFC 9207 `iss` + `authorization_response_iss_parameter_supported` | ⚠️ partial: metadata advertises support and successful code responses include `iss`; redirected authorization errors omit it, so MCP 2026-07-28 conformance remains blocked | §9.1, §9.3 |
| Scope accumulation on step-up — stored-DCR opaque clients only | ✅ v0.1; CIMD clients stand alone by documented profile decision | §9.3, §11, §17.1.6 |
| Refresh rotation + family replay revocation | ✅ v0.1 | §7.4, §12 |
| RFC 6749 §6 refresh client-binding | ✅ v0.1 | §7.4 |
| RFC 6749 §4.1.2.1 error-redirect channels | ✅ v0.1 | §9.3, §14 |
| RFC 7009 revocation (always 200; unknown = no-op) | ✅ v0.1 | §9.4 |
| Hashed single-use codes/tokens; single-use consent JTI | ✅ v0.1 | §7, §12 |
| Fail-closed boot + no identity bypass | ✅ v0.1 | §5, §9.3 |
| Consent Deny + error redirects | ✅ v0.1 core + adapter UI | §9.3, §9.6 |
| Rate-limit hook port — no-op default | ✅ v0.1 | §6.7 |
| CIMD (`draft-ietf-oauth-client-id-metadata-document-00`) | ⚠️ complete 44-statement mapping below: 27 conformant, 4 unresolved test-evidence rows, 0 runtime mismatches, 13 not applicable. Frozen acceptance suite `s6b-cimd-flow` is active | §6.6, §17.1, §16.1 |
| Framework adapters (`/fastify` `/express` `/hono`) | ✅ Phase 3 | §9.6, §15 |
| Identity ports (Cloudflare Access, Entra) | ✅ Phase 3 | §6.5 |
| `client_credentials` (MCP extension) | ✅ v0.2 shipped | §17.2 |
| Device authorization grant (RFC 8628) | 🔒 contract locked; not implemented | §17.3 |
| Entra group→scope ceiling | ✅ v0.2 shipped; live deny/ceiling rerun pending | §17.4 |
| Console-pairing identity | ✅ v0.2 shipped | §17.5 |
| `GenericOidcIdentity` + Google preset + GitHub port | ✅ generic + Google shipped; GitHub remains locked | §17.6 |
| Upstream redirect-leg orchestrator | ✅ v0.2 shipped | §17.11 |
| Audit reference sinks + expanded events | ✅ v0.2 shipped | §13, §17.7 |
| Quickstart secret persistence | ✅ v0.2 shipped | §17.8 |

## 16.1 CIMD draft `-00` requirement matrix

**Official input.** This audit used the complete IETF text of
[`draft-ietf-oauth-client-id-metadata-document-00`](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00),
published 2025-10-08, because that is the exact revision referenced by MCP
Authorization 2026-07-28. Compound sentences are split into atomic BCP 14
statements. `MAY`, `OPTIONAL`, and client/deployment recommendations are counted
so the inventory is complete, even when they impose no mcp-sso runtime duty.

**Counts.** 44 atomic normative statements reviewed, reported by class rather
than folded into a single "conformant" total:

| Class | Count | Meaning |
|---|---|---|
| `C` conformant | 27 | Enforced in source and pinned by a test that fails if the enforcement is removed. |
| `U` unresolved evidence | 4 | The enforcing source exists, but no test yet proves the complete hostile class or the shipped framework route. |
| Runtime mismatch | 0 | No statement was found that the implementation contradicts. |
| `N/A` not applicable | 13 | Excluded client-side duty, optional feature not implemented, or a conditional whose trigger provably never fires. |

Applicable to the implemented public-client authorization-server profile: 31
(27 `C` + 4 `U`). One `C` row carries a disclosed profile overlay: D00-4.5.2
adds RFC 8252 loopback any-port matching, which `-00` does not itself state.
Every `N/A` row records the specific reason its obligation cannot apply, so the
classification can be re-checked rather than taken on trust.

| ID | Draft statement and applicability | Status | Enforcing source | Test evidence and mutation strength |
|---|---|---|---|---|
| D00-3.1 | §3 `client_id` URL **MUST** use HTTPS. AS-applicable. | C | `src/cimd/admission.ts:27-52` | Frozen `test/acceptance/cimd/admission.test.ts:79-86`; removing the literal scheme gate makes the negative table fail. |
| D00-3.2 | §3 URL **MUST** contain a path. AS-applicable; profile requires a non-root path. | C | `src/cimd/admission.ts:39-52` | Frozen `admission.test.ts:119-122`; removing the path guard admits both witnesses. |
| D00-3.3 | §3 URL **MUST NOT** contain `.` or `..` segments. AS-applicable. | C | `src/cimd/admission.ts:39-43,79-89` | Frozen `admission.test.ts:110-117`; literal and encoded forms fail if raw pre-parse enforcement is removed. |
| D00-3.4 | §3 URL **MUST NOT** contain a fragment. AS-applicable. | C | `src/cimd/admission.ts:31-32,51` | Frozen `admission.test.ts:88-98`; trailing and non-empty fragments are both hostile witnesses. |
| D00-3.5 | §3 URL **MUST NOT** contain username/password. AS-applicable. | C | `src/cimd/admission.ts:39-43,51-52` | Frozen `admission.test.ts:88-92`; empty and non-empty userinfo fail. |
| D00-3.6 | §3 URL **SHOULD NOT** contain a query. AS-applicable; mcp-sso deliberately upgrades this to rejection. | C | `src/cimd/admission.ts:31-32,51` | Frozen `admission.test.ts:93-94`; removing the raw delimiter check admits the empty-query form after parsing. |
| D00-3.7 | §3 URL **MAY** contain a port. AS-applicable; allowed except a documented cross-protocol denylist. | C | `src/cimd/admission.ts:10-13,74-76` | Frozen `admission.test.ts:33-42,153-171`; non-default and explicit `:443` positives prevent a blanket-port rejection. |
| D00-3.8 | §3 short URL **RECOMMENDED**. Client-authoring guidance. | N/A | — | No AS rejection duty; mcp-sso applies its own 2048-byte hard cap for bounded input. |
| D00-3.9 | §3 stable URL **RECOMMENDED**. Client-authoring/operational guidance. | N/A | — | No runtime mechanism can prove client-domain longevity. |
| D00-4.1 | §4 AS **SHOULD** fetch the document named by `client_id`. AS-applicable. | U | `src/authorize-internals.ts:45-72`; `src/cimd/resolve.ts:167-240` | Frozen tests prove both resolution boundaries through the `Bridge`, which is the library's shipped AS surface (`s6b-dispatch.test.ts:94-145,197-251`); the adapters are thin pass-throughs to it, so no second decision path exists. Missing is only the framework HTTP-integration witness — no Fastify/Express/Hono test drives a URL `client_id` through real query wiring. |
| D00-4.1.1 | §4.1 document **MUST** contain `client_id`. AS-enforced. | C | `src/cimd/document.ts:13-28` | Frozen `document.test.ts:51-63`; absence and wrong JSON types fail. |
| D00-4.1.2 | §4.1 document `client_id` **MUST** equal the URL by RFC 3986 simple string comparison. AS-applicable. | C | `src/cimd/document.ts:23-27`; raw fetch key `src/cimd/guarded-fetcher.ts:26-31,105-107` | Frozen `document.test.ts:44-49` and `guarded-fetcher.test.ts:268-296`; normalization or comparison removal makes explicit-port/case witnesses pass. |
| D00-4.1.3 | §4.1 document **MAY** contain additional properties. AS-applicable extension tolerance. | C | Named reads `src/cimd/document.ts:23-38`; named projection `src/cimd/registration.ts:36-44` | Frozen `document.test.ts:130-133` and `s6b-redirect.test.ts:162-175,351-360`; unknown fields are accepted but cannot escape into signed state. |
| D00-4.1.4 | §4.1 JSON **MAY** use `application/*+json`. AS-applicable. | C | `src/cimd/guarded-fetcher.ts:100-103,149-154` | Frozen `guarded-fetcher.test.ts:147-163,299-303`; positive `+json` prevents `application/json`-only behavior. |
| D00-4.1.5 | §4.1 `token_endpoint_auth_method` **MUST NOT** use shared-symmetric-secret methods. AS-applicable; public-only profile rejects every value except absent/`none`. | U | `src/cimd/document.ts:31-34` | Frozen `document.test.ts:88-99` proves `client_secret_basic`, `private_key_jwt`, and secret fields, but lacks explicit `client_secret_post`, `client_secret_jwt`, and another symmetric-method witness. |
| D00-4.1.6 | §4.1 `client_secret` and `client_secret_expires_at` **MUST NOT** be used. AS-applicable. | C | `src/cimd/document.ts:33-35` | Frozen `document.test.ts:96-99` and route-level anti-oracle `s6b-anti-oracle.test.ts:119-126,164-167`; removing either presence check fails. |
| D00-4.1.7 | §4.1 other specs **MAY** impose stricter metadata restrictions. Profile-applicable: mcp-sso accepts public clients only. | C | `src/cimd/document.ts:31-38`; AS metadata `src/metadata.ts:31-38` | Frozen `document.test.ts:88-105` and `s6b-metadata.test.ts:35-45`; confidential declarations reject and `none` remains advertised. |
| D00-4.2.1 | §4.2 if the AS restricts the **relationship** between `redirect_uris` and `client_id`/`client_uri` (its same-origin example), it **SHOULD** provide an exempt CIMD service. Conditional trigger does not fire. | N/A | No relationship rule exists: `src/cimd/` contains no `client_uri` or same-origin comparison; `src/cimd/document.ts:29,48` applies only per-URI scheme/syntax hygiene | Verified by absence — a redirect entry on any host is accepted provided it is §10.0-valid (`document.test.ts:145-149` accepts `https://app.example.com/cb` against client id host `cdn.example.com`). Syntax hygiene is not the relationship restriction §4.2 conditions on, so the exempt-service `SHOULD` is never triggered. |
| D00-4.2.2 | §4.2 use of CIMD services is **RECOMMENDED** for development. Deployment-operator recommendation. | N/A | Not an AS runtime duty; mcp-sso is a library, not a hosted registration service | For local development the library instead admits an explicitly dev-gated loopback document (`src/cimd/admission.ts:68-75`), proven on and off by `s6b-boot.test.ts:104-140`. Operating a public CIMD service remains a deployment choice outside the library boundary. |
| D00-4.2.3 | §4.2 a CIMD service **MAY** expire clients. Optional service not implemented. | N/A | — | No CIMD service exists in this project. |
| D00-4.2.4 | §4.2 a CIMD service **MAY** require developer information. Optional service not implemented. | N/A | — | No CIMD service exists in this project. |
| D00-4.3.1 | §4.3 failed fetch **SHOULD** abort authorization. AS-applicable; profile upgrades to fail-closed. | C | `src/cimd/resolve.ts:167-199`; generic map `src/cimd/anti-oracle.ts:25-48` | Frozen `s6b-anti-oracle.test.ts:109-181,208-264`; every failure aborts both boundaries with no redirect/IdP hop. |
| D00-4.4.1 | §4.4 AS **MAY** cache discovered metadata. AS-applicable option exercised. | C | `src/cimd/cache.ts:45-75`; `src/cimd/resolve.ts:209-240` | Frozen `s6b-cache.test.ts:89-115,186-211`; positive hit and LRU rows fail if caching is removed or keyed by normalized URL. |
| D00-4.4.2 | §4.4 caching **SHOULD** respect RFC 9111 headers. AS-applicable. | C | `src/cimd/cache.ts:78-155`; duplicate-aware view `src/cimd/guarded-fetcher.ts:110-119` | Frozen `s6b-cache.test.ts:96-165`; max-age, Age, no-store/no-cache, malformed and elapsed-time cases are mutation-sensitive. |
| D00-4.4.3 | §4.4 AS **MAY** set upper/lower cache-lifetime bounds. Option exercised. | C | `src/cimd/options.ts:21-23,42-47`; `src/cimd/cache.ts:11,82-95` | Frozen `s6b-boot.test.ts:93-100` and `s6b-cache.test.ts:103-121`; cap and minimum-cacheable behavior are pinned. |
| D00-4.4.4 | §4.4 AS **MUST NOT** cache error responses. AS-applicable. | C | Only `fetchAndCache` success reaches `cache.set`: `src/cimd/resolve.ts:232-240` | Frozen `s6b-cache.test.ts:167-184`; a failed first resolution is fetched again, then a valid success caches. |
| D00-4.4.5 | §4.4 AS **MUST NOT** cache invalid/malformed documents. AS-applicable. | C | Validation precedes projection/cache: `src/cimd/guarded-fetcher.ts:104-108`; `src/cimd/resolve.ts:232-240` | Frozen `s6b-cache.test.ts:176-184`; mismatched documents are rejected and fetched on every attempt. |
| D00-4.5.1 | §4.5 AS **MUST** require redirect registration; the validated document supplies it. AS-applicable. | C | `src/cimd/document.ts:25-29`; `src/cimd/registration.ts:82-95`; `src/cimd/resolve.ts:178-183` | Frozen `s6b-redirect.test.ts:177-217` and `s6b-cache.test.ts:279-322`; an absent/nonmatching URI fails on misses and hits. |
| D00-4.5.2 | §4.5 request redirect **MUST** exactly match a registered URI. Exact match is conformant as written; the loopback any-port branch is an explicit RFC 8252 §7.3 native-app overlay that draft `-00` does not itself state (RFC 9700 §§2.1/4.1.3 permit exactly that one exception). | C, with the loopback overlay disclosed | Document match: `src/cimd/registration.ts:82-95`, called at authorize (`src/authorize-internals.ts:63,68`) and callback (`src/adapters/upstream-flow-cimd.ts:80`) | Frozen `s6b-redirect.test.ts:177-217,299-308,363-385`; HTTPS is raw-exact and loopback varies only by port. The loopback branch compares protocol, host, and path but not `search`: `src/redirect-entry.ts:46` rejects any raw `?` on both sides, so a differing query is unreachable rather than unchecked. **Scope limit:** `src/token.ts:207-218` binds the token request only to the stored authorization-code record; it does **not** re-match the document, and is not cited as document enforcement. |
| D00-5.1 | §5 an AS publishing RFC 8414 metadata **MUST** include the CIMD support property. AS-applicable. | U | `src/metadata.ts:17-39`; Bridge route `src/adapters/bridge.ts:95-97`; all adapters mount that handler | Frozen `s6b-metadata.test.ts:35-45` proves the builder pair, and `test/bin-init.test.ts:229-235` asserts `true` over a real HTTP route on a spawned **Fastify** server. Express and Hono assert only the metadata route's issuer (`test/lib/adapter-flow.ts:73-75`), so the served flag is unproven on two of the three shipped adapters. |
| D00-5.2 | §5 `client_id_metadata_document_supported` is an **OPTIONAL** registered field generally; supporting deployments publish `true`. AS-applicable. | C | `src/metadata.ts:36-39` | Frozen `s6b-metadata.test.ts:35-45`; enabled=`true`, disabled=absent, and `none` remains advertised. |
| D00-6.1.1 | §6.1 AS **MAY** impose redirect/client relationships. Optional policy exercised as syntax/scheme hygiene, not same-origin. | C | Shared redirect grammar §10; CIMD wrapper `src/cimd/document.ts:48-54` | Frozen `document.test.ts:135-193` plus nine-consumer `test/redirect-entry-grammar.test.ts`; no same-origin claim is made. |
| D00-6.2.1 | §6.2 clients **MAY** establish asymmetric credentials. Client option excluded by documented public-only profile. | N/A | Rejected at `src/cimd/document.ts:31-38` | Frozen `document.test.ts:88-105`; the branch is rejected rather than partially implemented. |
| D00-6.2.2 | §6.2 client **MAY** publish `private_key_jwt` metadata. Client option excluded by profile. | N/A | Same as D00-6.2.1 | `document.test.ts:88-94` proves rejection. |
| D00-6.2.3 | §6.2 confidential-client communication **MUST** authenticate with the registered type. Conditional branch never admitted. | N/A | Public-only rejection before authorization | The negative `private_key_jwt` test proves the condition cannot become true. |
| D00-6.3.1 | §6.3 AS **MAY** react to `jwks_uri`/key changes. Optional confidential-client behavior excluded by profile. | N/A | `jwks_uri` ignored; `jwks` public-only checked but unused | No key-authenticated CIMD client or key-change lifecycle exists. |
| D00-6.4.1 | §6.4 AS **SHOULD** fetch metadata for user context. AS-applicable. | C | Resolution in `src/authorize-internals.ts:45-72`; display projection `src/authorize-internals.ts:112-118` | Frozen direct/upstream consent tests `s6b-consent.test.ts:71-123`; removing fetch/projection loses the consent anchors. |
| D00-6.4.2 | §6.4 non-fetching AS **SHOULD** take additional UI measures. Conditional branch inapplicable: URL clients fail closed when not fetched/carried. | N/A | `src/authorize-internals.ts:55-71` | Frozen dispatch `s6b-dispatch.test.ts:105-128,208-227`; no unidentified URL client reaches consent. |
| D00-6.4.3 | §6.4 AS **SHOULD** display the `client_id` hostname with fetched information. AS-applicable. | C | `src/authorize-internals.ts:112-118`; `src/adapters/consent-page.ts:18-31` | Frozen `s6b-consent.test.ts:94-123` plus ordinary prominence test `test/consent-page.test.ts:26-48`; omission or reordering fails. |
| D00-6.5.1 | §6.5 AS **SHOULD** avoid private/loopback fetches. AS-applicable; production profile is stricter and blocks all special-use ranges. | C | `src/cimd/blocklist.ts:19-40,132-145`; all-record guard `src/cimd/guarded-fetcher.ts:68-87` | Frozen `blocklist.test.ts:19-123` and `guarded-fetcher.test.ts:109-131,257-277`; each range and mixed answer is hostile evidence. |
| D00-6.5.2 | §6.5 AS **SHOULD** account for non-HTTP schemes in document-contained URLs. AS-applicable; mcp-sso fetches no document-contained URL. | U | Named projection `src/cimd/registration.ts:36-44`; only client-id retrieval exists in `src/cimd/guarded-fetcher.ts` | Frozen projection tests show `logo_uri`/unknown fields do not enter signed state (`s6b-redirect.test.ts:162-175`), but no hostile test proves `logo_uri`, `jwks_uri`, `policy_uri`, and `tos_uri` trigger zero secondary network calls. |
| D00-6.6.1 | §6.6 AS **SHOULD** limit response size. AS-applicable. | C | Streaming cap `src/cimd/guarded-fetcher.ts:160-174`; cap config `src/cimd/options.ts:17-18,42-47` | Frozen `guarded-fetcher.test.ts:175-178,251-255,306-315`; single- and multi-chunk overflow fail without truncation. |
| D00-6.7.1 | §6.7 AS using `logo_uri` **SHOULD** prefetch/cache it. Optional UI feature not implemented; logo is neither fetched nor displayed. | N/A | `src/cimd/document.ts` ignores the member; named display projection excludes it | Frozen `document.test.ts:130-133` proves acceptance as unknown metadata; follow-up no-secondary-fetch test is tracked under D00-6.5.2. |
| D00-6.8.1 | §6.8 AS **MAY** apply domain-reputation heuristics. Optional feature not implemented. | N/A | — | Deterministic hostname display and IDNA rejection are implemented instead; no reputation claim is made. |

### Audit blockers and follow-up graph

No draft `-00` runtime change is currently required. The mapping is complete,
but the following evidence blockers remain before the CIMD profile can be called
fully proven:

1. **Test PR — symmetric client-auth declarations (security, P2).** Of the three
   methods draft `-00` §4.1 names, only `client_secret_basic` has a hostile
   witness (`document.test.ts:91`); `client_secret_post` and `client_secret_jwt`
   have none. The allowlist at `src/cimd/document.ts:31-32` admits only absent or
   `"none"`, so this is a coverage gap rather than a runtime hole — add the two
   missing witnesses plus one non-enumerated method, and prove both direct and
   upstream resolution fail generically.
2. **Test PR — shipped adapter parity (integration, P2).** No adapter test drives
   a `https://` CIMD `client_id` through a shipped route: `test/lib/adapter-flow.ts:77-95`
   registers through DCR and authorizes with the returned opaque id. Add a CIMD
   authorization across Fastify, Express, and Hono, and extend the served
   support-flag assertion to Express and Hono (Fastify is already covered by
   `test/bin-init.test.ts:229-235`). Keep the frozen suites unchanged.
3. **Test PR — lifecycle no-re-fetch call-count assertion (product §17.1.4, P3).**
   Not a draft `-00` obligation — `-00` sets no post-authorization re-fetch rule —
   so this is product-contract evidence, listed here only because it is adjacent.
   Re-fetching is already structurally impossible: `src/adapters/bridge.ts:92`
   constructs `OAuthTokenUseCase` with no `CimdResolver`, and callback carry-forward
   is frozen (`s6b-redirect.test.ts:143-160`, serve-once-then-throw). The CIMD
   suites do drive approve → `handleToken` (`s6b-scope.test.ts:72-78`) but assert
   no transport call count. Missing piece: a call-count assertion across code
   exchange, refresh, and revoke.
4. **Test PR — document-contained URLs are inert (SSRF, P2).** Publish hostile
   `logo_uri`, `jwks_uri`, `policy_uri`, and `tos_uri` values and assert exactly
   one outbound request: the Client Identifier URL itself.

Each concern is a separate reviewable PR. None should include the independent
RFC 9207 error-response or scope-hierarchy runtime changes.

### Independent review of this matrix

The mapping was reviewed by an independent adversarial pass over the complete
`-00` text, the raw diff, and every cited source and test line. Corrections it
produced are already applied above: D00-4.2.1 reclassified from a "documented
deviation" to `N/A` (its conditional antecedent never fires, since no
`redirect_uris` ↔ `client_id`/`client_uri` relationship rule exists); the
`src/token.ts` citation on D00-4.5.2 narrowed to authorization-code binding
because it never re-matches the document; the loopback any-port branch disclosed
as an RFC 8252 overlay rather than literal `-00` text; the lifecycle no-re-fetch
item demoted to product evidence after confirming `src/adapters/bridge.ts:92`
builds the token use-case without a resolver; and the counts split by class so
no single "conformant" integer absorbs a deviation.

## 16.2 Latest-draft supplemental check (`-02`)

The complete official
[`draft-ietf-oauth-client-id-metadata-document-02`](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02),
published 2026-07-06, was also checked. It is **supplemental hardening evidence,
not a substitute for the MCP-referenced `-00` matrix above**. The current profile
already enforces its material additions: direct Client Identifier URL string
identity, 200-only responses, no HTTP redirects, periodic re-fetch on the next
authorization after cache expiry, private/symmetric key-material rejection,
production special-use-address prohibition with a dev-only loopback exception,
and response-size limiting. Its `private_key_jwt` authentication branch remains
not applicable because mcp-sso rejects confidential CIMD clients. No `-02`-only
runtime mismatch was found; the four evidence blockers above still apply.

**MCP final-status boundary.** The stable MCP release/tag
[`2026-07-28`](https://github.com/modelcontextprotocol/modelcontextprotocol/releases/tag/2026-07-28)
resolves to commit `5f5440bb26a62e2cf3440b92da5a667efa03b267` and references
CIMD draft `-00`. Completing this mapping does not change the project target:
MCP Authorization 2025-11-25 remains current because redirected authorization
errors still omit RFC 9207 `iss`, scope hierarchy handling is absent, and the
four CIMD evidence PRs above remain open.
