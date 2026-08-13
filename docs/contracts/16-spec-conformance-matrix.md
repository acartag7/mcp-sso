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
| RFC 9207 `iss` + `authorization_response_iss_parameter_supported` | ✅ metadata advertises support; successful code responses and every library-owned authorization error redirect include the exact configured issuer; direct errors remain unredirected | §9.1, §9.3 |
| Scope accumulation on step-up — stored-DCR opaque clients only | ✅ v0.1; CIMD clients stand alone by documented profile decision | §9.3, §11, §17.1.6 |
| Refresh rotation + family replay revocation | ✅ v0.1 | §7.4, §12 |
| RFC 6749 §6 refresh client-binding | ✅ v0.1 | §7.4 |
| RFC 6749 §4.1.2.1 error-redirect channels | ✅ v0.1 | §9.3, §14 |
| RFC 7009 revocation (always 200; unknown = no-op) | ✅ v0.1 | §9.4 |
| Hashed single-use codes/tokens; single-use consent JTI | ✅ v0.1 | §7, §12 |
| Fail-closed boot + no identity bypass | ✅ v0.1 | §5, §9.3 |
| Consent Deny + error redirects | ✅ v0.1 core + adapter UI | §9.3, §9.6 |
| Rate-limit hook port — no-op default | ✅ v0.1 | §6.7 |
| CIMD (`draft-ietf-oauth-client-id-metadata-document-00`) | ⚠️ complete 44-statement mapping below: 25 conformant (1 with a disclosed caveat), 2 reasoned deviations, 4 unresolved test-evidence rows, **1 confirmed runtime mismatch (D00-4.5.2 native-app precondition)**, 12 not applicable. Frozen acceptance suite `s6b-cimd-flow` is active | §6.6, §17.1, §16.1 |
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

| Class | Count | Rows | Meaning |
|---|---|---|---|
| `C` conformant | 24 | — | Enforced in source and pinned by a test that fails if the enforcement is removed. |
| `C` with a disclosed caveat | 1 | D00-6.5.1 | Conformant in production, with a narrower environment-scoped departure (the dev-only loopback fetch) stated in the row rather than absorbed into the total. |
| Reasoned deviation | 2 | D00-4.2.1 (`SHOULD`), D00-4.2.2 (`RECOMMENDED`) | The obligation applies and is deliberately not met; rationale recorded. |
| `U` unresolved evidence | 4 | D00-4.1, D00-4.1.5, D00-5.1, D00-6.5.2 | The enforcing source exists, but no test yet proves the complete hostile class or the shipped framework route. |
| **Runtime mismatch** | **1** | **D00-4.5.2** | Implementation contradicts the statement. Reproduced by direct probe, not inferred. |
| `N/A` not applicable | 12 | — | Excluded client-side duty, optional feature not implemented, or a conditional whose trigger provably never fires. |

Applicable to the implemented public-client authorization-server profile: 32.
**All three runtime mismatches identified by the audit were found by independent
review, not by the original pass** — media-type acceptance (D00-4.1.4),
shared-cache directive handling (D00-4.4.2), and the unevaluated native-app
precondition on the loopback port exception (D00-4.5.2). The first two are now
closed; the native-app mismatch remains reproduced by probe.
Deviations are counted separately so no single "conformant" integer absorbs
them. Every `N/A` row records the specific reason its obligation cannot apply,
so the classification can be re-checked rather than taken on trust.

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
| D00-4.1.4 | §4.1 an alternate JSON media type is permitted only in the `application/<AS-defined>+json` form. AS-applicable. | C | `src/cimd/guarded-fetcher.ts:149-155` | Ordinary `test/cimd-json-media-types.test.ts` proves direct and upstream rejection of `text/vendor+json` and `image/svg+json`, while preserving parameterized `application/json` and `application/scim+json`. Restoring the old unrestricted `endsWith("+json")` condition makes both hostile resolution tests fail. |
| D00-4.1.5 | §4.1 `token_endpoint_auth_method` **MUST NOT** use shared-symmetric-secret methods. AS-applicable; public-only profile rejects every value except absent/`none`. | U | `src/cimd/document.ts:31-34` | Frozen `document.test.ts:88-99` proves `client_secret_basic`, `private_key_jwt`, and secret fields, but lacks explicit `client_secret_post`, `client_secret_jwt`, and another symmetric-method witness. |
| D00-4.1.6 | §4.1 `client_secret` and `client_secret_expires_at` **MUST NOT** be used. AS-applicable. | C | `src/cimd/document.ts:33-35` | Frozen `document.test.ts:96-99` and route-level anti-oracle `s6b-anti-oracle.test.ts:119-126,164-167`; removing either presence check fails. |
| D00-4.1.7 | §4.1 other specs **MAY** impose stricter metadata restrictions. Profile-applicable: mcp-sso accepts public clients only. | C | `src/cimd/document.ts:31-38`; AS metadata `src/metadata.ts:31-38` | Frozen `document.test.ts:88-105` and `s6b-metadata.test.ts:35-45`; confidential declarations reject and `none` remains advertised. |
| D00-4.2.1 | §4.2 if the AS "does place additional restrictions on the accepted `redirect_uris`" it **SHOULD** provide at least one exempt CIMD Metadata Document Service. Same-origin is only the draft's example, so the antecedent is broad and **does** fire. | Applicable — reasoned `SHOULD` deviation | Restrictions that trigger it: `src/cimd/document.ts:29,48` per-entry hygiene via the §10.0 grammar (scheme, query, fragment, canonical spelling) | mcp-sso is a library, not hosted infrastructure; it ships no CIMD Metadata Document Service, and operating one would be a separate abuse/retention/trust product a deployment must own. For local development it instead admits an explicitly dev-gated loopback document (`src/cimd/admission.ts:68-75`; `s6b-boot.test.ts:104-140`). Recorded as a deliberate BCP 14 `SHOULD` deviation, not conformance. |
| D00-4.2.2 | §4.2 "the usage of Client ID Metadata Document Services **by the authorization server** is **RECOMMENDED**." Addressed to the AS, so it is applicable — not a client or deployment-only duty. | Applicable — reasoned `RECOMMENDED` deviation | No such service ships | Same library boundary as D00-4.2.1: mcp-sso is a library, and operating a CIMD Metadata Document Service would be a separate hosted product with its own abuse, retention, and trust surface. For local development it instead admits an explicitly dev-gated loopback document (`src/cimd/admission.ts:68-75`), proven on and off by `s6b-boot.test.ts:104-140`. Recorded as a deliberate deviation rather than scored as inapplicable. *(Draft `-02` later moved this material to a non-normative appendix, which confirms it was normative in the `-00` text under audit.)* |
| D00-4.2.3 | §4.2 a CIMD service **MAY** expire clients. Optional service not implemented. | N/A | — | No CIMD service exists in this project. |
| D00-4.2.4 | §4.2 a CIMD service **MAY** require developer information. Optional service not implemented. | N/A | — | No CIMD service exists in this project. |
| D00-4.3.1 | §4.3 failed fetch **SHOULD** abort authorization. AS-applicable; profile upgrades to fail-closed. | C | `src/cimd/resolve.ts:167-199`; generic map `src/cimd/anti-oracle.ts:25-48` | Frozen `s6b-anti-oracle.test.ts:109-181,208-264`; every failure aborts both boundaries with no redirect/IdP hop. |
| D00-4.4.1 | §4.4 AS **MAY** cache discovered metadata. AS-applicable option exercised. | C | `src/cimd/cache.ts:45-77`; `src/cimd/resolve.ts:209-240` | Frozen `s6b-cache.test.ts:89-115,186-211`; positive hit and LRU rows fail if caching is removed or keyed by normalized URL. |
| D00-4.4.2 | §4.4 caching **SHOULD** respect RFC 9111 headers. AS-applicable — and the CIMD cache is a **shared** cache: one `CimdSuccessCache` per `Bridge`, keyed on `client_id` alone, with no user dimension. | C | `src/cimd/cache.ts:48-91,97-184`; `src/cimd/guarded-fetcher.ts:110-124,142-152`; `src/cimd/transport.ts:12-18`; `src/cimd/resolve.ts:209-240` | `test/cimd-shared-cache.test.ts:14-101` mutation-pins directives, Age/Date/delay, millisecond precision, `Expires` non-use, malformed runtime Vary, rollback recovery, and stale re-fetch failure; frozen `s6b-cache.test.ts:89-94` pins the ordinary hit, `s6b-cache.test.ts:167-184` error/invalid re-fetch, and `s6b-cache.test.ts:186-198` raw `:443` key separation. |
| D00-4.4.3 | §4.4 AS **MAY** set upper/lower cache-lifetime bounds. Option exercised. | C | `src/cimd/options.ts:21-23,42-47`; `src/cimd/cache.ts:11,94-115,128-161` | Frozen `s6b-boot.test.ts:93-100` and `s6b-cache.test.ts:103-121`; cap and minimum-cacheable behavior are pinned. |
| D00-4.4.4 | §4.4 AS **MUST NOT** cache error responses. AS-applicable. | C | Only `fetchAndCache` success reaches `cache.set`: `src/cimd/resolve.ts:232-240` | Frozen `s6b-cache.test.ts:167-184`; a failed first resolution is fetched again, then a valid success caches. |
| D00-4.4.5 | §4.4 AS **MUST NOT** cache invalid/malformed documents. AS-applicable. | C | Validation precedes projection/cache: `src/cimd/guarded-fetcher.ts:104-108`; `src/cimd/resolve.ts:232-240` | Frozen `s6b-cache.test.ts:176-184`; mismatched documents are rejected and fetched on every attempt. |
| D00-4.5.1 | §4.5 AS **MUST** require redirect registration; the validated document supplies it. AS-applicable. | C | `src/cimd/document.ts:25-29`; `src/cimd/registration.ts:82-95`; `src/cimd/resolve.ts:178-183` | Frozen `s6b-redirect.test.ts:177-217` and `s6b-cache.test.ts:279-322`; an absent/nonmatching URI fails on misses and hits. |
| D00-4.5.2 | §4.5: "According to [RFC9700], the authorization server … **MUST** ensure that the redirect URI in a request is an exact match of a registered redirect URI." The rule is delegated to RFC 9700, whose sole exception is **native-app** loopback ports. | **Runtime mismatch** | `src/cimd/registration.ts:82-95` (matcher receives no client type); `src/cimd/document.ts:23-38` accepts `application_type` but `src/cimd/registration.ts:36-44` drops it | Probed on this commit: a document declaring **`application_type: "web"`** with registered `http://localhost:5000/cb` **matches** a presented `http://localhost:7000/cb`. RFC 9700 §2.1 permits varying "port numbers in localhost redirection URIs **of native apps**" and §4.1.3 repeats "**native apps** using a localhost URI"; the host wording does cover `localhost` (RFC 8252 §8.3: it "function[s] similarly to" the §7.3 form), **but the native-app precondition is never evaluated**. `-00` §4.1 imports the IANA OAuth client-metadata registry, which registers `application_type`, so the signal is available in a CIMD document — the validator simply accepts and discards it. Applying a native-only exception to a self-declared web client, and defaulting to it when no type is present, is a fail-open trust-boundary decision. Frozen `s6b-redirect.test.ts:177-217,299-308,363-385` covers only host/port/path shapes, never a declared type, so it stays green. Fix in follow-up PR 2. *(Unrelated and sound: the loopback branch omits `search`, but `src/redirect-entry.ts:46` rejects any raw `?` on both sides; and `src/token.ts:207-218` binds only the stored authorization-code record, so it is not document enforcement.)* |
| D00-5.1 | §5 an AS publishing RFC 8414 metadata **MUST** include the CIMD support property. AS-applicable. | U | `src/metadata.ts:17-39`; Bridge route `src/adapters/bridge.ts:95-97`; all adapters mount that handler | Frozen `s6b-metadata.test.ts:35-45` proves the builder pair, and `test/bin-init.test.ts:229-235` asserts `true` over a real HTTP route on a spawned **Fastify** server. Express and Hono assert only the metadata route's issuer (`test/lib/adapter-flow.ts:73-75`), so the served flag is unproven on two of the three shipped adapters. |
| D00-5.2 | §5 `client_id_metadata_document_supported` is an **OPTIONAL** registered field generally; supporting deployments publish `true`. AS-applicable. | C | `src/metadata.ts:36-39` | Frozen `s6b-metadata.test.ts:35-45`; enabled=`true`, disabled=absent, and `none` remains advertised. |
| D00-6.1.1 | §6.1 AS **MAY** impose restrictions or relationships **between** `redirect_uris` and `client_id`/`client_uri` (e.g. same-origin). Optional policy **not** exercised. | N/A | No such comparison exists anywhere in `src/cimd/` | Verified by absence and by positive test: `document.test.ts:145-149` accepts `https://app.example.com/cb` for client id host `cdn.example.com`. The §10.0 per-entry hygiene mcp-sso does apply constrains each redirect URI on its own; it is **not** a relationship to the client identifier, and is scored under D00-4.2.1 instead. |
| D00-6.2.1 | §6.2 clients **MAY** establish asymmetric credentials. Client option excluded by documented public-only profile. | N/A | Rejected at `src/cimd/document.ts:31-38` | Frozen `document.test.ts:88-105`; the branch is rejected rather than partially implemented. |
| D00-6.2.2 | §6.2 client **MAY** publish `private_key_jwt` metadata. Client option excluded by profile. | N/A | Same as D00-6.2.1 | `document.test.ts:88-94` proves rejection. |
| D00-6.2.3 | §6.2 confidential-client communication **MUST** authenticate with the registered type. Conditional branch never admitted. | N/A | Public-only rejection before authorization | The negative `private_key_jwt` test proves the condition cannot become true. |
| D00-6.3.1 | §6.3 AS **MAY** react to `jwks_uri`/key changes. Optional confidential-client behavior excluded by profile. | N/A | `jwks_uri` ignored; `jwks` public-only checked but unused | No key-authenticated CIMD client or key-change lifecycle exists. |
| D00-6.4.1 | §6.4 AS **SHOULD** fetch metadata for user context. AS-applicable. | C | Resolution in `src/authorize-internals.ts:45-72`; display projection `src/authorize-internals.ts:112-118` | Frozen direct/upstream consent tests `s6b-consent.test.ts:71-123`; removing fetch/projection loses the consent anchors. |
| D00-6.4.2 | §6.4 non-fetching AS **SHOULD** take additional UI measures. Conditional branch inapplicable: URL clients fail closed when not fetched/carried. | N/A | `src/authorize-internals.ts:55-71` | Frozen dispatch `s6b-dispatch.test.ts:105-128,208-227`; no unidentified URL client reaches consent. |
| D00-6.4.3 | §6.4 AS **SHOULD** display the `client_id` hostname with fetched information. AS-applicable. | C | `src/authorize-internals.ts:112-118`; `src/adapters/consent-page.ts:18-31` | Frozen `s6b-consent.test.ts:94-123` plus ordinary prominence test `test/consent-page.test.ts:26-48`; omission or reordering fails. |
| D00-6.5.1 | §6.5 AS **SHOULD** avoid fetching URLs on private or loopback addresses. `-00` states no development exception. | C in production; disclosed `SHOULD` deviation on the dev path | Production: `src/cimd/blocklist.ts:19-40,132-145`, all-record guard `src/cimd/guarded-fetcher.ts:68-87`. Dev path: `src/cimd/guarded-fetcher.ts:78-83` | Production is stricter than the draft — every IANA special-use range blocks, proven by `blocklist.test.ts:19-123` and `guarded-fetcher.test.ts:109-131,257-277` (mixed answers and rebinding included). **Deviation:** under `dev.allowInsecureLocalhost` a loopback document is fetched when every resolved record is loopback (`s6b-boot.test.ts:104-140` proves it is off by default and on only under the flag). `-00` has no such carve-out; draft `-02` §8.6 later sanctions exactly this dev-only shape, which informs the rationale but does not retroactively make it `-00` text. |
| D00-6.5.2 | §6.5 AS **SHOULD** account for non-HTTP schemes in document-contained URLs. AS-applicable; mcp-sso fetches no document-contained URL. | U | Named projection `src/cimd/registration.ts:36-44`; only client-id retrieval exists in `src/cimd/guarded-fetcher.ts` | Frozen projection tests show `logo_uri`/unknown fields do not enter signed state (`s6b-redirect.test.ts:162-175`), but no hostile test proves `logo_uri`, `jwks_uri`, `policy_uri`, and `tos_uri` trigger zero secondary network calls. |
| D00-6.6.1 | §6.6 AS **SHOULD** limit response size. AS-applicable. | C | Streaming cap `src/cimd/guarded-fetcher.ts:160-174`; cap config `src/cimd/options.ts:17-18,42-47` | Frozen `guarded-fetcher.test.ts:175-178,251-255,306-315`; single- and multi-chunk overflow fail without truncation. |
| D00-6.7.1 | §6.7 AS using `logo_uri` **SHOULD** prefetch/cache it. Optional UI feature not implemented; logo is neither fetched nor displayed. | N/A | `src/cimd/document.ts` ignores the member; named display projection excludes it | Frozen `document.test.ts:130-133` proves acceptance as unknown metadata; follow-up no-secondary-fetch test is tracked under D00-6.5.2. |
| D00-6.8.1 | §6.8 AS **MAY** apply domain-reputation heuristics. Optional feature not implemented. | N/A | — | Deterministic hostname display and IDNA rejection are implemented instead; no reputation claim is made. |

### Audit blockers and follow-up graph

**Two runtime changes remain**, plus three normative evidence PRs. Each is a
separate reviewable concern; none should carry the independent RFC 9207
error-response or scope-hierarchy work. The media-type change is complete.

1. **Completed runtime PR — media-type acceptance (closed D00-4.1.4, P1).**
   `isJsonMediaType` now accepts exactly `application/json`, or an essence that
   both starts with `application/` and ends with `+json`. Ordinary hostile tests
   reject `text/vendor+json` and `image/svg+json` through direct and upstream
   resolution, while positive tests preserve parameters and
   `application/scim+json`.
2. **Runtime PR — native-app precondition on the loopback port exception
   (closes the D00-4.5.2 mismatch, P1).** RFC 9700 permits varying loopback
   ports only for **native apps**; `cimdRedirectMatches` never sees a client
   type, so a document declaring `application_type: "web"` still gets the
   exception (probed). `-00` §4.1 imports the IANA client-metadata registry,
   which registers `application_type`, so the signal exists — `document.ts`
   accepts it and `registration.ts:36-44` drops it. Carry the declared type into
   the projection and require exact matching unless it is `native`; decide
   explicitly (and fail closed) when the type is absent. Regressions across
   direct, upstream, callback, and prepare for `"web"`, `"native"`, and absent.
4. **Test PR — symmetric client-auth declarations (closes D00-4.1.5, P2).** Of
   the three methods §4.1 names, only `client_secret_basic` has a hostile witness
   (`document.test.ts:91`); `client_secret_post` and `client_secret_jwt` have
   none. The allowlist at `src/cimd/document.ts:31-32` admits only absent or
   `"none"`, so this is coverage rather than a hole — add the two missing
   witnesses plus one non-enumerated symmetric method, direct and upstream.
5. **Test PR — shipped adapter parity (closes D00-4.1 and D00-5.1, P2).** No
   adapter test drives a `https://` CIMD `client_id` through a shipped route:
   `test/lib/adapter-flow.ts:77-95` registers through DCR and authorizes with the
   returned opaque id. Scope is a **six-cell matrix** — direct and upstream CIMD
   authorization for each of Fastify, Express, and Hono — because each adapter
   mounts two mutually exclusive authorize branches and the upstream branch also
   registers a callback route; the upstream cells must complete callback →
   consent. Separately, extend the served support-flag assertion to Express and
   Hono (Fastify is covered by `test/bin-init.test.ts:229-235`).
6. **Test PR — document-contained URLs are inert (closes D00-6.5.2, P2).**
   Publish hostile `logo_uri`, `jwks_uri`, `policy_uri`, and `tos_uri` values and
   assert exactly one outbound request: the Client Identifier URL itself.

**Adjacent, not `-00` obligations.** Tracked so they are not lost, and
deliberately *not* counted as draft or MCP conformance blockers:

- **Lifecycle no-re-fetch call count (product §17.1.4, P3).** `-00` sets no
  post-authorization re-fetch rule. Re-fetching is already structurally
  impossible — `src/adapters/bridge.ts:92` builds `OAuthTokenUseCase` with no
  `CimdResolver` — and callback carry-forward is frozen
  (`s6b-redirect.test.ts:143-160`). Missing only a transport call-count
  assertion across code exchange, refresh, and revoke.
- **Draft `-02` AKP private-key member (P2).** See §16.2.
- **Stable-MCP localhost warning (P2).** See §16.3.

### Independent review of this matrix

Two independent adversarial reviews ran over the complete `-00` text, the raw
diff, and every cited source and test line. Their corrections are applied above:

- **D00-4.1.4 was reclassified to a runtime mismatch, then closed.** The original
  pass scored it `C`; a review probe showed `text/vendor+json` was accepted. The
  narrowed `application/` check and direct/upstream hostile regressions now make
  the row conformant. This was the finding that falsified the original "zero
  mismatches" headline.
- **D00-4.2.1 and D00-6.1.1 were inversely classified, and are now swapped.**
  §4.2's antecedent is any "additional restrictions on the accepted
  `redirect_uris`" — same-origin is only its example — so mcp-sso's §10.0 entry
  hygiene *does* fire it: recorded as a reasoned `SHOULD` deviation. §6.1 is
  specifically a *relationship* between `redirect_uris` and
  `client_id`/`client_uri`, which mcp-sso never compares: `N/A`.
- **D00-6.5.1 split by environment**, so the dev-loopback fetch is disclosed as
  a `-00` deviation instead of hidden behind production-only evidence.
- **D00-4.5.2 was wrongly defended twice before being classified correctly.**
  The first pass scored it `C`. A review round called it a mismatch on the
  grounds that RFC 8252 §7.3 names loopback **IP literals** while the matcher
  also accepts `localhost`; that specific premise is wrong — RFC 9700 §2.1 and
  §4.1.3, the rule `-00` §4.5 delegates to, both word the exception in terms of
  `localhost`, and RFC 8252 §8.3 says `localhost` "function[s] similarly to" the
  §7.3 form. On the strength of that I kept the row conformant and argued the
  native-app precondition was unenforceable because CIMD defines no
  `application_type`. **That was the error.** `-00` §4.1 imports the IANA OAuth
  client-metadata registry, which registers `application_type`; the validator
  accepts the property and the projection discards it. A probe then showed a
  document declaring `application_type: "web"` still receiving the native-only
  port exception — a fail-open trust-boundary decision. The row is now a runtime
  mismatch, and the fix is follow-up PR 2. Recorded at length because the wrong
  answer survived two rounds of reasoning that were each locally correct.
- **D00-4.4.2 was closed after implementing and mutation-testing shared-cache
  semantics.** The cache now refuses private/no-cache/no-store/Vary-star and
  malformed metadata, gives s-maxage precedence, accounts for Age/Date/delay in
  millisecond arithmetic, clears state on clock rollback, and never serves stale
  metadata after a failed re-fetch.
- **D00-4.2.2 reclassified from `N/A` to a reasoned deviation.** §4.2 addresses
  the recommendation to "the authorization server", so it applies; shipping no
  such service is a deliberate deviation, not an inapplicable obligation.
- **`src/token.ts` citation withdrawn** as document enforcement — it binds only
  the stored authorization-code record.
- **Counts split by class** so no single "conformant" integer absorbs a
  deviation, and the follow-up graph now names the actual `U` row IDs.

The reviews disagreed with each other on D00-4.2.1; the disagreement was
resolved against the verbatim `-00` §4.2 and §6.1 text rather than by preferring
either reviewer.

## 16.2 Latest-draft supplemental check (`-02`)

The complete official
[`draft-ietf-oauth-client-id-metadata-document-02`](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02),
published 2026-07-06, was also checked. It is **supplemental hardening evidence,
not a substitute for the MCP-referenced `-00` matrix above**. The current profile
already enforces most of its material additions: direct Client Identifier URL
string identity, 200-only responses, no HTTP redirects, periodic re-fetch on the
next authorization after cache expiry, production special-use-address
prohibition with a dev-only loopback exception, and response-size limiting. Its
`private_key_jwt` authentication branch remains not applicable because mcp-sso
rejects confidential CIMD clients.

**One `-02`-only gap (P2 follow-up, not a `-00` obligation — `-00` says nothing
about private key material).** `-02` §4.1 adds that private key material
`MUST NOT` appear in the document. `src/cimd/document.ts:11` enforces this with a
denylist of `d, p, q, dp, dq, qi, oth, k`, which predates RFC 9964's `AKP` key
type whose private member is `priv`. Probed on this commit: a document carrying
`{"kty":"AKP","pub":…,"priv":…}` is **accepted**, and the frozen test at
`document.test.ts:101-105` mirrors the same stale denylist so it stays green.
The exposure is bounded — v0.2 never uses document keys for anything, so no
private material is dereferenced — but the fail-closed conformance check is
incomplete. Preferred fix given the public-client-only profile: reject `jwks`
and `jwks_uri` outright; otherwise replace the denylist with a `kty`-aware
allowlist of registered public members.

## 16.3 MCP 2026-07-28 CIMD overlay duties

The stable MCP Client Registration page adds authorization-server duties beyond
draft `-00`, and its Security Considerations direct servers to the CIMD
security text. These are tracked here rather than folded into the 44 draft rows,
so neither inventory absorbs the other.

| MCP overlay duty | Status | Evidence |
|---|---|---|
| **MUST** clearly display the redirect URI hostname | C | `src/authorize-internals.ts:114-115`; `src/adapters/consent-page.ts:26-28`; frozen `s6b-consent.test.ts:116-122` asserts both hosts render, and `test/consent-page.test.ts:26-48` pins host prominence over the self-reported name. |
| **SHOULD** display an additional warning for localhost-only redirects | Implemented, unproven | `src/adapters/consent-page.ts:21-23` renders the warning when `allRedirectsLoopback`; `src/cimd/registration.ts:100-110` computes it. The frozen suite **deliberately declines** to assert it (`s6b-consent.test.ts:124-126`) because no warning marker was contracted. Follow-up: contract a stable marker, then assert it positively on direct and carried/upstream consent. |
| **MUST** validate the fetched `client_id` matches the URL exactly | C | Same evidence as D00-4.1.2. |
| **MUST** validate redirect URIs against the document | **Partial — carries the D00-4.5.2 mismatch** | Registration and membership are enforced (D00-4.5.1). But the loopback port exception is applied without RFC 9700's native-app precondition, so a document declaring `application_type: "web"` still matches a different loopback port (D00-4.5.2, probed). Closed by follow-up runtime PR 2. |
| **MUST** validate document structure and required fields | C | Same evidence as D00-4.1.1 and the `client_name`/`redirect_uris` checks at `src/cimd/document.ts:26-29`. |
| **SHOULD** cache respecting HTTP cache headers | C | The shared-cache rules in D00-4.4.2 are enforced and regression-tested; the remaining partial redirect-URI row is D00-4.5.2. |

**MCP final-status boundary.** The stable MCP release/tag
[`2026-07-28`](https://github.com/modelcontextprotocol/modelcontextprotocol/releases/tag/2026-07-28)
resolves to commit `5f5440bb26a62e2cf3440b92da5a667efa03b267` and references
CIMD draft `-00`. Completing this mapping does not change the project target:
MCP Authorization 2025-11-25 remains current because scope hierarchy handling
is absent; CIMD also carries **one** confirmed `-00` runtime mismatch (D00-4.5.2 native-app
precondition) plus three open evidence PRs. Counted individually the project has
**two** open MCP-2026 runtime defects.
