# Archived verification history

This archive preserves dated verification receipts for earlier release candidates and source revisions. For current release and source-tree status, see [Verification status](../verification-status.md). For current client results, see [Client compatibility](../client-compatibility.md).

## 2026-07-28 Tier 2 receipt

T2.1 through T2.6 passed from clean commit `e71a2bbaf6902f98502a788a8d1e4bfc604b9bbc`: 866 tests passed with zero skipped. The tarball contained only `dist/`, `docs/`, `README.md`, `LICENSE`, and `package.json`. A temporary install without optional peers imported the eight peer-free public entry points, all 13 public entry points imported after their declared optional peers were installed, and the installed root package produced authorization-server and protected-resource metadata.

## 2026-07-28 v0.3.1 candidate

Exact merged implementation commit `d9b4f089dc46cf832ac598c5fce2401b095a2654` passed typecheck, line, acceptance-seam, and dependency-policy checks. 886 local tests and 910 hosted integration tests passed with zero skipped, followed by a clean build and `npm pack --dry-run`. The 200-file dry-run artifact had only `dist/`, `docs/`, `README.md`, `LICENSE`, and `package.json` at its root. That input still declares package version 0.3.0 because the version bump is a separate release commit. It is not evidence of a `v0.3.1` tag or npm publication. The final versioned head, hosted CI and review, publish dry-run, and installed-artifact smoke remain release gates.

## 2026-07-28 v0.3.2 candidate

Exact merged implementation commit `526ad2a2f1167ba7d905cb05cd3c44ce3a2c1d99` contains the stored DCR grant-generation cutover. Version candidate `6b87d804084d899aa29942ae1348f9983ac79619` passed typecheck, line, acceptance-seam, dependency-policy, process-guard, and CodeQL checks. 899 local tests and 926 hosted tests with real MySQL and Redis passed with zero skipped, followed by a clean build. Its 204-file dry-run artifact declared version 0.3.2 and contained only `dist/`, `docs/`, `README.md`, `LICENSE`, and `package.json`. The documentation-status correction after that candidate must pass the same exact-head gates and review before merge. This receipt is not evidence of a `v0.3.2` tag or npm publication. The final versioned head, publish workflow, and installed registry-artifact smoke remain release gates.

## 2026-08-04 v0.3.3 candidate

The release-only candidate based on exact merged implementation commit `5725e77d26651f4c0a303554a3f0fd3bdf897df8` declares package version 0.3.3. The clean source-tree suite passed 1,012 tests with nine platform or release-selector skips and zero failures. The integration-enabled suite passed 1,051 tests with nine release-selector skips and zero failures against disposable MySQL 8.4 and Redis 7.4 services. The executable release matrix then reported all ten required rows passing with no required row skipped. The 210-file tarball contained only `dist/`, `docs/`, `README.md`, `LICENSE`, and `package.json`, and its package manifest retained `jose` as the sole runtime dependency. RM.1 installed that tarball and completed the generated-server lifecycle through the installed executable, including the official-SDK `ping`/`pong`, refresh rotation, replay-family rejection, and revocation. A separate temporary consumer imported the root, Fastify, Express, and Hono entry points and used the installed executable to scaffold the five documented project files. This is prepublication evidence, not evidence of a `v0.3.3` tag, npm publication, or GitHub Release.

## 2026-08-14 v0.3.4 candidate

The release-only candidate based on exact merged implementation commit `b16de3bee8f35021aeb86f6c23ff5d8ea95a5408` declares package version 0.3.4. The clean source-tree suite passed 1,214 tests with nine platform or release-selector skips and zero failures. The integration-enabled suite passed 1,269 tests with nine release-selector skips and zero failures against disposable MySQL 8.4 and Redis 7 services. The executable release matrix then reported all ten required rows passing with no required row skipped. The 240-file dry-run tarball contained only `dist/`, `docs/`, `README.md`, `LICENSE`, and `package.json` at its root, and its package manifest retained `jose` as the sole runtime dependency. RM.1 installed the actual tarball and completed the generated-server lifecycle through the installed executable, including the official-SDK `ping`/`pong`, refresh rotation, replay-family rejection, and revocation. All 13 public entry points imported. This is prepublication evidence, not evidence of a `v0.3.4` tag, npm publication, or GitHub Release.

## 2026-08-15 v0.3.5 candidate

The release-only candidate based on exact merged implementation commit `bfdd7b562cafce91c000c5d17c160aa289d5bee6` declares package version 0.3.5. The clean source-tree suite passed 1,246 tests with nine platform or release-selector skips and zero failures. The integration-enabled suite passed 1,301 tests with nine release-selector skips and zero failures against disposable MySQL 8.4 and Redis 7 services. The executable release matrix then reported all ten required rows passing with no required row skipped. The 242-file dry-run tarball contained only `dist/`, `docs/`, `README.md`, `LICENSE`, and `package.json` at its root, and its package manifest retained `jose` as the sole runtime dependency. RM.1 installed the actual tarball, exercised the generated server through the installed executable, completed the official-SDK `ping`/`pong`, refresh, replay-rejection, and revocation lifecycle, and imported all 13 public entry points. This is prepublication evidence, not evidence of a `v0.3.5` tag, npm publication, GitHub Release, or published-artifact conformance claim.


## 2026-08-02 spec-release re-verification

This maintainer receipt is manual. CI does not enforce it. The review used:

- official stable release/tag [`2026-07-28`](https://github.com/modelcontextprotocol/modelcontextprotocol/releases/tag/2026-07-28), commit `5f5440bb26a62e2cf3440b92da5a667efa03b267`.
- dated [Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [Client Registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration), and [Key Changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog) pages.
- the tagged source files under `docs/specification/2026-07-28/basic/authorization/` in the official `modelcontextprotocol/modelcontextprotocol` repository.

### DCR deprecation finding

The final text retained DCR as an optional `MAY` mechanism. It marked DCR as deprecated, directed new implementations to CIMD, and retained DCR for authorization servers without CIMD. The v0.3.2 design matched that text.

### CIMD draft finding

The final text kept CIMD at `SHOULD` and cited `draft-ietf-oauth-client-id-metadata-document-00`. The implementation had been built against later draft hardening. The review traced the checked MCP requirements to `src/metadata.ts`, `src/cimd/document.ts`, `src/cimd/registration.ts`, and the frozen `test/acceptance/cimd/` suites.

The complete 44-statement draft `-00` mapping moved to the [section 16.1 matrix](../contracts/16-spec-conformance-matrix.md#161-cimd-draft--00-requirement-matrix). D00-4.1.4 restricted alternate `+json` media types to the `application/` tree. The shared CIMD cache observed the applicable shared-cache directives, corrected `Age` and `Date` age, and bounded resident time.

The review still found one runtime mismatch. The loopback port exception did not check RFC 9700's native-app precondition. Four rows also lacked complete test evidence.

### RFC 9207 and `application_type` finding

The final text kept authorization-server inclusion of `iss` at `SHOULD`, including error responses, with a future `MUST`. A server that included `iss` had to advertise `authorization_response_iss_parameter_supported: true`. MCP clients still had to send an appropriate DCR `application_type`.

v0.3.2 validated `"native"` and `"web"`, treated omission as OIDC `"web"`, and enforced the stored redirect policy for each type. It advertised RFC 9207 and added `iss` to successful code responses. `buildErrorRedirect` still omitted `iss` from redirected errors.

### Recorded outcome

The review updated `docs/contracts.md`, the normative references, the section 9 bridge contract, the section 16 matrix, the section 17 CIMD citation, this receipt, and the contributor status.

### 2026-08-02 verdict

Later corrections closed all three items in this dated verdict. On 2026-08-02, the final spec was checked, but MCP Authorization 2026-07-28 conformance remained pending on three known items:

1. **RFC 9207 error responses.** `src/challenge.ts` builds `error`/`state`/`error_description` redirects without `iss`. `src/authorize.ts`, `src/adapters/http.ts`, and `src/adapters/upstream-flow-internals.ts` use that builder. Successful responses add `iss` in `src/authorize-internals.ts`, while AS metadata advertises support in `src/metadata.ts`.
2. **Scope hierarchies.** The final Authorization text says servers `MUST` account for hierarchies where a broader scope implies narrower scopes. `src/scopes.ts` `requireScope` currently performs exact array membership and has no hierarchy policy or proof.
3. **CIMD draft `-00` conformance.** The final artifact normatively references CIMD draft `-00`. The complete §16.1 mapping has **one confirmed runtime mismatch**, reproduced by probe. D00-4.5.2 concerns `cimdRedirectMatches`. (`src/cimd/registration.ts:82-95`) applies RFC 9700's native-app-only loopback port exception without evaluating the client type, so a document declaring `application_type: "web"` still receives it.

   D00-4.1.4 is closed: alternate `+json` media types are restricted to the `application/` tree, with hostile direct and upstream resolution tests. Four rows also lack complete hostile or shipped-route evidence: symmetric client-auth declarations (D00-4.1.5), adapter route parity (D00-4.1, D00-5.1), and inert document-contained URLs (D00-6.5.2).

These are separate contract/runtime follow-ups. Counted individually they are **three runtime defects** (RFC 9207 error responses, scope hierarchies, and the CIMD native-app precondition) plus **four CIMD test-evidence rows**. The conformance target must not move from 2025-11-25 until every one of them is resolved and the resulting implementation passes the full release gates.

### 2026-08-14 RFC 9207 closure

Item 1 above was superseded on the source branch. The shared builder now requires bridge config, and core Deny, adapter-mapped errors, and upstream callback rows 7/8/10/11 include its exact issuer while direct errors remain unredirected. Symmetric client-auth declarations now have direct and upstream hostile evidence. The six-cell shipped-adapter matrix now proves direct and upstream resolution plus served metadata on all three frameworks. Hostile document-contained URLs are inert through direct and upstream callback-to-consent flows. After this correction, two runtime defects remained and no CIMD test-evidence rows were unresolved. The target stayed at 2025-11-25.

### 2026-08-14 scope closure

Item 2 above was also superseded on the source branch. `createBridgeConfig` boot-validates and deeply freezes a bounded, exact-resource implication graph. `requireScope` stays exact unless explicitly passed that policy. `RequestAuthorizer` passes the policy for transitive sufficiency checks without adding implied strings to the token. After this correction, one runtime defect and four CIMD test-evidence rows remained. The target stayed at 2025-11-25.

### Corrections after the 2026-08-02 receipt

#### 2026-08-14 source-tree correction

The dated verdict and incremental closure notes above remain as historical evidence. RFC 9207 error redirects carry the configured issuer. The bounded, exact-resource implication graph closes scope hierarchy handling. D00-4.5.2 validates and carries optional `application_type`, grants the loopback any-port exception only to exact `"native"`, and has an active frozen four-group suite. The source tree therefore targeted MCP Authorization 2026-07-28 with no unresolved runtime or CIMD evidence row. Published v0.3.4 retained its earlier baseline.

#### 2026-08-17 loopback interoperability correction

This correction superseded the 2026-08-14 explicit-`native` conclusion. Published v0.3.5 rejected Claude Code's real CIMD document. The document registered port-less loopback callbacks without `application_type`, while the runtime supplied an ephemeral port. The source then allowed the port to differ for a validated loopback `http` entry when `application_type` was `"native"` or absent. An explicit `"web"` value still required an exact match. Malformed values still failed. The frozen acceptance suite used the published Claude Code document. The npm package needed a patch release to regain Claude Code compatibility.


## 2026-08 independent review of the conformance matrix

Two independent adversarial reviews ran over the complete CIMD draft `-00` text, the raw diff of [the conformance matrix](../contracts/16-spec-conformance-matrix.md), and every cited source and test line. The matrix carries their corrections. This record keeps the reasoning, including the one place where the maintainer's own defense of a row was wrong, so that a later reader can see how the final classifications were reached.

- D00-4.1.4 was reclassified from conformant to a runtime mismatch, then closed. The first pass scored it conformant. A review probe showed that `text/vendor+json` was accepted. The media-type check was narrowed to `application/json`, or an essence that starts with `application/` and ends with `+json`, with hostile direct and upstream regressions. This was the finding that falsified the original "zero mismatches" headline.
- D00-4.2.1 and D00-6.1.1 were inversely classified and were swapped. Section 4.2's antecedent is any "additional restrictions on the accepted `redirect_uris`", and same-origin is only its example, so the redirect-entry hygiene in [contract 10.0](../contracts/10-redirect-uri-policy.md) does fire it. It is recorded as a reasoned `SHOULD` deviation. Section 6.1 is specifically a relationship between `redirect_uris` and `client_id` or `client_uri`, which `mcp-sso` never compares, so it is not applicable.
- D00-6.5.1 was split by environment, so the development-loopback fetch is disclosed as a `-00` deviation instead of being hidden behind production-only evidence.
- D00-4.5.2 was wrongly defended twice before it was classified correctly. The first pass scored it conformant. A review round called it a mismatch because RFC 8252 section 7.3 names loopback IP literals while the matcher also accepts `localhost`. That premise is wrong: RFC 9700 sections 2.1 and 4.1.3, which `-00` section 4.5 delegates to, both word the exception in terms of `localhost`, and RFC 8252 section 8.3 says that `localhost` functions similarly to the section 7.3 form. On the strength of that, the maintainer kept the row conformant and argued that the native-app precondition was unenforceable because CIMD defines no `application_type`. That was the error. Draft `-00` section 4.1 imports the IANA OAuth client-metadata registry, which registers `application_type`; the validator accepted the property and the projection discarded it. A probe then showed a document declaring `application_type: "web"` still receiving the native-only port exception, a fail-open trust-boundary decision. The row became a runtime mismatch and was fixed in a follow-up. The wrong answer survived two rounds of reasoning that were each locally correct, which is why it is recorded at length.
- 2026-08-17 operational evidence narrowed the explicit-type conclusion without erasing the probe above. Published `v0.3.5` applied a native-only gate and broke Claude Code, whose real document registers port-less `localhost` and `127.0.0.1` callbacks without `application_type` and binds an ephemeral port at runtime. D00-4.5.2 permits the native-app exception but does not make that optional metadata member its precondition. The corrected contract treats a validated loopback `http` registration as the native-app signal when `application_type` is absent, preserves scheme, host, path, and search exactly, and frees only the port. An explicit `"native"` receives the same exception. An explicit `"web"` is a restrictive signal and keeps exact matching, which closes the fail-open probe.
- D00-4.4.2 was closed after shared-cache semantics were implemented and mutation-tested. The cache refuses `private`, `no-cache`, `no-store`, `Vary: *`, and malformed metadata, gives `s-maxage` precedence, accounts for `Age`, `Date`, and delay in millisecond arithmetic, clears state on clock rollback, and never serves stale metadata after a failed re-fetch.
- D00-4.2.2 was reclassified from not applicable to a reasoned deviation. Section 4.2 addresses the recommendation to the authorization server, so it applies; shipping no metadata document service is a deliberate deviation, not an inapplicable obligation.
- The `src/token.ts` citation was withdrawn as document enforcement. It binds only the stored authorization-code record.
- Counts were split by class so that no single "conformant" integer absorbs a deviation.

The reviews disagreed with each other on D00-4.2.1. The disagreement was resolved against the verbatim `-00` section 4.2 and section 6.1 text rather than by preferring either reviewer.

## 2026-07-26 and 2026-07-28 live campaign

The v0.3 feature rows already implemented on `main` are backed by the current automated suite. Rows for unshipped GitHub identity and device flow remain future plans, not release claims. A 2026-07-26/27 patched, uncommitted checkout based on `ee8994a` produced CIMD and refresh-replay observations, but its exact dirty tree was not archived and those observations do not qualify as verified rows under the minimum evidence contract. On 2026-07-28, an autonomous clean-main rerun at `e71a2bb` completed three metadata/tokenless-challenge probes and DCR registrations, Cloudflare Access path gating, public-CIMD resolution to authorization redirects on the Entra- and Google-configured gateways, and the CIMD literal-IP, DNS-rebinding, DNS-failure, non-200, content-type, size, and timeout deny legs. At exact runtime commit `af2a61f`, Claude Code 2.1.220 then completed CIMD authorization and protected `status` calls with Cloudflare Access, Entra, and Google. A corrected refresh harness required and observed 200 responses for A to B to C rotation, HTTP 400 `invalid_grant` for replayed A, and HTTP 400 `invalid_grant` for current C after family revocation. Retained client results and all three audit logs contained zero backend-key matches.

## 2026-07-28 package and spec status

The packed-artifact pre-tag smoke passed at exact clean-main commit `e71a2bb`. The published `mcp-sso@0.3.0` artifact repeated the eight peer-free and all-13 with-peers import smokes, produced both metadata documents, and carried verified registry signatures and attestations. The implementation was reviewed against `2026-07-28-RC`, and the official stable artifact was manually checked on 2026-08-02. The published release keeps the three-gap result in that dated receipt. This source branch closes RFC 9207 error redirects, scope-hierarchy handling, and the CIMD native-app policy. The source tree therefore targets MCP Authorization 2026-07-28 with no unresolved runtime or governed CIMD evidence row. **v0.4.0 is the first published version to claim conformance to MCP Authorization 2026-07-28, with the two reasoned deviations recorded in the §16 matrix (D00-4.2.1 and D00-4.2.2, both the CIMD Metadata Document Service the library does not ship).** Earlier published versions do not carry the claim: v0.3.5 packaged the work without claiming it, and v0.3.4 retains its earlier baseline. The [current verification status](../verification-status.md) records the post-v0.3.5 result and does not upgrade the dated live evidence. Historical Codex CLI success remains recorded, and the compatibility gap this block previously described is closed. Installed Codex CLI 0.144.1 showed an RFC 9207 `iss` callback regression on 2026-07-28, and published v0.3.5's production Fastify/SQLite composition does not expose the stored DCR mode that current ephemeral loopback callbacks require.

## 2026-08-19 client retest

Both conditions were retested at runtime commit `d6143b3`. Codex CLI `0.148.0`, a stable release, completed all three identity legs, and the stored DCR example wiring was live-driven rather than merely implemented. That wiring ships in v0.4.0, so it is no longer unreleased.

Two limits apply to that result. Both this library and the client changed between the observations, so a clear run does not show which change removed the regression. The client build is recorded on the operator's authority because the clients ran on a different machine. The [client compatibility reference](../client-compatibility.md#current-matrix) contains the result.

## 2026-08-21 v0.4.0 release snapshot

`v0.4.0` fixed two compatibility failures in published `v0.3.5`. The CIMD redirect matcher began accepting a loopback port difference when `application_type` was `"native"` or absent. The Fastify and SQLite example also exposed `OAUTH_DCR_MODE=stored` for Codex CLI's ephemeral callback.

The release rejected three configurations that had booted before:

1. Stored DCR without a bounded `RateLimitPort`.
2. Hono with stored DCR and no `clientIp` extractor.
3. Stateless DCR with generic loopback redirect trust, no bounded `RateLimitPort`, and no application-specific HTTPS redirect. An acknowledged local composition remained available when both the issuer and the resource used loopback.

`POST /oauth/register` in stored DCR mode returned 503 when `RateLimitPort.check` threw. The rejection happened before body selection, a registration write, or a success audit. Stateless registration and the authorize, approve, token, and revoke keys continued after the same exception. A limiter denial still returned 429.

The release also added `upstream:<ip>` admission to `/oauth/callback`. At publication time, the examples supplied the limiter to the redirect flow only in stored mode. The default stateless examples therefore still used `noopRateLimit` for upstream authorize and callback requests.

Other release changes included these controls:

- The default Generic OIDC discovery and token transports counted response bytes against a limit. A custom `discoveryFetch` or token transport retained responsibility for its own response limits.
- A non-numeric Redis response threw an error instead of permitting the request.
- The configuration loader rejected issuer and resource strings whose raw form differed from the WHATWG URL form. It retained origin form without the root slash, such as `https://auth.test`.
- Fastify, Express, and Hono rejected ambiguous bearer input, repeated OAuth form fields, ambiguous content types, and oversized OAuth request bodies.
- The release added approve and revoke admission, one clock snapshot per token operation, observable JSONL disablement, observable revocation-store failures, and clock-bound expiry collection in all three reference stores.
- The package exported `mcp-sso/testing/store-conformance` and `mcp-sso/testing/client-store-conformance`.

The Windows permission change added one shared warning per Node worker. The first persistent quickstart, state-directory, or SQLite call emitted a fixed message with no path. A warning transport failure did not replace the boot result. The change added visibility, not DACL enforcement.

## 2026-08-21 example limiter correction

The source correction for issue #280 superseded the stateless example behavior above. Both runnable example factories began creating a finite process-local `RateLimitPort` in stateless and stored DCR modes. They passed the same instance to `createUpstreamRedirectFlow`.

The default stateless examples then used a bounded `upstream:<ip>` bucket for authorize and callback requests. Direct identity authorization used a separate `authorize:<ip>` bucket. The library still used `noopRateLimit` when a composition did not supply a `RateLimitPort`.

| Baseline | Evidence completed | Still pending |
| --- | --- | --- |
| Patched, uncommitted checkout based on `ee8994a` (2026-07-26/27) | Observed CIMD happy paths with Cloudflare Access, Entra ID, and Google. Refresh rotation plus replay/family revocation. Retained audit-log search found no backend credential. | Historical observation only: the exact dirty tree was neither committed nor archived, so this campaign does not satisfy the minimum live-row evidence contract and does not qualify as verified. |
| Clean `main` at `e71a2bb` (2026-07-28) | Three metadata/tokenless-challenge probes and DCR registrations. Cloudflare Access path gating. Entra- and Google-configured gateways resolving a public CIMD document to their authorization redirects. CIMD rejection of literal IP, DNS rebinding, DNS failure, non-200 response, wrong content type, oversized body, and timeout. See the [sanitized receipt](#2026-07-28-clean-main-rerun-receipt). | Browser completion stopped before identity and consent. The exact-runtime campaign below completed those legs. |
| Exact runtime commit `af2a61f` (2026-07-28) | Claude Code 2.1.220 completed CIMD authorization and protected `status` calls with Cloudflare Access, Entra ID, and Google. A corrected refresh harness proved A→B→C rotation, HTTP 400 `invalid_grant` on replayed A, then HTTP 400 `invalid_grant` on current C. Audit and retained client-result scans found zero backend-credential matches. See the [sanitized receipt](#2026-07-28-exact-runtime-live-receipt). | The claude.ai and ChatGPT CIMD observations were re-driven on a committed runtime in the 2026-08-19 campaign and are now verified rows. Of the Entra deny/ceiling cases, no-group, no-mapped-group, and group-overage were driven on 2026-08-19. Wrong-tenant and allowlist are runner-expressible since #279 (through the marked `MCP_SSO_ENTRA_ALLOWED_TENANT_IDS` / `MCP_SSO_ENTRA_SUBJECT_ALLOWLIST` channels) but the drives themselves remain pending, as does guest/B2B. |

No secrets, tenant/team identifiers, provider subjects, or deployment URLs from these campaigns are retained in this public record.

## 2026-07-28 clean-main rerun receipt

The partial rerun used a clean worktree at exact commit `e71a2bbaf6902f98502a788a8d1e4bfc604b9bbc`. Provider configuration was loaded from uncommitted private environment files. The retained public receipt contains no provider value or deployment URL.

| Probe | Observed result |
| --- | --- |
| Discovery and tokenless protected-resource request | All three configured gateways returned their metadata, then rejected a tokenless `/mcp` request with 401 and a `resource_metadata` challenge constructed by `buildUnauthorizedChallenge`. |
| Dynamic registration | All three gateways returned 201 for a valid DCR registration. |
| CIMD redirect entry | The Entra- and Google-configured gateways resolved the public CIMD document and redirected to their configured identity provider. This stopped before browser login and is not a provider happy-path claim. |
| Cloudflare Access path gate | The public metadata, registration, token, and protected-resource paths remained reachable while the browser authorization path required the Access assertion. |
| Guarded CIMD rejection | Authorization rejected literal-IP admission, DNS rebinding, DNS failure, non-200 response, wrong content type, body over 5 KiB, and timeout cases. These requests exercised `createGuardedFetcher` through the gateway authorization path. |

## 2026-07-28 exact-runtime live receipt

The three gateways ran from exact commit `af2a61f1aa772a7f3963acfa9dab15c47f676607`. Its runtime code is identical to `e71a2bb` because the intervening changes are documentation and source comments only. Provider secrets and identifiers remained in private environment files.

| Probe | Observed result |
| --- | --- |
| Cloudflare Access CIMD | Claude Code 2.1.220 completed CIMD fetch, Access identity verification, consent approval, authorization-code exchange, and a protected `status` call. The audit `clientId` for the protected call was an HTTPS CIMD identifier. |
| Entra ID CIMD | Claude Code 2.1.220 completed CIMD fetch, Entra identity verification, upstream callback, consent approval, authorization-code exchange, and a protected `status` call. The audit `clientId` for the protected call was an HTTPS CIMD identifier. |
| Google CIMD | Claude Code 2.1.220 completed CIMD fetch, Google identity verification, upstream callback, consent approval, authorization-code exchange, and a protected `status` call. The audit `clientId` for the protected call was an HTTPS CIMD identifier. |
| Refresh replay | A corrected harness required the full response shape: refresh A→B and B→C returned 200. Replayed A returned HTTP 400 `invalid_grant`. Current C then returned HTTP 400 `invalid_grant`, proving family revocation rather than a generic outage. |
| Credential containment | All three retained `status` tool results contained only the expected `ok`, `backend`, and `via` fields and contained no backend key. Each provider's audit log also had zero backend-key matches. |

## 2026-08-19 live harness receipts

The Entra probe passed 13 live checks and one local group-denial control through `scripts/live/run.sh`. The Google probe passed 11 live checks. The stored-mode end-to-end probe passed 43 checks against local Redis. Each run used runtime commit `4290b0f`, which PR #276 later squash-merged as `d6143b3`. The trees differ only in the receipt document.

The Cloudflare probe stopped when it needed the operator's Access login. That stop was expected and did not produce Cloudflare provider evidence.

The stored-mode end-to-end run predates the DCR mode-selection change. It does not establish stateless DCR behavior. `test/live-e2e-probe.test.mjs` now runs both modes in CI, but a live stateless run remains pending.
