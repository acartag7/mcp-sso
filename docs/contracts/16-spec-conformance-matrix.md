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
| Redirect-entry grammar §10.0 (ONE definition, all NINE consumers: boot · DCR write in both modes · stored read · CIMD doc · exported matcher `assertAllowedRedirectUri` · flow-cookie CIMD registration · flow-cookie opaque params · consent-token redirect at approve · authorization-code record at token exchange) | ✅ implemented — the nine-leg differential test passes across every consumer | §10.0, §10.1, §10.2, §17.1.5 rule 20, §17.1.6 dec 1c |
| PKCE S256 (timing-safe) | ✅ v0.1 | §7.5 |
| RFC 8707 audience fail-closed | ✅ v0.1 | §7.2 |
| RFC 9207 `iss` + `authorization_response_iss_parameter_supported` | ⚠️ partial: metadata advertises support and successful code responses include `iss`; redirected authorization errors omit it, so MCP 2026-07-28 conformance remains blocked | §9.1, §9.3 |
| Scope accumulation on step-up *(RC c)* — **stored-DCR opaque clients only** (CIMD clients stand alone; CIMD accumulation deferred — §17.1.6 dec 3) | ✅ v0.1 (core+store; delta UI Phase 3) | §9.3, §11, §17.1.6 |
| Refresh rotation + family replay revocation | ✅ v0.1 | §7.4, §12 |
| RFC 6749 §6 refresh client-binding | ✅ v0.1 | §7.4 |
| RFC 6749 §4.1.2.1 error-redirect channels | ✅ v0.1 | §9.3, §14 |
| RFC 7009 revocation (always 200; unknown = no-op) | ✅ v0.1 | §9.4 |
| Hashed single-use codes/tokens; single-use consent JTI | ✅ v0.1 | §7, §12 |
| Fail-closed boot + no identity bypass | ✅ v0.1 | §5, §9.3 |
| Consent Deny *(fix #5)* + error redirects | ✅ v0.1 core + adapter UI | §9.3, §9.6 |
| Rate-limit hook port *(fix #7)* — no-op default | ✅ v0.1 | §6.7 |
| CIMD (SSRF-guarded FetcherPort) | ⚠️ implemented and proven for the explicitly checked MCP-page requirements: capability advertisement, exact document `client_id`, required fields, redirect binding, and guarded retrieval. Final MCP 2026-07-28 keeps CIMD at `SHOULD` and references draft `-00`; a complete normative draft `-00` requirement-to-source/test mapping remains pending. Frozen acceptance suite `s6b-cimd-flow` is active. Claude Code 2.1.220 completed CIMD authorization and protected tool calls through exact runtime commit `af2a61f` with Cloudflare Access, Entra, and Google on 2026-07-28 | §6.6, §17.1 |
| Framework adapters (`/fastify` `/express` `/hono`) | ✅ Phase 3 | §9.6, §15 |
| Identity ports (Cloudflare Access, Entra) | ✅ Phase 3 | §6.5 |
| `client_credentials` (MCP ext `io.modelcontextprotocol/oauth-client-credentials`) | ✅ v0.2 shipped (S3a provisioning/rotation + S3b grant: Basic+post auth, `MachineTokenResponse`, metadata-gated advertisement) | §17.2 |
| Device authorization grant (RFC 8628) | 🔒 contract locked; not implemented | §17.3 |
| Entra group→scope ceiling (Gate 2) | ✅ v0.2 shipped (`createEntraRedirectIdentity` + `resolveGroupCeiling`); member, deny, overage, and guest/B2B outcomes were observed only on an unarchived patched checkout and require a clean-runtime rerun before being claimed as currently live-verified | §17.4 |
| Console-pairing identity | ✅ v0.2 shipped (S1b) — `createConsolePairingIdentity`, 12-char base-20 code, lazy/single-use/TTL/attempt-cap, `oauth.pairing.attempt` | §17.5 |
| `GenericOidcIdentity` + Google preset + GitHub port | ✅ v0.2 shipped (S4a) — GenericOidcIdentity + Google preset as `RedirectIdentityPort`s (discovery + manual endpoints, multi-audience reject, at_hash, iat required); Google is historically live-verified, while a second non-Google generic issuer remains pending; GitHub port still 🔒 locked and unimplemented | §17.6 |
| Upstream redirect-leg orchestrator (`RedirectIdentityPort` + flow cookie) | ✅ v0.2 shipped — `createUpstreamRedirectFlow` + `createEntraRedirectIdentity`, signed flow cookie (HS256 consent secret, per-flow aud `mcp-sso/upstream-flow` + `callbackPath`, single-use `upf_` jti), 13-row callback failure table, `oauth.upstream.callback` audit | §17.11 |
| Audit reference sinks + expanded events | ✅ v0.2 shipped (S1a) — JsonlFileAudit/WebhookAudit/combineAudit + 9 event names + `ip` | §13, §17.7 |
| Quickstart secret persistence | ✅ v0.2 shipped (S1b) — `loadOrCreateQuickstartSecrets`, 0700/0600/O_EXCL + perm check, fail-closed | §17.8 |

**Spec-final re-check (2026-08-02):** completed against official stable tag
[`2026-07-28`](https://github.com/modelcontextprotocol/modelcontextprotocol/releases/tag/2026-07-28),
commit `5f5440bb26a62e2cf3440b92da5a667efa03b267`, and the dated Authorization
pages. DCR deprecation and the client-side DCR `application_type` requirement
do not block v0.3.2's single-resource AS scope. The target remains MCP
Authorization 2025-11-25 because redirected authorization errors omit RFC 9207
`iss`, the flat `requireScope` helper does not account for scope hierarchies,
and the referenced CIMD draft `-00` still lacks a complete requirement mapping.
See the completed
[`docs/verification.md` receipt](../verification.md#spec-release-re-verification-completed-2026-08-02).
