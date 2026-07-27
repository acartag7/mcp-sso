# 16. Spec-conformance matrix

| Requirement | Status | Where |
|---|---|---|
| RFC 9728 PRM (root) | ✅ v0.1 | §9.1 |
| RFC 9728 PRM (path-inserted) | ✅ v0.1 *(fix #2)* | §9.1 |
| `WWW-Authenticate: … resource_metadata=…, scope=…` (401) | ✅ v0.1 *(fix #1)* | §8.2 |
| `insufficient_scope` 403 step-up | ✅ v0.1 | §8.3 |
| RFC 8414 AS metadata | ✅ v0.1 | §9.1 |
| RFC 7591 DCR (stateless) | ✅ v0.1 | §9.2 |
| Stored-client DCR + `application_type` *(fix #4, RC b)* | ✅ implemented, including the §10.0 stored-state read guard | §9.2, §10.2 |
| Redirect-entry grammar §10.0 (ONE definition, all NINE consumers: boot · DCR write in both modes · stored read · CIMD doc · exported matcher `assertAllowedRedirectUri` · flow-cookie CIMD registration · flow-cookie opaque params · consent-token redirect at approve · authorization-code record at token exchange) | ✅ implemented — the nine-leg differential test passes across every consumer | §10.0, §10.1, §10.2, §17.1.5 rule 20, §17.1.6 dec 1c |
| PKCE S256 (timing-safe) | ✅ v0.1 | §7.5 |
| RFC 8707 audience fail-closed | ✅ v0.1 | §7.2 |
| RFC 9207 `iss` + `authorization_response_iss_parameter_supported` *(RC a)* | ✅ v0.1 | §9.1, §9.3 |
| Scope accumulation on step-up *(RC c)* — **stored-DCR opaque clients only** (CIMD clients stand alone; CIMD accumulation deferred — §17.1.6 dec 3) | ✅ v0.1 (core+store; delta UI Phase 3) | §9.3, §11, §17.1.6 |
| Refresh rotation + family replay revocation | ✅ v0.1 | §7.4, §12 |
| RFC 6749 §6 refresh client-binding | ✅ v0.1 | §7.4 |
| RFC 6749 §4.1.2.1 error-redirect channels | ✅ v0.1 | §9.3, §14 |
| RFC 7009 revocation (always 200; unknown = no-op) | ✅ v0.1 | §9.4 |
| Hashed single-use codes/tokens; single-use consent JTI | ✅ v0.1 | §7, §12 |
| Fail-closed boot + no identity bypass | ✅ v0.1 | §5, §9.3 |
| Consent Deny *(fix #5)* + error redirects | ✅ v0.1 core + adapter UI | §9.3, §9.6 |
| Rate-limit hook port *(fix #7)* — no-op default | ✅ v0.1 | §6.7 |
| CIMD (SSRF-guarded FetcherPort) | ✅ implemented — `createGuardedFetcher` + S6b flow integration (§17.1.5/§17.1.6), frozen acceptance suite active (`s6b-cimd-flow`), including §10.0 redirect-entry canonicality. Historically live-verified with real CIMD-first clients across Cloudflare Access, Entra, and Google; the clean-`main` pre-release rerun remains pending. Any 2026-07-28 spec-final conformance claim remains gated on publication of the final text and the `docs/verification.md` re-verification | §6.6, §17.1 |
| Framework adapters (`/fastify` `/express` `/hono`) | ✅ Phase 3 | §9.6, §15 |
| Identity ports (Cloudflare Access, Entra) | ✅ Phase 3 | §6.5 |
| `client_credentials` (MCP ext `io.modelcontextprotocol/oauth-client-credentials`) | ✅ v0.2 shipped (S3a provisioning/rotation + S3b grant: Basic+post auth, `MachineTokenResponse`, metadata-gated advertisement) | §17.2 |
| Device authorization grant (RFC 8628) | 🔒 contract locked; not implemented | §17.3 |
| Entra group→scope ceiling (Gate 2) | ✅ v0.2 shipped (`createEntraRedirectIdentity` + `resolveGroupCeiling`); historically live-verified for member, deny, overage, and guest/B2B outcomes; clean-`main` rerun pending | §17.4 |
| Console-pairing identity | ✅ v0.2 shipped (S1b) — `createConsolePairingIdentity`, 12-char base-20 code, lazy/single-use/TTL/attempt-cap, `oauth.pairing.attempt` | §17.5 |
| `GenericOidcIdentity` + Google preset + GitHub port | ✅ v0.2 shipped (S4a) — GenericOidcIdentity + Google preset as `RedirectIdentityPort`s (discovery + manual endpoints, multi-audience reject, at_hash, iat required); Google is historically live-verified, while a second non-Google generic issuer remains pending; GitHub port still 🔒 locked and unimplemented | §17.6 |
| Upstream redirect-leg orchestrator (`RedirectIdentityPort` + flow cookie) | ✅ v0.2 shipped — `createUpstreamRedirectFlow` + `createEntraRedirectIdentity`, signed flow cookie (HS256 consent secret, per-flow aud `mcp-sso/upstream-flow` + `callbackPath`, single-use `upf_` jti), 13-row callback failure table, `oauth.upstream.callback` audit | §17.11 |
| Audit reference sinks + expanded events | ✅ v0.2 shipped (S1a) — JsonlFileAudit/WebhookAudit/combineAudit + 9 event names + `ip` | §13, §17.7 |
| Quickstart secret persistence | ✅ v0.2 shipped (S1b) — `loadOrCreateQuickstartSecrets`, 0700/0600/O_EXCL + perm check, fail-closed | §17.8 |

**Spec-final re-check gate:** the RC's (locked 2026-05-21) backward-compatible
hardening items are built in now. The 2026-07-28 final text is not yet
published; before any release claims conformance with it, complete
[`docs/verification.md` — "Spec-release
re-verification (due
2026-07-28)"](../verification.md#spec-release-re-verification-due-2026-07-28).
The RC changes nothing about the RS model or the bridge architecture.
