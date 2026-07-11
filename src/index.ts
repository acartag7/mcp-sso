// mcp-sso — OAuth 2.1 for remote MCP servers.
// Framework-free core: a resource-server verifier + an AS-lite bridge. Store
// implementations live at /store/memory and /store/sqlite; framework adapters
// and identity ports arrive in Phase 3. See docs/contracts.md.

export {
  type BridgeConfig, type DcrMode, type DevOptions, type ClientCredentialsOptions,
  AuthConfigError, createBridgeConfig, originOf, pathAfterOrigin,
} from "./config.ts";

export {
  type RedirectTarget, OAuthError, oauthErrorBody, withRedirect,
} from "./errors.ts";

export {
  type AuthorizedSubject, normalizeScopes, resolveClientCredentialsScope, scopeString, requireScope,
} from "./scopes.ts";

export {
  type ConsentRequestClaims, type AccessTokenClaims, type VerifiedAccessToken,
  verifyAccessToken, signAccessToken, verifyConsentToken, verifyPkceS256,
  pkceChallenge, publicJwk, sha256Hex, generateAuthorizationCode,
  generateRefreshToken, generateRefreshFamilyId, parseRefreshFamilyId,
  generateConsentJti, expiresAtIso,
} from "./crypto.ts";

export {
  DEFAULT_ALLOWED_REDIRECT_ORIGINS,
  assertAllowedRedirectUri, assertRedirectAllowedForClient,
} from "./redirect.ts";

export {
  type ChallengeOptions, buildUnauthorizedChallenge, buildBasicClientChallenge, buildErrorRedirect,
  protectedResourceMetadataUrl,
} from "./challenge.ts";

export {
  authorizationServerMetadata, protectedResourceMetadata,
  protectedResourceMetadataUrls, jwks,
} from "./metadata.ts";

// Confidential-client authentication helpers (§17.2 / RFC 6749 §2.3.1). The
// client_credentials grant composes these; a custom adapter may reuse them.
export { parseBasicAuth, isBasicAttempt } from "./client-auth.ts";

export {
  type OAuthAuthorizationDeps, type AuthorizeRequestInput,
  type PreparedConsent, type ApproveInput, type ApproveResult,
  OAuthAuthorizationUseCase,
} from "./authorize.ts";

export {
  type OAuthTokenDeps, type AuthorizationCodeGrantInput,
  type RefreshGrantInput, type ClientCredentialsGrantInput,
  type UserTokenResponse, type MachineTokenResponse, type TokenResponse,
  OAuthTokenUseCase,
} from "./token.ts";

export {
  type RequestAuthDeps, type RequestAuthInput, type RequestAuthResult,
  RequestAuthorizer, createRequestAuthorizer,
} from "./verifier.ts";

export {
  type RegisterDeps, type RegisterInput, type RegisteredClient, registerClient,
} from "./register.ts";

// Machine-client provisioning primitives (§17.2). Library functions, not
// endpoints: machine clients are provisioned out-of-band. The client_credentials
// token grant that consumes these records is `OAuthTokenUseCase.exchangeClientCredentials`.
export {
  type MachineClientDeps, type ProvisionMachineClientInput,
  type ProvisionedMachineClient, type RotateSecretOptions, type RotatedSecret,
  DEFAULT_ROTATION_GRACE_SECONDS,
  provisionMachineClient, rotateMachineClientSecret, verifyMachineClientSecret,
} from "./machine-client.ts";

export { type ClockPort, SystemClock } from "./ports/clock.ts";
export { type AuditPort, type AuthAuditEvent, type AuthAuditStatus, type AuthAuditEventName, noopAudit } from "./ports/audit.ts";
// v0.2 reference audit sinks (§17.7). Dep-free (node:fs + global fetch), so they
// ship from the main entry — no subpath/peer-dep isolation needed.
export { JsonlFileAudit, createJsonlFileAudit } from "./audit/jsonl-file.ts";
export { WebhookAudit, createWebhookAudit, type WebhookAuditOptions } from "./audit/webhook.ts";
export { combineAudit } from "./audit/combine.ts";
// Quickstart secret persistence (§17.8) — dep-free boot helper (jose + node
// builtins), so it ships from the root entry like the audit sinks. assertRealDir is
// the state-dir fs-trust bar (rejects a symlink / group-writable dir) a consumer may
// want standalone; the full atomic bar is ensureStateDir below (contracts §15 DX).
export { loadOrCreateQuickstartSecrets, assertRealDir, type QuickstartSecrets, type QuickstartOptions } from "./quickstart.ts";
// ensureStateDir — the atomic state-dir setup helper (mkdir 0o700 + assertRealDir +
// ensureGitignore), fail-safe by construction: it derives whether the managed `*`
// .gitignore may be created from mkdir's return, so a caller cannot drop a `*` ignore
// into a pre-existing tree (the footgun the raw ensureGitignore(dir, canCreate)
// boolean would expose). The public surface for the CF/Entra/gateway path (§15 DX).
export { ensureStateDir } from "./state-dir.ts";
// Console-pairing authorize surface (§17.5) — framework-free, so root-exported.
// A consumer pairs these with the `./identity/console-pairing` subpath identity
// and the `skipAuthorize` option on the framework adapters.
export { handlePairingAuthorize, type PairingAuthorizeDeps } from "./adapters/pairing-flow.ts";
export { renderPairingPage, type PairingPageInput } from "./adapters/pairing-page.ts";
// Upstream redirect-leg orchestrator (§17.11) — framework-free, so root-exported.
// A consumer pairs `createUpstreamRedirectFlow` with a `RedirectIdentityPort`
// (e.g. createEntraRedirectIdentity via ./identity/entra) and the `upstream`
// option on the framework adapters.
export { createUpstreamRedirectFlow, type UpstreamRedirectFlow, type UpstreamFlowDeps } from "./adapters/upstream-flow.ts";
// assertCallbackPath — the upstream callback-PATH validator (§17.11): the pathname
// starts with '/', is plain (no ?#%\/ whitespace/control or dot-segments), normalizes
// to itself under the issuer origin, and is not a reserved OAuth route / the resource
// path. Validates the PATH only — the redirectUri===issuerOrigin+callbackPath
// equality is enforced at mount by createUpstreamRedirectFlow (§15 DX). Lives in the
// -internals module but is public surface via this re-export.
export { assertCallbackPath } from "./adapters/upstream-flow-internals.ts";
// The framework-free Bridge — the central class a consumer constructs and passes
// to a framework adapter (root-exported so `import { Bridge } from "mcp-sso"` works;
// previously only the adapters reached it internally).
export { Bridge, type BridgeDeps } from "./adapters/bridge.ts";
// isMcpPath — the /mcp Streamable-HTTP path check (contracts §15). A consumer's
// onRequest Origin-gate hook (DNS-rebinding protection that runs BEFORE the bearer
// check + for every method) scopes to MCP paths via isMcpPath(request.url); see
// examples/fastify-sqlite. Root-exported so adopters of the recommended Origin-gate
// pattern import it from the package root, not an internal adapter path. NormRequest
// / NormResponse are the normalized shapes the framework-free surface speaks — the
// types handlePairingAuthorize + createUpstreamRedirectFlow take/return — so a
// consumer mounting those surfaces can type-check them (contracts §15 DX).
export { isMcpPath, type NormRequest, type NormResponse } from "./adapters/http.ts";
export {
  type StorePort, type AuthCodeRecord, type RefreshTokenRecord,
  type SaveAuthCodeInput, type SaveRefreshTokenInput,
  StoreInputError, assertSha256Hex, assertUtcIsoTimestamp,
} from "./ports/store.ts";
export {
  type ClientStore, type ClientRegistration, type ApplicationType,
  type ClientSecret, type UserClientRegistration, type MachineClientRegistration,
} from "./ports/client-store.ts";
export { type IdentityPort, type IdentityClaims, type IdentityResult, type RedirectIdentityPort, type RedirectExchangeResult } from "./ports/identity.ts";
export { type FetcherPort, type FetchInit, type FetchResult } from "./ports/fetcher.ts";
export { type RateLimitPort, noopRateLimit } from "./ports/rate-limit.ts";
