// mcp-sso — OAuth 2.1 for remote MCP servers.
// Framework-free core: a resource-server verifier + an AS-lite bridge. Store
// implementations live at /store/memory and /store/sqlite; framework adapters
// and identity ports arrive in Phase 3. See docs/contracts.md.

export {
  type BridgeConfig, type DcrMode, type DevOptions, AuthConfigError,
  createBridgeConfig, originOf, pathAfterOrigin,
} from "./config.ts";

export {
  type RedirectTarget, OAuthError, oauthErrorBody, withRedirect,
} from "./errors.ts";

export {
  type AuthorizedSubject, normalizeScopes, scopeString, requireScope,
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
  type ChallengeOptions, buildUnauthorizedChallenge, buildErrorRedirect,
  protectedResourceMetadataUrl,
} from "./challenge.ts";

export {
  authorizationServerMetadata, protectedResourceMetadata,
  protectedResourceMetadataUrls, jwks,
} from "./metadata.ts";

export {
  type OAuthAuthorizationDeps, type AuthorizeRequestInput,
  type PreparedConsent, type ApproveInput, type ApproveResult,
  OAuthAuthorizationUseCase,
} from "./authorize.ts";

export {
  type OAuthTokenDeps, type AuthorizationCodeGrantInput,
  type RefreshGrantInput, type TokenResponse, OAuthTokenUseCase,
} from "./token.ts";

export {
  type RequestAuthDeps, type RequestAuthInput, type RequestAuthResult,
  RequestAuthorizer, createRequestAuthorizer,
} from "./verifier.ts";

export {
  type RegisterDeps, type RegisterInput, type RegisteredClient, registerClient,
} from "./register.ts";

export { type ClockPort, SystemClock } from "./ports/clock.ts";
export { type AuditPort, type AuthAuditEvent, type AuthAuditStatus, type AuthAuditEventName, noopAudit } from "./ports/audit.ts";
// v0.2 reference audit sinks (§17.7). Dep-free (node:fs + global fetch), so they
// ship from the main entry — no subpath/peer-dep isolation needed.
export { JsonlFileAudit, createJsonlFileAudit } from "./audit/jsonl-file.ts";
export { WebhookAudit, createWebhookAudit, type WebhookAuditOptions } from "./audit/webhook.ts";
export { combineAudit } from "./audit/combine.ts";
// Quickstart secret persistence (§17.8) — dep-free boot helper (jose + node
// builtins), so it ships from the root entry like the audit sinks.
export { loadOrCreateQuickstartSecrets, type QuickstartSecrets, type QuickstartOptions } from "./quickstart.ts";
// Console-pairing authorize surface (§17.5) — framework-free, so root-exported.
// A consumer pairs these with the `./identity/console-pairing` subpath identity
// and the `skipAuthorize` option on the framework adapters.
export { handlePairingAuthorize, type PairingAuthorizeDeps } from "./adapters/pairing-flow.ts";
export { renderPairingPage, type PairingPageInput } from "./adapters/pairing-page.ts";
// The framework-free Bridge — the central class a consumer constructs and passes
// to a framework adapter (root-exported so `import { Bridge } from "mcp-sso"` works;
// previously only the adapters reached it internally).
export { Bridge, type BridgeDeps } from "./adapters/bridge.ts";
export {
  type StorePort, type AuthCodeRecord, type RefreshTokenRecord,
  type SaveAuthCodeInput, type SaveRefreshTokenInput,
  StoreInputError, assertSha256Hex, assertUtcIsoTimestamp,
} from "./ports/store.ts";
export { type ClientStore, type ClientRegistration, type ApplicationType } from "./ports/client-store.ts";
export { type IdentityPort, type IdentityClaims, type IdentityResult } from "./ports/identity.ts";
export { type FetcherPort, type FetchInit, type FetchResult } from "./ports/fetcher.ts";
export { type RateLimitPort, noopRateLimit } from "./ports/rate-limit.ts";
