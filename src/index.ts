// mcp-idp-bridge — OAuth 2.1 for remote MCP servers.
// Framework-free core: a resource-server verifier + an AS-lite bridge. Store
// implementations live at /store/memory and /store/sqlite; framework adapters
// and identity ports arrive in Phase 3. See docs/contracts.md.

export {
  type BridgeConfig, type DcrMode, type DevOptions, AuthConfigError,
  createBridgeConfig, originOf, pathAfterOrigin,
} from "./config.js";

export {
  type RedirectTarget, OAuthError, oauthErrorBody, withRedirect,
} from "./errors.js";

export {
  type AuthorizedSubject, normalizeScopes, scopeString, requireScope,
} from "./scopes.js";

export {
  type ConsentRequestClaims, type AccessTokenClaims, type VerifiedAccessToken,
  verifyAccessToken, signAccessToken, verifyConsentToken, verifyPkceS256,
  pkceChallenge, publicJwk, sha256Hex, generateAuthorizationCode,
  generateRefreshToken, generateRefreshFamilyId, parseRefreshFamilyId,
  generateConsentJti, expiresAtIso,
} from "./crypto.js";

export {
  DEFAULT_ALLOWED_REDIRECT_ORIGINS,
  assertAllowedRedirectUri, assertRedirectAllowedForClient,
} from "./redirect.js";

export {
  type ChallengeOptions, buildUnauthorizedChallenge, buildErrorRedirect,
  protectedResourceMetadataUrl,
} from "./challenge.js";

export {
  authorizationServerMetadata, protectedResourceMetadata,
  protectedResourceMetadataUrls, jwks,
} from "./metadata.js";

export {
  type OAuthAuthorizationDeps, type AuthorizeRequestInput,
  type PreparedConsent, type ApproveInput, type ApproveResult,
  OAuthAuthorizationUseCase,
} from "./authorize.js";

export {
  type OAuthTokenDeps, type AuthorizationCodeGrantInput,
  type RefreshGrantInput, type TokenResponse, OAuthTokenUseCase,
} from "./token.js";

export {
  type RequestAuthDeps, type RequestAuthInput, type RequestAuthResult,
  RequestAuthorizer, createRequestAuthorizer,
} from "./verifier.js";

export {
  type RegisterDeps, type RegisterInput, type RegisteredClient, registerClient,
} from "./register.js";

export { type ClockPort, SystemClock } from "./ports/clock.js";
export { type AuditPort, type AuthAuditEvent, type AuthAuditEventName, noopAudit } from "./ports/audit.js";
export {
  type StorePort, type AuthCodeRecord, type RefreshTokenRecord,
  type SaveAuthCodeInput, type SaveRefreshTokenInput,
  StoreInputError, assertSha256Hex, assertUtcIsoTimestamp,
} from "./ports/store.js";
export { type ClientStore, type ClientRegistration, type ApplicationType } from "./ports/client-store.js";
export { type IdentityPort, type IdentityClaims, type IdentityResult } from "./ports/identity.js";
export { type FetcherPort, type FetchInit, type FetchResult } from "./ports/fetcher.js";
