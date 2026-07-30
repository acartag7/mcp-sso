// OAuthTokenUseCase — auth-code exchange, refresh rotation, revocation (contracts §9.4). Refresh enforces RFC 6749 §6 client binding (mismatch revokes the family); revoke follows RFC 7009 (always succeeds; unknown token is a no-op).
import type { ClockPort } from "./ports/clock.ts";
import type { AuditPort } from "./ports/audit.ts";
import type { AuthCodeRecord, RefreshTokenRecord, StorePort } from "./ports/store.ts";
import type { AnyBridgeConfig as BridgeConfig } from "./config.ts";
import { OAuthError } from "./errors.ts"; import { assertOAuthRedirectEntry } from "./redirect.ts";
import { expiresAtIso, generateRefreshToken, parseRefreshFamilyId, sha256Hex, signAccessToken, verifyPkceS256 } from "./crypto.ts";
import { resolveClientCredentialsScope, scopeString, storedScopes } from "./scopes.ts";
import { authenticateMachineClientSecret } from "./machine-client-auth.ts";
import { resolveMachineClientTokenResource } from "./machine-client-resource.ts";
import { isBasicAttempt, parseBasicAuth } from "./client-auth.ts";
import { writeTokenAudit } from "./token-audit.ts";
import { expectedStoredDcrGrantGeneration, hasExpectedGrantGeneration } from "./stored-dcr-generation.ts";
import { assertRequestResourceMatchesRecord, initTokenCatalog, refreshBindingExpectation, resolveRecordResource, requiredStr, type ResourceCatalog } from "./token-resource.ts";
export interface OAuthTokenDeps {
  config: BridgeConfig;
  store: StorePort;
  clock: ClockPort;
  audit: AuditPort;
}
export interface AuthorizationCodeGrantInput {
  grantType?: string;
  code?: string;
  redirectUri?: string;
  clientId?: string;
  codeVerifier?: string; resource?: string;   // resource: RFC 8707, must match the code's lineage
}
export interface RefreshGrantInput {
  grantType?: string; refreshToken?: string; clientId?: string;
  resource?: string;   // RFC 8707; omission resolves only for a one-entry catalog (§9.7)
}
/** §17.2 `client_credentials` grant input. `authorization` is the raw
 *  Authorization header (Basic parsed here); `clientId`/`clientSecret` are the
 *  `client_secret_post` form fields. The grant resolves which method was used. */
export interface ClientCredentialsGrantInput {
  grantType?: string;
  authorization?: string;
  clientId?: string;
  clientSecret?: string;
  scope?: string;
  resource?: string;
}
/** User-grant response (authorization_code / refresh / device): access + refresh. */
export interface UserTokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
}

/** Backward-compatible alias (v0.1 name); §17.2 split it into User vs Machine responses. */
export type TokenResponse = UserTokenResponse;

/** §17.2 machine-grant response: NO `refresh_token` member (not optional) — the
 *  client holds a durable credential, so a refresh token is a second bearer
 *  secret with zero benefit (RFC 6749 §4.4.3). */
export interface MachineTokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
}

export class OAuthTokenUseCase {
  private readonly config: BridgeConfig;
  private readonly catalog: ResourceCatalog;
  private readonly store: StorePort;
  private readonly clock: ClockPort;
  private readonly audit: AuditPort;

  constructor(deps: OAuthTokenDeps) {
    this.config = deps.config;
    this.store = deps.store;
    this.clock = deps.clock;
    this.audit = deps.audit;
    this.catalog = initTokenCatalog(this.config, this.store);
  }

  async exchangeAuthorizationCode(input: AuthorizationCodeGrantInput): Promise<UserTokenResponse> {
    try {
      if (input.grantType !== "authorization_code") {
        throw new OAuthError("unsupported_grant_type", "grant_type is not supported");
      }
      const record = await this.consumeValidCode(input);
      assertRequestResourceMatchesRecord(this.catalog, record.resource, input.resource); // §9.7; after burn, before lineage
      if (record.subject.startsWith("mcc_")) throw new OAuthError("invalid_grant", "Grant subject uses the reserved machine-client namespace"); // pre-side-effect (§9.3): code burned, NO refresh token saved, no success audited
      const refreshToken = generateRefreshToken();
      const familyId = parseRefreshFamilyId(refreshToken);
      if (!familyId) throw new OAuthError("server_error", "Refresh token generation failed", 500);
      const prepared = await this.tokenResponse(record, refreshToken);
      await this.store.saveRefreshToken({
        tokenHash: sha256Hex(refreshToken), familyId, previousTokenHash: null,
        clientId: record.clientId, subject: record.subject, scopes: prepared.scopes,
        expiresAt: expiresAtIso(this.clock, this.config.refreshTokenTtlSeconds),
        grantGeneration: record.grantGeneration, resource: prepared.resource,
      });
      await this.auditToken("oauth.token.authorization_code", "success", record);
      return prepared.response;
    } catch (error) {
      await this.auditFailure("oauth.token.authorization_code", error, input.clientId);
      throw error;
    }
  }

  async refresh(input: RefreshGrantInput): Promise<UserTokenResponse> {
    try {
      if (input.grantType !== "refresh_token") {
        throw new OAuthError("unsupported_grant_type", "grant_type is not supported");
      }
      const raw = requiredStr(input.refreshToken, "refresh_token");
      const familyId = parseRefreshFamilyId(raw);
      if (!familyId) throw new OAuthError("invalid_grant", "Refresh token is invalid");
      const nextRaw = generateRefreshToken(familyId);
      const previousHash = sha256Hex(raw);
      const rotatedAtIso = new Date(this.clock.nowMs()).toISOString();
      const rotated = await this.store.rotateRefreshToken(
        previousHash,
        {
          tokenHash: sha256Hex(nextRaw), familyId, previousTokenHash: previousHash,
          clientId: input.clientId ?? "", subject: "", scopes: [],
          expiresAt: expiresAtIso(this.clock, this.config.refreshTokenTtlSeconds),
        },
        rotatedAtIso,
        expectedStoredDcrGrantGeneration(this.config),
        refreshBindingExpectation(this.catalog, input.resource),
      );
      if (!rotated) throw new OAuthError("invalid_grant", "Refresh token is invalid");
      if ("status" in rotated) throw new OAuthError("invalid_target", "refresh token bound to a different resource"); // fieldless mismatch, no mutation -> no §7.4 family revocation
      try {
        if (!hasExpectedGrantGeneration(rotated, expectedStoredDcrGrantGeneration(this.config))) throw new OAuthError("invalid_grant", "Refresh token is invalid");
        if (!input.clientId || input.clientId !== rotated.clientId) throw new OAuthError("invalid_grant", "Refresh token client binding is invalid"); // stored client authoritative (RFC 6749 §6)
        if (rotated.subject.startsWith("mcc_")) throw new OAuthError("invalid_grant", "Grant subject uses the reserved machine-client namespace");
        const prepared = await this.tokenResponse(rotated, nextRaw);
        await this.auditToken("oauth.token.refresh", "success", rotated);
        return prepared.response;
      } catch (error) {
        // Preparation stays after replay-authoritative rotation; failures revoke its unreturned successor.
        await this.store.revokeRefreshTokenFamily(familyId, rotatedAtIso);
        throw error;
      }
    } catch (error) {
      await this.auditFailure("oauth.token.refresh", error, input.clientId);
      throw error;
    }
  }

  /** §17.2 `client_credentials` grant: authenticate a provisioned machine client
   *  (Basic or post), resolve scope against its `allowedScopes` ceiling, mint an
   *  access token with `sub = client_id` (RFC 9068 §2.2) — NO refresh token
   *  (§4.4.3). Authenticates one parsed store snapshot: wrong secret / unknown
   *  client / malformed record ⇒ invalid_client, with a fixed
   *  two digest comparisons (custom-store lookup timing remains external). */
  async exchangeClientCredentials(input: ClientCredentialsGrantInput): Promise<MachineTokenResponse> {
    let clientId: string | undefined; let resolved: string | undefined; // for the failure audit
    try {
      // Fail-closed (defense-in-depth): metadata does not advertise the surface
      // unless enabled; boot already requires stored DCR when it is.
      if (input.grantType !== "client_credentials" || !this.config.clientCredentials?.enabled) {
        throw new OAuthError("unsupported_grant_type", "grant_type is not supported");
      }
      const clientStore = this.config.dcr.mode === "stored" ? this.config.dcr.store : null;
      // RFC 6749 §2.3.1 / OAuth 2.1 §2.4.1: Basic takes precedence; a Basic header
      // AND a body secret = two methods ⇒ rejected (§2.3), keyed on scheme presence.
      const basic = parseBasicAuth(input.authorization);
      clientId = basic ? basic.clientId : input.clientId;
      if (isBasicAttempt(input.authorization) && input.clientSecret) throw new OAuthError("invalid_client", "Multiple client authentication methods present", 401);
      const clientSecret = basic ? basic.clientSecret : input.clientSecret;
      if (!clientId || !clientSecret || !clientStore) throw new OAuthError("invalid_client", "Client authentication is required", 401);
      const client = await authenticateMachineClientSecret(
        { store: clientStore, clock: this.clock },
        clientId,
        clientSecret,
      );
      if (!client) throw new OAuthError("invalid_client", "Client authentication failed", 401);
      const selected = resolveMachineClientTokenResource(client.resource, this.catalog, input.resource);
      resolved = selected.resource;   // §13: a later failure attributes to it
      const scopes = resolveClientCredentialsScope(input.scope, client.allowedScopes, selected.scopeCatalog);
      const accessToken = await signAccessToken({ subject: clientId, clientId, scopes, resource: selected.resource, machine: true }, this.config, this.clock);
      await writeTokenAudit(this.audit, {
        occurredAt: new Date(this.clock.nowMs()).toISOString(), event: "oauth.token.client_credentials", status: "success",
        clientId, subject: clientId, scopes, resource: selected.resource,
      });
      return { access_token: accessToken, token_type: "Bearer", expires_in: this.config.accessTokenTtlSeconds, scope: scopeString(scopes) };
    } catch (error) {
      await writeTokenAudit(this.audit, {
        occurredAt: new Date(this.clock.nowMs()).toISOString(), event: "oauth.token.client_credentials", status: "failure",
        clientId, ...(resolved === undefined ? {} : { resource: resolved }), reason: error instanceof OAuthError ? error.code : "internal_error",
      });
      throw error;
    }
  }

  /** RFC 7009: always succeeds (the adapter returns 200). An unknown or
   *  already-revoked token is a no-op — it never leaks existence via 4xx. */
  async revoke(refreshToken: string | undefined): Promise<void> {
    const nowIso = new Date(this.clock.nowMs()).toISOString();
    let resource: string | undefined;   // from VERIFIED stored lineage (§13), never request text
    const existing = refreshToken ? await this.store.findRefreshToken(sha256Hex(refreshToken)) : null;
    if (existing) {
      try { resource = resolveRecordResource(this.catalog, existing.resource).resource; } catch { /* omit */ }
      await this.store.revokeRefreshTokenFamily(existing.familyId, nowIso);
    }
    await writeTokenAudit(this.audit, {
      occurredAt: nowIso, event: "oauth.revoke", status: "success",
      ...(resource === undefined ? {} : { resource }),
      reason: existing ? undefined : "unrecognized_token",
    });
  }

  private async consumeValidCode(input: AuthorizationCodeGrantInput): Promise<AuthCodeRecord> {
    const code = requiredStr(input.code, "code"), expected = expectedStoredDcrGrantGeneration(this.config);
    const record = await this.store.consumeAuthCode(sha256Hex(code), new Date(this.clock.nowMs()).toISOString(), expected);
    if (!record || !hasExpectedGrantGeneration(record, expected)) throw new OAuthError("invalid_grant", "Authorization code is invalid"); const redirectUri = record.redirectUri;
    try { assertOAuthRedirectEntry(redirectUri); } catch { throw new OAuthError("invalid_grant", "Authorization code is invalid"); }
    if (input.clientId !== record.clientId || input.redirectUri !== redirectUri) {
      throw new OAuthError("invalid_grant", "Authorization code is invalid");
    }
    if (!verifyPkceS256(requiredStr(input.codeVerifier, "code_verifier"), record.codeChallenge)) {
      throw new OAuthError("invalid_grant", "Authorization code is invalid");
    }
    return record;
  }

  private async tokenResponse(record: AuthCodeRecord | RefreshTokenRecord, refreshToken: string): Promise<{ response: UserTokenResponse; scopes: string[]; resource: string }> {
    const resolved = resolveRecordResource(this.catalog, record.resource);
    const scopes = storedScopes(record.scopes, resolved.scopeCatalog);
    const accessToken = await signAccessToken({ subject: record.subject, clientId: record.clientId, scopes, resource: resolved.resource }, this.config, this.clock);
    return { scopes, resource: resolved.resource, response: {
      access_token: accessToken, token_type: "Bearer",
      expires_in: this.config.accessTokenTtlSeconds, refresh_token: refreshToken,
      scope: scopeString(scopes),
    } };
  }

  private async auditToken(event: "oauth.token.authorization_code" | "oauth.token.refresh", status: "success", record: AuthCodeRecord | RefreshTokenRecord): Promise<void> {
    await writeTokenAudit(this.audit, {
      occurredAt: new Date(this.clock.nowMs()).toISOString(), event, status,
      clientId: record.clientId, subject: record.subject, scopes: record.scopes,
      resource: typeof record.resource === "string" ? record.resource : this.catalog.legacySingletonResource,
    });
  }
  private async auditFailure(event: "oauth.token.authorization_code" | "oauth.token.refresh", error: unknown, clientId?: string): Promise<void> {
    await writeTokenAudit(this.audit, {
      occurredAt: new Date(this.clock.nowMs()).toISOString(), event, status: "failure",
      clientId, reason: error instanceof OAuthError ? error.code : "internal_error",
    });
  }
}
