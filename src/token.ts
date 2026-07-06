// OAuthTokenUseCase — auth-code exchange, refresh rotation, revocation
// (contracts §9.4). Refresh enforces RFC 6749 §6 client binding (mismatch revokes
// the family). Revoke follows RFC 7009: always succeeds, unknown token is a no-op.

import type { ClockPort } from "./ports/clock.ts";
import type { AuditPort } from "./ports/audit.ts";
import type { AuthCodeRecord, RefreshTokenRecord, StorePort } from "./ports/store.ts";
import type { BridgeConfig } from "./config.ts";
import { OAuthError } from "./errors.ts";
import {
  expiresAtIso, generateRefreshToken, parseRefreshFamilyId, sha256Hex,
  signAccessToken, verifyPkceS256,
} from "./crypto.ts";
import { normalizeScopes, resolveClientCredentialsScope, scopeString } from "./scopes.ts";
import { verifyMachineClientSecret } from "./machine-client.ts";
import { isBasicAttempt, parseBasicAuth } from "./client-auth.ts";

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
  codeVerifier?: string;
}

export interface RefreshGrantInput {
  grantType?: string;
  refreshToken?: string;
  clientId?: string;
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

/** Backward-compatible alias (v0.1 published this name). §17.2 splits this into
 *  {@link UserTokenResponse} vs {@link MachineTokenResponse}. */
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
  private readonly store: StorePort;
  private readonly clock: ClockPort;
  private readonly audit: AuditPort;

  constructor(deps: OAuthTokenDeps) {
    this.config = deps.config;
    this.store = deps.store;
    this.clock = deps.clock;
    this.audit = deps.audit;
  }

  async exchangeAuthorizationCode(input: AuthorizationCodeGrantInput): Promise<UserTokenResponse> {
    try {
      if (input.grantType !== "authorization_code") {
        throw new OAuthError("unsupported_grant_type", "grant_type is not supported");
      }
      const record = await this.consumeValidCode(input);
      const refreshToken = generateRefreshToken();
      const familyId = parseRefreshFamilyId(refreshToken);
      if (!familyId) throw new OAuthError("server_error", "Refresh token generation failed", 500);
      await this.store.saveRefreshToken({
        tokenHash: sha256Hex(refreshToken), familyId, previousTokenHash: null,
        clientId: record.clientId, subject: record.subject, scopes: record.scopes,
        expiresAt: expiresAtIso(this.clock, this.config.refreshTokenTtlSeconds),
      });
      await this.auditToken("oauth.token.authorization_code", "success", record);
      return await this.tokenResponse(record, refreshToken);
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
      const rotated = await this.store.rotateRefreshToken(
        previousHash,
        {
          tokenHash: sha256Hex(nextRaw), familyId, previousTokenHash: previousHash,
          clientId: input.clientId ?? "", subject: "", scopes: [],
          expiresAt: expiresAtIso(this.clock, this.config.refreshTokenTtlSeconds),
        },
        new Date(this.clock.nowMs()).toISOString(),
      );
      if (!rotated) throw new OAuthError("invalid_grant", "Refresh token is invalid");
      // RFC 6749 §6: the grant must bind to the token's stored client_id. The
      // rotated record carries the STORED client (rotation backfill, §12.2.4); a
      // missing/mismatched client_id signals theft/replay — revoke and reject.
      if (!input.clientId || input.clientId !== rotated.clientId) {
        await this.store.revokeRefreshTokenFamily(familyId, new Date(this.clock.nowMs()).toISOString());
        throw new OAuthError("invalid_grant", "Refresh token client binding is invalid");
      }
      await this.auditToken("oauth.token.refresh", "success", rotated);
      return await this.tokenResponse(rotated, nextRaw);
    } catch (error) {
      await this.auditFailure("oauth.token.refresh", error, input.clientId);
      throw error;
    }
  }

  /** §17.2 `client_credentials` grant: authenticate a provisioned machine client
   *  (Basic or post), resolve scope against its `allowedScopes` ceiling, mint an
   *  access token with `sub = client_id` (RFC 9068 §2.2) — NO refresh token
   *  (§4.4.3). Composes {@link verifyMachineClientSecret} (uniform-work,
   *  fail-closed: wrong secret / unknown client / poisoned record ⇒ false ⇒
   *  invalid_client, no existence or active-count oracle). */
  async exchangeClientCredentials(input: ClientCredentialsGrantInput): Promise<MachineTokenResponse> {
    let clientId: string | undefined; // captured for the failure audit where known
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
      const ok = await verifyMachineClientSecret(
        { store: clientStore, catalog: this.config.scopeCatalog, clock: this.clock, audit: this.audit }, clientId, clientSecret,
      );
      if (!ok) throw new OAuthError("invalid_client", "Client authentication failed", 401);
      const client = await clientStore.find(clientId);
      if (!client || client.applicationType !== "machine") throw new OAuthError("invalid_client", "Client authentication failed", 401);
      const scopes = resolveClientCredentialsScope(input.scope, client.allowedScopes, this.config.scopeCatalog);
      if (input.resource !== undefined && input.resource !== this.config.resource) throw new OAuthError("invalid_target", "resource does not match the configured resource");
      const accessToken = await signAccessToken({ subject: clientId, clientId, scopes }, this.config, this.clock);
      await this.audit.writeAuthEvent({
        occurredAt: new Date(this.clock.nowMs()).toISOString(), event: "oauth.token.client_credentials", status: "success",
        clientId, subject: clientId, scopes, resource: this.config.resource,
      });
      return { access_token: accessToken, token_type: "Bearer", expires_in: this.config.accessTokenTtlSeconds, scope: scopeString(scopes) };
    } catch (error) {
      await this.audit.writeAuthEvent({
        occurredAt: new Date(this.clock.nowMs()).toISOString(), event: "oauth.token.client_credentials", status: "failure",
        clientId, reason: error instanceof OAuthError ? error.code : "internal_error",
      });
      throw error;
    }
  }

  /** RFC 7009: always succeeds (the adapter returns 200). An unknown or
   *  already-revoked token is a no-op — it never leaks existence via 4xx. */
  async revoke(refreshToken: string | undefined): Promise<void> {
    const nowIso = new Date(this.clock.nowMs()).toISOString();
    let revoked = false;
    if (refreshToken) {
      const existing = await this.store.findRefreshToken(sha256Hex(refreshToken));
      if (existing) {
        await this.store.revokeRefreshTokenFamily(existing.familyId, nowIso);
        revoked = true;
      }
    }
    await this.audit.writeAuthEvent({
      occurredAt: nowIso, event: "oauth.revoke", status: "success",
      reason: revoked ? undefined : "unrecognized_token",
    });
  }

  private async consumeValidCode(input: AuthorizationCodeGrantInput): Promise<AuthCodeRecord> {
    const code = requiredStr(input.code, "code");
    const record = await this.store.consumeAuthCode(sha256Hex(code), new Date(this.clock.nowMs()).toISOString());
    if (!record) throw new OAuthError("invalid_grant", "Authorization code is invalid");
    if (input.clientId !== record.clientId || input.redirectUri !== record.redirectUri) {
      throw new OAuthError("invalid_grant", "Authorization code is invalid");
    }
    if (!verifyPkceS256(requiredStr(input.codeVerifier, "code_verifier"), record.codeChallenge)) {
      throw new OAuthError("invalid_grant", "Authorization code is invalid");
    }
    return record;
  }

  private async tokenResponse(record: AuthCodeRecord | RefreshTokenRecord, refreshToken: string): Promise<UserTokenResponse> {
    const scopes = normalizeScopes(record.scopes, this.config.scopeCatalog, this.config.defaultScopes);
    const accessToken = await signAccessToken({ subject: record.subject, clientId: record.clientId, scopes }, this.config, this.clock);
    return {
      access_token: accessToken, token_type: "Bearer",
      expires_in: this.config.accessTokenTtlSeconds, refresh_token: refreshToken,
      scope: scopeString(scopes),
    };
  }

  private async auditToken(event: "oauth.token.authorization_code" | "oauth.token.refresh", status: "success", record: AuthCodeRecord | RefreshTokenRecord): Promise<void> {
    await this.audit.writeAuthEvent({
      occurredAt: new Date(this.clock.nowMs()).toISOString(), event, status,
      clientId: record.clientId, subject: record.subject, resource: this.config.resource, scopes: record.scopes,
    });
  }

  private async auditFailure(event: "oauth.token.authorization_code" | "oauth.token.refresh", error: unknown, clientId?: string): Promise<void> {
    await this.audit.writeAuthEvent({
      occurredAt: new Date(this.clock.nowMs()).toISOString(), event, status: "failure",
      clientId, reason: error instanceof OAuthError ? error.code : "internal_error",
    });
  }
}

function requiredStr(value: string | undefined, label: string): string {
  if (typeof value === "string" && value) return value;
  throw new OAuthError("invalid_request", `${label} is required`);
}
