// OAuthTokenUseCase — auth-code exchange, refresh rotation, revocation (contracts §9.4). Refresh enforces RFC 6749 §6 client binding (mismatch revokes the family); revoke follows RFC 7009 (always succeeds; unknown token is a no-op).

import type { ClockPort } from "./ports/clock.ts";
import type { AuditPort } from "./ports/audit.ts";
import type { AuthCodeRecord, RefreshTokenRecord, StorePort } from "./ports/store.ts";
import { assertBridgeConfig, type BridgeConfig } from "./config.ts";
import { OAuthError } from "./errors.ts";
import { ownBooleanTrue, ownDataValue, snapshotOwnDataRecord } from "./own-property.ts";
import { expiresAtIso, generateRefreshToken, parseRefreshFamilyId, sha256Hex, signAccessToken, verifyPkceS256 } from "./crypto.ts";
import { resolveClientCredentialsScope, scopeString } from "./scopes.ts";
import { authenticateMachineClient } from "./machine-client.ts";
import { isBasicAttempt, parseBasicAuth } from "./client-auth.ts";
import {
  parseConsumedAuthCode, parseFoundRefreshToken, parseRotatedRefreshToken,
} from "./stored-records.ts";
import { grantFields, optionalString, requiredStr, storedScopes } from "./token-internals.ts";
import type {
  AuthorizationCodeGrantInput, ClientCredentialsGrantInput, MachineTokenResponse,
  OAuthTokenDeps, RefreshGrantInput, UserTokenResponse,
} from "./token-types.ts";

export type {
  AuthorizationCodeGrantInput, ClientCredentialsGrantInput, MachineTokenResponse,
  OAuthTokenDeps, RefreshGrantInput, TokenResponse, UserTokenResponse,
} from "./token-types.ts";

export class OAuthTokenUseCase {
  private readonly config: BridgeConfig;
  private readonly store: StorePort;
  private readonly clock: ClockPort;
  private readonly audit: AuditPort;

  constructor(deps: OAuthTokenDeps) {
    const fields = snapshotOwnDataRecord(deps);
    if (fields === null || !fields.config || !fields.store || !fields.clock || !fields.audit) {
      throw new TypeError("Token dependencies must be own data properties");
    }
    this.config = assertBridgeConfig(fields.config);
    this.store = fields.store as StorePort;
    this.clock = fields.clock as ClockPort;
    this.audit = fields.audit as AuditPort;
  }

  async exchangeAuthorizationCode(input: AuthorizationCodeGrantInput): Promise<UserTokenResponse> {
    let clientId: string | undefined;
    try {
      const fields = grantFields(input);
      clientId = optionalString(fields.clientId, "client_id");
      if (fields.grantType !== "authorization_code") {
        throw new OAuthError("unsupported_grant_type", "grant_type is not supported");
      }
      const record = await this.consumeValidCode(fields);
      if (record.subject.startsWith("mcc_")) throw new OAuthError("invalid_grant", "Grant subject uses the reserved machine-client namespace"); // pre-side-effect (§9.3): code burned, NO refresh token saved, no success audited
      const refreshToken = generateRefreshToken();
      const familyId = parseRefreshFamilyId(refreshToken);
      if (!familyId) throw new OAuthError("server_error", "Refresh token generation failed", 500);
      await this.store.saveRefreshToken({
        tokenHash: sha256Hex(refreshToken), familyId, previousTokenHash: null,
        clientId: record.clientId, subject: record.subject, scopes: record.scopes,
        expiresAt: expiresAtIso(this.clock, this.config.refreshTokenTtlSeconds),
      });
      const response = await this.tokenResponse(record, refreshToken);
      await this.auditToken("oauth.token.authorization_code", "success", record);
      return response;
    } catch (error) {
      await this.auditFailure("oauth.token.authorization_code", error, clientId);
      throw error;
    }
  }

  async refresh(input: RefreshGrantInput): Promise<UserTokenResponse> {
    let clientId: string | undefined;
    try {
      const fields = grantFields(input);
      clientId = optionalString(fields.clientId, "client_id");
      if (fields.grantType !== "refresh_token") {
        throw new OAuthError("unsupported_grant_type", "grant_type is not supported");
      }
      const raw = requiredStr(fields.refreshToken as string | undefined, "refresh_token");
      const familyId = parseRefreshFamilyId(raw);
      if (!familyId) throw new OAuthError("invalid_grant", "Refresh token is invalid");
      const nextRaw = generateRefreshToken(familyId);
      const previousHash = sha256Hex(raw);
      const nowMs = this.clock.nowMs();
      const nowIso = new Date(nowMs).toISOString();
      const rotated = await this.store.rotateRefreshToken(
        previousHash,
        {
          tokenHash: sha256Hex(nextRaw), familyId, previousTokenHash: previousHash,
          clientId: clientId ?? "", subject: "", scopes: [],
          expiresAt: new Date(nowMs + this.config.refreshTokenTtlSeconds * 1000).toISOString(),
        },
        nowIso,
      );
      const record = parseRotatedRefreshToken(rotated, {
        tokenHash: previousHash, familyId, nowIso,
      });
      if (record === null) throw new OAuthError("invalid_grant", "Refresh token is invalid");
      // RFC 6749 §6: the grant must bind to the token's stored client_id. The
      // rotated record carries the STORED client (rotation backfill, §12.2.4); a
      // missing/mismatched client_id signals theft/replay — revoke and reject.
      if (!clientId || clientId !== record.clientId) {
        await this.store.revokeRefreshTokenFamily(familyId, nowIso);
        throw new OAuthError("invalid_grant", "Refresh token client binding is invalid");
      }
      if (record.subject.startsWith("mcc_")) { // pre-success-audit (§9.3): revoke the legacy family outright — it can never mint
        await this.store.revokeRefreshTokenFamily(familyId, nowIso);
        throw new OAuthError("invalid_grant", "Grant subject uses the reserved machine-client namespace");
      }
      const response = await this.tokenResponse(record, nextRaw);
      await this.auditToken("oauth.token.refresh", "success", record);
      return response;
    } catch (error) {
      await this.auditFailure("oauth.token.refresh", error, clientId);
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
      const fields = grantFields(input);
      // Fail-closed (defense-in-depth): metadata does not advertise the surface
      // unless enabled; boot already requires stored DCR when it is.
      if (fields.grantType !== "client_credentials"
        || !ownBooleanTrue(ownDataValue(this.config, "clientCredentials"), "enabled")) {
        throw new OAuthError("unsupported_grant_type", "grant_type is not supported");
      }
      const clientStore = this.config.dcr.mode === "stored" ? this.config.dcr.store : null;
      // RFC 6749 §2.3.1 / OAuth 2.1 §2.4.1: Basic takes precedence; a Basic header
      // AND a body secret = two methods ⇒ rejected (§2.3), keyed on scheme presence.
      const authorization = optionalString(fields.authorization, "authorization");
      const postedSecret = optionalString(fields.clientSecret, "client_secret");
      const basic = parseBasicAuth(authorization);
      clientId = basic ? basic.clientId : optionalString(fields.clientId, "client_id");
      if (isBasicAttempt(authorization) && postedSecret) throw new OAuthError("invalid_client", "Multiple client authentication methods present", 401);
      const clientSecret = basic ? basic.clientSecret : postedSecret;
      if (!clientId || !clientSecret || !clientStore) throw new OAuthError("invalid_client", "Client authentication is required", 401);
      const client = await authenticateMachineClient(
        { store: clientStore, catalog: this.config.scopeCatalog, clock: this.clock, audit: this.audit },
        clientId,
        clientSecret,
      );
      // verify validates secret slots only; the grant defends the mcc_ sub-prefix (RS distinguishability) + the allowedScopes ceiling ⇒ invalid_client.
      if (!client || !clientId.startsWith("mcc_")) throw new OAuthError("invalid_client", "Client authentication failed", 401);
      const scope = optionalString(fields.scope, "scope");
      const resource = optionalString(fields.resource, "resource");
      const scopes = resolveClientCredentialsScope(scope, client.allowedScopes, this.config.scopeCatalog);
      if (resource !== undefined && resource !== this.config.resource) throw new OAuthError("invalid_target", "resource does not match the configured resource");
      const accessToken = await signAccessToken({ subject: clientId, clientId, scopes, machine: true }, this.config, this.clock);
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
      const tokenHash = sha256Hex(refreshToken);
      const existing = parseFoundRefreshToken(await this.store.findRefreshToken(tokenHash), tokenHash);
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

  private async consumeValidCode(input: Readonly<Record<string, unknown>>): Promise<AuthCodeRecord> {
    const code = requiredStr(input.code as string | undefined, "code");
    const codeHash = sha256Hex(code);
    const nowIso = new Date(this.clock.nowMs()).toISOString();
    const record = parseConsumedAuthCode(
      await this.store.consumeAuthCode(codeHash, nowIso),
      { codeHash, resource: this.config.resource, nowIso },
    );
    if (record === null) throw new OAuthError("invalid_grant", "Authorization code is invalid");
    if (input.clientId !== record.clientId || input.redirectUri !== record.redirectUri) {
      throw new OAuthError("invalid_grant", "Authorization code is invalid");
    }
    if (!verifyPkceS256(requiredStr(input.codeVerifier as string | undefined, "code_verifier"), record.codeChallenge)) {
      throw new OAuthError("invalid_grant", "Authorization code is invalid");
    }
    return record;
  }

  private async tokenResponse(record: AuthCodeRecord | RefreshTokenRecord, refreshToken: string): Promise<UserTokenResponse> {
    const scopes = storedScopes(record.scopes, this.config.scopeCatalog);
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
