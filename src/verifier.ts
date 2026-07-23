// RequestAuthorizer — the resource-server verifier (contracts §8.4). Extracts the
// bearer token, verifies it (audience fail-closed), enforces scope step-up, and
// audits. NO bypass path: there is intentionally no local/unauthenticated flavor.

import type { ClockPort } from "./ports/clock.ts";
import type { AuditPort } from "./ports/audit.ts";
import { assertBridgeConfig, type BridgeConfig } from "./config.ts";
import type { AuthorizedSubject } from "./scopes.ts";
import { requireScope } from "./scopes.ts";
import { OAuthError } from "./errors.ts";
import { verifyAccessToken } from "./crypto.ts";
import { snapshotOwnDataArray, snapshotOwnDataRecord } from "./own-property.ts";

export interface RequestAuthDeps {
  config: BridgeConfig;
  clock: ClockPort;
  audit: AuditPort;
}

export interface RequestAuthInput {
  authorization?: string | string[];
  requiredScope?: string;
}

export type RequestAuthResult = AuthorizedSubject;

export class RequestAuthorizer {
  private readonly config: BridgeConfig;
  private readonly clock: ClockPort;
  private readonly audit: AuditPort;

  constructor(deps: RequestAuthDeps) {
    const fields = snapshotOwnDataRecord(deps);
    if (fields === null || !fields.config || !fields.clock || !fields.audit) {
      throw new TypeError("Request-authorizer dependencies must be own data properties");
    }
    this.config = assertBridgeConfig(fields.config);
    this.clock = fields.clock as ClockPort;
    this.audit = fields.audit as AuditPort;
  }

  async authorize(input: RequestAuthInput): Promise<RequestAuthResult> {
    try {
      const fields = snapshotOwnDataRecord(input);
      if (fields === null) throw new OAuthError("invalid_token", "Authorization input is malformed", 401);
      const token = bearerToken(fields.authorization);
      const verified = await verifyAccessToken(token, this.config, this.clock);
      if (fields.requiredScope !== undefined && typeof fields.requiredScope !== "string") {
        throw new OAuthError("invalid_token", "requiredScope is malformed", 401);
      }
      if (fields.requiredScope) requireScope(verified, fields.requiredScope);
      await this.audit.writeAuthEvent({
        occurredAt: new Date(this.clock.nowMs()).toISOString(),
        event: "auth.request", status: "success",
        clientId: verified.clientId, subject: verified.subject, scopes: verified.scopes,
        reason: fields.requiredScope as string | undefined,
      });
      return verified;
    } catch (error) {
      await this.audit.writeAuthEvent({
        occurredAt: new Date(this.clock.nowMs()).toISOString(),
        event: "auth.request", status: "failure",
        reason: error instanceof OAuthError ? error.code : "invalid_token",
      });
      throw error;
    }
  }
}

export function createRequestAuthorizer(deps: RequestAuthDeps): RequestAuthorizer {
  return new RequestAuthorizer(deps);
}

function bearerToken(header: unknown): string {
  const values = snapshotOwnDataArray(header);
  const value = values === null ? header : values[0];
  if (typeof value !== "string") throw new OAuthError("invalid_token", "Bearer token is required", 401);
  if (!value) throw new OAuthError("invalid_token", "Bearer token is required", 401);
  // Capture a whitespace-free token68 (RFC 6750 §2.1: `Bearer 1*SP b64token`). The
  // prior `(.+)` shared the space character with `\s+` (a `\s`/`.` overlap), the
  // CodeQL js/polynomial-redos trigger; `\S+` is complementary to `\s`, so the two
  // quantifiers cannot backtrack ambiguously. It is also stricter: a bearer value
  // with internal whitespace is malformed and fails closed here (401).
  const match = /^Bearer\s+(\S+)$/i.exec(value.trim());
  if (!match?.[1]) throw new OAuthError("invalid_token", "Bearer token is required", 401);
  return match[1];
}
