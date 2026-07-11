// RequestAuthorizer — the resource-server verifier (contracts §8.4). Extracts the
// bearer token, verifies it (audience fail-closed), enforces scope step-up, and
// audits. NO bypass path: there is intentionally no local/unauthenticated flavor.

import type { ClockPort } from "./ports/clock.ts";
import type { AuditPort } from "./ports/audit.ts";
import type { BridgeConfig } from "./config.ts";
import type { AuthorizedSubject } from "./scopes.ts";
import { requireScope } from "./scopes.ts";
import { OAuthError } from "./errors.ts";
import { verifyAccessToken } from "./crypto.ts";

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
    this.config = deps.config;
    this.clock = deps.clock;
    this.audit = deps.audit;
  }

  async authorize(input: RequestAuthInput): Promise<RequestAuthResult> {
    try {
      const token = bearerToken(input.authorization);
      const verified = await verifyAccessToken(token, this.config, this.clock);
      if (input.requiredScope) requireScope(verified, input.requiredScope);
      await this.audit.writeAuthEvent({
        occurredAt: new Date(this.clock.nowMs()).toISOString(),
        event: "auth.request", status: "success",
        clientId: verified.clientId, subject: verified.subject, scopes: verified.scopes,
        reason: input.requiredScope,
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

function bearerToken(header: string | string[] | undefined): string {
  const value = Array.isArray(header) ? header[0] : header;
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
