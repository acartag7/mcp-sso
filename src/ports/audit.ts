// Append-only, metadata-only auth audit (contracts §13). No token values, no
// Authorization/Set-Cookie, no request bodies. Tool-call auditing is the host
// app's concern, not this library's.

export type AuthAuditStatus = "success" | "failure";

export type AuthAuditEventName =
  | "oauth.register"
  | "oauth.authorize.prepare"
  | "oauth.authorize.approve"
  | "oauth.token.authorization_code"
  | "oauth.token.refresh"
  | "oauth.revoke"
  | "auth.request";

export interface AuthAuditEvent {
  occurredAt: string;
  event: AuthAuditEventName;
  status: AuthAuditStatus;
  clientId?: string;
  subject?: string;
  resource?: string;
  scopes?: string[];
  redirectHost?: string;
  reason?: string;
}

export interface AuditPort {
  writeAuthEvent(event: AuthAuditEvent): Promise<void>;
}

export const noopAudit: AuditPort = {
  async writeAuthEvent(): Promise<void> {
    // Intentionally empty for tests / local composition.
  },
};
