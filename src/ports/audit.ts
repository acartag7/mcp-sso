// Append-only, metadata-only auth audit (contracts §13). No token values, no
// Authorization/Set-Cookie, no request bodies. Tool-call auditing is the host
// app's concern, not this library's.

export type AuthAuditStatus = "success" | "failure";

// The v0.1 names cover the shipped flow (register, authorize prepare/approve,
// the two token grants, revoke, RS auth.request). The v0.2 names (§17.7) cover
// features whose use-cases land later (S2–S6): identity verify, console pairing,
// device flow, client_credentials, machine-client provisioning/rotation, CIMD.
// They are part of the type now so sinks and tests can carry them before the
// emitting code exists.
export type AuthAuditEventName =
  | "oauth.register"
  | "oauth.authorize.prepare"
  | "oauth.authorize.approve"
  | "oauth.token.authorization_code"
  | "oauth.token.refresh"
  | "oauth.revoke"
  | "auth.request"
  | "identity.verify"
  | "oauth.pairing.attempt"
  | "oauth.device.authorization"
  | "oauth.device.approve"
  | "oauth.token.device_code"
  | "oauth.token.client_credentials"
  | "oauth.client.provision"
  | "oauth.client.rotate_secret"
  | "oauth.cimd.fetch";

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
  /** Adapter-populated client IP (§17.7). Personal data — the deployer owns
   *  retention/redaction (a reverse proxy often yields a better value than the
   *  socket peer). Metadata-only like the rest of the event; never a secret. */
  ip?: string;
}

export interface AuditPort {
  writeAuthEvent(event: AuthAuditEvent): Promise<void>;
}

export const noopAudit: AuditPort = {
  async writeAuthEvent(): Promise<void> {
    // Intentionally empty for tests / local composition.
  },
};
