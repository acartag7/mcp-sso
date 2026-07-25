// `oauth.authorize.*` audit emitters. Extracted from `authorize.ts` so the
// use-case stays under the 250-line cap without shortening the security
// rationale in `prepare`/`approve`; the two events are a pair and read better
// side by side, where the success/failure field sets can be compared directly.

import type { AuditPort } from "./ports/audit.ts";
import type { ClockPort } from "./ports/clock.ts";
import { OAuthError } from "./errors.ts";
import { hostOf } from "./authorize-internals.ts";

export type AuthorizeAuditEvent = "oauth.authorize.prepare" | "oauth.authorize.approve";

export interface AuthorizeAuditSuccess {
  clientId: string;
  redirectUri: string;
  resource: string;
  scopes: string[];
  subject: string;
}

export async function writeAuthorizeSuccess(
  audit: AuditPort, clock: ClockPort, event: AuthorizeAuditEvent, r: AuthorizeAuditSuccess,
): Promise<void> {
  await audit.writeAuthEvent({
    occurredAt: new Date(clock.nowMs()).toISOString(), event, status: "success",
    clientId: r.clientId, subject: r.subject, resource: r.resource, scopes: r.scopes,
    redirectHost: hostOf(r.redirectUri),
  });
}

/** Only the OAuth error CODE is audited — never the description, which can
 *  carry externally-influenced text (log-injection / leak). An unrecognized
 *  throwable is the fixed `internal_error`. */
export async function writeAuthorizeFailure(
  audit: AuditPort, clock: ClockPort, event: AuthorizeAuditEvent, error: unknown,
  clientId?: string, redirectUri?: string, subject?: string,
): Promise<void> {
  await audit.writeAuthEvent({
    occurredAt: new Date(clock.nowMs()).toISOString(), event, status: "failure",
    clientId, subject, redirectHost: redirectUri ? hostOf(redirectUri) : undefined,
    reason: error instanceof OAuthError ? error.code : "internal_error",
  });
}
