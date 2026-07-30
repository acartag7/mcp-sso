import type { AuditPort, AuthAuditEvent } from "./ports/audit.ts";
import type { ClockPort } from "./ports/clock.ts";
import { OAuthError } from "./errors.ts";

/** Token outcomes must not depend on a custom audit sink staying healthy. */
export async function writeTokenAudit(audit: AuditPort, event: AuthAuditEvent): Promise<void> {
  try {
    await audit.writeAuthEvent(event);
  } catch {
    // Audit evidence is fail-open by contract; the OAuth result is authoritative.
  }
}

/** Failure audit for the two user-grant token events. `resource` is supplied ONLY
 *  once it has been resolved from verified stored lineage (§13) — a failure
 *  before that boundary omits the field rather than guessing or echoing
 *  unvalidated request text. */
export async function writeTokenFailure(
  audit: AuditPort,
  clock: ClockPort,
  event: "oauth.token.authorization_code" | "oauth.token.refresh",
  error: unknown,
  clientId?: string,
  resource?: string,
): Promise<void> {
  await writeTokenAudit(audit, {
    occurredAt: new Date(clock.nowMs()).toISOString(), event, status: "failure",
    clientId, ...(resource === undefined ? {} : { resource }),
    reason: error instanceof OAuthError ? error.code : "internal_error",
  });
}
