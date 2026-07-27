import type { AuditPort, AuthAuditEvent } from "./ports/audit.ts";

/** Token outcomes must not depend on a custom audit sink staying healthy. */
export async function writeTokenAudit(audit: AuditPort, event: AuthAuditEvent): Promise<void> {
  try {
    await audit.writeAuthEvent(event);
  } catch {
    // Audit evidence is fail-open by contract; the OAuth result is authoritative.
  }
}
