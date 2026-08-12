import type { AuditPort, AuthAuditEvent } from "../ports/audit.ts";

/** Submit evidence without allowing sink failure to replace the caller's result. */
export async function writeAuditBestEffort(audit: AuditPort, event: AuthAuditEvent): Promise<void> {
  try {
    await audit.writeAuthEvent(event);
  } catch {
    // Audit evidence is fail-open; the caller's security response is authoritative.
  }
}
