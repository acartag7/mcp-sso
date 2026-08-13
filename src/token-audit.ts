import type { AuditPort, AuthAuditEvent } from "./ports/audit.ts";
import { writeAuditBestEffort } from "./audit/best-effort.ts";

/** Token outcomes must not depend on a custom audit sink staying healthy. */
export async function writeTokenAudit(audit: AuditPort, event: AuthAuditEvent): Promise<void> {
  await writeAuditBestEffort(audit, event);
}
