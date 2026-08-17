import { writeAuditBestEffort } from "../audit/best-effort.ts";
import type { AuditPort } from "../ports/audit.ts";
import { finiteClockSnapshot, type ClockPort } from "../ports/clock.ts";

export async function writeCimdAudit(
  audit: AuditPort,
  clock: ClockPort,
  status: "success" | "failure",
  reason: string | undefined,
  clientId: string,
  ip?: string,
  selectedClientAuthMethod?: "none",
): Promise<void> {
  await writeAuditBestEffort(audit, {
    occurredAt: new Date(finiteClockSnapshot(clock)).toISOString(),
    event: "oauth.cimd.fetch", status, reason, clientId, ip,
    ...(selectedClientAuthMethod === undefined ? {} : { selectedClientAuthMethod }),
  });
}
