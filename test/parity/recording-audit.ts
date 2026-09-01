import type { AuthAuditEvent, AuditPort } from "../../src/ports/audit.ts";

export class RecordingAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];

  async writeAuthEvent(event: AuthAuditEvent): Promise<void> {
    this.events.push(structuredClone(event));
  }
}
