import type { AuthAuditEvent, AuditPort } from "../../src/ports/audit.ts";

export class RecordingAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];

  async writeAuthEvent(event: AuthAuditEvent): Promise<void> {
    const snapshot = structuredClone(event);
    for (const [key, value] of Object.entries(snapshot)) {
      if (value === undefined) Reflect.deleteProperty(snapshot, key);
    }
    this.events.push(snapshot);
  }
}
