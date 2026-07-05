// combineAudit — fan-out over multiple AuditPort sinks (contracts §17.7).
// Each event is delivered to every sink; one sink's failure NEVER stops the
// others (threat-model row 24, "fan-out isolation").
//
// Fail-open by design (matches each sink's own posture): the returned sink
// NEVER rejects from writeAuthEvent. Each sink call is wrapped so a SYNCHRONOUS
// throw — an `undefined` sink slipped in by a conditional composition root, or
// a custom sink whose `writeAuthEvent` throws before returning a promise — is
// converted to a rejected promise that `Promise.allSettled` then absorbs.
// (allSettled alone does NOT catch a `.map` callback throw, which would otherwise
// reject the composite and break the never-reject invariant.) A per-sink failure
// is surfaced on stderr without the payload or the rejection reason. Audit is
// evidence, not a gate (§17.7).

import type { AuthAuditEvent, AuditPort } from "../ports/audit.ts";

export function combineAudit(...sinks: AuditPort[]): AuditPort {
  if (sinks.length === 0) {
    // An empty fan-out is a no-op sink; it is never a useful configuration, but
    // returning a working AuditPort (rather than throwing) keeps combineAudit
    // safe to use as a default in composition roots that may wire zero sinks.
    return { async writeAuthEvent(): Promise<void> { /* no sinks configured */ } };
  }
  return {
    async writeAuthEvent(event: AuthAuditEvent): Promise<void> {
      const results = await Promise.allSettled(
        sinks.map((sink) => {
          try {
            return sink.writeAuthEvent(event);
          } catch (error) {
            return Promise.reject(error);
          }
        }),
      );
      let failed = 0;
      for (const r of results) {
        if (r.status === "rejected") failed++;
      }
      if (failed > 0) {
        // Never echo the payload (metadata-only though it is) and never echo the
        // rejection reason verbatim — a misbehaving sink could put anything there.
        console.error(
          `[mcp-sso] audit combine: ${failed}/${sinks.length} sink(s) rejected for ${event.event}/${event.status}`,
        );
      }
    },
  };
}
