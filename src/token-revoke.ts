import type { AuditPort } from "./ports/audit.ts";
import type { ClockPort } from "./ports/clock.ts";
import type { StorePort } from "./ports/store.ts";
import { sha256Hex } from "./crypto.ts";
import { writeTokenAudit } from "./token-audit.ts";

interface RevokeDeps {
  store: StorePort;
  clock: ClockPort;
  audit: AuditPort;
}

/** RFC 7009 keeps the response non-oracular while audit distinguishes outage. */
export async function revokeRefreshToken(deps: RevokeDeps, refreshToken: string | undefined): Promise<void> {
  const occurredAt = new Date(deps.clock.nowMs()).toISOString();
  try {
    let revoked = false;
    if (refreshToken) {
      const existing = await deps.store.findRefreshToken(sha256Hex(refreshToken));
      if (existing) {
        await deps.store.revokeRefreshTokenFamily(existing.familyId, occurredAt);
        revoked = true;
      }
    }
    await writeTokenAudit(deps.audit, {
      occurredAt, event: "oauth.revoke", status: "success",
      reason: revoked ? undefined : "unrecognized_token",
    });
  } catch (error) {
    await writeTokenAudit(deps.audit, {
      occurredAt, event: "oauth.revoke", status: "failure", reason: "internal_error",
    });
    throw error;
  }
}
