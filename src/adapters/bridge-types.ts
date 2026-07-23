import type { BridgeConfig } from "../config.ts";
import type { AuditPort } from "../ports/audit.ts";
import type { ClockPort } from "../ports/clock.ts";
import type { RateLimitPort } from "../ports/rate-limit.ts";
import type { StorePort } from "../ports/store.ts";

export interface BridgeDeps {
  config: BridgeConfig;
  store: StorePort;
  clock: ClockPort;
  audit: AuditPort;
  rateLimit?: RateLimitPort;
}
