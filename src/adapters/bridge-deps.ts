import type { BridgeConfig } from "../config.ts";
import type { AuditPort } from "../ports/audit.ts";
import type { ClockPort } from "../ports/clock.ts";
import type { RateLimitPort } from "../ports/rate-limit.ts";
import type { StorePort } from "../ports/store.ts";
import type { CimdTransport, DnsResolver } from "../cimd/transport.ts";

export interface BridgeDeps {
  config: BridgeConfig;
  store: StorePort;
  clock: ClockPort;
  audit: AuditPort;
  /** Optional register/token/revoke/direct-identity limiter; no-op if absent. */
  rateLimit?: RateLimitPort;
  /** Temporary localhost-starter escape hatch. Emits a loud boot warning. */
  acknowledgeUnsafeStatelessDefaults?: true;
  /** Below-guard CIMD test seams. The guard pipeline always surrounds them. */
  cimdTransport?: CimdTransport;
  cimdResolver?: DnsResolver;
}
