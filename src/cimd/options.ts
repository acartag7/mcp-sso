// `BridgeConfig.cimd` shape + fail-closed boot validation (contracts §17.1 /
// §17.1.5 rule 21 / §17.1.6 decision 5). Kept out of `config.ts` so the
// canonical config file stays under the 250-line limit; the validator returns a
// message rather than throwing so there is no import cycle with
// `AuthConfigError` — `createBridgeConfig` throws it.

/** Opt-in to CIMD — Client ID Metadata Documents. Absent ⇒ CIMD disabled and
 *  every scheme-shaped `client_id` is rejected `invalid_client` (direct).
 *  There is deliberately **no `fetcher` knob and no `allowLoopback` field**
 *  (decision 5): the core constructs the branded guarded fetcher itself from
 *  these caps, with `allowLoopback` derived SOLELY from
 *  `dev.allowInsecureLocalhost`. Each cap has a closed integer domain — an
 *  out-of-domain, non-integer, `NaN`, `Infinity`, `null`, or wrong-typed value
 *  is an `AuthConfigError` at boot (rule 21, fail-closed). */
export interface CimdOptions {
  enabled: true;
  /** [1024, 65536], default 5120. */
  maxDocumentBytes?: number;
  /** [1000, 30000], default 5000 — one wall-clock deadline, DNS→body. */
  fetchTimeoutMs?: number;
  /** [60, 86400], default 3600. */
  cacheTtlCapSeconds?: number;
  /** [1, 64], default 8 — the global in-flight fetch cap. */
  maxInFlight?: number;
}

/** Every accepted `cimd` key. A `fetcher` or `allowLoopback` key is REJECTED
 *  here — not silently ignored — so a deployer-supplied whole fetcher can never
 *  become a production injection point and loopback can never be widened
 *  outside `dev.allowInsecureLocalhost` (decision 5). */
const KNOWN_CIMD_KEYS: ReadonlySet<string> = new Set([
  "enabled", "maxDocumentBytes", "fetchTimeoutMs", "cacheTtlCapSeconds", "maxInFlight",
]);

const CIMD_CAPS: ReadonlyArray<{ key: string; min: number; max: number }> = [
  { key: "maxDocumentBytes", min: 1024, max: 65536 },
  { key: "fetchTimeoutMs", min: 1000, max: 30000 },
  { key: "cacheTtlCapSeconds", min: 60, max: 86400 },
  { key: "maxInFlight", min: 1, max: 64 },
];

/** Returns a boot-failure message, or `null` when the block is acceptable. */
export function cimdConfigProblem(cimd: unknown): string | null {
  if (typeof cimd !== "object" || cimd === null || Array.isArray(cimd)) return "cimd must be an object";
  for (const key of Reflect.ownKeys(cimd)) {
    if (typeof key === "symbol" || !KNOWN_CIMD_KEYS.has(key)) {
      return `unknown cimd key "${String(key)}": there is no whole-fetcher knob and no allowLoopback field `
        + `(§17.1.6 decision 5 — the core constructs the guarded fetcher; loopback derives solely from dev.allowInsecureLocalhost)`;
    }
  }
  const value = cimd as Record<string, unknown>;
  if (value.enabled !== true) {
    return "cimd.enabled must be true when the cimd block is present (omit the block to disable)";
  }
  for (const cap of CIMD_CAPS) {
    if (!Object.hasOwn(value, cap.key)) continue;
    const raw = value[cap.key];
    if (typeof raw !== "number" || !Number.isInteger(raw) || raw < cap.min || raw > cap.max) {
      return `cimd.${cap.key} must be an integer in [${cap.min}, ${cap.max}]`;
    }
  }
  return null;
}
