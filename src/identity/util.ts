// Shared identity-port helpers: raw `^https://` trust-root checks and safe
// capture of Fetch-compatible transport responses.
// (addendum 11, contracts §6.5) hoisted here so every identity port (Entra,
// Cloudflare Access, the §17.6 generic/Google ports) enforces the SAME logic —
// the "sweep for sibling instances" rule. The check runs BEFORE `new URL()`
// because Node's lenient parser normalizes `https:/host` into a valid-looking
// URL, which would let an http JWKS/issuer slip through → a MITM substitutes
// signing keys → total auth bypass.

import { bindClassDataMethod, classDataValue } from "../own-property.ts";

/** Throw unless `value` starts with the literal `https://`. The label names the
 *  offending field in the thrown message (errors may be logged; the value
 *  itself is never echoed). */
export function assertHttpsRaw(value: string, label: string): void {
  if (typeof value !== "string" || !value.startsWith("https://")) {
    throw new Error(`${label} must be an https:// URL (http trust roots allow key substitution)`);
  }
}

export interface CapturedHttpResponse {
  readonly status: number;
  read(): Promise<unknown>;
}

/** Capture a trusted transport response without consulting Object.prototype.
 * Accepts both object-literal seams and standard Response/class instances. */
export function captureHttpResponse(
  value: unknown,
  method: "json" | "text",
): CapturedHttpResponse | null {
  const status = classDataValue(value, "status");
  const read = bindClassDataMethod<() => Promise<unknown>>(value, method);
  if (typeof status !== "number" || !Number.isFinite(status) || read === undefined) return null;
  return Object.freeze({ status, read });
}
