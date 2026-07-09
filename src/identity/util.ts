// Shared identity-port helpers. Currently: the raw `^https://` trust-root check
// (addendum 11, contracts §6.5) hoisted here so every identity port (Entra,
// Cloudflare Access, the §17.6 generic/Google ports) enforces the SAME logic —
// the "sweep for sibling instances" rule. The check runs BEFORE `new URL()`
// because Node's lenient parser normalizes `https:/host` into a valid-looking
// URL, which would let an http JWKS/issuer slip through → a MITM substitutes
// signing keys → total auth bypass.

/** Throw unless `value` starts with the literal `https://`. The label names the
 *  offending field in the thrown message (errors may be logged; the value
 *  itself is never echoed). */
export function assertHttpsRaw(value: string, label: string): void {
  if (!value.startsWith("https://")) {
    throw new Error(`${label} must be an https:// URL (http trust roots allow key substitution)`);
  }
}
