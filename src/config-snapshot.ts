// Boot-time snapshots for the nested `BridgeConfig` blocks and arrays
// (contracts §5, "Publication"). Kept out of `config.ts` so that file stays
// under the 250-line limit; validators return a message rather than throwing, so
// there is no import cycle with `AuthConfigError` — `createBridgeConfig` throws.
//
// Why this exists (issue #100): `Object.freeze` is SHALLOW. Returning the
// caller's own `dcr`/`clientCredentials` block — or its arrays — freezes the top
// level and leaves every nested security setting mutable, while those settings
// are read PER REQUEST (authorize/register/token/metadata/upstream-flow), not
// captured at boot. Boot validation would then describe the object only at the
// instant it ran. Copying one level from an explicit key allowlist makes the
// value read at request time the value boot approved.

import type { JWK } from "jose";
import type { ClientStore } from "./ports/client-store.ts";
import type { ClientCredentialsOptions, DcrMode } from "./config.ts";

/** Validate an array-of-strings field and return the frozen snapshot that was
 *  checked. The returned copy — never the caller's array — is what gets
 *  published (§5 "Publication").
 *
 *  `makeError` is injected rather than imported: `config.ts` imports this
 *  module, so importing `AuthConfigError` back from it would be a cycle. */
export function checkedStringArray(
  label: string,
  value: unknown,
  makeError: (message: string) => Error,
): string[] {
  const checked = stringArrayProblem(label, value);
  if ("problem" in checked) throw makeError(checked.problem);
  return checked.value as string[];
}

/** Validate an array-of-strings config field and return a frozen copy.
 *
 *  A bare string is REJECTED rather than treated as a one-element list, and that
 *  matters beyond tidiness: `allowedOrigins` is consumed with `.includes()`,
 *  which on a string is SUBSTRING matching. A string `"https://a.test"` would
 *  admit the Origin `a.test` (and `ttps://a.tes`), widening the consent-approve
 *  CSRF gate from what looks like a harmless config typo. */
export function stringArrayProblem(
  label: string,
  value: unknown,
): { problem: string } | { value: readonly string[] } {
  if (!Array.isArray(value)) {
    return { problem: `${label} must be an array of strings${typeof value === "string" ? ' (a bare string is not a one-element list — it would be matched by substring)' : ""}` };
  }
  // Read every index ONCE, then validate THAT copy — a getter-backed or
  // later-mutated caller array cannot swap in an unvalidated entry after the
  // check (the read-once rule).
  const entries: unknown[] = [...(value as unknown[])];
  for (const entry of entries) {
    if (typeof entry !== "string") {
      return { problem: `${label} entries must be strings (got ${typeof entry})` };
    }
  }
  return { value: Object.freeze(entries as string[]) };
}

/** Frozen one-level copy of the `dcr` block, built from the ALREADY-READ values.
 *
 *  Takes `mode`/`store` as arguments rather than re-reading them off the caller's
 *  block: an accessor- or Proxy-backed `dcr` can return the approved store during
 *  validation and a different one when the snapshot reads it again, so
 *  re-reading here would publish a store boot never approved — the same
 *  validate-then-copy TOCTOU this module exists to close. The caller reads each
 *  field once, validates THAT value, and hands it in.
 *
 *  `store` is deliberately carried by reference: it is a live port object with
 *  methods, so it cannot be frozen or cloned. The snapshot closes
 *  swap-the-store and flip-the-mode — an attacker holding the caller's `dcr`
 *  object can no longer redirect `find`/`save` to another store, or change
 *  which registration path runs — without touching the port itself. */
export function snapshotDcr(mode: DcrMode["mode"], store: ClientStore | undefined): DcrMode {
  if (mode === "stored") {
    // Named projection, never a spread: an unknown member on the caller's block
    // must not ride along onto the published object.
    return Object.freeze({ mode: "stored" as const, store: store as ClientStore });
  }
  return Object.freeze({ mode: "stateless" as const });
}

/** Frozen one-level copy of the `clientCredentials` block, built from the
 *  ALREADY-VALIDATED boolean.
 *
 *  Takes `enabled` as an argument for the same read-once reason as above: a
 *  getter returning `false` at validation and `true` here would pass the
 *  disabled-grant boot checks while publishing the grant as ENABLED, so AS
 *  metadata and `/oauth/token` would expose a grant boot validated as off.
 *
 *  Prevents flipping `enabled` on a deployment that booted with the grant off —
 *  which would both enable the machine-client grant and change what AS metadata
 *  advertises, bypassing the boot rule that enabling requires stored DCR
 *  (§17.2). */
export function snapshotClientCredentials(enabled: boolean): ClientCredentialsOptions {
  return Object.freeze({ enabled: enabled === true });
}

/** Frozen one-level copy of the signing JWK.
 *
 *  The most sensitive value in `BridgeConfig`, and it was published by
 *  reference: `signKey()` and `publicJwk()` read its properties per use, and
 *  `crypto-keys.ts` memoizes the imported key in a `WeakMap` keyed by this
 *  object — its header calls that a "stable (frozen) reference", which was not
 *  true. A mutation before the first import replaced the validated signing and
 *  JWKS material; a mutation after it desynchronized the cached signer from the
 *  published JWKS, breaking verification of every token the deployment issues.
 *
 *  Copied via an explicit key allowlist rather than a spread: a JWK is a plain
 *  data record, so unknown members must not ride onto the published object.
 *  `undefined` members are omitted so the shape matches what was validated. */
export function snapshotJwk(jwk: JWK): JWK {
  const out: Record<string, unknown> = {};
  for (const key of JWK_KEYS) {
    const value = (jwk as Record<string, unknown>)[key];
    if (value !== undefined) out[key] = value;
  }
  return Object.freeze(out) as JWK;
}

/** Every JWK member this library reads or republishes: the EC key parameters
 *  (RFC 7518 §6.2) plus the JOSE header-ish metadata `publicJwk`/`keyId` use.
 *  A member outside this set is DROPPED, never published — the same fail-closed
 *  direction as `KNOWN_CONFIG_KEYS`. */
const JWK_KEYS: readonly string[] = [
  "kty", "crv", "x", "y", "d", "alg", "kid", "use", "key_ops", "ext",
];

/** Shape predicate for the signing key: EC P-256 with the private scalar and
 *  both public coordinates. Pure — the caller throws (no import cycle). */
export function isEcP256PrivateJwk(jwk: JWK): boolean {
  return jwk.kty === "EC" && jwk.crv === "P-256" && !!jwk.d && !!jwk.x && !!jwk.y;
}
