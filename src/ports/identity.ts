// IdentityPort — the upstream identity boundary (contracts §6.5). The core's
// authorize use-case takes a REQUIRED verified `subject`; the adapter/composition
// root calls an IdentityPort to obtain it (or fails closed). v0.1 states the
// boundary so the core never depends on a specific IdP; concrete implementations
// (CloudflareAccessIdentity, EntraIdentity) arrive in Phase 3.

import {
  snapshotClassDataRecord, snapshotOwnDataRecord, snapshotOwnStringArray,
} from "../own-property.ts";

export interface IdentityClaims {
  subject: string;
  /** Optional authorization ceiling (contracts §17.4): when present, the
   *  authorize flow narrows requested/default scopes to this set by
   *  intersection (empty ⇒ access_denied). Set by an identity port from an
   *  IdP-specific source (e.g. Entra group→scope mapping); any port may set it. */
  allowedScopes?: string[];
  /** Optional verified attributes (e.g. email, oid, tid) the host may carry. */
  claims?: Record<string, unknown>;
}

export type IdentityResult = { ok: true; identity: IdentityClaims } | { ok: false; reason: string };

/** Resolves a verified subject from an inbound authorize request. The shape of
 *  `input` is IdP-specific (a header value, an upstream code, etc.); the core
 *  never inspects it — the adapter translates and calls the port. */
export interface IdentityPort {
  verify(input: unknown): Promise<IdentityResult>;
}

/** A redirect-based upstream IdP (contracts §17.11). The orchestrator
 *  (`createUpstreamRedirectFlow`) drives the browser↔IdP leg: it generates
 *  `state`/`nonce`/PKCE, redirects to `buildAuthorizationUrl`, then at the
 *  callback calls `exchangeAndVerify`. One port instance per flow/adapter
 *  (exactly one upstream IdP on one bridge — §17.11 out-of-scope). */
export interface RedirectIdentityPort {
  /** The exact redirect URI registered at the IdP. Boot-asserted equal to
   *  `issuerOrigin(config) + callbackPath` — the callback is served by the same
   *  app at the issuer origin, and a mismatch is silent breakage at the IdP. */
  readonly redirectUri: string;
  /** Build the IdP authorization URL (auth-code + PKCE S256). The orchestrator
   *  owns `state`/`nonce`/`codeChallenge` (uniform CSPRNG); the port contributes
   *  its fixed upstream scope + `response_mode=query`. */
  buildAuthorizationUrl(req: {
    state: string; nonce: string;
    codeChallenge: string; codeChallengeMethod: "S256";
  }): string;
  /** Exchange the code and verify the resulting identity. MUST bind the id_token
   *  to `nonce` when the provider issues id_tokens (OIDC); a provider with no
   *  id_token (the §17.6 GitHub port) verifies via its REST calls and reports
   *  through the same result type — that gap is documented per-port, never silent.
   *  A THROW is always classified `exchange_failed` by the orchestrator (one
   *  deterministic rule, so the two failure channels never depend on which
   *  exception a port happened to raise); `identity_rejected` is returned only. */
  exchangeAndVerify(args: {
    code: string; codeVerifier: string; nonce: string;
  }): Promise<RedirectExchangeResult>;
}

/** Outcome of a redirect exchange+verify (§17.11). */
export type RedirectExchangeResult =
  | { ok: true; identity: IdentityClaims }
  /** Transport/protocol failure — non-200, timeout, malformed body, missing
   *  id_token (for a provider that issues them). No identity decision made. */
  | { ok: false; kind: "exchange_failed"; reason: string }
  /** Verified-context denial — bad iss/aud/tid/nonce, allowlist, group
   *  rejection. An identity decision WAS made: the user is refused. */
  | { ok: false; kind: "identity_rejected"; reason: string };

/** Parse an untrusted port result into an own-data identity decision. */
export function parseIdentityResult(value: unknown): IdentityResult | null {
  const result = snapshotClassDataRecord(value, ["ok", "reason", "identity"]);
  if (result === null) return null;
  if (result.ok === false) {
    return typeof result.reason === "string" && result.reason
      ? Object.freeze({ ok: false, reason: result.reason }) : null;
  }
  if (result.ok !== true) return null;
  const identityFields = snapshotClassDataRecord(
    result.identity,
    ["subject", "allowedScopes", "claims"],
  );
  if (identityFields !== null && typeof identityFields.subject === "string"
    && identityFields.subject && identityFields.allowedScopes !== undefined
    && snapshotOwnStringArray(identityFields.allowedScopes) === null) {
    // Preserve the boundary's specific audit classification while still
    // converting the malformed success result into a closed decision.
    return Object.freeze({ ok: false, reason: "malformed_allowed_scopes" });
  }
  const identity = parseIdentityClaims(result.identity);
  return identity ? Object.freeze({ ok: true, identity }) : null;
}

export function parseRedirectExchangeResult(value: unknown): RedirectExchangeResult | null {
  const result = snapshotClassDataRecord(value, ["ok", "kind", "reason", "identity"]);
  if (result === null) return null;
  if (result.ok === true) {
    const identity = parseIdentityClaims(result.identity);
    return identity ? Object.freeze({ ok: true, identity }) : null;
  }
  if (result.ok !== false || (result.kind !== "exchange_failed" && result.kind !== "identity_rejected")
    || typeof result.reason !== "string" || !result.reason) return null;
  return Object.freeze({ ok: false, kind: result.kind, reason: result.reason });
}

function parseIdentityClaims(value: unknown): IdentityClaims | null {
  const identity = snapshotClassDataRecord(value, ["subject", "allowedScopes", "claims"]);
  if (identity === null || typeof identity.subject !== "string" || !identity.subject) return null;
  const scopes = identity.allowedScopes === undefined ? undefined
    : snapshotOwnStringArray(identity.allowedScopes);
  if (scopes === null) return null;
  const claims = identity.claims === undefined ? undefined : snapshotOwnDataRecord(identity.claims);
  if (claims === null) return null;
  return Object.freeze({
    subject: identity.subject,
    allowedScopes: scopes === undefined ? undefined : Object.freeze([...scopes]) as string[],
    claims,
  });
}
