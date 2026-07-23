// IdentityPort — the upstream identity boundary (contracts §6.5). The core's
// authorize use-case takes a REQUIRED verified `subject`; the adapter/composition
// root calls an IdentityPort to obtain it (or fails closed). v0.1 states the
// boundary so the core never depends on a specific IdP; concrete implementations
// (CloudflareAccessIdentity, EntraIdentity) arrive in Phase 3.

import {
  bindClassDataMethod, classDataValue, inspectClassDataRecord,
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
   *  exception a port happened to raise); `identity_rejected` is returned only
   *  for a verified-context denial or malformed authorization ceiling after a
   *  subject decision was reached. */
  exchangeAndVerify(args: {
    code: string; codeVerifier: string; nonce: string;
  }): Promise<RedirectExchangeResult>;
}

/** Outcome of a redirect exchange+verify (§17.11). */
export type RedirectExchangeResult =
  | { ok: true; identity: IdentityClaims }
  /** Transport/protocol failure — non-200, timeout, malformed upstream
   *  response/JWKS, missing id_token. No identity decision made. */
  | { ok: false; kind: "exchange_failed"; reason: string }
  /** Verified-context denial — bad iss/aud/tid/nonce, allowlist, group
   *  rejection, or malformed authorization ceiling after a valid subject.
   *  An identity decision WAS made: the user is refused. */
  | { ok: false; kind: "identity_rejected"; reason: string };

/** Capture caller-supplied identity ports once without consulting plain
 * prototypes or accessors. Returned methods stay bound to their source. */
export function captureIdentityPort(value: unknown): Readonly<IdentityPort> | null {
  const verify = bindClassDataMethod<IdentityPort["verify"]>(value, "verify");
  return verify === undefined ? null : Object.freeze({ verify });
}

export function captureRedirectIdentityPort(
  value: unknown,
): Readonly<RedirectIdentityPort> | null {
  const redirectUri = classDataValue(value, "redirectUri");
  const buildAuthorizationUrl =
    bindClassDataMethod<RedirectIdentityPort["buildAuthorizationUrl"]>(
      value, "buildAuthorizationUrl",
    );
  const exchangeAndVerify =
    bindClassDataMethod<RedirectIdentityPort["exchangeAndVerify"]>(
      value, "exchangeAndVerify",
    );
  if (typeof redirectUri !== "string" || buildAuthorizationUrl === undefined
    || exchangeAndVerify === undefined) return null;
  return Object.freeze({ redirectUri, buildAuthorizationUrl, exchangeAndVerify });
}

/** Parse an untrusted port result into an own-data identity decision. */
export function parseIdentityResult(value: unknown): IdentityResult | null {
  const result = snapshotClassDataRecord(value, ["ok", "reason", "identity"]);
  if (result === null) return null;
  if (result.ok === false) {
    return typeof result.reason === "string" && result.reason
      ? Object.freeze({ ok: false, reason: result.reason }) : null;
  }
  if (result.ok !== true) return null;
  const parsed = parseIdentityClaims(result.identity);
  if (!parsed.ok && parsed.reason === "malformed_allowed_scopes") {
    return Object.freeze({ ok: false, reason: "malformed_allowed_scopes" });
  }
  return parsed.ok ? Object.freeze({ ok: true, identity: parsed.identity }) : null;
}

export function parseRedirectExchangeResult(value: unknown): RedirectExchangeResult | null {
  const result = snapshotClassDataRecord(value, ["ok", "kind", "reason", "identity"]);
  if (result === null) return null;
  if (result.ok === true) {
    const parsed = parseIdentityClaims(result.identity);
    if (!parsed.ok && parsed.reason === "malformed_allowed_scopes") {
      return Object.freeze({
        ok: false, kind: "identity_rejected", reason: "malformed_allowed_scopes",
      });
    }
    return parsed.ok ? Object.freeze({ ok: true, identity: parsed.identity }) : null;
  }
  if (result.ok !== false || (result.kind !== "exchange_failed" && result.kind !== "identity_rejected")
    || typeof result.reason !== "string" || !result.reason) return null;
  return Object.freeze({ ok: false, kind: result.kind, reason: result.reason });
}

type ParsedIdentityClaims =
  | { readonly ok: true; readonly identity: IdentityClaims }
  | { readonly ok: false; readonly reason: "malformed_identity" | "malformed_allowed_scopes" };

function parseIdentityClaims(value: unknown): ParsedIdentityClaims {
  const inspected = inspectClassDataRecord(value, ["subject", "allowedScopes", "claims"]);
  if (inspected === null) return { ok: false, reason: "malformed_identity" };
  const identity = inspected.values;
  const validSubject = typeof identity.subject === "string" && identity.subject;
  if (inspected.invalidField !== undefined) {
    return {
      ok: false,
      reason: inspected.invalidField === "allowedScopes" && validSubject
        ? "malformed_allowed_scopes" : "malformed_identity",
    };
  }
  if (!validSubject) return { ok: false, reason: "malformed_identity" };
  const scopes = identity.allowedScopes === undefined
    ? undefined : snapshotOwnStringArray(identity.allowedScopes);
  if (scopes === null) return { ok: false, reason: "malformed_allowed_scopes" };
  const claims = identity.claims === undefined
    ? undefined : snapshotOwnDataRecord(identity.claims);
  if (claims === null) return { ok: false, reason: "malformed_identity" };
  return { ok: true, identity: Object.freeze({
    subject: identity.subject as string,
    allowedScopes: scopes === undefined ? undefined : Object.freeze([...scopes]) as string[],
    claims,
  }) };
}
