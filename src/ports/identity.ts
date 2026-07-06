// IdentityPort — the upstream identity boundary (contracts §6.5). The core's
// authorize use-case takes a REQUIRED verified `subject`; the adapter/composition
// root calls an IdentityPort to obtain it (or fails closed). v0.1 states the
// boundary so the core never depends on a specific IdP; concrete implementations
// (CloudflareAccessIdentity, EntraIdentity) arrive in Phase 3.

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
