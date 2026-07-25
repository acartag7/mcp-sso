// CIMD resolution use-case (§17.1.6 decisions 1a/1b, 2, 4, 6). ONE service owns
// the shared validated-success cache, the single-flight registry, the global
// in-flight cap, the `cimd:<ip>` pre-resolution rate-limit guard, the
// `oauth.cimd.fetch` audit, and the anti-oracle error map. It serves BOTH
// resolution boundaries — direct-mode `prepare` and the upstream-redirect
// authorize — so a cross-mode repeat of one raw client_id is ONE fetch.

import type { BridgeConfig } from "../config.ts";
import type { ClockPort } from "../ports/clock.ts";
import type { AuditPort } from "../ports/audit.ts";
import type { RateLimitPort } from "../ports/rate-limit.ts";
import { noopRateLimit } from "../ports/rate-limit.ts";
import { OAuthError } from "../errors.ts";
import { AuthConfigError } from "../config.ts";
import { CimdError, type CimdReason } from "./errors.ts";
import { createGuardedFetcher, type GuardedFetcher } from "./guarded-fetcher.ts";
import type { CimdTransport, DnsResolver } from "./transport.ts";
import { CimdSuccessCache, computeCacheExpiryMs } from "./cache.ts";
import { cimdRedirectMatches, projectCimdRegistration, type CimdRegistration } from "./registration.ts";

/** The ONE client-facing description every CIMD resolution failure collapses to
 *  (decision 2 — the SSRF content/reachability oracle stays closed). */
const GENERIC_DESCRIPTION = "client_id could not be resolved";

/** Allowlisted audit reasons. An unrecognized (future) `CimdError.reason`, and
 *  any non-`CimdError` throw, audit the fixed `fetch_failed` — never free-form
 *  exception text (log injection / leak). */
const AUDIT_REASONS: ReadonlySet<string> = new Set<CimdReason>([
  "url_admission_denied", "dns_failed", "ip_blocked", "redirect_refused",
  "status_not_200", "content_type", "encoding", "size_exceeded", "timeout",
  "fetch_failed", "document_invalid", "overloaded",
]);

export const CIMD_AUDIT_EVENT = "oauth.cimd.fetch";

export function cimdGenericError(): OAuthError {
  return new OAuthError("invalid_client", GENERIC_DESCRIPTION, 401);
}

/** Exhaustive switch over `CimdReason` + a fail-closed default (decision 2/6). */
export function mapCimdError(error: unknown): OAuthError {
  if (error instanceof CimdError) {
    switch (error.reason) {
      case "url_admission_denied": case "dns_failed": case "ip_blocked":
      case "redirect_refused": case "status_not_200": case "content_type":
      case "encoding": case "size_exceeded": case "timeout":
      case "fetch_failed": case "document_invalid": case "overloaded":
        return cimdGenericError();
      default:
        return cimdGenericError(); // unknown/future reason ⇒ same fail-closed generic
    }
  }
  return cimdGenericError();
}

function auditReason(error: unknown): string {
  if (error instanceof CimdError && AUDIT_REASONS.has(error.reason)) return error.reason;
  return "fetch_failed";
}

export interface CimdResolverDeps {
  config: BridgeConfig;
  clock: ClockPort;
  audit: AuditPort;
  rateLimit?: RateLimitPort;
  /** Below-guard test seams (rule 14 / decision 1e) — never a whole fetcher. */
  cimdTransport?: CimdTransport;
  cimdResolver?: DnsResolver;
}

export interface CimdResolveInput {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly ip?: string;
  /** Below-guard seams ONLY (rule 14 / decision 1e). Deliberately NOT a whole
   *  `GuardedFetcher`: the brand proves a fetcher came from
   *  `createGuardedFetcher`, not that it carries THIS resolver's validated
   *  profile — a genuine `createGuardedFetcher({allowLoopback: true})` is
   *  branded, so accepting one would let a caller resolve and cache a
   *  `https://localhost/...` document on a bridge whose config has loopback
   *  disabled, and every later authorization reads it from the shared cache.
   *  The fetcher is always constructed here from the validated caps. */
  readonly seams?: { readonly transport?: CimdTransport; readonly resolver?: DnsResolver };
}

export interface CimdResolution {
  readonly registration: CimdRegistration;
  /** Deferred so the redirect-mode caller can emit the success event only
   *  AFTER its 4096-byte cookie-oversize guard passes (decision 1b). */
  emitSuccess(): Promise<void>;
}

export class CimdResolver {
  readonly enabled: boolean;
  private readonly config: BridgeConfig;
  private readonly clock: ClockPort;
  private readonly audit: AuditPort;
  private readonly rateLimit: RateLimitPort;
  private readonly cache: CimdSuccessCache;
  private readonly inFlight = new Map<string, Promise<CimdRegistration>>();
  private readonly maxInFlight: number;
  private readonly cacheTtlCapSeconds: number;
  private defaultFetcher: GuardedFetcher | undefined;
  private readonly seams: { transport?: CimdTransport; resolver?: DnsResolver };
  /** Captured ONCE at construction. `config.dev` is the caller's object and the
   *  outer freeze is shallow, so reading it lazily (the default fetcher is
   *  memoized; per-call seam fetchers re-read every request) would let a
   *  post-boot `dev.allowInsecureLocalhost = true` widen loopback after boot
   *  validated it disabled. Same read-once rule as the cap snapshot. */
  private readonly allowLoopback: boolean;
  private readonly maxDocumentBytes: number;
  private readonly fetchTimeoutMs: number;

  constructor(deps: CimdResolverDeps) {
    this.config = deps.config;
    this.clock = deps.clock;
    this.audit = deps.audit;
    this.rateLimit = deps.rateLimit ?? noopRateLimit;
    const cimd = deps.config.cimd;
    this.enabled = cimd?.enabled === true;
    this.maxInFlight = cimd?.maxInFlight ?? 8;
    this.cacheTtlCapSeconds = cimd?.cacheTtlCapSeconds ?? 3600;
    this.cache = new CimdSuccessCache();
    this.seams = { transport: deps.cimdTransport, resolver: deps.cimdResolver };
    // Read-once: capture every fetcher-profile value at construction.
    this.allowLoopback = deps.config.dev?.allowInsecureLocalhost === true;
    this.maxDocumentBytes = cimd?.maxDocumentBytes ?? 5120;
    this.fetchTimeoutMs = cimd?.fetchTimeoutMs ?? 5000;
  }

  /** Build a guarded fetcher for a boundary's own below-guard seams. The caps
   *  and `allowLoopback` always come from the validated config — a seam can
   *  never widen them (decision 5). A cap-domain `TypeError` from the primitive
   *  is reconciled to `AuthConfigError` so boot never leaks a raw TypeError. */
  createFetcher(transport?: CimdTransport, resolver?: DnsResolver): GuardedFetcher {
    try {
      return createGuardedFetcher({
        ...(transport === undefined ? {} : { transport }),
        ...(resolver === undefined ? {} : { resolver }),
        allowLoopback: this.allowLoopback,
        maxDocumentBytes: this.maxDocumentBytes,
        fetchTimeoutMs: this.fetchTimeoutMs,
      });
    } catch (error) {
      throw error instanceof AuthConfigError ? error
        : new AuthConfigError(`cimd configuration is invalid: ${error instanceof TypeError ? error.message : "unknown"}`);
    }
  }

  private fetcher(): GuardedFetcher {
    this.defaultFetcher ??= this.createFetcher(this.seams.transport, this.seams.resolver);
    return this.defaultFetcher;
  }

  /** Per-call below-guard seams (decision 1e) still yield a fetcher built from
   *  the validated profile — only the transport/resolver differ. */
  private fetcherFor(seams?: { readonly transport?: CimdTransport; readonly resolver?: DnsResolver }): GuardedFetcher {
    if (seams?.transport === undefined && seams?.resolver === undefined) return this.fetcher();
    return this.createFetcher(seams.transport, seams.resolver);
  }

  /** Pre-resolution `cimd:<ip>` rate-limit guard (decision 2 — OUTSIDE the
   *  anti-oracle map: a direct 429 `temporarily_unavailable`, no DNS, no
   *  connect, no `oauth.cimd.fetch` audit). Fail-open on a limiter outage,
   *  mirroring the existing register/token/upstream guards. */
  private async rateGuard(ip: string | undefined): Promise<void> {
    let allowed = true;
    try { allowed = await this.rateLimit.check(`cimd:${ip ?? "unknown"}`); } catch { allowed = true; }
    if (!allowed) throw new OAuthError("temporarily_unavailable", "Rate limit exceeded; retry later", 429);
  }

  async resolve(input: CimdResolveInput): Promise<CimdResolution> {
    await this.rateGuard(input.ip);
    try {
      // The fetcher is ALWAYS built here from this resolver's validated caps
      // and config-derived `allowLoopback`; a caller may substitute only the
      // below-guard transport/resolver seams, never the guard itself.
      const outcome = await this.registrationFor(input.clientId, this.fetcherFor(input.seams));
      // A cache HIT reuses the fetched DOCUMENT, never the authorization
      // decision: the shared matcher re-runs on EVERY request.
      if (!cimdRedirectMatches(input.redirectUri, outcome.registration.redirect_uris)) {
        throw new CimdError("document_invalid");
      }
      // Every SUCCESSFUL resolution emits success, cache hit included. Decision
      // 1b's outcome rule is about the resolution, not about whether the network
      // was touched, and the failure side ALREADY audits cache-hit rejections —
      // so auditing only fetches made cached successes invisible while their
      // failures stayed visible, and monitoring silently under-counted.
      // The frozen "no additional success audit for the rejected cache-hit
      // request" row still holds: this closure runs only on the success path,
      // after the matcher passed.
      const emitSuccess = (): Promise<void> =>
        this.emit("success", undefined, input.clientId, input.ip);
      return { registration: outcome.registration, emitSuccess };
    } catch (error) {
      if (error instanceof OAuthError) throw error; // the rate-limit channel is not a resolution outcome
      await this.emit("failure", auditReason(error), input.clientId, input.ip);
      throw mapCimdError(error);
    }
  }

  /** Audit a redirect-mode-only failure (e.g. the cookie-oversize residual)
   *  with a fixed allowlisted reason, then map to the decision-2 generic. */
  async rejectAfterResolve(reason: "oversize", clientId: string, ip?: string): Promise<OAuthError> {
    await this.emit("failure", reason, clientId, ip);
    return cimdGenericError();
  }

  private async registrationFor(rawClientId: string, fetcher: GuardedFetcher): Promise<{ registration: CimdRegistration; fetched: boolean }> {
    const hit = this.cache.get(rawClientId, this.clock.nowMs());
    if (hit !== undefined) return { registration: hit, fetched: false };
    const existing = this.inFlight.get(rawClientId);
    // A coalesced follower does NOT consume an in-flight slot (rule 24).
    if (existing !== undefined) return { registration: await existing, fetched: false };
    if (this.inFlight.size >= this.maxInFlight) throw new CimdError("overloaded");
    const pending = this.fetchAndCache(rawClientId, fetcher);
    this.inFlight.set(rawClientId, pending);
    try {
      return { registration: await pending, fetched: true };
    } finally {
      this.inFlight.delete(rawClientId); // removed on settle: success, error, or timeout
    }
  }

  private async fetchAndCache(rawClientId: string, fetcher: GuardedFetcher): Promise<CimdRegistration> {
    const t0Ms = this.clock.nowMs();
    const result = await fetcher.fetch(rawClientId);
    const t1Ms = this.clock.nowMs();
    // Project BEFORE caching: a raw CimdDocument is never cached or signed.
    const registration = projectCimdRegistration(result.document);
    const expiresAtMs = computeCacheExpiryMs(result.cacheView, this.cacheTtlCapSeconds, t0Ms, t1Ms);
    if (expiresAtMs !== null) this.cache.set(rawClientId, registration, expiresAtMs);
    return registration;
  }

  private async emit(status: "success" | "failure", reason: string | undefined, clientId: string, ip?: string): Promise<void> {
    await this.audit.writeAuthEvent({
      occurredAt: new Date(this.clock.nowMs()).toISOString(),
      event: "oauth.cimd.fetch", status, reason, clientId, ip,
    });
  }
}
