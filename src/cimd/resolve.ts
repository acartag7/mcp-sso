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
import { noopRateLimit, rateLimitIdentity } from "../ports/rate-limit.ts";
import { OAuthError } from "../errors.ts";
import { AuthConfigError } from "../config.ts";
import { CimdError } from "./errors.ts";
import { CIMD_AUDIT_EVENT, auditReason, cimdGenericError, mapCimdError } from "./anti-oracle.ts";
export { CIMD_AUDIT_EVENT, cimdGenericError, mapCimdError } from "./anti-oracle.ts";
import { createGuardedFetcher, type GuardedFetcher } from "./guarded-fetcher.ts";
import type { CimdTransport, DnsResolver } from "./transport.ts";
import { CimdSuccessCache, computeCacheExpiryMs } from "./cache.ts";
import { WaiterCounts } from "./waiters.ts";
import { cimdRedirectMatches, projectCimdRegistration, type CimdRegistration } from "./registration.ts";
import { writeAuditBestEffort } from "../audit/best-effort.ts";
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
  /** Below-guard seams ONLY (rule 14 / decision 1e) — never a whole
   *  `GuardedFetcher`: the brand proves provenance, not that a fetcher carries
   *  THIS resolver's validated profile (a genuine
   *  `createGuardedFetcher({allowLoopback: true})` is branded, and the shared
   *  cache would serve its document to every later authorization). */
  readonly seams?: { readonly transport?: CimdTransport; readonly resolver?: DnsResolver };
  /** The calling boundary's own limiter for the `cimd:<ip>` guard.
   *  `UpstreamFlowDeps.rateLimit` is independent of `BridgeDeps.rateLimit` and
   *  the upstream flow shares the Bridge's resolver, so without this a limiter
   *  wired only into `createUpstreamRedirectFlow` never ran. */
  readonly rateLimit?: RateLimitPort;
}

export interface CimdResolution {
  readonly registration: CimdRegistration;
  /** Deferred so the redirect-mode caller can emit the success event only
   *  AFTER its 4096-byte cookie-oversize guard passes (decision 1b). */
  emitSuccess(): Promise<void>;
}

export class CimdResolver {
  readonly #enabled: boolean;
  readonly #clock: ClockPort;
  readonly #audit: AuditPort;
  readonly #rateLimit: RateLimitPort;
  readonly #cache: CimdSuccessCache;
  readonly #inFlight = new Map<string, Promise<CimdRegistration>>();
  readonly #maxInFlight: number;
  readonly #maxWaitersPerFetch: number;
  readonly #waiters = new WaiterCounts();
  readonly #cacheTtlCapSeconds: number;
  #defaultFetcher: GuardedFetcher | undefined;
  readonly #seams: { transport?: CimdTransport; resolver?: DnsResolver };
  /** Captured ONCE at construction (read-once rule): reading `config.dev`
   *  lazily would let a post-boot `allowInsecureLocalhost = true` widen
   *  loopback after boot validated it disabled. */
  readonly #allowLoopback: boolean;
  readonly #maxDocumentBytes: number;
  readonly #fetchTimeoutMs: number;

  constructor(deps: CimdResolverDeps) {
    this.#clock = deps.clock;
    this.#audit = deps.audit;
    this.#rateLimit = deps.rateLimit ?? noopRateLimit;
    const cimd = deps.config.cimd;
    this.#enabled = cimd?.enabled === true;
    this.#maxInFlight = cimd?.maxInFlight ?? 8;
    this.#maxWaitersPerFetch = cimd?.maxWaitersPerFetch ?? 256;
    this.#cacheTtlCapSeconds = cimd?.cacheTtlCapSeconds ?? 3600;
    this.#cache = new CimdSuccessCache();
    this.#seams = { transport: deps.cimdTransport, resolver: deps.cimdResolver };
    // Read-once: capture every fetcher-profile value at construction.
    this.#allowLoopback = deps.config.dev?.allowInsecureLocalhost === true;
    this.#maxDocumentBytes = cimd?.maxDocumentBytes ?? 5120;
    this.#fetchTimeoutMs = cimd?.fetchTimeoutMs ?? 5000;
  }

  /** Boot-only projection; `resolve()` uses the unshadowable private slot. */
  get enabled(): boolean { return this.#enabled; }
  /** Boot-time validation of the cap profile. Constructs and DISCARDS a fetcher
   *  so an out-of-domain cap fails at construction rather than on the first
   *  request; returns nothing, so it is not a network-capable handle. */
  assertCapProfile(transport?: CimdTransport, resolver?: DnsResolver): void {
    this.#createFetcher(transport, resolver);
  }

  /** A true ECMAScript #private (NOT the TS `private` keyword, which is erased
   *  at runtime and left the method callable from JS). Decision 5. Was public,
   *  which left a second network-capable
   *  entry point on the root-exported `bridge.cimd`: a consumer could call
   *  `createFetcher().fetch(url)` even with the `cimd` block ABSENT, bypassing
   *  `resolve()`'s enabled gate, the rate limiter, single-flight, the
   *  concurrency and waiter caps, the cache and the audit — unbounded guarded
   *  egress from a supposedly disabled service. The caps and `allowLoopback`
   *  still always come from the validated config; a cap-domain `TypeError` is
   *  reconciled to `AuthConfigError` so boot never leaks a raw TypeError. */
  #createFetcher(transport?: CimdTransport, resolver?: DnsResolver): GuardedFetcher {
    try {
      return createGuardedFetcher({
        ...(transport === undefined ? {} : { transport }),
        ...(resolver === undefined ? {} : { resolver }),
        allowLoopback: this.#allowLoopback,
        maxDocumentBytes: this.#maxDocumentBytes,
        fetchTimeoutMs: this.#fetchTimeoutMs,
      });
    } catch (error) {
      throw error instanceof AuthConfigError ? error
        : new AuthConfigError(`cimd configuration is invalid: ${error instanceof TypeError ? error.message : "unknown"}`);
    }
  }

  #fetcher(): GuardedFetcher {
    this.#defaultFetcher ??= this.#createFetcher(this.#seams.transport, this.#seams.resolver);
    return this.#defaultFetcher;
  }

  /** Per-call below-guard seams (decision 1e) still yield a fetcher built from
   *  the validated profile — only the transport/resolver differ. */
  #fetcherFor(seams?: { readonly transport?: CimdTransport; readonly resolver?: DnsResolver }): GuardedFetcher {
    if (seams?.transport === undefined && seams?.resolver === undefined) return this.#fetcher();
    return this.#createFetcher(seams.transport, seams.resolver);
  }

  /** Pre-resolution `cimd:<ip>` rate-limit guard (decision 2 — OUTSIDE the
   *  anti-oracle map: a direct 429 `temporarily_unavailable`, no DNS, no
   *  connect, no `oauth.cimd.fetch` audit). Fail-open on a limiter outage,
   *  mirroring the existing register/token/upstream guards. */
  async #rateGuard(ip: string | undefined, limiter?: RateLimitPort): Promise<void> {
    // BOTH limiters apply — never replace. `UpstreamFlowDeps.rateLimit` is
    // independent of `BridgeDeps.rateLimit` and the upstream flow shares this
    // resolver, so a limiter wired only there would otherwise never run; but a
    // caller-supplied allow-all must NOT be able to weaken an operator's
    // configured guard. Either one denying is a denial.
    const key = `cimd:${ip ?? "unknown"}`;
    // Deduplicate by IDENTITY: a deployer commonly passes ONE RateLimitPort to
    // both `Bridge` and `createUpstreamRedirectFlow`. `check()` is a counting
    // side effect (RedisRateLimit does an atomic INCR), so charging the same
    // instance twice for one request halves the effective limit — and a limit
    // of 1 would reject the very first CIMD authorization.
    const ports = limiter === undefined
      || rateLimitIdentity(limiter) === rateLimitIdentity(this.#rateLimit)
      ? [this.#rateLimit] : [this.#rateLimit, limiter];
    for (const port of ports) {
      let allowed = true;
      try { allowed = await port.check(key); } catch { allowed = true; } // fail-open on a limiter outage
      if (!allowed) throw new OAuthError("temporarily_unavailable", "Rate limit exceeded; retry later", 429);
    }
  }

  async resolve(input: CimdResolveInput): Promise<CimdResolution> {
    // Opt-in enforced at the SERVICE, not only at the HTTP handlers. `bridge.cimd`
    // is publicly reachable, so without this a consumer could drive DNS/network
    // activity on a deployment that never enabled CIMD. Before the rate guard and
    // before any fetch — a rejection must cause no side effect.
    if (!this.#enabled) throw cimdGenericError();
    await this.#rateGuard(input.ip, input.rateLimit);
    try {
      // The fetcher is ALWAYS built here from this resolver's validated caps
      // and config-derived `allowLoopback`; a caller may substitute only the
      // below-guard transport/resolver seams, never the guard itself.
      const outcome = await this.#registrationFor(input.clientId, this.#fetcherFor(input.seams));
      // A cache HIT reuses the fetched DOCUMENT, never the authorization
      // decision: the shared matcher re-runs on EVERY request.
      if (!cimdRedirectMatches(input.redirectUri, outcome.registration)) {
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
        this.#emit("success", undefined, input.clientId, input.ip);
      return { registration: outcome.registration, emitSuccess };
    } catch (error) {
      if (error instanceof OAuthError) throw error; // the rate-limit channel is not a resolution outcome
      await this.#emit("failure", auditReason(error), input.clientId, input.ip);
      throw mapCimdError(error);
    }
  }

  /** Audit a redirect-mode-only failure (e.g. the cookie-oversize residual)
   *  with a fixed allowlisted reason, then map to the decision-2 generic. */
  async rejectAfterResolve(reason: "oversize", clientId: string, ip?: string): Promise<OAuthError> {
    await this.#emit("failure", reason, clientId, ip);
    return cimdGenericError();
  }

  async #registrationFor(rawClientId: string, fetcher: GuardedFetcher): Promise<{ registration: CimdRegistration; fetched: boolean }> {
    const hit = this.#cache.get(rawClientId, this.#clock.nowMs());
    if (hit !== undefined) return { registration: hit, fetched: false };
    const existing = this.#inFlight.get(rawClientId);
    // A coalesced follower consumes no FETCH slot (rule 24) but IS bounded
    // (decision 7 — rationale in waiters.ts). The rejection reuses the EXISTING
    // `overloaded` reason, so it stays byte-identical to every other resolution
    // failure (decision 2).
    if (existing !== undefined) {
      if (!this.#waiters.tryAcquire(rawClientId, this.#maxWaitersPerFetch)) throw new CimdError("overloaded");
      try { return { registration: await existing, fetched: false }; }
      finally { this.#waiters.release(rawClientId); }
    }
    if (this.#inFlight.size >= this.#maxInFlight) throw new CimdError("overloaded");
    const pending = this.#fetchAndCache(rawClientId, fetcher);
    this.#inFlight.set(rawClientId, pending);
    try {
      return { registration: await pending, fetched: true };
    } finally {
      this.#inFlight.delete(rawClientId); // removed on settle: success, error, or timeout
    }
  }

  async #fetchAndCache(rawClientId: string, fetcher: GuardedFetcher): Promise<CimdRegistration> {
    const t0Ms = this.#clock.nowMs();
    const result = await fetcher.fetch(rawClientId);
    const t1Ms = this.#clock.nowMs();
    // Project BEFORE caching: a raw CimdDocument is never cached or signed.
    const registration = projectCimdRegistration(result.document);
    const expiresAtMs = computeCacheExpiryMs(result.cacheView, this.#cacheTtlCapSeconds, t0Ms, t1Ms);
    if (expiresAtMs !== null) this.#cache.set(rawClientId, registration, expiresAtMs, t1Ms);
    return registration;
  }

  async #emit(status: "success" | "failure", reason: string | undefined, clientId: string, ip?: string): Promise<void> {
    await writeAuditBestEffort(this.#audit, {
      occurredAt: new Date(this.#clock.nowMs()).toISOString(),
      event: "oauth.cimd.fetch", status, reason, clientId, ip,
    });
  }
}
