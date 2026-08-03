// Below-guard CIMD I/O seam types (§17.1.5 rule 14 / §17.1.6 decision 1e).
// Split out of `guarded-fetcher.ts` so the guard pipeline, the Node I/O
// implementations, and the resolution use-case can share them without a
// circular import. These are TYPES only — no I/O lives here.

import type { CimdDocument } from "./document.ts";

/** The minimal duplicate-aware cache view (§17.1.6 decision 4): the
 *  cache-relevant header occurrences only — never the full header
 *  map (an unnecessary trust-boundary expansion). `undefined` means the header
 *  was absent; a present-but-malformed header map yields `[""]`, which no
 *  freshness rule accepts (fail toward re-fetch). */
export interface CimdCacheView {
  readonly cacheControl: readonly string[] | undefined;
  readonly age: readonly string[] | undefined;
  readonly date: readonly string[] | undefined;
  readonly expires: readonly string[] | undefined;
  readonly vary: readonly string[] | undefined;
}

export interface CimdFetchResult {
  readonly document: CimdDocument;
  /** Present only on a validated success; error results are never cached. */
  readonly cacheView?: CimdCacheView;
}

export interface DnsResolver {
  resolve(hostname: string): Promise<{ address: string; family: 4 | 6 }[]>;
  cancel?(): void;
}

export interface CimdTransport {
  connectAndGet(req: {
    readonly connectIp: string; readonly family: 4 | 6; readonly port: number;
    readonly servername: string; readonly hostHeader: string; readonly requestTarget: string;
    readonly signal: AbortSignal; readonly redirect: "manual";
  }): Promise<{
    readonly status: number; readonly redirected: boolean; readonly finalUrl: string;
    readonly headersDistinct: Readonly<Record<string, readonly string[]>>;
    readonly encodedBody: AsyncIterable<Uint8Array> | ReadableStream<Uint8Array>;
  }>;
}
