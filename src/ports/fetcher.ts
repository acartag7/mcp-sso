// FetcherPort — generic outbound-fetch boundary (contracts §6.6). CIMD (§17.1)
// accepts https only and requires its branded guarded fetcher: all resolved addresses
// checked, connect-to-IP with original SNI/Host, zero redirects, byte cap, and one
// DNS-to-body timeout. For that profile `result.url` is the requested URL because no
// redirect is permitted; CIMD never accepts an arbitrary FetcherPort implementation.

export interface FetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  maxBytes?: number;
  timeoutMs?: number;
}

export interface FetchResult {
  ok: boolean;
  status: number;
  url: string; // requested URL; guarded profiles reject any redirect
  bytes: number;
  contentType?: string;
  text(): Promise<string>;
}

export interface FetcherPort {
  fetch(url: string, init?: FetchInit): Promise<FetchResult>;
}
