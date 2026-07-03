// FetcherPort — boundary reserved for v0.2 Client-issued Metadata Discovery
// (contracts §6.6). v0.1 does NO outbound fetching. Any v0.2 metadata fetch MUST
// go through an SSRF-guarded implementation: scheme allow-list (http/https only),
// CRLF rejection, resolved-IP private-range check, connect-to-IP with original
// SNI/Host, per-hop re-validation, byte cap, and timeout. The boundary exists now
// so v0.2 cannot accidentally add a raw fetch.

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
  url: string; // final URL after redirects
  bytes: number;
  contentType?: string;
  text(): Promise<string>;
}

export interface FetcherPort {
  fetch(url: string, init?: FetchInit): Promise<FetchResult>;
}
