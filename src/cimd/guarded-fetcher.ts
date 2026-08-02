import { admitCimdUrl, type AdmittedUrl } from "./admission.ts";
import { isBlockedIp, ownBooleanTrue, ownValue, parseIp, type ParsedIp } from "./blocklist.ts";
import { validateCimdDocument } from "./document.ts";
import { CimdError } from "./errors.ts";
import { NODE_TRANSPORT, NodeDnsResolver } from "./node-io.ts";
import type { CimdCacheView, CimdFetchResult, CimdTransport, DnsResolver } from "./transport.ts";
const BRAND: unique symbol = Symbol("GuardedFetcher");
export type { CimdCacheView, CimdFetchResult, CimdTransport, DnsResolver } from "./transport.ts";
export { NodeDnsResolver } from "./node-io.ts";
export interface GuardedFetcher { readonly [BRAND]: true; fetch(rawClientId: string): Promise<CimdFetchResult>; }
interface ResolvedAddress {
  readonly address: string; readonly family: 4 | 6; readonly parsed: ParsedIp;
}
const INSTANCES = new WeakSet<object>();
export function createGuardedFetcher(opts: {
  transport?: CimdTransport; resolver?: DnsResolver; allowLoopback?: boolean;
  maxDocumentBytes?: number; fetchTimeoutMs?: number;
} = {}): GuardedFetcher {
  assertOptions(opts);
  const transport = (ownValue(opts, "transport") as CimdTransport | undefined) ?? NODE_TRANSPORT;
  const resolver = ownValue(opts, "resolver") as DnsResolver | undefined;
  const maxBytes = integerOption(ownValue(opts, "maxDocumentBytes"), 5120, 1024, 65536, "maxDocumentBytes");
  const timeoutMs = integerOption(ownValue(opts, "fetchTimeoutMs"), 5000, 1000, 30000, "fetchTimeoutMs");
  const allowLoopback = ownBooleanTrue(opts, "allowLoopback");
  const fetcher = {
    async fetch(rawClientId: string): Promise<CimdFetchResult> {
      const admitted = admitCimdUrl(rawClientId, { allowLoopback });
      // A FRESH default resolver per fetch: `cancel()` on one request's deadline
      // must never cancel another concurrent request's in-flight DNS queries.
      return fetchWithDeadline(admitted, resolver ?? new NodeDnsResolver(), transport,
        allowLoopback, maxBytes, timeoutMs);
    },
  };
  Object.defineProperty(fetcher, BRAND, { value: true, enumerable: false });
  INSTANCES.add(fetcher);
  return Object.freeze(fetcher) as GuardedFetcher;
}
export function isGuardedFetcher(value: unknown): value is GuardedFetcher {
  return typeof value === "object" && value !== null && INSTANCES.has(value)
    && (value as Record<PropertyKey, unknown>)[BRAND] === true;
}
async function fetchWithDeadline(admitted: AdmittedUrl, resolver: DnsResolver, transport: CimdTransport,
  allowLoopback: boolean, maxBytes: number, timeoutMs: number): Promise<CimdFetchResult> {
  const controller = new AbortController();
  let expired = false;
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      expired = true;
      controller.abort();
      try { resolver.cancel?.(); } catch { /* deadline still rejects */ }
      reject(new CimdError("timeout"));
    }, timeoutMs);
  });
  try {
    return await Promise.race([
      fetchOnce(admitted, resolver, transport, allowLoopback, maxBytes, controller), timeout,
    ]);
  } catch (error) {
    controller.abort(); // tear down the socket on ANY failure (header-check rejection, body, timeout)
    if (error instanceof CimdError) throw error;
    if (expired) throw new CimdError("timeout");
    throw new CimdError("fetch_failed");
  } finally {
    if (timer) clearTimeout(timer);
  }
}
async function fetchOnce(admitted: AdmittedUrl, resolver: DnsResolver, transport: CimdTransport,
  allowLoopback: boolean, maxBytes: number, controller: AbortController): Promise<CimdFetchResult> {
  let answer: unknown;
  try { answer = await resolver.resolve(admitted.hostname); }
  catch {
    if (controller.signal.aborted) throw new CimdError("timeout");
    try { resolver.cancel?.(); } catch { /* DNS failure remains closed */ }
    throw new CimdError("dns_failed");
  }
  const addresses = validateAnswer(answer);
  const loopbackHost = allowLoopback
    && (admitted.hostname === "localhost" || admitted.hostname.endsWith(".localhost"));
  if (loopbackHost) {
    if (!addresses.every(isLoopback)) throw new CimdError("dns_failed");
  } else if (addresses.some(({ parsed }) => isBlockedIp(parsed, { allowLoopback: false }))) {
    throw new CimdError("ip_blocked");
  }
  // DNS-rebinding: the validated address is PINNED here and handed to the
  // transport as `connectIp` — no second resolution can re-point the connect.
  const target = addresses[0]!;
  const url = new URL(admitted.raw);
  const response = await transport.connectAndGet({
    connectIp: target.address, family: target.family, port: admitted.port,
    servername: admitted.hostname,
    hostHeader: admitted.hostname + (url.port === "" ? "" : `:${url.port}`),
    requestTarget: url.pathname + url.search, signal: controller.signal, redirect: "manual",
  });
  // redirected===false is load-bearing; sameSerializedUrl is defense-in-depth (seam-only).
  if (response.redirected !== false || !sameSerializedUrl(response.finalUrl, admitted.raw)) {
    throw new CimdError("redirect_refused");
  }
  if (response.status !== 200) throw new CimdError("status_not_200");
  const contentType = headerValues(response.headersDistinct, "content-type");
  if (contentType === null || contentType === undefined || contentType.length !== 1
    || !isJsonMediaType(contentType[0]!)) throw new CimdError("content_type");
  if (headerValues(response.headersDistinct, "content-encoding") !== undefined) throw new CimdError("encoding");
  const body = await readBody(response.encodedBody, maxBytes);
  return {
    document: validateCimdDocument(body, admitted.raw),
    cacheView: cacheView(response.headersDistinct),
  };
}
/** §17.1.6 decision 4: the MINIMAL duplicate-aware cache view — the
 *  `Cache-Control` and `Age` occurrences ONLY, never the full header map. A
 *  malformed header map yields `[""]`, which every freshness rule rejects. */
function cacheView(headers: unknown): CimdCacheView {
  const cacheControl = headerValues(headers, "cache-control");
  const age = headerValues(headers, "age");
  return Object.freeze({
    cacheControl: cacheControl === null ? [""] : cacheControl,
    age: age === null ? [""] : age,
  });
}
function validateAnswer(answer: unknown): ResolvedAddress[] {
  if (!Array.isArray(answer) || answer.length < 1 || answer.length > 64) throw new CimdError("dns_failed");
  return answer.map((entry: unknown) => {
    if (typeof entry !== "object" || entry === null) throw new CimdError("dns_failed");
    const { address, family } = entry as Record<string, unknown>;
    if (typeof address !== "string" || (family !== 4 && family !== 6)) throw new CimdError("dns_failed");
    const parsed = parseIp(address);
    if (parsed === null || parsed.family !== family) throw new CimdError("dns_failed");
    return { address, family, parsed };
  });
}
function isLoopback(value: ResolvedAddress): boolean {
  if (value.family === 4) return value.parsed.bytes[0] === 127;
  return value.parsed.bytes.slice(0, 15).every((byte) => byte === 0)
    && value.parsed.bytes[15] === 1;
}
function headerValues(headers: unknown, name: string): string[] | undefined | null {
  if (typeof headers !== "object" || headers === null || Array.isArray(headers)) return null;
  const values: string[] = [];
  let present = false;
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== name) continue;
    present = true;
    if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) return null;
    values.push(...value);
  }
  return present ? values : undefined;
}
function isJsonMediaType(value: string): boolean {
  if (value.includes(",")) return false;
  const essence = value.split(";", 1)[0]!.trim().toLowerCase();
  if (!/^[!#$%&'*+.^_`|~0-9a-z-]+\/[!#$%&'*+.^_`|~0-9a-z-]+$/.test(essence)) return false;
  return essence === "application/json"
    || /^application\/[0-9a-z][!#$&^_.+0-9a-z-]*\+json$/.test(essence);
}
function sameSerializedUrl(finalUrl: unknown, requested: string): boolean {
  if (typeof finalUrl !== "string") return false;
  try { return new URL(finalUrl).href === new URL(requested).href; }
  catch { return false; }
}
async function readBody(body: AsyncIterable<Uint8Array> | ReadableStream<Uint8Array>,
  maxBytes: number): Promise<string> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of bodyChunks(body)) {
    if (!(chunk instanceof Uint8Array)) throw new CimdError("fetch_failed");
    total += chunk.byteLength;
    if (total > maxBytes) throw new CimdError("size_exceeded");
    chunks.push(chunk);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw new CimdError("document_invalid"); }
}
async function* bodyChunks(body: AsyncIterable<Uint8Array> | ReadableStream<Uint8Array>) {
  if (body && typeof (body as AsyncIterable<Uint8Array>)[Symbol.asyncIterator] === "function") {
    yield* body as AsyncIterable<Uint8Array>;
    return;
  }
  if (!body || typeof (body as ReadableStream<Uint8Array>).getReader !== "function") {
    throw new CimdError("fetch_failed");
  }
  const reader = (body as ReadableStream<Uint8Array>).getReader();
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) return;
      yield item.value;
    }
  } finally { reader.releaseLock(); }
}
function integerOption(value: unknown, fallback: number, min: number, max: number, name: string): number {
  const result = value === undefined ? fallback : value; // null/NaN/etc are present-but-invalid -> reject below
  if (typeof result !== "number" || !Number.isInteger(result) || result < min || result > max) throw new TypeError(`${name} is out of range`);
  return result;
}
function assertOptions(opts: unknown): asserts opts is Record<string, unknown> {
  if (typeof opts !== "object" || opts === null || Array.isArray(opts)) throw new TypeError("CIMD fetcher options are invalid");
  const value = opts as Record<string, unknown>;
  for (const k of Object.keys(value)) if (!["transport", "resolver", "allowLoopback", "maxDocumentBytes", "fetchTimeoutMs"].includes(k)) throw new TypeError(`unknown CIMD fetcher option: ${k}`);
  const allowLoopback = ownValue(value, "allowLoopback");
  const transport = ownValue(value, "transport"), resolver = ownValue(value, "resolver");
  if (allowLoopback !== undefined && typeof allowLoopback !== "boolean") throw new TypeError("allowLoopback must be boolean");
  if (transport !== undefined && (typeof transport !== "object"
    || transport === null || typeof (transport as CimdTransport).connectAndGet !== "function")) throw new TypeError("transport is invalid");
  if (resolver !== undefined && (typeof resolver !== "object"
    || resolver === null || typeof (resolver as DnsResolver).resolve !== "function")) throw new TypeError("resolver is invalid");
}
