import { Resolver } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { admitCimdUrl, type AdmittedUrl } from "./admission.ts";
import { isBlockedIp, parseIp, type ParsedIp } from "./blocklist.ts";
import { validateCimdDocument, type CimdDocument } from "./document.ts";
import { CimdError } from "./errors.ts";
const BRAND: unique symbol = Symbol("GuardedFetcher");
export interface CimdFetchResult { readonly document: CimdDocument; }
export interface GuardedFetcher { readonly [BRAND]: true; fetch(rawClientId: string): Promise<CimdFetchResult>; }
export interface DnsResolver {
  resolve(hostname: string): Promise<{ address: string; family: 4 | 6 }[]>; cancel?(): void;
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
interface ResolvedAddress {
  readonly address: string; readonly family: 4 | 6; readonly parsed: ParsedIp;
}
const INSTANCES = new WeakSet<object>();
const NODE_TRANSPORT: CimdTransport = { connectAndGet: nodeConnectAndGet };
export function createGuardedFetcher(opts: {
  transport?: CimdTransport; resolver?: DnsResolver; allowLoopback?: boolean;
  maxDocumentBytes?: number; fetchTimeoutMs?: number;
} = {}): GuardedFetcher {
  assertOptions(opts);
  const transport = opts.transport ?? NODE_TRANSPORT;
  const maxBytes = integerOption(opts.maxDocumentBytes, 5120, 1024, 65536, "maxDocumentBytes");
  const timeoutMs = integerOption(opts.fetchTimeoutMs, 5000, 1000, 30000, "fetchTimeoutMs");
  const allowLoopback = opts.allowLoopback === true;
  const fetcher = {
    async fetch(rawClientId: string): Promise<CimdFetchResult> {
      const admitted = admitCimdUrl(rawClientId, { allowLoopback });
      return fetchWithDeadline(admitted, opts.resolver ?? new NodeDnsResolver(), transport,
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
  } else if (addresses.some(({ parsed }) => isBlockedIp(parsed))) {
    throw new CimdError("ip_blocked");
  }
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
  return { document: validateCimdDocument(body, admitted.raw) };
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
  return essence === "application/json" || essence.endsWith("+json");
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
function integerOption(value: number | undefined, fallback: number, min: number,
  max: number, name: string): number {
  const result = value === undefined ? fallback : value; // null/NaN/etc are present-but-invalid -> reject below
  if (!Number.isInteger(result) || result < min || result > max) throw new TypeError(`${name} is out of range`);
  return result;
}
function assertOptions(opts: unknown): asserts opts is Record<string, unknown> {
  if (typeof opts !== "object" || opts === null || Array.isArray(opts)) throw new TypeError("CIMD fetcher options are invalid");
  const value = opts as Record<string, unknown>;
  for (const k of Object.keys(value)) if (!["transport", "resolver", "allowLoopback", "maxDocumentBytes", "fetchTimeoutMs"].includes(k)) throw new TypeError(`unknown CIMD fetcher option: ${k}`);
  if (value.allowLoopback !== undefined && typeof value.allowLoopback !== "boolean") throw new TypeError("allowLoopback must be boolean");
  if (value.transport !== undefined && (typeof value.transport !== "object"
    || value.transport === null || typeof (value.transport as CimdTransport).connectAndGet !== "function")) {
    throw new TypeError("transport is invalid");
  }
  if (value.resolver !== undefined && (typeof value.resolver !== "object"
    || value.resolver === null || typeof (value.resolver as DnsResolver).resolve !== "function")) {
    throw new TypeError("resolver is invalid");
  }
}
export class NodeDnsResolver implements DnsResolver {
  readonly resolver = new Resolver();
  async resolve(hostname: string): Promise<{ address: string; family: 4 | 6 }[]> {
    if (hostname === "localhost" || hostname.endsWith(".localhost")) return [{ address: "127.0.0.1", family: 4 }, { address: "::1", family: 6 }]; // c-ares can't resolve localhost
    const [v4, v6] = await Promise.all([
      resolveFamily(this.resolver.resolve4(hostname), 4),
      resolveFamily(this.resolver.resolve6(hostname), 6),
    ]);
    return [...v4, ...v6];
  }
  cancel(): void { this.resolver.cancel(); }
}
async function resolveFamily(promise: Promise<string[]>, family: 4 | 6) {
  try { return (await promise).map((address) => ({ address, family })); }
  catch (error) {
    const code = typeof error === "object" && error !== null
      ? (error as { code?: unknown }).code : undefined;
    if (code === "ENODATA" || code === "ENOTFOUND") return [];
    throw error;
  }
}
function nodeConnectAndGet(req: Parameters<CimdTransport["connectAndGet"]>[0]) {
  return new Promise<Awaited<ReturnType<CimdTransport["connectAndGet"]>>>((resolve, reject) => {
    const request = httpsRequest({
      hostname: req.connectIp, family: req.family, port: req.port, servername: req.servername,
      method: "GET", path: req.requestTarget,
      headers: { Host: req.hostHeader, Accept: "application/json", "Accept-Encoding": "identity" },
      agent: false, signal: req.signal, rejectUnauthorized: true, // enforce TLS even under NODE_TLS_REJECT_UNAUTHORIZED=0
    }, (response) => {
      const headersDistinct: Record<string, string[]> = Object.create(null) as Record<string, string[]>;
      for (let index = 0; index < response.rawHeaders.length; index += 2) {
        const name = response.rawHeaders[index]!.toLowerCase();
        (headersDistinct[name] ??= []).push(response.rawHeaders[index + 1]!);
      }
      resolve({ status: response.statusCode ?? 0, redirected: false,
        finalUrl: new URL(`https://${req.hostHeader}${req.requestTarget}`).href,
        headersDistinct, encodedBody: response });
    });
    request.once("error", reject);
    request.end();
  });
}
