import { Resolver } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { admitCimdUrl, type AdmittedUrl } from "./admission.ts";
import { isBlockedIp, parseIp, type ParsedIp } from "./blocklist.ts";
import { validateCimdDocument, type CimdDocument } from "./document.ts";
import { CimdError } from "./errors.ts";
import {
  bindDataMethod, classDataValue, ownDataValue, snapshotOwnDataArray, snapshotOwnDataRecord,
} from "../own-property.ts";
import { readCimdBody } from "./body-reader.ts";
import {
  parseGuardedFetcherOptions,
  type CimdTransport,
  type DnsResolver,
  type GuardedFetcherOptions,
} from "./fetcher-options.ts";
export type { CimdTransport, DnsResolver, GuardedFetcherOptions } from "./fetcher-options.ts";
const BRAND: unique symbol = Symbol("GuardedFetcher");
export interface CimdFetchResult { readonly document: CimdDocument; }
export interface GuardedFetcher { readonly [BRAND]: true; fetch(rawClientId: string): Promise<CimdFetchResult>; }
interface ResolvedAddress {
  readonly address: string; readonly family: 4 | 6; readonly parsed: ParsedIp;
}
const INSTANCES = new WeakSet<object>();
const NODE_TRANSPORT: CimdTransport = { connectAndGet: nodeConnectAndGet };
export function createGuardedFetcher(opts: GuardedFetcherOptions = {}): GuardedFetcher {
  const options = parseGuardedFetcherOptions(opts);
  const transport = options.transport ?? NODE_TRANSPORT;
  const injectedResolver = options.resolver;
  const maxBytes = options.maxDocumentBytes;
  const timeoutMs = options.fetchTimeoutMs;
  const allowLoopback = options.allowLoopback;
  const fetcher = {
    async fetch(rawClientId: string): Promise<CimdFetchResult> {
      const admitted = admitCimdUrl(rawClientId, { allowLoopback });
      return fetchWithDeadline(admitted, injectedResolver ?? new NodeDnsResolver(), transport,
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
      cancelResolver(resolver);
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
    cancelResolver(resolver);
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
  const response = captureTransportResponse(await transport.connectAndGet({
    connectIp: target.address, family: target.family, port: admitted.port,
    servername: admitted.hostname,
    hostHeader: admitted.hostname + (url.port === "" ? "" : `:${url.port}`),
    requestTarget: url.pathname + url.search, signal: controller.signal, redirect: "manual",
  }));
  if (response === null) throw new CimdError("fetch_failed");
  // redirected===false is load-bearing; sameSerializedUrl is defense-in-depth (seam-only).
  if (response.redirected !== false || !sameSerializedUrl(response.finalUrl, admitted.raw)) {
    throw new CimdError("redirect_refused");
  }
  if (response.status !== 200) throw new CimdError("status_not_200");
  const contentType = headerValues(response.headersDistinct, "content-type");
  if (contentType === null || contentType === undefined || contentType.length !== 1
    || !isJsonMediaType(contentType[0]!)) throw new CimdError("content_type");
  if (headerValues(response.headersDistinct, "content-encoding") !== undefined) throw new CimdError("encoding");
  const body = await readCimdBody(response.encodedBody, maxBytes);
  return { document: validateCimdDocument(body, admitted.raw) };
}
function captureTransportResponse(value: unknown): Readonly<Record<string, unknown>> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  return Object.freeze({
    status: classDataValue(value, "status"),
    redirected: classDataValue(value, "redirected"),
    finalUrl: classDataValue(value, "finalUrl"),
    headersDistinct: classDataValue(value, "headersDistinct"),
    encodedBody: classDataValue(value, "encodedBody"),
  });
}
function validateAnswer(answer: unknown): ResolvedAddress[] {
  const entries = snapshotOwnDataArray(answer);
  if (entries === null || entries.length < 1 || entries.length > 64) throw new CimdError("dns_failed");
  return entries.map((entry: unknown) => {
    const fields = snapshotOwnDataRecord(entry);
    if (fields === null) throw new CimdError("dns_failed");
    const { address, family } = fields;
    if (typeof address !== "string" || (family !== 4 && family !== 6)) throw new CimdError("dns_failed");
    const parsed = parseIp(address);
    if (parsed === null || parsed.family !== family) throw new CimdError("dns_failed");
    return { address, family, parsed };
  });
}
function cancelResolver(resolver: DnsResolver): void {
  const cancel = bindDataMethod<() => void>(resolver, "cancel");
  if (cancel !== undefined) try { cancel(); } catch { /* primary failure remains closed */ }
}
function isLoopback(value: ResolvedAddress): boolean {
  if (value.family === 4) return value.parsed.bytes[0] === 127;
  return value.parsed.bytes.slice(0, 15).every((byte) => byte === 0)
    && value.parsed.bytes[15] === 1;
}
function headerValues(headers: unknown, name: string): string[] | undefined | null {
  const fields = snapshotOwnDataRecord(headers);
  if (fields === null) return null;
  const values: string[] = [];
  let present = false;
  for (const [key, value] of Object.entries(fields)) {
    if (key.toLowerCase() !== name) continue;
    present = true;
    const entries = snapshotOwnDataArray(value);
    if (entries === null || !entries.every((item) => typeof item === "string")) return null;
    values.push(...entries as string[]);
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
    const code = ownDataValue(error, "code");
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
      agent: false, signal: req.signal, rejectUnauthorized: true, // pin TLS verification independently of ambient process settings
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
