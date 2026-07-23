import { bindClassDataMethod, isDataDescriptor, ownDataValue } from "../own-property.ts";

export interface DnsResolver {
  resolve(hostname: string): Promise<{ address: string; family: 4 | 6 }[]>;
  cancel?(): void;
}

export interface CimdTransport {
  connectAndGet(req: {
    readonly connectIp: string;
    readonly family: 4 | 6;
    readonly port: number;
    readonly servername: string;
    readonly hostHeader: string;
    readonly requestTarget: string;
    readonly signal: AbortSignal;
    readonly redirect: "manual";
  }): Promise<{
    readonly status: number;
    readonly redirected: boolean;
    readonly finalUrl: string;
    readonly headersDistinct: Readonly<Record<string, readonly string[]>>;
    readonly encodedBody: AsyncIterable<Uint8Array> | ReadableStream<Uint8Array>;
  }>;
}

export interface GuardedFetcherOptions {
  transport?: CimdTransport;
  resolver?: DnsResolver;
  allowLoopback?: boolean;
  maxDocumentBytes?: number;
  fetchTimeoutMs?: number;
}

export interface ParsedGuardedFetcherOptions {
  readonly transport?: CimdTransport;
  readonly resolver?: DnsResolver;
  readonly allowLoopback: boolean;
  readonly maxDocumentBytes: number;
  readonly fetchTimeoutMs: number;
}

const OPTION_KEYS = new Set([
  "transport", "resolver", "allowLoopback", "maxDocumentBytes", "fetchTimeoutMs",
]);

export function parseGuardedFetcherOptions(opts: unknown): ParsedGuardedFetcherOptions {
  if (typeof opts !== "object" || opts === null || Array.isArray(opts)) throw invalidOptions();

  let descriptors: Record<PropertyKey, PropertyDescriptor>;
  try {
    descriptors = Object.getOwnPropertyDescriptors(opts) as Record<PropertyKey, PropertyDescriptor>;
  } catch {
    throw invalidOptions();
  }

  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== "string" || !OPTION_KEYS.has(key)) {
      throw new TypeError(`unknown CIMD fetcher option: ${String(key)}`);
    }
    const descriptor = descriptors[key]!;
    if (!descriptor.enumerable || !isDataDescriptor(descriptor)) throw invalidOptions();
  }

  const transportInput = value<unknown>(descriptors, "transport");
  const resolverInput = value<unknown>(descriptors, "resolver");
  const allowLoopback = value<unknown>(descriptors, "allowLoopback");
  const maxDocumentBytes = integerOption(
    value<number>(descriptors, "maxDocumentBytes"), 5120, 1024, 65536, "maxDocumentBytes",
  );
  const fetchTimeoutMs = integerOption(
    value<number>(descriptors, "fetchTimeoutMs"), 5000, 1000, 30000, "fetchTimeoutMs",
  );

  if (allowLoopback !== undefined && typeof allowLoopback !== "boolean") {
    throw new TypeError("allowLoopback must be boolean");
  }
  const transport = snapshotTransport(transportInput);
  const resolver = snapshotResolver(resolverInput);

  return Object.freeze({
    transport, resolver, allowLoopback: allowLoopback === true, maxDocumentBytes, fetchTimeoutMs,
  });
}

function snapshotTransport(value: unknown): CimdTransport | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "object" || value === null) throw new TypeError("transport is invalid");
  const connectAndGet =
    bindClassDataMethod<CimdTransport["connectAndGet"]>(value, "connectAndGet");
  if (connectAndGet === undefined) throw new TypeError("transport is invalid");
  return Object.freeze({ connectAndGet });
}

function snapshotResolver(value: unknown): DnsResolver | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "object" || value === null) throw new TypeError("resolver is invalid");
  const resolve = bindClassDataMethod<DnsResolver["resolve"]>(value, "resolve");
  if (resolve === undefined) throw new TypeError("resolver is invalid");
  const cancel = bindClassDataMethod<NonNullable<DnsResolver["cancel"]>>(value, "cancel");
  return Object.freeze({ resolve, ...(cancel === undefined ? {} : { cancel }) });
}

function value<T>(descriptors: Record<PropertyKey, PropertyDescriptor>, key: string): T | undefined {
  const descriptor = ownDataValue(descriptors, key) as PropertyDescriptor | undefined;
  return isDataDescriptor(descriptor) ? descriptor.value as T : undefined;
}

function integerOption(value: number | undefined, fallback: number, min: number,
  max: number, name: string): number {
  const result = value === undefined ? fallback : value;
  if (!Number.isInteger(result) || result < min || result > max) {
    throw new TypeError(`${name} is out of range`);
  }
  return result;
}

function invalidOptions(): TypeError {
  return new TypeError("CIMD fetcher options are invalid");
}
