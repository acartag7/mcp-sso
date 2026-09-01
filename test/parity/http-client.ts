import { request as httpRequest, type ClientRequest, type IncomingMessage } from "node:http";
import { FixtureRunnerError } from "./error.ts";
import type { ObservedMessage } from "./types.ts";

export interface RealHttpRequest {
  base: string;
  method: string;
  path: string;
  headers: Array<[string, string]>;
  body?: Buffer;
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 5000;
const MAX_BODY_BYTES = 1024 * 1024;
const HTTP_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const CR_OR_LF = /[\r\n]/u;

const HEADER_CR_LF = "HTTP request headers cannot contain CR or LF";
const TARGET_CR_LF = "HTTP request method and path cannot contain CR or LF";
const OFF_HOST = "HTTP request path cannot leave the mounted host";
const BAD_METHOD = "HTTP request method is not an HTTP token";
const BAD_BASE = "HTTP request base is not an http URL";
const UNBUILDABLE = "HTTP request could not be built";
const UPGRADE_UNSUPPORTED = "HTTP protocol upgrade responses are unsupported";
const TRANSPORT_FAILED = "HTTP request failed on the wire";
const TIMED_OUT = "HTTP request timed out";
const BODY_TOO_LARGE = "HTTP response body exceeded the observation limit";
const NO_STATUS = "HTTP response carried no status code";

export async function sendRealHttp(input: RealHttpRequest): Promise<ObservedMessage> {
  const base = parseBase(input.base);
  requireTarget(input.method, input.path, base);
  const headers = composeHeaders(input, base);
  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  return await observe(open(input, base, headers), input.body, timeoutMs);
}

function parseBase(base: string): URL {
  let url: URL;
  try { url = new URL(base); }
  catch (cause) { throw new FixtureRunnerError(BAD_BASE, { cause }); }
  if (url.protocol !== "http:") throw new FixtureRunnerError(BAD_BASE);
  return url;
}

function requireTarget(method: string, path: string, base: URL): void {
  if (CR_OR_LF.test(method) || CR_OR_LF.test(path)) throw new FixtureRunnerError(TARGET_CR_LF);
  if (!HTTP_TOKEN.test(method)) throw new FixtureRunnerError(BAD_METHOD);
  let resolved: URL;
  try { resolved = new URL(path, base); }
  catch (cause) { throw new FixtureRunnerError(OFF_HOST, { cause }); }
  if (resolved.origin !== base.origin) throw new FixtureRunnerError(OFF_HOST);
}

function composeHeaders(input: RealHttpRequest, base: URL): string[] {
  const declared: string[] = [];
  const names = new Set<string>();
  for (const [name, value] of input.headers) {
    if (CR_OR_LF.test(name) || CR_OR_LF.test(value)) throw new FixtureRunnerError(HEADER_CR_LF);
    names.add(name.toLowerCase());
    declared.push(name, value);
  }
  const composed = names.has("host") ? [] : ["Host", base.host];
  for (const entry of declared) composed.push(entry);
  if (!names.has("connection")) composed.push("Connection", "close");
  if (input.body !== undefined && !names.has("content-length") && !names.has("transfer-encoding")) {
    composed.push("Content-Length", String(input.body.byteLength));
  }
  return composed;
}

function open(input: RealHttpRequest, base: URL, headers: string[]): ClientRequest {
  try {
    return httpRequest({
      host: socketHostname(base),
      port: base.port === "" ? 80 : Number(base.port),
      path: input.path,
      method: input.method,
      headers,
      agent: false,
    });
  } catch (cause) { throw new FixtureRunnerError(UNBUILDABLE, { cause }); }
}

/** `URL.hostname` keeps the brackets of an IPv6 literal, which `http.request`
 *  would treat as a DNS name; the socket wants the bare address. */
function socketHostname(base: URL): string {
  const bracketed = /^\[(.*)\]$/u.exec(base.hostname);
  return bracketed ? bracketed[1]! : base.hostname;
}

function observe(
  request: ClientRequest, body: Buffer | undefined, timeoutMs: number,
): Promise<ObservedMessage> {
  return new Promise<ObservedMessage>((resolve, reject) => {
    let settled = false;
    const finish = (outcome: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      request.destroy();
      outcome();
    };
    const fail = (message: string, cause?: unknown): void => finish(() => {
      reject(new FixtureRunnerError(message, cause === undefined ? undefined : { cause }));
    });
    const deadline = setTimeout(() => fail(TIMED_OUT), timeoutMs);
    request.setTimeout(timeoutMs, () => fail(TIMED_OUT));
    request.on("information", () => {});
    request.on("upgrade", (_response, socket) => {
      socket.destroy();
      fail(UPGRADE_UNSUPPORTED);
    });
    request.on("error", (cause) => fail(TRANSPORT_FAILED, cause));
    request.on("response", (response) => {
      readResponse(response, (outcome) => finish(() => resolve(outcome)), fail);
    });
    if (body === undefined) request.end();
    else request.end(body);
  });
}

function readResponse(
  response: IncomingMessage,
  succeed: (message: ObservedMessage) => void,
  fail: (message: string, cause?: unknown) => void,
): void {
  const chunks: Buffer[] = [];
  let total = 0;
  response.on("data", (chunk: Buffer) => {
    total += chunk.byteLength;
    if (total > MAX_BODY_BYTES) { fail(BODY_TOO_LARGE); return; }
    chunks.push(chunk);
  });
  response.on("error", (cause) => fail(TRANSPORT_FAILED, cause));
  response.on("end", () => {
    const status = response.statusCode;
    if (status === undefined) { fail(NO_STATUS); return; }
    succeed({ status, headers: collectHeaders(response.rawHeaders), body: Buffer.concat(chunks) });
  });
}

function collectHeaders(raw: string[]): Record<string, string | string[]> {
  const headers = Object.create(null) as Record<string, string | string[]>;
  for (let index = 0; index + 1 < raw.length; index += 2) {
    const name = raw[index]!.toLowerCase();
    const value = raw[index + 1]!;
    const existing = Object.hasOwn(headers, name) ? headers[name] : undefined;
    if (existing === undefined) { headers[name] = value; continue; }
    headers[name] = Array.isArray(existing) ? [...existing, value] : [existing, value];
  }
  return headers;
}
