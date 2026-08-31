import assert from "node:assert/strict";
import type { AuthAuditEvent, AuditPort } from "../../src/ports/audit.ts";
import { OAuthError } from "../../src/errors.ts";
import type { IdentityPort, IdentityResult } from "../../src/ports/identity.ts";
import type { RateLimitPort } from "../../src/ports/rate-limit.ts";
import type { CimdTransport, DnsResolver } from "../../src/cimd/transport.ts";
import type { BodyValue, HttpExchange, IdentityCheck, ObservedOutbound, OutboundCall, RateLimitCheck } from "./types.ts";
import {
  assertExactHeaders, assertMatcher, bodyObservation, headerObservation, observationMatches,
} from "./matchers.ts";
import { FixtureRunnerError } from "./error.ts";
import { encodeResponseBody } from "./response-body.ts";

export class RecordingAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(structuredClone(event)); }
}

export class ScriptedIdentity implements IdentityPort {
  readonly #checks: IdentityCheck[];
  #index = 0;
  constructor(checks: IdentityCheck[]) { this.#checks = checks; }
  async verify(input: unknown): Promise<IdentityResult> {
    const check = this.#checks[this.#index++];
    if (!check) throw new FixtureRunnerError("unmatched IdentityPort.verify call");
    assertBodyValue(input, check.input, `identity check ${this.#index} input`);
    if (check.throw?.kind === "oauth") throw new OAuthError(check.throw.code, check.throw.description, check.throw.status);
    if (check.throw?.kind === "generic") throw new Error("scripted generic identity failure");
    if (!check.result) throw new FixtureRunnerError("identity check has no result or throw");
    return structuredClone(check.result);
  }
  assertConsumed(): void { assert.equal(this.#index, this.#checks.length, "all identity checks must be consumed"); }
}

export class ScriptedRateLimit implements RateLimitPort {
  readonly #checks: RateLimitCheck[];
  #index = 0;
  constructor(checks: RateLimitCheck[]) { this.#checks = checks; }
  async check(key: string): Promise<boolean> {
    const check = this.#checks[this.#index++];
    if (!check) throw new FixtureRunnerError(`unmatched RateLimitPort.check call: ${key}`);
    assert.equal(key, check.key, `rate-limit check ${this.#index} key`);
    if (typeof check.outcome === "object") throw new Error(check.outcome.throws);
    return check.outcome === "allow";
  }
  assertConsumed(): void { assert.equal(this.#index, this.#checks.length, "all rate-limit checks must be consumed"); }
}

export class OutboundScript {
  readonly observed: ObservedOutbound[] = [];
  readonly transport: CimdTransport;
  readonly resolver: DnsResolver;
  readonly exchanges: HttpExchange[];
  readonly #used = new Set<number>();
  constructor(exchanges: HttpExchange[]) {
    this.exchanges = exchanges;
    this.transport = { connectAndGet: async (request) => {
      const url = `https://${request.hostHeader}${request.requestTarget}`;
      const headers = { host: request.hostHeader, accept: "application/json", "accept-encoding": "identity" };
      const response = this.#next({ method: "GET", url, headers });
      const responseHeaders = explicitHeaders(response.headers);
      return { status: response.status, redirected: false, finalUrl: url,
        headersDistinct: responseHeaders, encodedBody: bodyChunks(response.body, responseHeaders) };
    } };
    this.resolver = { async resolve() { return [{ address: "93.184.216.34", family: 4 }]; } };
  }

  readonly fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const request = new Request(input, init);
    const headers = observedRequestHeaders(input, init, request);
    const body = request.method === "GET" || request.method === "HEAD"
      ? undefined : Buffer.from(await request.arrayBuffer());
    const response = this.#next({ method: request.method, url: request.url, headers, body });
    const responseHeaders = explicitHeaders(response.headers);
    const encoded = encodeResponseBody(response.body, responseHeaders);
    return scriptedResponse(encoded, response.status, responseHeaders);
  };

  assertComplete(expected: OutboundCall[], label: string): void {
    assert.equal(this.#used.size, this.exchanges.length, `${label} all outbound scripts consumed`);
    assert.equal(this.observed.length, expected.length, `${label} outbound call count`);
    for (let index = 0; index < expected.length; index += 1) {
      const actual = this.observed[index]!, wanted = expected[index]!;
      assert.equal(actual.method, wanted.method, `${label} outbound ${index + 1} method`);
      assert.equal(actual.url, wanted.url, `${label} outbound ${index + 1} URL`);
      assertExactHeaders(actual.headers, wanted.headers, `${label} outbound ${index + 1}`);
      assertMatcher(bodyObservation(actual.body, actual.headers), wanted.body, `${label} outbound ${index + 1} body`);
    }
  }

  #next(call: ObservedOutbound): HttpExchange["response"] {
    this.observed.push(call);
    const index = this.exchanges.findIndex((exchange, candidate) =>
      !this.#used.has(candidate) && exchangeMatches(call, exchange));
    if (index < 0) throw new FixtureRunnerError(`unmatched outbound call: ${call.method} ${call.url}`);
    this.#used.add(index);
    const exchange = this.exchanges[index]!;
    return exchange.response;
  }
}

function observedRequestHeaders(
  input: string | URL | Request, init: RequestInit | undefined, request: Request,
): Record<string, string | string[]> {
  if (Array.isArray(init?.headers)) {
    const occurrences = new Map<string, string[]>();
    for (const [rawName, value] of init.headers) {
      const name = rawName.toLowerCase();
      occurrences.set(name, [...(occurrences.get(name) ?? []), value]);
    }
    return Object.fromEntries([...occurrences].map(([name, values]) => [
      name, values.length === 1 ? values[0]! : values,
    ]));
  }
  const headers: Record<string, string | string[]> = {};
  request.headers.forEach((value, name) => { headers[name] = value; });
  const source = init?.headers ?? (input instanceof Request ? input.headers : undefined);
  if (source instanceof Headers) {
    const cookies = source.getSetCookie();
    if (cookies.length > 1) headers["set-cookie"] = cookies;
  }
  return headers;
}

function exchangeMatches(call: ObservedOutbound, exchange: HttpExchange): boolean {
  if (call.method !== exchange.request.method || call.url !== exchange.request.url) return false;
  if (!Object.entries(exchange.request.headers).every(([name, matcher]) =>
    observationMatches(headerObservation(call.headers, name), matcher))) return false;
  return observationMatches(bodyObservation(call.body, call.headers), exchange.request.body);
}

function assertBodyValue(actual: unknown, expected: BodyValue, label: string): void {
  if ("absent" in expected) assert.equal(actual, undefined, `${label} absent`);
  else assert.deepStrictEqual(actual, expected.value, label);
}

function explicitHeaders(headers: Record<string, unknown>): Record<string, string[]> {
  const result: Record<string, string[]> = {};
  for (const [name, raw] of Object.entries(headers)) {
    const values = Array.isArray(raw) ? raw : [raw];
    if (!values.every((value) => typeof value === "string")) {
      throw new FixtureRunnerError(`outbound response header ${name} contains a capture or non-string value`);
    }
    result[name] = values as string[];
  }
  return result;
}

function scriptedResponse(body: Buffer, status: number, headers: Record<string, string[]>): Response {
  const response = new Response(body.byteLength === 0 ? null : body, { status });
  const distinct = new DistinctHeaders(headers) as unknown as Headers;
  Object.defineProperty(response, "headers", { value: distinct });
  Object.defineProperty(response, "clone", { value: () => {
    const clone = Response.prototype.clone.call(response);
    Object.defineProperty(clone, "headers", { value: new DistinctHeaders(headers) as unknown as Headers });
    return clone;
  } });
  return response;
}

class DistinctHeaders {
  readonly #entries: Array<[string, string]>;
  constructor(headers: Record<string, string[]>) {
    this.#entries = Object.entries(headers).flatMap(([name, values]) =>
      values.map((value): [string, string] => [name, value]));
  }
  append(): never { throw new FixtureRunnerError("scripted response headers are read-only"); }
  delete(): never { throw new FixtureRunnerError("scripted response headers are read-only"); }
  set(): never { throw new FixtureRunnerError("scripted response headers are read-only"); }
  get(name: string): string | null {
    const values = this.#values(name);
    if (values.length > 1) throw new FixtureRunnerError(`outbound response header ${name} has multiple occurrences`);
    return values[0] ?? null;
  }
  getSetCookie(): string[] { return this.#values("set-cookie"); }
  has(name: string): boolean { return this.#values(name).length > 0; }
  forEach(callback: (value: string, key: string, parent: Headers) => void, thisArg?: unknown): void {
    for (const [name, value] of this.#entries) callback.call(thisArg, value, name, this as unknown as Headers);
  }
  *entries(): IterableIterator<[string, string]> {
    for (const [name, value] of this.#entries) yield [name, value];
  }
  *keys(): IterableIterator<string> { for (const [name] of this.#entries) yield name; }
  *values(): IterableIterator<string> { for (const [, value] of this.#entries) yield value; }
  [Symbol.iterator](): IterableIterator<[string, string]> { return this.entries(); }
  #values(name: string): string[] {
    const lower = name.toLowerCase();
    return this.#entries.filter(([candidate]) => candidate === lower).map(([, value]) => value);
  }
}

async function* bodyChunks(body: BodyValue, headers: Record<string, string[]>): AsyncGenerator<Uint8Array> {
  const encoded = encodeResponseBody(body, headers); if (encoded.byteLength > 0) yield encoded;
}
