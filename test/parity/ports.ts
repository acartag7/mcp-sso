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
      return { status: response.status, redirected: false, finalUrl: url,
        headersDistinct: explicitHeaders(response.headers), encodedBody: bodyChunks(response.body) };
    } };
    this.resolver = { async resolve() { return [{ address: "93.184.216.34", family: 4 }]; } };
  }

  readonly fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const request = new Request(input, init);
    const headers: Record<string, string> = {};
    request.headers.forEach((value, name) => { headers[name] = value; });
    const body = request.method === "GET" || request.method === "HEAD"
      ? undefined : Buffer.from(await request.arrayBuffer());
    const response = this.#next({ method: request.method, url: request.url, headers, body });
    const responseHeaders = new Headers();
    for (const [name, values] of Object.entries(explicitHeaders(response.headers))) {
      for (const value of values) responseHeaders.append(name, value);
    }
    const encoded = encodeBody(response.body);
    return new Response(encoded.byteLength === 0 ? null : encoded, { status: response.status, headers: responseHeaders });
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

function encodeBody(body: BodyValue): Buffer {
  if ("absent" in body) return Buffer.alloc(0);
  return Buffer.from(typeof body.value === "string" ? body.value : JSON.stringify(body.value), "utf8");
}

async function* bodyChunks(body: BodyValue): AsyncGenerator<Uint8Array> {
  const encoded = encodeBody(body); if (encoded.byteLength > 0) yield encoded;
}
