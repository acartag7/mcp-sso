import { FixtureRunnerError } from "./error.ts";
import { encodeResponseBody } from "./response-body.ts";
import type { HeaderMap, HttpExchange, ObservedOutbound } from "./types.ts";

const AMBIGUOUS_HEADER = "scripted response header has multiple occurrences";
const INVALID_HEADER = "scripted response header contains a capture or non-string value";
const INVALID_HEADER_LINE = "scripted response header cannot contain CR or LF";
const READ_ONLY_HEADERS = "scripted response headers are read-only";
type ConsumeOutbound = (call: ObservedOutbound) => HttpExchange["response"];

export class ScriptedFetch {
  readonly #consume: ConsumeOutbound;

  constructor(consume: ConsumeOutbound) {
    this.#consume = consume;
  }

  readonly fetch = async (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const request = new Request(input, init);
    const call: ObservedOutbound = {
      method: request.method,
      url: request.url,
      headers: observedHeaders(request.headers),
      ...request.method === "GET" || request.method === "HEAD"
        ? {}
        : { body: Buffer.from(await request.arrayBuffer()) },
    };
    const scripted = this.#consume(call);
    const headers = explicitHeaders(scripted.headers);
    const body = encodeResponseBody(scripted.body, headers);
    return scriptedResponse(body, scripted.status, headers);
  };
}

function observedHeaders(source: Headers): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = {};
  source.forEach((value, name) => { defineHeader(result, name, value); });
  const cookies = source.getSetCookie();
  if (cookies.length > 1) defineHeader(result, "set-cookie", cookies);
  return result;
}

function explicitHeaders(source: HeaderMap): Record<string, string[]> {
  const result: Record<string, string[]> = {};
  for (const raw of Object.values(source)) {
    const values = Array.isArray(raw) ? raw : [raw];
    if (!values.every((value) => typeof value === "string")) {
      throw new FixtureRunnerError(INVALID_HEADER);
    }
    if (values.some((value) => /[\r\n]/u.test(value))) {
      throw new FixtureRunnerError(INVALID_HEADER_LINE);
    }
  }
  for (const [name, raw] of Object.entries(source)) {
    defineHeader(result, name, [...(Array.isArray(raw) ? raw : [raw])] as string[]);
  }
  return result;
}

function defineHeader<T extends string | string[]>(target: Record<string, T>, name: string, value: T): void {
  Object.defineProperty(target, name, { value, enumerable: true, configurable: true, writable: true });
}

function scriptedResponse(body: Buffer, status: number, headers: Record<string, string[]>): Response {
  const response = new Response(body.byteLength === 0 ? null : body, { status });
  installHeaderView(response, headers);
  return response;
}

function installHeaderView(response: Response, headers: Record<string, string[]>): void {
  Object.defineProperty(response, "headers", { value: new DistinctHeaders(headers) as unknown as Headers });
  Object.defineProperty(response, "clone", { value: () => {
    const clone = Response.prototype.clone.call(response);
    installHeaderView(clone, headers);
    return clone;
  } });
}

class DistinctHeaders {
  readonly #entries: Array<[string, string]>;

  constructor(headers: Record<string, string[]>) {
    this.#entries = Object.entries(headers).flatMap(([name, values]) =>
      values.map((value): [string, string] => [name, value]));
  }

  append(): never { throw new FixtureRunnerError(READ_ONLY_HEADERS); }
  delete(): never { throw new FixtureRunnerError(READ_ONLY_HEADERS); }
  set(): never { throw new FixtureRunnerError(READ_ONLY_HEADERS); }
  get(name: string): string | null {
    const values = this.#matching(name);
    if (values.length > 1) throw new FixtureRunnerError(AMBIGUOUS_HEADER);
    return values[0] ?? null;
  }
  getSetCookie(): string[] { return this.#matching("set-cookie"); }
  has(name: string): boolean { return this.#matching(name).length > 0; }
  forEach(callback: (value: string, key: string, parent: Headers) => void, thisArg?: unknown): void {
    for (const [name, value] of this.#entries) callback.call(thisArg, value, name, this as unknown as Headers);
  }
  *entries(): IterableIterator<[string, string]> {
    for (const [name, value] of this.#entries) yield [name, value];
  }
  *keys(): IterableIterator<string> { for (const [name] of this.#entries) yield name; }
  *values(): IterableIterator<string> { for (const [, value] of this.#entries) yield value; }
  [Symbol.iterator](): IterableIterator<[string, string]> { return this.entries(); }

  #matching(name: string): string[] {
    const normalized = name.toLowerCase();
    return this.#entries.filter(([candidate]) => candidate === normalized).map(([, value]) => value);
  }
}
