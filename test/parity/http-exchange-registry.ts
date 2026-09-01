import { FixtureRunnerError } from "./error.ts";
import { matcherMatches } from "./matchers.ts";
import { bodyObservation, headerObservation, type Observation } from "./observations.ts";
import type { HttpExchange, Matcher, ObservedOutbound } from "./types.ts";

const UNMATCHED_CALL = "outbound call did not match a declared HTTP exchange",
  UNCONSUMED_EXCHANGE = "not all declared HTTP exchanges were consumed";

export class HttpExchangeRegistry {
  readonly #exchanges: HttpExchange[];
  readonly #used = new Set<number>();
  readonly #observed: ObservedOutbound[] = [];
  #mismatch = false;

  constructor(exchanges: HttpExchange[]) {
    this.#exchanges = exchanges.map(cloneExchange);
  }

  get observed(): ObservedOutbound[] {
    return this.#observed.map(cloneCall);
  }

  consume(call: ObservedOutbound): HttpExchange["response"] {
    this.#observed.push(cloneCall(call));
    let index: number;
    try {
      index = this.#exchanges.findIndex((exchange, candidate) =>
        !this.#used.has(candidate) && exchangeMatches(call, exchange));
    } catch {
      this.#mismatch = true;
      throw new FixtureRunnerError(UNMATCHED_CALL);
    }
    if (index < 0) {
      this.#mismatch = true;
      throw new FixtureRunnerError(UNMATCHED_CALL);
    }
    this.#used.add(index);
    return cloneResponse(this.#exchanges[index]!.response);
  }

  assertAllConsumed(): void {
    if (this.#mismatch) throw new FixtureRunnerError(UNMATCHED_CALL);
    if (this.#used.size !== this.#exchanges.length) {
      throw new FixtureRunnerError(UNCONSUMED_EXCHANGE);
    }
  }
}

function exchangeMatches(call: ObservedOutbound, exchange: HttpExchange): boolean {
  if (call.method !== exchange.request.method || call.url !== exchange.request.url) return false;
  for (const [name, matcher] of Object.entries(exchange.request.headers)) {
    if (!observationMatches(headerObservation(call.headers, name), matcher)) return false;
  }
  return observationMatches(bodyObservation(call.body, call.headers), exchange.request.body);
}

function observationMatches(observation: Observation, matcher: Matcher): boolean {
  if (isAbsentMatcher(matcher)) return !observation.present;
  return observation.present && matcherMatches(observation.value, matcher);
}

function isAbsentMatcher(matcher: Matcher): matcher is { absent: true } {
  return typeof matcher === "object" && "absent" in matcher;
}

function cloneExchange(exchange: HttpExchange): HttpExchange { return structuredClone(exchange); }

function cloneResponse(response: HttpExchange["response"]): HttpExchange["response"] { return structuredClone(response); }

function cloneCall(call: ObservedOutbound): ObservedOutbound {
  return {
    method: call.method,
    url: call.url,
    headers: cloneHeaders(call.headers),
    ...(call.body === undefined ? {} : { body: Buffer.from(call.body) }),
  };
}

function cloneHeaders(headers: Record<string, string | string[]>): Record<string, string | string[]> {
  const clone: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    Object.defineProperty(clone, name, {
      value: Array.isArray(value) ? [...value] : value,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return clone;
}
