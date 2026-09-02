import assert from "node:assert/strict";
import { Bridge } from "../../src/adapters/bridge.ts";
import type { BridgeConfig } from "../../src/config.ts";
import { RequestAuthorizer } from "../../src/verifier.ts";
import { assertAudit } from "./audit-assertions.ts";
import { captureResponse, materializeRequest } from "./captures.ts";
import { fixtureClock } from "./clock.ts";
import { materializeConfig, materializeConfigInput } from "./config.ts";
import { FIXTURES_ROOT } from "./corpus.ts";
import { fixtureFailure, FixtureRunnerError } from "./error.ts";
import { mountHost } from "./host.ts";
import { publicKey } from "./keys.ts";
import { sendRealHttp } from "./http-client.ts";
import { RecordingAudit } from "./recording-audit.ts";
import { HttpExchangeRegistry } from "./http-exchange-registry.ts";
import { matcherMatches } from "./matchers.ts";
import { assertOutbound } from "./outbound-assertions.ts";
import { bodyObservation, headerObservation, type Observation } from "./observations.ts";
import { SeededRandom } from "./random.ts";
import { ScriptedCimdTransport } from "./scripted-cimd-transport.ts";
import { ScriptedDnsResolver } from "./scripted-dns.ts";
import { ScriptedFetch } from "./scripted-fetch.ts";
import { ScriptedIdentity } from "./scripted-identity.ts";
import { ScriptedRateLimit } from "./scripted-rate-limit.ts";
import { assertState } from "./state-assertions.ts";
import { FixtureStore } from "./store.ts";
import type { LogicalState } from "./types.ts";
import type {
  AdapterKind, BootFixture, CaptureValues, HttpExchange, HttpFixture, Matcher, ObservedMessage,
  ParityFixture,
} from "./types.ts";

export async function runFixture(
  fixture: ParityFixture, adapter: AdapterKind = "fastify", captures: CaptureValues = new Map(),
): Promise<Required<LogicalState>> {
  if (fixture.status === "superseded") {
    throw fixtureFailure(fixture.id, "superseded fixtures are not executable");
  }
  if (fixture.kind === "boot") return await runBoot(fixture);
  if (fixture.profile === "host" && adapter !== "fastify") {
    throw fixtureFailure(fixture.id, "host fixture requires Fastify");
  }
  return await runHttp(fixture, adapter, captures);
}

interface OutboundAssembly {
  registry: HttpExchangeRegistry;
  transport: ScriptedCimdTransport;
  resolver: ScriptedDnsResolver;
  fetch: ScriptedFetch;
}

function outboundAssembly(exchanges: HttpExchange[]): OutboundAssembly {
  const registry = new HttpExchangeRegistry(exchanges);
  const transport = new ScriptedCimdTransport((call) => registry.consume(call));
  const resolver = new ScriptedDnsResolver(exchanges);
  return { registry, transport, resolver, fetch: new ScriptedFetch((call) => registry.consume(call)) };
}

async function runHttp(
  fixture: HttpFixture, adapter: AdapterKind, captures: CaptureValues,
): Promise<Required<LogicalState>> {
  const clock = fixtureClock(fixture.given.clock, fixture.id);
  const request = materializeRequest(fixture.when.request, captures);
  const random = new SeededRandom(fixture.given.random.seed);
  const store = new FixtureStore(fixture.given.state, random);
  const audit = new RecordingAudit();
  const identity = new ScriptedIdentity(fixture.given.identity.checks);
  const rateLimit = new ScriptedRateLimit(fixture.given.rateLimit.checks);
  const originalFetch = globalThis.fetch;
  let host: Awaited<ReturnType<typeof mountHost>> | undefined;
  let failure: { error: unknown } | undefined;
  try {
    const outbound = outboundAssembly(fixture.given.http);
    globalThis.fetch = outbound.fetch.fetch as typeof fetch;
    const config = await materializeConfig(fixture.given.config, fixture.given.keys, store);
    const bridge = new Bridge({ config, store, clock, audit, rateLimit, random,
      cimdTransport: outbound.transport, cimdResolver: outbound.resolver });
    const authorizer = new RequestAuthorizer({ config, clock, audit });
    host = await mountHost({ adapter, bridge, authorizer, config, identity,
      protectedResource: fixture.given.protectedResource });
    const response = await sendRealHttp({ base: host.base, ...request });
    if (host.failure()) throw host.failure();
    assertHttpResponse(response, fixture);
    if (fixture.then.audit) assertAudit(audit.events, fixture.then.audit, fixture.id);
    if (fixture.then.state) await assertState(store.snapshot(), fixture.then.state, fixture.id);
    assertOutbound(outbound.registry, fixture.then.outbound);
    outbound.resolver.assertNoUnexpectedCalls();
    identity.assertConsumed();
    rateLimit.assertConsumed();
    await captureResponses(fixture, response, captures);
    const postState = store.snapshot();
    await finalizeRun(fixture.id, adapter, host, store, originalFetch, undefined);
    return postState;
  } catch (error) {
    failure = { error: error instanceof FixtureRunnerError && error.message.startsWith(`${fixture.id}:`)
      ? error : fixtureFailure(fixture.id, `${adapter} run failed`, error) };
    await finalizeRun(fixture.id, adapter, host, store, originalFetch, failure);
    throw new Error("unreachable");
  }
}

/** Shared cleanup: restore fetch, close host and store, then surface the
 *  primary fixture failure or, failing that, the cleanup failure. */
async function finalizeRun(
  fixtureId: string, adapter: AdapterKind,
  host: Awaited<ReturnType<typeof mountHost>> | undefined, store: FixtureStore,
  originalFetch: typeof fetch, failure: { error: unknown } | undefined,
): Promise<void> {
  const cleanedUp = await Promise.allSettled([host?.close() ?? Promise.resolve(), store.close()]);
  globalThis.fetch = originalFetch;
  if (failure) throw failure.error;
  const cleanup = cleanedUp.find((result): result is PromiseRejectedResult => result.status === "rejected");
  if (cleanup) throw fixtureFailure(fixtureId, "cleanup failed", cleanup.reason);
}

async function runBoot(fixture: BootFixture): Promise<Required<LogicalState>> {
  const clock = fixtureClock(fixture.given.clock, fixture.id);
  const random = new SeededRandom(fixture.given.random.seed);
  const store = new FixtureStore(fixture.given.state, random);
  const audit = new RecordingAudit();
  const identity = new ScriptedIdentity(fixture.given.identity.checks);
  const rateLimit = new ScriptedRateLimit(fixture.given.rateLimit.checks);
  const originalFetch = globalThis.fetch;
  let error: unknown;
  try {
    const outbound = outboundAssembly(fixture.given.http);
    globalThis.fetch = outbound.fetch.fetch as typeof fetch;
    try {
      if (fixture.given.entrypoint === "Bridge") {
        const config = await materializeConfigInput(
          fixture.given.config, fixture.given.keys, FIXTURES_ROOT, store,
        ) as BridgeConfig;
        new Bridge({ config, store, clock, audit, rateLimit, random,
          cimdTransport: outbound.transport, cimdResolver: outbound.resolver });
      } else {
        await materializeConfig(fixture.given.config, fixture.given.keys, store);
      }
    } catch (caught) { error = caught; }
    assertBoot(error, fixture);
    if (fixture.then.audit) assertAudit(audit.events, fixture.then.audit, fixture.id);
    if (fixture.then.state) await assertState(store.snapshot(), fixture.then.state, fixture.id);
    assertOutbound(outbound.registry, fixture.then.outbound);
    outbound.resolver.assertNoUnexpectedCalls();
    identity.assertConsumed();
    rateLimit.assertConsumed();
    return store.snapshot();
  } catch (caught) {
    if (caught instanceof FixtureRunnerError && caught.message.startsWith(`${fixture.id}:`)) throw caught;
    throw fixtureFailure(fixture.id, "boot run failed", caught);
  } finally {
    let cleanupFailure: { error: unknown } | undefined;
    try { await store.close(); }
    catch (error) { cleanupFailure = { error }; }
    finally { globalThis.fetch = originalFetch; }
    if (cleanupFailure) throw fixtureFailure(fixture.id, "cleanup failed", cleanupFailure.error);
  }
}

async function captureResponses(
  fixture: HttpFixture, response: ObservedMessage, captures: CaptureValues,
): Promise<void> {
  if (!fixture.then.captures?.length) return;
  const signingPublic = fixture.given.keys.signingPublic === undefined
    ? undefined : await publicKey(fixture.given.keys.signingPublic);
  await captureResponse(fixture.id, fixture.then.captures, response,
    signingPublic === undefined ? {} : { signingPublic }, captures);
}

function assertHttpResponse(response: ObservedMessage, fixture: HttpFixture): void {
  assert.equal(response.status, fixture.then.status,
    `${fixture.id} response status; headers=${JSON.stringify(response.headers)}; body=${JSON.stringify(response.body.toString("utf8"))}`);
  for (const [name, matcher] of Object.entries(fixture.then.headers ?? {})) {
    assertMember(headerObservation(response.headers, name), matcher, `${fixture.id} response header ${name}`);
  }
  if (fixture.then.body !== undefined) {
    assertMember(bodyObservation(response.body, response.headers), fixture.then.body, `${fixture.id} response body`);
  }
}

function assertBoot(error: unknown, fixture: BootFixture): void {
  const expected = fixture.then.boot;
  if (expected.outcome === "accepted") {
    if (error !== undefined) throw error;
    return;
  }
  if (error === undefined) {
    assert.fail(`${fixture.id} boot was accepted; expected ${expected.error.code}`);
  }
  if (error instanceof FixtureRunnerError) throw error;
  const record = typeof error === "object" && error !== null ? error as Record<string, unknown> : {};
  assert.equal(record.code, expected.error.code, `${fixture.id} boot error code`);
  if (expected.error.name) {
    assertMember(observedText(record.name), expected.error.name, `${fixture.id} boot error name`);
  }
  if (expected.error.message) {
    assertMember(observedText(record.message), expected.error.message, `${fixture.id} boot error message`);
  }
}

function observedText(value: unknown): Observation {
  if (typeof value === "string") return { present: true, value };
  return { present: false };
}

function assertMember(observed: Observation, matcher: Matcher, label: string): void {
  if (isAbsentMatcher(matcher)) {
    assert.equal(observed.present, false, `${label} must be absent`);
    return;
  }
  assert.equal(observed.present, true, `${label} must be present`);
  if (!matcherMatches(observed.value, matcher)) {
    assert.fail(`${label} did not match ${JSON.stringify(matcher)}; observed ${JSON.stringify(observed.value)}`);
  }
}

function isAbsentMatcher(matcher: Matcher): matcher is { absent: true } {
  return typeof matcher === "object" && "absent" in matcher;
}
