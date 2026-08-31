import assert from "node:assert/strict";
import { Bridge } from "../../src/adapters/bridge.ts";
import { RequestAuthorizer } from "../../src/verifier.ts";
import type { AdapterKind, BootFixture, CaptureValues, HttpFixture, ObservedMessage, ParityFixture } from "./types.ts";
import { SeededRandom } from "./random.ts";
import { FixtureStore } from "./store.ts";
import { RecordingAudit, OutboundScript, ScriptedIdentity, ScriptedRateLimit } from "./ports.ts";
import { materializeConfig, materializeConfigInput } from "./config.ts";
import type { BridgeConfig } from "../../src/config.ts";
import { mountHost } from "./host.ts";
import { materializeRequest, captureResponse } from "./captures.ts";
import { sendRealHttp } from "./http-client.ts";
import { assertMatcher, bodyObservation, headerObservation } from "./matchers.ts";
import { assertAudit, assertState } from "./assertions.ts";
import { FixtureRunnerError, fixtureFailure } from "./error.ts";

export async function runFixture(
  fixture: ParityFixture, adapter: AdapterKind = "fastify", captures: CaptureValues = new Map(),
): Promise<void> {
  if (fixture.status === "superseded") throw fixtureFailure(fixture.id, "superseded fixtures are not executable");
  if (fixture.kind === "boot") { await runBoot(fixture); return; }
  if (fixture.profile === "host" && adapter !== "fastify") throw fixtureFailure(fixture.id, "host fixture requires Fastify");
  await runHttp(fixture, adapter, captures);
}

async function runHttp(fixture: HttpFixture, adapter: AdapterKind, captures: CaptureValues): Promise<void> {
  const request = materializeRequest(fixture.when.request, captures);
  const random = new SeededRandom(fixture.given.random.seed);
  const store = new FixtureStore(fixture.given.state, random);
  const audit = new RecordingAudit();
  const identity = new ScriptedIdentity(fixture.given.identity.checks);
  const rateLimit = new ScriptedRateLimit(fixture.given.rateLimit.checks);
  const outbound = new OutboundScript(fixture.given.http);
  const originalFetch = globalThis.fetch;
  let host: Awaited<ReturnType<typeof mountHost>> | undefined;
  let failure: { error: unknown } | undefined;
  try {
    globalThis.fetch = outbound.fetch as typeof fetch;
    const config = await materializeConfig(fixture.given.config, fixture.given.keys, store);
    const clock = { nowMs: () => Date.parse(fixture.given.clock) };
    const bridge = new Bridge({ config, store, clock, audit, rateLimit, random,
      cimdTransport: outbound.transport, cimdResolver: outbound.resolver });
    const authorizer = new RequestAuthorizer({ config, clock, audit });
    host = await mountHost({ adapter, bridge, authorizer, config, identity,
      protectedResource: fixture.given.protectedResource });
    const response = await sendRealHttp({ base: host.base, ...request });
    if (host.failure()) throw host.failure();
    assertHttpResponse(response, fixture);
    if (fixture.then.audit) assertAudit(audit.events, fixture.then.audit, fixture.id);
    if (fixture.then.state) assertState(store.snapshot(), fixture.then.state, fixture.id);
    outbound.assertComplete(fixture.then.outbound, fixture.id);
    identity.assertConsumed(); rateLimit.assertConsumed();
    await captureResponse(fixture.id, fixture.then.captures, response,
      fixture.given.keys.signingPublic, captures);
  } catch (error) {
    failure = { error: error instanceof FixtureRunnerError && error.message.startsWith(`${fixture.id}:`)
      ? error : fixtureFailure(fixture.id, `${adapter} run failed`, error) };
  } finally {
    const failures = await Promise.allSettled([host?.close() ?? Promise.resolve(), store.close()]);
    globalThis.fetch = originalFetch;
    if (failure) throw failure.error;
    const cleanup = failures.find((result): result is PromiseRejectedResult => result.status === "rejected");
    if (cleanup) throw fixtureFailure(fixture.id, "cleanup failed", cleanup.reason);
  }
}

async function runBoot(fixture: BootFixture): Promise<void> {
  const random = new SeededRandom(fixture.given.random.seed);
  const store = new FixtureStore(fixture.given.state, random);
  const audit = new RecordingAudit();
  const identity = new ScriptedIdentity(fixture.given.identity.checks);
  const rateLimit = new ScriptedRateLimit(fixture.given.rateLimit.checks);
  const outbound = new OutboundScript(fixture.given.http);
  const originalFetch = globalThis.fetch;
  let error: unknown;
  try {
    globalThis.fetch = outbound.fetch as typeof fetch;
    try {
      if (fixture.given.entrypoint === "Bridge") {
        const config = await materializeConfigInput(
          fixture.given.config, fixture.given.keys, store,
        ) as BridgeConfig;
        const clock = { nowMs: () => Date.parse(fixture.given.clock) };
        new Bridge({ config, store, clock, audit, rateLimit, random,
          cimdTransport: outbound.transport, cimdResolver: outbound.resolver });
      } else {
        await materializeConfig(fixture.given.config, fixture.given.keys, store);
      }
    } catch (caught) { error = caught; }
    assertBoot(error, fixture);
    if (fixture.then.audit) assertAudit(audit.events, fixture.then.audit, fixture.id);
    if (fixture.then.state) assertState(store.snapshot(), fixture.then.state, fixture.id);
    outbound.assertComplete(fixture.then.outbound, fixture.id);
    identity.assertConsumed(); rateLimit.assertConsumed();
  } catch (caught) {
    if (caught instanceof FixtureRunnerError && caught.message.startsWith(`${fixture.id}:`)) throw caught;
    throw fixtureFailure(fixture.id, "boot run failed", caught);
  } finally {
    try { await store.close(); } finally { globalThis.fetch = originalFetch; }
  }
}

function assertHttpResponse(response: ObservedMessage, fixture: HttpFixture): void {
  assert.equal(response.status, fixture.then.status,
    `${fixture.id} response status; headers=${JSON.stringify(response.headers)}; body=${JSON.stringify(response.body.toString("utf8"))}`);
  for (const [name, matcher] of Object.entries(fixture.then.headers ?? {})) {
    assertMatcher(headerObservation(response.headers, name), matcher, `${fixture.id} response header ${name}`);
  }
  if (fixture.then.body !== undefined) {
    assertMatcher(bodyObservation(response.body, response.headers), fixture.then.body, `${fixture.id} response body`);
  }
}

function assertBoot(error: unknown, fixture: BootFixture): void {
  const expected = fixture.then.boot;
  if (expected.outcome === "accepted") {
    if (error !== undefined) throw error;
    return;
  }
  if (error === undefined) assert.fail(`${fixture.id} boot was accepted; expected ${expected.error.code}`);
  if (error instanceof FixtureRunnerError) throw error;
  const record = typeof error === "object" && error !== null ? error as Record<string, unknown> : {};
  assert.equal(record.code, expected.error.code, `${fixture.id} boot error code`);
  if (expected.error.name) assertMatcher({ present: typeof record.name === "string", value: record.name }, expected.error.name, `${fixture.id} boot error name`);
  if (expected.error.message) assertMatcher({ present: typeof record.message === "string", value: record.message }, expected.error.message, `${fixture.id} boot error message`);
}
