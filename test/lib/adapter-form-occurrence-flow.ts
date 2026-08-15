// Shared raw URL-encoded occurrence regressions (contracts §9.2–§9.6 / HB.11).
// The same wire bodies exercise Fastify, Express, and Hono so framework parser
// policy cannot select a first or last OAuth value before Bridge rejects it.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { Bridge } from "../../src/adapters/bridge.ts";
import type { AuditPort, AuthAuditEvent } from "../../src/ports/audit.ts";
import type { IdentityPort } from "../../src/ports/identity.ts";
import type { RateLimitPort } from "../../src/ports/rate-limit.ts";
import type { AdapterClient } from "./adapter-flow.ts";

const REDIRECT = "https://client.test/callback";
const SENTINEL = "must-not-reach-endpoint-work";

class MemoryAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(event); }
}

interface FormCase {
  label: string;
  path: string;
  key: string;
  value: string;
  other: ReadonlyArray<readonly [string, string]>;
  headers?: ReadonlyArray<readonly [string, string]>;
  limiter: string;
}

const FORM_CASES: readonly FormCase[] = [
  {
    label: "register", path: "/oauth/register", key: "redirect_uris", value: REDIRECT,
    other: [], limiter: "register",
  },
  {
    label: "approve", path: "/oauth/authorize/approve", key: "consent_token", value: SENTINEL,
    other: [["approved", "true"]], headers: [["Origin", "https://auth.test"]], limiter: "approve",
  },
  {
    label: "token", path: "/oauth/token", key: "grant_type", value: "authorization_code",
    other: [["code", SENTINEL]], limiter: "token",
  },
  {
    label: "revoke", path: "/oauth/revoke", key: "token", value: SENTINEL,
    other: [], limiter: "revoke",
  },
];

export function runAdapterFormOccurrenceFlow(
  name: string,
  mount: (bridge: Bridge, identity: IdentityPort) => Promise<AdapterClient>,
  makeBridge: (rateLimit?: RateLimitPort, audit?: AuditPort) => Bridge,
): void {
  test(`${name} adapter: repeated OAuth form keys reject before endpoint work`, async (t) => {
    for (const formCase of FORM_CASES) {
      for (const [order, values] of [
        ["empty-first", ["", formCase.value]],
        ["empty-last", [formCase.value, ""]],
        ["two-values", [formCase.value, formCase.value]],
      ] as const) {
        await t.test(`${formCase.label} ${order}`, async () => {
          const keys: string[] = [];
          const audit = new MemoryAudit();
          const bridge = makeBridge({ async check(key) { keys.push(key); return true; } }, audit);
          const identity: IdentityPort = { async verify() { return { ok: false, reason: "unused" }; } };
          const client = await mount(bridge, identity);
          try {
            const params = new URLSearchParams();
            params.append(formCase.key, values[0]);
            params.append(formCase.key, values[1]);
            for (const [key, value] of formCase.other) params.append(key, value);
            const body = params.toString();
            const response = await client.requestOccurrences("POST", formCase.path, [
              ["Content-Type", "application/x-www-form-urlencoded"], ...(formCase.headers ?? []),
            ], body);
            assert.equal(response.status, 400);
            assert.equal(response.headers.location, undefined);
            assert.equal(JSON.parse(response.body).error, "invalid_request");
            assert.equal(response.body.includes(SENTINEL), false);
            const ip = name === "hono" ? "unknown" : "127.0.0.1";
            assert.deepEqual(keys, [`${formCase.limiter}:${ip}`], "the existing limiter is charged exactly once");
            assert.deepEqual(audit.events, [], "duplicate rejection precedes endpoint audit work");
          } finally {
            await client.close?.();
          }
        });
      }
    }
  });

  test(`${name} adapter: ambiguous OAuth Content-Type rejects before endpoint work`, async (t) => {
    for (const formCase of FORM_CASES) {
      await t.test(formCase.label, async () => {
        const keys: string[] = [];
        const audit = new MemoryAudit();
        const bridge = makeBridge({ async check(key) { keys.push(key); return true; } }, audit);
        const identity: IdentityPort = { async verify() { return { ok: false, reason: "unused" }; } };
        const client = await mount(bridge, identity);
        try {
          const params = new URLSearchParams();
          params.append(formCase.key, formCase.value);
          params.append(formCase.key, formCase.value);
          for (const [key, value] of formCase.other) params.append(key, value);
          const response = await client.requestOccurrences("POST", formCase.path, [
            ["Content-Type", "application/x-www-form-urlencoded"],
            ["Content-Type", "application/x-www-form-urlencoded"],
            ...(formCase.headers ?? []),
          ], params.toString());
          assert.equal(response.status, 400);
          assert.equal(response.headers.location, undefined);
          assert.equal(JSON.parse(response.body).error, "invalid_request");
          assert.equal(response.body.includes(SENTINEL), false);
          const ip = name === "hono" ? "unknown" : "127.0.0.1";
          assert.deepEqual(keys, [`${formCase.limiter}:${ip}`], "the existing limiter is charged exactly once");
          assert.deepEqual(audit.events, [], "header ambiguity precedes endpoint audit work");
        } finally {
          await client.close?.();
        }
      });
    }

    await t.test("JSON registration", async () => {
      const keys: string[] = [];
      const audit = new MemoryAudit();
      const bridge = makeBridge({ async check(key) { keys.push(key); return true; } }, audit);
      const identity: IdentityPort = { async verify() { return { ok: false, reason: "unused" }; } };
      const client = await mount(bridge, identity);
      try {
        const response = await client.requestOccurrences("POST", "/oauth/register", [
          ["Content-Type", "application/json"], ["Content-Type", "application/json"],
        ], JSON.stringify({ redirect_uris: [REDIRECT] }));
        assert.equal(response.status, 400);
        assert.equal(JSON.parse(response.body).error, "invalid_request");
        const ip = name === "hono" ? "unknown" : "127.0.0.1";
        assert.deepEqual(keys, [`register:${ip}`]);
        assert.deepEqual(audit.events, []);
      } finally {
        await client.close?.();
      }
    });
  });
}
