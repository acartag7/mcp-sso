// §13 no-secrets serialization, extended to every AuthAuditEventName (§17.7).
// The metadata-only rule is a use-case obligation (no token values are ever
// placed in an AuthAuditEvent); these tests pin the SINK side of it: each sink
// is a pure conduit that serializes EXACTLY the event it was given — it never
// injects secret-bearing keys (`authorization`, `cookie`, `set-cookie`,
// `access_token`, `refresh_token`, `code`) or any extra field, across every
// event name and including the new `ip` field.

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { JsonlFileAudit } from "../src/audit/jsonl-file.ts";
import { WebhookAudit } from "../src/audit/webhook.ts";
import type { AuthAuditEvent, AuthAuditEventName } from "../src/ports/audit.ts";

const ALL_EVENTS: AuthAuditEventName[] = [
  // v0.1 names
  "oauth.register", "oauth.authorize.prepare", "oauth.authorize.approve",
  "oauth.token.authorization_code", "oauth.token.refresh", "oauth.revoke", "auth.request",
  // v0.2 names (§17.7)
  "identity.verify", "oauth.pairing.attempt", "oauth.device.authorization",
  "oauth.device.approve", "oauth.token.device_code", "oauth.token.client_credentials",
  "oauth.client.provision", "oauth.client.rotate_secret", "oauth.cimd.fetch",
  "oauth.upstream.callback",
];

const SECRET_KEYS = ["authorization", "cookie", "set-cookie", "access_token", "refresh_token", "code", "token"];

function eventFor(name: AuthAuditEventName): AuthAuditEvent {
  return {
    occurredAt: "2026-07-05T12:00:00.000Z",
    event: name,
    status: name.endsWith(".approve") || name === "auth.request" ? "success" : "failure",
    clientId: "client-1",
    subject: "agent@test",
    resource: "https://api.test/mcp",
    scopes: ["mcp:read"],
    redirectHost: "client.test",
    reason: "invalid_grant",
    ip: "203.0.113.7",
  };
}

test("JsonlFileAudit: every event name serializes as the exact event (no injected secret keys)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-nosec-"));
  try {
    const path = join(dir, "audit.jsonl");
    const sink = new JsonlFileAudit(path);
    for (const name of ALL_EVENTS) await sink.writeAuthEvent(eventFor(name));

    const raw = await readFile(path, "utf8");
    const lines = raw.split("\n").filter((l) => l.length > 0);
    assert.equal(lines.length, ALL_EVENTS.length, "one line per event name");
    lines.forEach((line, i) => {
      const parsed = JSON.parse(line);
      assert.deepEqual(parsed, eventFor(ALL_EVENTS[i]!), `conduit mismatch for ${ALL_EVENTS[i]}`);
      for (const key of SECRET_KEYS) {
        assert.equal(key in parsed, false, `sink injected secret-bearing key '${key}' into ${ALL_EVENTS[i]}`);
      }
    });
    // Belt-and-suspenders: no leaked secret VALUE pattern appears in the file.
    // (The words "secret"/"token" are NOT needles — they occur legitimately in
    // event names like `oauth.client.rotate_secret` and `oauth.token.refresh`.)
    for (const needle of ["Bearer", "password", "rt.", "mcs_", "mcc_"]) {
      assert.equal(raw.toLowerCase().includes(needle.toLowerCase()), false, `raw sink output contained '${needle}'`);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("WebhookAudit: every event name POSTs the exact event body (no injected secret keys)", async () => {
  const calls: { body: string }[] = [];
  const fetchImpl = (async (_url: unknown, init?: RequestInit) => {
    calls.push({ body: (init?.body as string) ?? "" });
    return { ok: true, status: 200, redirected: false } as Response;
  }) as typeof fetch;
  const sink = new WebhookAudit("https://siem.test/ingest", { fetchImpl });

  for (const name of ALL_EVENTS) await sink.writeAuthEvent(eventFor(name));

  assert.equal(calls.length, ALL_EVENTS.length, "one POST per event name");
  calls.forEach((c, i) => {
    const parsed = JSON.parse(c.body);
    assert.deepEqual(parsed, eventFor(ALL_EVENTS[i]!), `body mismatch for ${ALL_EVENTS[i]}`);
    for (const key of SECRET_KEYS) {
      assert.equal(key in parsed, false, `webhook injected secret-bearing key '${key}' into ${ALL_EVENTS[i]}`);
    }
  });
});
