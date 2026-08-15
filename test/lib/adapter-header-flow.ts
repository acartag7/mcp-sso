// Shared raw-occurrence adapter regressions (contracts §9.6). Node socket calls
// preserve duplicate field lines; Fetch/Hono coalesces them as its platform does.
import assert from "node:assert/strict";
import { Socket } from "node:net";
import { test } from "node:test";
import type { Bridge } from "../../src/adapters/bridge.ts";
import type { IdentityPort } from "../../src/ports/identity.ts";
import type { AdapterClient, AdapterResp } from "./adapter-flow.ts";
const REDIRECT = "https://client.test/callback", STUB_TOKEN = "stub-good";
const IDENTITY_HEADER = "cf-access-jwt-assertion";
/** Real Node socket request whose flat header list preserves duplicate names/casing. */
export function rawOccurrenceCall(
  port: number, method: "GET" | "POST", path: string,
  occurrences: ReadonlyArray<readonly [string, string]>,
  body?: string,
): Promise<AdapterResp> {
  return new Promise((resolve, reject) => {
    const socket = new Socket();
    const chunks: Buffer[] = [];
    socket.connect(port, "127.0.0.1", () => {
      const lines = [
        `${method} ${path} HTTP/1.1`,
        `Host: 127.0.0.1:${port}`,
        ...occurrences.map(([name, value]) => `${name}: ${value}`),
        ...(body === undefined ? [] : [`Content-Length: ${Buffer.byteLength(body)}`]),
        "Connection: close", "", body ?? "",
      ];
      socket.write(lines.join("\r\n"));
    });
    socket.on("data", (chunk) => chunks.push(chunk));
    socket.on("error", reject);
    socket.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      const boundary = raw.indexOf("\r\n\r\n");
      const head = raw.slice(0, boundary);
      const responseHeaders: Record<string, string> = {};
      for (const line of head.split("\r\n").slice(1)) {
        const colon = line.indexOf(":");
        if (colon > 0) responseHeaders[line.slice(0, colon).toLowerCase()] = line.slice(colon + 1).trim();
      }
      resolve({ status: Number(/^HTTP\/1\.1 (\d+)/.exec(head)?.[1] ?? 0),
        headers: responseHeaders, body: raw.slice(boundary + 4) });
    });
    socket.setTimeout(5_000, () => socket.destroy(new Error("raw adapter request timed out")));
  });
}
export function runAdapterHeaderFlow(
  name: string, mount: (bridge: Bridge, identity: IdentityPort) => Promise<AdapterClient>,
  makeBridge: () => Bridge,
): void {
  test(`${name} adapter: duplicate Authorization occurrences reject before grant dispatch`, async () => {
    const client = await mount(makeBridge(), { async verify() { return { ok: false, reason: "unused" }; } });
    const body = new URLSearchParams({ grant_type: "authorization_code" }).toString();
    try {
      for (const headers of [
        [["Authorization", "Basic Zm9vOmJhcg=="], ["authorization", "Bearer ignored"]],
        [["authorization", "Bearer ignored"], ["Authorization", "Basic Zm9vOmJhcg=="]],
      ] as const) {
        const response = await client.requestOccurrences("POST", "/oauth/token",
          [["Content-Type", "application/x-www-form-urlencoded"], ...headers], body);
        assert.equal(response.status, 401);
        assert.match(response.headers["www-authenticate"] ?? "", /^Basic /);
        assert.match(response.body, /"error":"invalid_client"/);
        assert.doesNotMatch(response.body, /access_token/);
      }
    } finally {
      await client.close?.();
    }
  });

  test(`${name} adapter: duplicate identity-header occurrences never select one value`, async () => {
    const seen: unknown[] = [];
    const identity: IdentityPort = { async verify(input) {
      seen.push(input);
      return { ok: false, reason: "rejected" };
    } };
    const client = await mount(makeBridge(), identity);
    try {
      for (const headers of [
        [["Cf-Access-Jwt-Assertion", STUB_TOKEN], ["cf-access-jwt-assertion", "attacker"]],
        [["cf-access-jwt-assertion", "attacker"], ["Cf-Access-Jwt-Assertion", STUB_TOKEN]],
      ] as const) {
        const response = await client.requestOccurrences("GET", "/oauth/authorize", headers);
        assert.equal(response.status, 401);
        assert.equal(seen.at(-1), undefined);
      }
    } finally {
      await client.close?.();
    }
  });

  test(`${name} adapter: duplicate approve Origin occurrences fail closed in either order`, async () => {
    const identity: IdentityPort = { async verify(input) {
      return input === STUB_TOKEN
        ? { ok: true, identity: { subject: "agent@test" } }
        : { ok: false, reason: "bad_token" };
    } };
    const client = await mount(makeBridge(), identity);
    try {
      const registered = await client.postJson("/oauth/register", { redirect_uris: [REDIRECT] });
      const clientId = JSON.parse(registered.body).client_id as string;
      const authorize = await client.get(`/oauth/authorize?${new URLSearchParams({
        response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
        code_challenge: "A".repeat(43), code_challenge_method: "S256",
      })}`, { [IDENTITY_HEADER]: STUB_TOKEN });
      const consentToken = /name="consent_token" value="([^"]+)"/.exec(authorize.body)?.[1];
      assert.ok(consentToken);
      const body = new URLSearchParams({ consent_token: consentToken, approved: "true" }).toString();
      for (const origins of [
        [["Origin", "https://auth.test"], ["origin", "https://evil.test"]],
        [["origin", "https://evil.test"], ["Origin", "https://auth.test"]],
      ] as const) {
        const response = await client.requestOccurrences("POST", "/oauth/authorize/approve",
          [["Content-Type", "application/x-www-form-urlencoded"], ...origins], body);
        assert.equal(response.status, 403);
        assert.equal(response.headers.location, undefined);
        assert.match(response.body, /"error":"invalid_origin"/);
      }
    } finally {
      await client.close?.();
    }
  });

  test(`${name} adapter: duplicate approved form fields reject before last-wins approve`, async () => {
    const client = await mount(makeBridge(), { async verify() { return { ok: true, identity: { subject: "op" } }; } });
    try {
      const registered = await client.postJson("/oauth/register", { redirect_uris: [REDIRECT] });
      const clientId = JSON.parse(registered.body).client_id as string;
      const authorize = await client.get(`/oauth/authorize?${new URLSearchParams({
        response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
        code_challenge: "A".repeat(43), code_challenge_method: "S256",
      })}`, { [IDENTITY_HEADER]: STUB_TOKEN });
      const consentToken = /name="consent_token" value="([^"]+)"/.exec(authorize.body)?.[1];
      assert.ok(consentToken);
      const body = new URLSearchParams([
        ["consent_token", consentToken],
        ["approved", "false"],
        ["approved", "true"],
      ]).toString();
      const response = await client.requestOccurrences("POST", "/oauth/authorize/approve",
        [["Content-Type", "application/x-www-form-urlencoded"], ["Origin", "https://auth.test"]], body);
      assert.equal(response.status, 400);
      assert.equal(response.headers.location, undefined);
      assert.match(response.body, /"error":"invalid_request"/);
      assert.doesNotMatch(response.body, /code=/);
    } finally {
      await client.close?.();
    }
  });
}
