import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { JWK } from "jose";
import { createBridgeConfig } from "../src/config.ts";
import { disableMachineClient, provisionMachineClient, rotateMachineClientSecret } from "../src/machine-client.ts";
import type {
  ClientRegistration, MachineClientMutationAudit, MachineClientStore, VersionedMachineClientRegistration,
} from "../src/ports/client-store.ts";
import type { AuthAuditEvent, AuditPort } from "../src/ports/audit.ts";
import { SystemClock } from "../src/ports/clock.ts";
import { buildApp } from "../examples/fastify-sqlite/app.ts";

const RESOURCE_A = "http://localhost/mcp";
const RESOURCE_B = "http://localhost:3001/mcp";
const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;

class SharedMachineStore implements MachineClientStore {
  readonly rows = new Map<string, ClientRegistration>();
  readonly durableAudits: MachineClientMutationAudit[] = [];
  async save(client: ClientRegistration): Promise<void> { this.rows.set(client.clientId, structuredClone(client)); }
  async find(clientId: string): Promise<ClientRegistration | null> { return structuredClone(this.rows.get(clientId) ?? null); }
  async createMachineClient(client: VersionedMachineClientRegistration & { status: "active" }, audit: MachineClientMutationAudit): Promise<boolean> {
    if (this.rows.has(client.clientId)) return false;
    this.rows.set(client.clientId, structuredClone(client)); this.durableAudits.push(structuredClone(audit)); return true;
  }
  async compareAndSwapMachineClient(expectedVersion: number, client: VersionedMachineClientRegistration, audit: MachineClientMutationAudit): Promise<boolean> {
    const current = this.rows.get(client.clientId) as { version?: number } | undefined;
    if (!current || current.version !== expectedVersion) return false;
    this.rows.set(client.clientId, structuredClone(client)); this.durableAudits.push(structuredClone(audit)); return true;
  }
}

class RecordingAudit implements AuditPort {
  readonly events: AuthAuditEvent[] = [];
  async writeAuthEvent(event: AuthAuditEvent): Promise<void> { this.events.push(structuredClone(event)); }
}

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "release" } as JWK;
}

function config(resource: string, store: SharedMachineStore) {
  const issuer = new URL(resource).origin;
  return createBridgeConfig({ issuer, resource, consentSigningSecret: "m".repeat(40), signingPrivateJwk: jwk(), signingKeyId: "release",
    redirectAllowlist: ["http://localhost:4321/callback"], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: [issuer], dcr: { mode: "stored", store }, clientCredentials: { enabled: true }, dev: { allowInsecureLocalhost: true },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300 });
}

function basic(clientId: string, secret: string): string { return `Basic ${Buffer.from(`${clientId}:${secret}`).toString("base64")}`; }

async function sdkPing(app: Awaited<ReturnType<typeof buildApp>>["app"], token: string, expected: string): Promise<void> {
  const base = await app.listen({ host: "127.0.0.1", port: 0 });
  const transport = new StreamableHTTPClientTransport(new URL("/mcp", base), { requestInit: { headers: { authorization: `Bearer ${token}` } } });
  const client = new Client({ name: "release-machine", version: "1" }, { capabilities: {} });
  try {
    await client.connect(transport);
    const result = await client.callTool({ name: "ping", arguments: {} });
    const text = (result.content as Array<{ type: string; text?: string }>).find((part) => part.type === "text")?.text;
    assert.equal(text, expected);
  } finally { await client.close(); await transport.close(); }
}

releaseTest("RM.7 machine credentials compose through the shipped token route and remain resource-bound", async () => {
  const store = new SharedMachineStore();
  const audit = new RecordingAudit();
  const clock = new SystemClock();
  const configA = config(RESOURCE_A, store);
  const configB = config(RESOURCE_B, store);
  const depsA = { store, catalog: configA.scopeCatalog, resource: configA.resource, clock, audit };
  const depsB = { store, catalog: configB.scopeCatalog, resource: configB.resource, clock, audit };
  const credential = await provisionMachineClient(depsA, { name: "release", allowedScopes: ["mcp:read"] });
  const appA = await buildApp({ config: configA, audit, identity: { async verify() { return { ok: false as const, reason: "unused" }; } } });
  const appB = await buildApp({ config: configB, audit, identity: { async verify() { return { ok: false as const, reason: "unused" }; } } });
  try {
    const basicToken = await appA.app.inject({ method: "POST", url: "/oauth/token", headers: {
      "content-type": "application/x-www-form-urlencoded", authorization: basic(credential.clientId, credential.clientSecret),
    }, payload: new URLSearchParams({ grant_type: "client_credentials", scope: "mcp:read" }).toString() });
    assert.equal(basicToken.statusCode, 200);
    const accessToken = basicToken.json<{ access_token: string }>().access_token;
    await sdkPing(appA.app, accessToken, `pong: ${credential.clientId}`);

    const postToken = await appA.app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: new URLSearchParams({ grant_type: "client_credentials", client_id: credential.clientId, client_secret: credential.clientSecret }).toString() });
    assert.equal(postToken.statusCode, 200);

    const beforeB = structuredClone(store.rows.get(credential.clientId));
    const successBeforeB = audit.events.filter((event) => event.status === "success").length;
    const rejected = await appB.app.inject({ method: "POST", url: "/oauth/token", headers: {
      "content-type": "application/x-www-form-urlencoded", authorization: basic(credential.clientId, credential.clientSecret),
    }, payload: new URLSearchParams({ grant_type: "client_credentials" }).toString() });
    assert.equal(rejected.statusCode, 401);
    for (const action of [
      () => rotateMachineClientSecret(depsB, credential.clientId),
      () => disableMachineClient(depsB, credential.clientId),
    ]) await assert.rejects(action);
    assert.deepEqual(store.rows.get(credential.clientId), beforeB, "resource B cannot mutate A's credential");
    assert.equal(audit.events.filter((event) => event.status === "success").length, successBeforeB, "resource B emits no success audit");

    const rotated = await rotateMachineClientSecret(depsA, credential.clientId, { graceSeconds: 300 });
    for (const secret of [credential.clientSecret, rotated.clientSecret]) {
      const response = await appA.app.inject({ method: "POST", url: "/oauth/token", headers: {
        "content-type": "application/x-www-form-urlencoded", authorization: basic(credential.clientId, secret),
      }, payload: new URLSearchParams({ grant_type: "client_credentials" }).toString() });
      assert.equal(response.statusCode, 200, "old and new secrets work during grace");
    }
    await disableMachineClient(depsA, credential.clientId);
    const disabled = await appA.app.inject({ method: "POST", url: "/oauth/token", headers: {
      "content-type": "application/x-www-form-urlencoded", authorization: basic(credential.clientId, rotated.clientSecret),
    }, payload: new URLSearchParams({ grant_type: "client_credentials" }).toString() });
    assert.equal(disabled.statusCode, 401);
  } finally {
    await appA.app.close(); await appA.store.close();
    await appB.app.close(); await appB.store.close();
  }
});
