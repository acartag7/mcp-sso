// RM.13 — the shipped audit sinks under a real OAuth flow.
//
// `JsonlFileAudit`, `WebhookAudit`, and `combineAudit` are root-exported public
// API (§15, §17.7), and the audit trail is a security artifact rather than a
// convenience: it is the record an operator reconstructs an incident from. The
// unit tests cover each sink in isolation. Nothing proved the fan-out survives
// composition — that a real authorize/consent/token flow through the shipped
// Fastify routes actually reaches BOTH sinks, and that neither publishes a
// credential when it gets there.
//
// The webhook transport is injected rather than dialled, so this row makes no
// network call; what it exercises is the wiring and the event payload.
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { JWK } from "jose";
import { JsonlFileAudit, WebhookAudit, combineAudit } from "../src/index.ts";
import { createBridgeConfig } from "../src/config.ts";
import { pkceChallenge } from "../src/crypto.ts";
import { buildApp } from "../examples/fastify-sqlite/app.ts";

const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;

const REDIRECT = "https://private.test/callback";
const VERIFIER = "release-audit-sink-verifier-0123456789abcdef0123";

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "release" } as JWK;
}

releaseTest("RM.13 both shipped audit sinks receive a real flow through combineAudit without leaking credentials", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-rm13-"));
  const jsonlPath = join(dir, "audit.jsonl");
  const posted: Array<Record<string, unknown>> = [];
  // A delivery FAILURE must not read as success: the sink logs to stderr and
  // swallows the error, so without this the row would pass against a webhook
  // that never actually accepted anything.
  const sinkErrors: string[] = [];
  const realError = console.error;
  console.error = (...args: unknown[]) => { sinkErrors.push(args.join(" ")); };

  // Injected transport: the row proves wiring and payload, not network behavior.
  const webhook = new WebhookAudit("https://collector.test/ingest", {
    headers: { authorization: "Bearer collector-secret-token" },
    fetchImpl: (async (_url: unknown, init?: { body?: string }) => {
      posted.push(JSON.parse(init?.body ?? "{}") as Record<string, unknown>);
      return new Response(null, { status: 204 });
    }) as unknown as typeof fetch,
  });

  const { app } = await buildApp({
    config: createBridgeConfig({
      issuer: "http://localhost", resource: "http://localhost/mcp",
      consentSigningSecret: "r".repeat(40), signingPrivateJwk: jwk(), signingKeyId: "release",
      redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
      allowedOrigins: ["http://localhost"], dcr: { mode: "stateless" },
      dev: { allowInsecureLocalhost: true },
      accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 3600,
      consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
    }),
    identityHeader: "x-release-identity",
    identity: { async verify() { return { ok: true, identity: { subject: "release-user" } }; } },
    audit: combineAudit(new JsonlFileAudit(jsonlPath), webhook),
    acknowledgeUnsafeStatelessDefaults: true,
  } as Parameters<typeof buildApp>[0]);

  try {
    const registered = await app.inject({
      method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" },
      payload: JSON.stringify({ redirect_uris: [REDIRECT], application_type: "web" }),
    });
    assert.equal(registered.statusCode, 201, registered.body);
    const clientId = registered.json<{ client_id: string }>().client_id;

    const authorize = await app.inject({
      method: "GET",
      url: `/oauth/authorize?${new URLSearchParams({
        response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
        code_challenge: pkceChallenge(VERIFIER), code_challenge_method: "S256", scope: "mcp:read",
      })}`,
      headers: { "x-release-identity": "release-token" },
    });
    assert.equal(authorize.statusCode, 200, authorize.body);

    // Fan-out reached BOTH sinks for the same flow.
    const jsonl = await readFile(jsonlPath, "utf8");
    const fileEvents = jsonl.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line) as Record<string, unknown>);
    assert.ok(fileEvents.length > 0, "the JSONL sink recorded no event for a real flow");
    assert.ok(posted.length > 0, "the webhook sink received no event for a real flow");
    assert.equal(
      fileEvents.length, posted.length,
      "combineAudit must deliver the same events to every sink, not a subset",
    );

    // Neither sink publishes a credential. The webhook's own collector token is
    // a header, so it must not appear in a body either.
    const everything = `${jsonl}\n${JSON.stringify(posted)}`;
    for (const secret of ["collector-secret-token", VERIFIER, "release-token", "r".repeat(40)]) {
      assert.ok(!everything.includes(secret), `an audit sink published a credential: ${secret.slice(0, 16)}…`);
    }
    // The consent token is a bearer-equivalent for the approve step.
    const consent = /name="consent_token" value="([^"]+)"/.exec(authorize.body)?.[1];
    assert.ok(consent, "expected a consent token in the rendered page");
    assert.ok(!everything.includes(consent), "an audit sink published the consent token");
    assert.deepEqual(
      sinkErrors.filter((line) => line.includes("audit webhook write failed")), [],
      "the webhook sink reported a delivery failure; delivery must actually succeed",
    );
  } finally {
    console.error = realError;
    await app.close();
    await rm(dir, { recursive: true, force: true });
  }
});
