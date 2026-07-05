// Integration tests of the STANDALONE ENTRY wiring (examples/fastify-sqlite's
// buildExample — what index.ts calls). The earlier e2e tests drove buildApp()
// directly, so index.ts's branch selection / state-dir creation / sqlite+audit
// path derivation were never exercised — which is why the "CF branch doesn't
// create the dir" crash, the "routes CF startup to pairing" misrouting, and the
// "drops sqliteFile" regressions all shipped past 179 green unit tests. These
// tests cover exactly that wiring, both branches.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { JWK } from "jose";
import { buildExample } from "../examples/fastify-sqlite/app.ts";

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }) } as JWK;
}

const AUTHORIZE_QUERY = "/oauth/authorize?response_type=code&client_id=c&redirect_uri=http://localhost/cb&code_challenge=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx&code_challenge_method=S256&scope=mcp:read";

test("integration — zero-setup branch: buildExample creates a fresh state dir, runs quickstart, selects pairing", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-zs-"));
  const dir = join(base, "nested-state"); // does NOT exist — buildExample must create it
  try {
    const { app, store } = await buildExample({ MCP_SSO_DIR: dir });
    // quickstart created the signing material + .gitignore + the dir.
    assert.ok(existsSync(dir), "state dir created");
    assert.ok(existsSync(join(dir, "secrets.json")), "quickstart wrote secrets.json");
    assert.ok(existsSync(join(dir, ".gitignore")), "quickstart wrote .gitignore");
    // Pairing mode (NOT header-based): GET /oauth/authorize renders the pairing page.
    const page = await app.inject({ method: "GET", url: AUTHORIZE_QUERY });
    assert.equal(page.statusCode, 200);
    assert.match(page.body, /Pair this device/);
    await app.close();
    await store.close();
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — Cloudflare Access branch: buildExample creates the state dir, opens auth.db, selects CF identity (NOT pairing)", async () => {
  // This is the regression class that shipped untested: the CF branch derives
  // auth.db/audit.jsonl under MCP_SSO_DIR but must also CREATE that dir, or
  // openSqliteStore crashes ("unable to open database file") and audit appends
  // fail. It also must not route to pairing.
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-cf-"));
  const dir = join(base, "nested-state"); // does NOT exist
  try {
    const key = jwk();
    const { app, store, config } = await buildExample({
      MCP_SSO_DIR: dir,
      CF_ACCESS_AUDIENCE: "https://cf.test/aud",
      CF_ACCESS_CERTS_URL: "https://cf.test/certs",
      CF_ACCESS_ISSUER: "https://cf.test",
      OAUTH_ISSUER: "http://localhost",
      OAUTH_RESOURCE: "http://localhost/mcp",
      OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40),
      OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(key),
      OAUTH_ALLOW_INSECURE_LOCALHOST: "true",
    });
    assert.equal(config.issuer, "http://localhost");
    assert.ok(existsSync(dir), "CF branch created the state dir (the regression)");
    assert.ok(existsSync(join(dir, "auth.db")), "sqlite opened auth.db in the state dir");
    assert.ok(existsSync(join(dir, ".gitignore")), "CF branch protected the state dir from git (managed .gitignore)");
    // CF header-based identity (NOT pairing): no Cf-Access-Jwt-Assertion → 401,
    // not the 200 pairing page.
    const page = await app.inject({ method: "GET", url: AUTHORIZE_QUERY });
    assert.equal(page.statusCode, 401);
    await app.close();
    await store.close();
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — OAUTH_SQLITE_FILE overrides the default auth.db location (both branches)", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-sql-"));
  const dir = join(base, "state");
  const customDb = join(base, "custom.db");
  try {
    await buildExample({ MCP_SSO_DIR: dir, OAUTH_SQLITE_FILE: customDb });
    assert.ok(existsSync(customDb), "OAUTH_SQLITE_FILE honored (custom db created)");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
