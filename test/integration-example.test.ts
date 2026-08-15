// Integration tests of the STANDALONE ENTRY wiring (examples/fastify-sqlite's
// buildExample — what index.ts calls). The earlier e2e tests drove buildApp()
// directly, so index.ts's branch selection / state-dir creation / sqlite+audit
// path derivation were never exercised — which is why the "CF branch doesn't
// create the dir" crash, the "routes CF startup to pairing" misrouting, and the
// "drops sqliteFile" regressions all shipped past 179 green unit tests. These
// tests cover exactly that wiring, both branches.

import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { FastifyRateLimitOptions, FastifyRateLimitStore } from "@fastify/rate-limit";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { pkceChallenge } from "../src/crypto.ts";
import { AuthConfigError, createBridgeConfig } from "../src/config.ts";
import {
  buildApp,
  buildExample,
  configFromEnv,
  createOidcUpstreamFromEnv,
  defaultListenHost,
  assertConsolePairingListenHostBeforeState,
  entraGroupAuthorizationFromEnv,
  UNSAFE_NON_LOOPBACK_PAIRING_ENV,
} from "../examples/fastify-sqlite/app.ts";
import { buildGateway, buildGatewayExample } from "../examples/api-key-gateway/app.ts";
import { TRUSTED_PROXIES_ENV } from "../examples/fastify-sqlite/trusted-proxy.ts";
import { rawOccurrenceCall } from "./lib/adapter-header-flow.ts";

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }) } as JWK;
}

const AUTHORIZE_QUERY = "/oauth/authorize?response_type=code&client_id=c&redirect_uri=http://localhost/cb&code_challenge=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx&code_challenge_method=S256&scope=mcp:read";

test("integration — zero-setup branch: buildExample creates a fresh state dir, runs quickstart, selects pairing", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-zs-"));
  const dir = join(base, "nested-state"); // does NOT exist — buildExample must create it
  try {
    const { app, store, config } = await buildExample({ MCP_SSO_DIR: dir });
    // quickstart created the signing material + .gitignore + the dir.
    assert.ok(existsSync(dir), "state dir created");
    assert.ok(existsSync(join(dir, "secrets.json")), "quickstart wrote secrets.json");
    assert.ok(existsSync(join(dir, ".gitignore")), "quickstart wrote .gitignore");
    assert.equal(config.cimd?.enabled, true, "zero-setup example advertises CIMD");
    assert.equal(config.dcr.mode, "stateless", "DCR remains available as a compatibility path");
    assert.deepEqual(config.redirectAllowlist, ["http://localhost", "http://127.0.0.1"], "zero-setup composition explicitly declares loopback callback origins");
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

test("integration — gateway zero-setup branch enables CIMD and retains DCR", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-gateway-cimd-"));
  const dir = join(base, "state");
  try {
    const { app, store, config } = await buildGatewayExample(
      { MCP_SSO_DIR: dir },
      { backendUrl: "http://127.0.0.1:1/mcp", getBackendCredential: () => "unused" },
    );
    assert.equal(config.cimd?.enabled, true, "gateway example advertises CIMD");
    assert.equal(config.dcr.mode, "stateless", "gateway keeps DCR as a compatibility path");
    assert.deepEqual(config.redirectAllowlist, ["http://localhost", "http://127.0.0.1"], "zero-setup gateway explicitly declares loopback callback origins");
    await app.close();
    await store.close();
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — explicit empty redirect allowlist removes local composition defaults", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-zs-empty-redirects-"));
  const appDir = join(base, "app");
  const gatewayDir = join(base, "gateway");
  try {
    const appResult = await buildExample({ MCP_SSO_DIR: appDir, OAUTH_REDIRECT_ALLOWLIST: "" });
    assert.deepEqual(appResult.config.redirectAllowlist, [], "example explicit empty value removes loopback trust");
    await appResult.app.close();
    await appResult.store.close();

    const gatewayResult = await buildGatewayExample(
      { MCP_SSO_DIR: gatewayDir, OAUTH_REDIRECT_ALLOWLIST: "" },
      { backendUrl: "http://127.0.0.1:1/mcp", getBackendCredential: () => "unused" },
    );
    assert.deepEqual(gatewayResult.config.redirectAllowlist, [], "gateway explicit empty value removes loopback trust");
    await gatewayResult.app.close();
    await gatewayResult.store.close();
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — unsupported loopback URL schemes fail before starter state creation", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-bad-loopback-scheme-"));
  try {
    for (const target of ["fastify", "gateway"] as const) {
      const dir = join(base, target);
      const env = {
        MCP_SSO_DIR: dir,
        OAUTH_ISSUER: "ftp://localhost:3000",
        OAUTH_RESOURCE: "ftp://localhost:3000/mcp",
      };
      const boot = target === "fastify"
        ? buildExample(env)
        : buildGatewayExample(env, {
          backendUrl: "http://127.0.0.1:1/mcp", getBackendCredential: () => "unused",
        });
      await assert.rejects(boot, /console-pairing starter requires loopback/);
      assert.equal(existsSync(dir), false, `${target}: no signing state was created`);
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — no-IdP non-loopback HOST fails before state in both examples unless the unsafe escape is exact", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-nonloopback-refuse-"));
  try {
    for (const target of ["fastify", "gateway"] as const) {
      for (const override of [undefined, "false", "TRUE"] as const) {
        const dir = join(base, `${target}-${override ?? "unset"}`);
        const env = {
          MCP_SSO_DIR: dir,
          HOST: "0.0.0.0",
          ...(override === undefined ? {} : { [UNSAFE_NON_LOOPBACK_PAIRING_ENV]: override }),
        };
        const boot = target === "fastify"
          ? buildExample(env)
          : buildGatewayExample(env, {
            backendUrl: "http://127.0.0.1:1/mcp", getBackendCredential: () => "unused",
          });
        await assert.rejects(boot, new RegExp(`${UNSAFE_NON_LOOPBACK_PAIRING_ENV}=true`));
        assert.equal(existsSync(dir), false, `${target}/${override ?? "unset"}: no state was created`);
      }
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — exact unsafe non-loopback escape warns before state and neither zero-setup example auto-acknowledges", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-nonloopback-escape-"));
  const errors: string[] = [];
  const warnings: string[] = [];
  const originalError = console.error;
  const originalWarn = console.warn;
  console.error = (...args: unknown[]) => { errors.push(args.map(String).join(" ")); };
  console.warn = (...args: unknown[]) => { warnings.push(args.map(String).join(" ")); };
  try {
    for (const target of ["fastify", "gateway"] as const) {
      const dir = join(base, target);
      const env = {
        MCP_SSO_DIR: dir,
        HOST: "0.0.0.0",
        [UNSAFE_NON_LOOPBACK_PAIRING_ENV]: "true",
      };
      const built = target === "fastify"
        ? await buildExample(env)
        : await buildGatewayExample(env, {
          backendUrl: "http://127.0.0.1:1/mcp", getBackendCredential: () => "unused",
        });
      assert.ok(existsSync(join(dir, "secrets.json")), `${target}: escape permitted state creation`);
      await built.app.close();
      await built.store.close();
    }
  } finally {
    console.error = originalError;
    console.warn = originalWarn;
    rmSync(base, { recursive: true, force: true });
  }
  const escapeWarnings = errors.filter((line) => line.includes(`DANGER: ${UNSAFE_NON_LOOPBACK_PAIRING_ENV}=true`));
  assert.equal(escapeWarnings.length, 2, "each example emits one loud unsafe-escape warning");
  assert.ok(escapeWarnings.every((line) => line.includes("HOST=0.0.0.0")));
  assert.equal(
    warnings.filter((line) => line.includes("acknowledgeUnsafeStatelessDefaults")).length,
    0,
    "zero-setup builders no longer auto-acknowledge the core unsafe-composition escape",
  );
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
      OAUTH_REDIRECT_ALLOWLIST: "https://client.test/callback",
    });
    assert.equal(config.issuer, "http://localhost");
    assert.equal(config.cimd?.enabled, true, "production example advertises CIMD");
    assert.equal(config.dcr.mode, "stateless", "DCR remains available as a compatibility path");
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

test("integration — Cloudflare Access branch rejects a group/other-accessible pre-existing state dir", async () => {
  // A world-writable MCP_SSO_DIR lets another local user replace auth.db with
  // OAuth state they control. The CF branch must mirror quickstart's assertRealDir.
  if (process.platform === "win32") return;
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-cf-unsafe-"));
  const dir = join(base, "state");
  mkdirSync(dir, { recursive: true, mode: 0o777 });
  chmodSync(dir, 0o777);
  writeFileSync(join(dir, ".gitignore"), "*\n", { mode: 0o600 }); // valid ignore → only the dir mode is at fault
  try {
    await assert.rejects(
      buildExample({
        MCP_SSO_DIR: dir,
        CF_ACCESS_AUDIENCE: "https://cf.test/aud",
        CF_ACCESS_CERTS_URL: "https://cf.test/certs",
        CF_ACCESS_ISSUER: "https://cf.test",
        OAUTH_ISSUER: "http://localhost:3000",
        OAUTH_RESOURCE: "http://localhost:3000/mcp",
        OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40),
        OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(jwk()),
        OAUTH_ALLOW_INSECURE_LOCALHOST: "true",
      }),
      AuthConfigError,
    );
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — listen host: pairing binds loopback; Cloudflare binds 0.0.0.0 (HOST overrides)", () => {
  // Pairing's trust envelope is single-operator/private-console: the authorize
  // surface + the printed-code attempt budget must not be exposed to the network
  // by default. CF/proxy is externally bound (fronted by CF / a reverse proxy).
  assert.equal(defaultListenHost({}), "127.0.0.1", "pairing mode → loopback");
  assert.equal(defaultListenHost({ CF_ACCESS_AUDIENCE: "x" }), "0.0.0.0", "CF mode → all interfaces");
  assert.equal(defaultListenHost({ ENTRA_TENANT_ID: "" }), "0.0.0.0", "blank Entra selector remains production mode (boot later rejects it)");
  assert.equal(defaultListenHost({ CF_ACCESS_AUDIENCE: "" }), "0.0.0.0", "blank CF selector remains production mode (boot later rejects it)");
  assert.equal(defaultListenHost({ GOOGLE_CLIENT_ID: "x" }), "0.0.0.0", "Google redirect mode → all interfaces");
  assert.equal(defaultListenHost({ OIDC_ISSUER: "https://issuer.test" }), "0.0.0.0", "generic OIDC redirect mode → all interfaces");
  assert.equal(defaultListenHost({ GOOGLE_CLIENT_ID: "" }), "0.0.0.0", "blank Google selector remains production mode (boot later rejects it)");
  assert.equal(defaultListenHost({ OIDC_ISSUER: "" }), "0.0.0.0", "blank OIDC selector remains production mode (boot later rejects it)");
  for (const host of ["localhost", "127.0.0.1", "::1"]) {
    assert.doesNotThrow(() => assertConsolePairingListenHostBeforeState({ HOST: host }), `${host} is an admitted exact loopback bind`);
  }
});

test("integration — every provider-selector pair fails before state creation in both examples", async () => {
  const consentSigningSecret = randomBytes(32).toString("base64url");
  const googleClientSecret = randomBytes(24).toString("base64url");
  const selectors = [
    ["ENTRA_TENANT_ID", "00000000-0000-0000-0000-000000000001"],
    ["CF_ACCESS_AUDIENCE", "cf-audience"],
    ["GOOGLE_CLIENT_ID", "google-client"],
    ["OIDC_ISSUER", ""], // blank-but-present still makes selection ambiguous
  ] as const;
  const pairs = selectors.flatMap((left, index) =>
    selectors.slice(index + 1).map((right) => [left, right] as const)
  );
  assert.equal(pairs.length, 6, "four selectors have exactly six unordered pairs");

  const redirectIdentity = {
    redirectUri: "http://localhost:3000/oauth/callback",
    buildAuthorizationUrl: () => "https://idp.test/authorize",
    exchangeAndVerify: async () => ({ ok: false, kind: "exchange_failed", reason: "unused" } as const),
  };
  const identityFactories = {
    google: async () => redirectIdentity,
    genericOidc: async () => redirectIdentity,
  };
  const builders = [
    { name: "fastify", run: (env: Record<string, string | undefined>) => buildExample(env, identityFactories) },
    {
      name: "gateway",
      run: (env: Record<string, string | undefined>) => buildGatewayExample(env, {
        backendUrl: "http://127.0.0.1:1/mcp",
        getBackendCredential: () => { throw new Error("provider-selector guard did not run first"); },
        identityFactories,
      }),
    },
  ];

  for (const builder of builders) {
    for (const [left, right] of pairs) {
      const base = mkdtempSync(join(tmpdir(), `mcp-sso-int-${builder.name}-selector-pair-`));
      const dir = join(base, "state");
      const env = {
        MCP_SSO_DIR: dir,
        OAUTH_ISSUER: "http://localhost:3000",
        OAUTH_RESOURCE: "http://localhost:3000/mcp",
        OAUTH_CONSENT_SIGNING_SECRET: consentSigningSecret,
        OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(jwk()),
        OAUTH_ALLOW_INSECURE_LOCALHOST: "true",
        ENTRA_CLIENT_ID: "entra-client",
        ENTRA_REDIRECT_URI: "http://localhost:3000/oauth/callback",
        CF_ACCESS_CERTS_URL: "https://cf.test/certs",
        CF_ACCESS_ISSUER: "https://cf.test",
        GOOGLE_CLIENT_SECRET: googleClientSecret,
        GOOGLE_REDIRECT_URI: "http://localhost:3000/oauth/callback",
        OIDC_CLIENT_ID: "oidc-client",
        OIDC_REDIRECT_URI: "http://localhost:3000/oauth/callback",
        [left[0]]: left[1],
        [right[0]]: right[1],
      };
      try {
        await assert.rejects(
          builder.run(env),
          /exactly one identity provider selector may be present/,
          `${builder.name}: ${left[0]} + ${right[0]}`,
        );
        assert.equal(existsSync(dir), false, `${builder.name}: ${left[0]} + ${right[0]} leaves no state`);
      } finally {
        rmSync(base, { recursive: true, force: true });
      }
    }
  }
});

test("integration — Entra group authorization env preserves the complete object and absence", () => {
  const value = {
    mapping: {
      "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee": ["mcp:write"],
    },
    baseScopes: ["mcp:read"],
  };

  assert.deepEqual(
    entraGroupAuthorizationFromEnv({
      ENTRA_GROUP_AUTHORIZATION_JSON: JSON.stringify(value),
    }),
    value,
  );
  assert.equal(entraGroupAuthorizationFromEnv({}), undefined);
});

test("integration — Google branch boot-fails on a missing confidential-client secret before creating state", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-google-secret-"));
  const dir = join(base, "state");
  try {
    await assert.rejects(
      buildExample({
        MCP_SSO_DIR: dir,
        GOOGLE_CLIENT_ID: "google-client",
        GOOGLE_REDIRECT_URI: "http://localhost:3000/google/callback",
        OAUTH_ISSUER: "http://localhost:3000",
        OAUTH_RESOURCE: "http://localhost:3000/mcp",
        OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40),
        OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(jwk()),
        OAUTH_ALLOW_INSECURE_LOCALHOST: "true",
      }),
      /Missing env: GOOGLE_CLIENT_SECRET/,
    );
    assert.equal(existsSync(dir), false, "missing Google secret fails before state-dir creation");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — Google branch rejects a malformed email-allowlist opt-in instead of silently disabling it", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-google-bool-"));
  const dir = join(base, "state");
  try {
    await assert.rejects(
      buildExample({
        MCP_SSO_DIR: dir,
        GOOGLE_CLIENT_ID: "google-client",
        GOOGLE_CLIENT_SECRET: "google-secret",
        GOOGLE_REDIRECT_URI: "http://localhost:3000/google/callback",
        GOOGLE_ALLOW_EMAIL_ALLOWLIST: "yes",
        OAUTH_ISSUER: "http://localhost:3000",
        OAUTH_RESOURCE: "http://localhost:3000/mcp",
        OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40),
        OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(jwk()),
        OAUTH_ALLOW_INSECURE_LOCALHOST: "true",
      }),
      /Invalid env: GOOGLE_ALLOW_EMAIL_ALLOWLIST must be 'true' or 'false'/,
    );
    assert.equal(existsSync(dir), false, "malformed opt-in fails before state-dir creation");
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — blank production identity env fails closed before state creation in both examples", async () => {
  const invalidCases = [
    {
      name: "blank Entra selector",
      provider: { ENTRA_TENANT_ID: "", ENTRA_CLIENT_ID: "entra-client", ENTRA_REDIRECT_URI: "http://localhost:3000/entra/callback" },
      pattern: /Missing env: ENTRA_TENANT_ID/,
    },
    {
      name: "blank Entra group authorization JSON",
      provider: {
        ENTRA_TENANT_ID: "00000000-0000-0000-0000-000000000001",
        ENTRA_CLIENT_ID: "entra-client", ENTRA_REDIRECT_URI: "http://localhost:3000/oauth/callback",
        ENTRA_GROUP_AUTHORIZATION_JSON: "",
      },
      pattern: /ENTRA_GROUP_AUTHORIZATION_JSON must be a non-empty JSON object/,
    },
    {
      name: "malformed Entra group authorization JSON",
      provider: {
        ENTRA_TENANT_ID: "00000000-0000-0000-0000-000000000001",
        ENTRA_CLIENT_ID: "entra-client", ENTRA_REDIRECT_URI: "http://localhost:3000/oauth/callback",
        ENTRA_GROUP_AUTHORIZATION_JSON: "{",
      },
      pattern: /ENTRA_GROUP_AUTHORIZATION_JSON must be valid JSON/,
    },
    {
      name: "non-GUID Entra group authorization mapping",
      provider: {
        ENTRA_TENANT_ID: "00000000-0000-0000-0000-000000000001",
        ENTRA_CLIENT_ID: "entra-client", ENTRA_REDIRECT_URI: "http://localhost:3000/oauth/callback",
        ENTRA_GROUP_AUTHORIZATION_JSON: JSON.stringify({ mapping: { Administrators: ["mcp:read"] } }),
      },
      pattern: /mapping key "Administrators" is not a GUID/,
    },
    {
      name: "out-of-catalog Entra group authorization scope",
      provider: {
        ENTRA_TENANT_ID: "00000000-0000-0000-0000-000000000001",
        ENTRA_CLIENT_ID: "entra-client", ENTRA_REDIRECT_URI: "http://localhost:3000/oauth/callback",
        ENTRA_GROUP_AUTHORIZATION_JSON: JSON.stringify({
          mapping: { "00000000-0000-0000-0000-000000000002": ["mcp:admin"] },
        }),
      },
      pattern: /mapped scope "mcp:admin".*is not in scopeCatalog/,
    },
    {
      name: "blank Cloudflare selector",
      provider: { CF_ACCESS_AUDIENCE: "", CF_ACCESS_CERTS_URL: "https://cf.test/certs", CF_ACCESS_ISSUER: "https://cf.test" },
      pattern: /Missing env: CF_ACCESS_AUDIENCE/,
    },
    {
      name: "blank Google selector",
      provider: { GOOGLE_CLIENT_ID: "", GOOGLE_REDIRECT_URI: "http://localhost:3000/google/callback" },
      pattern: /Missing env: GOOGLE_CLIENT_ID/,
    },
    {
      name: "blank generic OIDC selector",
      provider: { OIDC_ISSUER: "", OIDC_CLIENT_ID: "oidc-client", OIDC_REDIRECT_URI: "http://localhost:3000/oidc/callback" },
      pattern: /Missing env: OIDC_ISSUER/,
    },
    {
      name: "blank Google hosted domain",
      provider: {
        GOOGLE_CLIENT_ID: "google-client", GOOGLE_CLIENT_SECRET: "google-secret",
        GOOGLE_REDIRECT_URI: "http://localhost:3000/google/callback", GOOGLE_HOSTED_DOMAIN: "",
      },
      pattern: /google_bad_config: hostedDomain must be a non-empty string/,
    },
    {
      name: "blank generic OIDC secret",
      provider: {
        OIDC_ISSUER: "https://issuer.test", OIDC_CLIENT_ID: "oidc-client", OIDC_CLIENT_SECRET: "",
        OIDC_REDIRECT_URI: "http://localhost:3000/oidc/callback",
      },
      pattern: /generic_oidc_bad_config: clientSecret must be a non-empty string/,
    },
    {
      name: "blank generic OIDC scopes",
      provider: {
        OIDC_ISSUER: "https://issuer.test", OIDC_CLIENT_ID: "oidc-client", OIDC_SCOPES: "",
        OIDC_REDIRECT_URI: "http://localhost:3000/oidc/callback",
      },
      pattern: /generic_oidc_bad_config: scopes must be a non-empty/,
    },
  ];
  const builders = [
    { name: "fastify", run: (env: Record<string, string | undefined>) => buildExample(env) },
    {
      name: "gateway",
      run: (env: Record<string, string | undefined>) => buildGatewayExample(env, {
        backendUrl: "http://127.0.0.1:1/mcp", getBackendCredential: () => "unused",
      }),
    },
  ];
  for (const builder of builders) {
    for (const invalid of invalidCases) {
      const base = mkdtempSync(join(tmpdir(), `mcp-sso-int-${builder.name}-blank-env-`));
      const dir = join(base, "state");
      try {
        await assert.rejects(builder.run({
          MCP_SSO_DIR: dir,
          OAUTH_ISSUER: "http://localhost:3000",
          OAUTH_RESOURCE: "http://localhost:3000/mcp",
          OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40),
          OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(jwk()),
          OAUTH_ALLOW_INSECURE_LOCALHOST: "true",
          ...invalid.provider,
        }), invalid.pattern, `${builder.name}: ${invalid.name}`);
        assert.equal(existsSync(dir), false, `${builder.name}: ${invalid.name} fails before state creation`);
      } finally {
        rmSync(base, { recursive: true, force: true });
      }
    }
  }
});

test("integration — invalid upstream callback config fails before state creation in both examples", async () => {
  const redirectCases = [
    { name: "foreign origin", redirectUri: "http://other.test/google/callback", pattern: /identity.redirectUri must equal issuerOrigin/ },
    { name: "reserved route", redirectUri: "http://localhost:3000/oauth/token", pattern: /callbackPath must not be a reserved route/ },
  ];
  const providers = [
    {
      name: "Entra",
      env: (redirectUri: string) => ({
        ENTRA_TENANT_ID: "00000000-0000-0000-0000-000000000001",
        ENTRA_CLIENT_ID: "entra-client", ENTRA_REDIRECT_URI: redirectUri,
      }),
      identityFactories: {},
    },
    {
      name: "Google",
      env: (redirectUri: string) => ({
        GOOGLE_CLIENT_ID: "google-client", GOOGLE_CLIENT_SECRET: "google-secret", GOOGLE_REDIRECT_URI: redirectUri,
      }),
      identityFactories: { google: async () => { throw new Error("Google identity factory ran before callback validation"); } },
    },
    {
      name: "generic OIDC",
      env: (redirectUri: string) => ({
        OIDC_ISSUER: "https://issuer.test", OIDC_CLIENT_ID: "oidc-client", OIDC_REDIRECT_URI: redirectUri,
      }),
      identityFactories: { genericOidc: async () => { throw new Error("generic OIDC identity factory ran before callback validation"); } },
    },
  ];
  for (const target of ["fastify", "gateway"] as const) {
    for (const provider of providers) {
      for (const invalid of redirectCases) {
        const base = mkdtempSync(join(tmpdir(), `mcp-sso-int-${target}-${provider.name.replace(" ", "-")}-callback-`));
        const dir = join(base, "state");
        const env = {
          MCP_SSO_DIR: dir,
          ...provider.env(invalid.redirectUri),
          OAUTH_ISSUER: "http://localhost:3000",
          OAUTH_RESOURCE: "http://localhost:3000/mcp",
          OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40),
          OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(jwk()),
          OAUTH_ALLOW_INSECURE_LOCALHOST: "true",
        };
        try {
          const boot = target === "fastify"
            ? buildExample(env, provider.identityFactories)
            : buildGatewayExample(env, {
              backendUrl: "http://127.0.0.1:1/mcp", getBackendCredential: () => "unused",
              identityFactories: provider.identityFactories,
            });
          await assert.rejects(boot, invalid.pattern, `${target} ${provider.name}: ${invalid.name}`);
          assert.equal(existsSync(dir), false, `${target} ${provider.name}: ${invalid.name} fails before state creation`);
        } finally {
          rmSync(base, { recursive: true, force: true });
        }
      }
    }
  }
});

test("integration — unsafe OIDC deployment fails before provider discovery in both examples", async () => {
  const providers = [
    {
      name: "Google",
      env: {
        GOOGLE_CLIENT_ID: "google-client",
        GOOGLE_CLIENT_SECRET: "google-secret",
        GOOGLE_REDIRECT_URI: "https://mcp.example/oauth/callback",
      },
      factoryKey: "google" as const,
    },
    {
      name: "generic OIDC",
      env: {
        OIDC_ISSUER: "https://issuer.example",
        OIDC_CLIENT_ID: "oidc-client",
        OIDC_REDIRECT_URI: "https://mcp.example/oauth/callback",
      },
      factoryKey: "genericOidc" as const,
    },
  ];
  for (const target of ["fastify", "gateway"] as const) {
    for (const provider of providers) {
      const base = mkdtempSync(join(tmpdir(), `mcp-sso-int-${target}-guard-before-oidc-`));
      const dir = join(base, "state");
      let factoryCalls = 0;
      const factory = async () => {
        factoryCalls++;
        throw new Error("provider discovery ran before deployment guard");
      };
      const identityFactories = { [provider.factoryKey]: factory };
      const env = {
        MCP_SSO_DIR: dir,
        OAUTH_ISSUER: "https://mcp.example",
        OAUTH_RESOURCE: "https://mcp.example/mcp",
        OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40),
        OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(jwk()),
        OAUTH_REDIRECT_ALLOWLIST: "",
        ...provider.env,
      };
      try {
        const boot = target === "fastify"
          ? buildExample(env, identityFactories)
          : buildGatewayExample(env, {
            backendUrl: "http://127.0.0.1:1/mcp", getBackendCredential: () => "unused",
            identityFactories,
          });
        await assert.rejects(boot, /stateless DCR/, `${target} ${provider.name}`);
        assert.equal(factoryCalls, 0, `${target} ${provider.name}: discovery was not started`);
        assert.equal(existsSync(dir), false, `${target} ${provider.name}: no state was created`);
      } finally {
        rmSync(base, { recursive: true, force: true });
      }
    }
  }
});

test("integration — Google/generic env wiring defaults to the shipped production factories (stubbed discovery, no network)", async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: URL | Request | string): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const issuer = url.startsWith("https://accounts.google.com/") ? "https://accounts.google.com" : "https://issuer.test";
    return new Response(JSON.stringify({
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/jwks`,
      code_challenge_methods_supported: ["S256"],
      id_token_signing_alg_values_supported: ["RS256"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
    }), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  try {
    const config = configFromEnv({
      OAUTH_ISSUER: "https://bridge.test", OAUTH_RESOURCE: "https://bridge.test/mcp",
      OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40), OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(jwk()),
    });
    const google = await createOidcUpstreamFromEnv({
      GOOGLE_CLIENT_ID: "google-client", GOOGLE_CLIENT_SECRET: "google-secret",
      GOOGLE_REDIRECT_URI: "https://bridge.test/google/callback",
    }, config);
    assert.ok(google);
    assert.equal(google.callbackPath, "/google/callback");
    assert.equal(new URL(google.identity.buildAuthorizationUrl({ state: "s", nonce: "n", codeChallenge: "c", codeChallengeMethod: "S256" })).origin, "https://accounts.google.com");

    const generic = await createOidcUpstreamFromEnv({
      OIDC_ISSUER: "https://issuer.test", OIDC_CLIENT_ID: "oidc-client",
      OIDC_REDIRECT_URI: "https://bridge.test/oidc/callback",
    }, config);
    assert.ok(generic);
    assert.equal(generic.callbackPath, "/oidc/callback");
    assert.equal(new URL(generic.identity.buildAuthorizationUrl({ state: "s", nonce: "n", codeChallenge: "c", codeChallengeMethod: "S256" })).origin, "https://issuer.test");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("integration — gateway Google branch boot failures also occur before state-dir creation", async () => {
  const cases = [
    { name: "missing secret", env: {}, pattern: /Missing env: GOOGLE_CLIENT_SECRET/ },
    { name: "malformed boolean", env: { GOOGLE_CLIENT_SECRET: "google-secret", GOOGLE_ALLOW_EMAIL_ALLOWLIST: "yes" }, pattern: /Invalid env: GOOGLE_ALLOW_EMAIL_ALLOWLIST/ },
  ];
  for (const c of cases) {
    const base = mkdtempSync(join(tmpdir(), `mcp-sso-int-gateway-google-${c.name.replace(" ", "-")}-`));
    const dir = join(base, "state");
    try {
      await assert.rejects(
        buildGatewayExample({
          MCP_SSO_DIR: dir,
          GOOGLE_CLIENT_ID: "google-client",
          GOOGLE_REDIRECT_URI: "http://localhost:3000/google/callback",
          OAUTH_ISSUER: "http://localhost:3000",
          OAUTH_RESOURCE: "http://localhost:3000/mcp",
          OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40),
          OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(jwk()),
          OAUTH_ALLOW_INSECURE_LOCALHOST: "true",
          ...c.env,
        }, { backendUrl: "http://127.0.0.1:1/mcp", getBackendCredential: () => "unused" }),
        c.pattern,
      );
      assert.equal(existsSync(dir), false, `${c.name}: gateway fails before state-dir creation`);
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
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

// ---------------------------------------------------------------------------
// Flow-level entry wiring (the boot-level tests above stop at GET /authorize).
// These drive register → authorize → (pairing or CF header) → consent → approve
// → token → protected /mcp → refresh through buildExample — the actual index.ts
// path. Both catch the S1b wiring-bug class (branch routing, sqliteFile, dir
// creation) at the flow level, not just boot.
// ---------------------------------------------------------------------------

const FLOW_REDIRECT = "http://localhost:4321/callback";

function extractValue(html: string, name: string): string {
  const m = new RegExp(`name="${name}" value="([^"]+)"`).exec(html);
  assert.ok(m?.[1], `hidden field ${name} not found`);
  return m[1] as string;
}

/** Parse a fastify inject response body. (buildExample's app is typed as
 *  ReturnType<typeof Fastify>, whose inject reply's .json() is untyped — so parse
 *  the body explicitly.) */
function json<T>(res: { body: unknown }): T {
  assert.equal(typeof res.body, "string", "inject response body is a string");
  return JSON.parse(res.body as string) as T;
}

function extractPairingCode(text: string): string {
  const m = /code: ([BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4})/.exec(text);
  assert.ok(m?.[1], "pairing code not printed");
  return m[1]!.replace(/-/g, "");
}

/** A Fastify app that can both inject (in-process OAuth legs) and listen on a real
 *  loopback socket (the SDK /mcp call). The minimal shape callProtectedMcp needs. */
interface RealSocketApp {
  inject(args: unknown): Promise<unknown>;
  listen(opts: { port: number; host: string }): Promise<string>;
  server: { listening: boolean; address(): AddressInfo | string | null };
}

/** Real fetch captured at module load — BEFORE any test stubs globalThis.fetch. The
 *  CF-flow test below stubs globalThis.fetch to serve JWKS at the cf certs URL; the SDK
 *  /mcp call must hit the real loopback server, not that stub (which 404s loopback). */
const networkFetch = globalThis.fetch.bind(globalThis) as typeof fetch;

/** Race a promise against a hard deadline (reject after `ms` with `label`). The MCP
 *  SDK transport overrides requestInit.signal with its own AbortController.signal, so
 *  the abort lever is transport.close() (in the caller's finally), not a bounded
 *  requestInit.signal. (Sweep of the Codex P2 on the full-flow driver.) */
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    p.then((v) => { clearTimeout(timer); resolve(v); }, (e) => { clearTimeout(timer); reject(e); });
  });
}

async function callProtectedMcp(app: RealSocketApp, resource: string, accessToken: string, expectedSubject: string, extraHeaders: Record<string, string> = {}): Promise<void> {
  // Real loopback socket — the inject-mock socket lacks destroySoon(); the SDK server
  // transport's @hono/node-server forceClose timer throws on it ~500 ms later (issue
  // #66). Idempotent: the zero-setup test calls this twice on the same app (absent
  // Origin, then the allowlisted Origin), so reuse the address if already listening
  // rather than calling listen() twice on one server.
  const base = app.server.listening
    ? `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`
    : await app.listen({ port: 0, host: "127.0.0.1" });
  const transport = new StreamableHTTPClientTransport(new URL(new URL(resource).pathname, base), { fetch: networkFetch, requestInit: { headers: { authorization: `Bearer ${accessToken}`, ...extraHeaders } } });
  const client = new Client({ name: "int-entry-flow", version: "0.0.1" }, { capabilities: {} });
  try {
    await withTimeout(client.connect(transport), 10_000, "MCP client connect");
    const result = await withTimeout(client.callTool({ name: "ping", arguments: {} }), 10_000, "MCP client callTool");
    const text = (result.content as Array<{ type: string; text?: string }>).find((c) => c.type === "text")?.text;
    assert.equal(text, `pong: ${expectedSubject}`, "the entry-resolved subject reached /mcp");
  } finally {
    await client.close();
    await transport.close();
  }
}

test("integration — zero-setup branch: full flow through the entry (pairing code from stderr → token → /mcp → refresh)", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-zsflow-"));
  const dir = join(base, "state"); // does NOT exist — buildExample must create it
  const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
  const ORIGIN = "http://localhost:3000";
  try {
    const { app, store, config } = await buildExample({
      MCP_SSO_DIR: dir,
      OAUTH_ISSUER: ORIGIN,
      OAUTH_RESOURCE: `${ORIGIN}/mcp`,
      OAUTH_REDIRECT_ALLOWLIST: FLOW_REDIRECT,
    });
    try {
      const reg = await app.inject({ method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" }, payload: JSON.stringify({ redirect_uris: [FLOW_REDIRECT] }) });
      assert.equal(reg.statusCode, 201);
      const clientId = json<{ client_id: string }>(reg).client_id;
      const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: FLOW_REDIRECT, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read", state: "s1" });

      // GET /authorize renders the pairing page; the code is printed to process.stderr
      // (buildExample passes pairing:{}, so ConsolePairingOptions.output defaults to
      // process.stderr — no env seam). Capture by wrapping process.stderr.write and
      // restore in finally so a failure can't corrupt the run's stderr. node --test
      // runs each file in its own process, so this never touches another file's stderr.
      let code: string;
      let pairingNonce: string;
      const originalWrite = process.stderr.write.bind(process.stderr);
      const chunks: string[] = [];
      process.stderr.write = ((s: string | Uint8Array): boolean => {
        chunks.push(typeof s === "string" ? s : Buffer.from(s).toString());
        return true;
      }) as typeof process.stderr.write;
      try {
        const pairingPage = await app.inject({ method: "GET", url: `/oauth/authorize?${q}` });
        assert.equal(pairingPage.statusCode, 200);
        assert.match(pairingPage.body, /Pair this device/);
        pairingNonce = extractValue(pairingPage.body, "pairing_nonce");
        code = extractPairingCode(chunks.join(""));
      } finally {
        process.stderr.write = originalWrite;
      }

      // POST the pasted code + nonce → consent page.
      const consentPage = await app.inject({ method: "POST", url: "/oauth/authorize", headers: { "content-type": "application/x-www-form-urlencoded", origin: ORIGIN }, payload: new URLSearchParams({ ...Object.fromEntries(q), pairing_code: code, pairing_nonce: pairingNonce }).toString() });
      assert.equal(consentPage.statusCode, 200);
      assert.match(consentPage.body, /Authorize access/);
      const consentToken = extractValue(consentPage.body, "consent_token");

      // Approve → 302 with an auth code.
      const approve = await app.inject({ method: "POST", url: "/oauth/authorize/approve", headers: { "content-type": "application/x-www-form-urlencoded", origin: ORIGIN }, payload: new URLSearchParams({ consent_token: consentToken, approved: "true" }).toString() });
      assert.equal(approve.statusCode, 302);
      const authCode = new URL(approve.headers.location as string).searchParams.get("code");
      assert.ok(authCode);

      // Exchange → tokens.
      const tokenResp = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "authorization_code", code: authCode as string, redirect_uri: FLOW_REDIRECT, client_id: clientId, code_verifier: verifier }).toString() });
      assert.equal(tokenResp.statusCode, 200);
      const { access_token: accessToken, refresh_token: refreshToken } = json<{ access_token: string; refresh_token: string }>(tokenResp);

      // Protected /mcp via the OFFICIAL MCP SDK client — the pairing-resolved
      // subject ("console-operator") reaches /mcp through the entry wiring.
      await callProtectedMcp(app, config.resource, accessToken, "console-operator");
      // A PRESENT, allowlisted Origin on /mcp is admitted by the Origin gate: the
      // full SDK round-trip still succeeds (the MCP client sends no Origin by
      // default; this injects the allowlisted one to exercise the gate's admit
      // path, not only the absent-Origin path every other call proves).
      await callProtectedMcp(app, config.resource, accessToken, "console-operator", { origin: ORIGIN });

      const port = (app.server.address() as AddressInfo).port;
      const init = JSON.stringify({ jsonrpc: "2.0", method: "initialize", params: {
        protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "duplicate-bearer", version: "0" },
      }, id: 1 });
      for (const authorization of [
        [["Authorization", `Bearer ${accessToken}`], ["authorization", "Bearer attacker"]],
        [["authorization", "Bearer attacker"], ["Authorization", `Bearer ${accessToken}`]],
      ] as const) {
        const response = await rawOccurrenceCall(
          port, "POST", "/mcp", [["Content-Type", "application/json"], ...authorization], init,
        );
        assert.equal(response.status, 401, "runnable example rejects duplicate bearer field lines");
        assert.match(response.headers["www-authenticate"] ?? "", /^Bearer resource_metadata=/);
      }

      // Refresh rotates.
      const refreshed = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId }).toString() });
      assert.equal(refreshed.statusCode, 200);
      assert.notEqual(json<{ refresh_token: string }>(refreshed).refresh_token, refreshToken);
    } finally {
      await app.close();
      await store.close();
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — Cloudflare Access branch: full header flow through the entry (in-test JWKS + signed RS256 Access JWT, zero real network) → token → /mcp → refresh", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-cfflow-"));
  const dir = join(base, "state");
  const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
  const ORIGIN = "http://localhost";
  const CERTS_URL = "https://cf.test/certs";
  const CF_ISSUER = "https://cf.test";
  const CF_AUDIENCE = "https://cf.test/aud";
  const CALLBACK = "https://client.test/callback";

  // RSA keypair for the CF Access JWT: the public half is served as JWKS at the
  // https certsUrl (stubbed globalThis.fetch), the private half signs the assertion.
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const publicJwk = { ...(await exportJWK(publicKey)), kid: "cf-test-key", alg: "RS256", use: "sig" };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: URL | Request | string): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url === CERTS_URL) return new Response(JSON.stringify({ keys: [publicJwk] }), { status: 200, headers: { "content-type": "application/json" } });
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  try {
    const signingKey = jwk(); // the bridge's own ES256 access-token key (from env)
    const { app, store, config } = await buildExample({
      MCP_SSO_DIR: dir,
      CF_ACCESS_AUDIENCE: CF_AUDIENCE,
      CF_ACCESS_CERTS_URL: CERTS_URL,
      CF_ACCESS_ISSUER: CF_ISSUER,
      OAUTH_ISSUER: ORIGIN,
      OAUTH_RESOURCE: `${ORIGIN}/mcp`,
      OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40),
      OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(signingKey),
      OAUTH_REDIRECT_ALLOWLIST: CALLBACK,
      OAUTH_ALLOW_INSECURE_LOCALHOST: "true",
    });
    assert.equal(config.issuer, ORIGIN);
    try {
      const reg = await app.inject({ method: "POST", url: "/oauth/register", headers: { "content-type": "application/json" }, payload: JSON.stringify({ redirect_uris: [CALLBACK] }) });
      assert.equal(reg.statusCode, 201);
      const clientId = json<{ client_id: string }>(reg).client_id;

      // A valid CF Access JWT (RS256, matching the served JWKS; aud/iss/exp per the
      // port's checks). Sent in the cf-access-jwt-assertion header → resolveIdentity.
      const now = Math.floor(Date.now() / 1000);
      const cfJwt = await new SignJWT({ email: "operator@cf.test", sub: "cf-operator" })
        .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: "cf-test-key" })
        .setIssuer(CF_ISSUER).setAudience(CF_AUDIENCE).setIssuedAt(now).setExpirationTime(now + 3600)
        .sign(privateKey);

      const q = new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: CALLBACK, code_challenge: pkceChallenge(verifier), code_challenge_method: "S256", scope: "mcp:read", state: "s1" });
      const authPage = await app.inject({ method: "GET", url: `/oauth/authorize?${q}`, headers: { "cf-access-jwt-assertion": cfJwt } });
      assert.equal(authPage.statusCode, 200, "CF identity accepted → consent page (NOT 401, NOT the pairing page)");
      assert.match(authPage.body, /Authorize access/);
      const consentToken = extractValue(authPage.body, "consent_token");

      const approve = await app.inject({ method: "POST", url: "/oauth/authorize/approve", headers: { "content-type": "application/x-www-form-urlencoded", origin: ORIGIN }, payload: new URLSearchParams({ consent_token: consentToken, approved: "true" }).toString() });
      assert.equal(approve.statusCode, 302);
      const authCode = new URL(approve.headers.location as string).searchParams.get("code");
      assert.ok(authCode);

      const tokenResp = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "authorization_code", code: authCode as string, redirect_uri: CALLBACK, client_id: clientId, code_verifier: verifier }).toString() });
      assert.equal(tokenResp.statusCode, 200);
      const { access_token: accessToken, refresh_token: refreshToken } = json<{ access_token: string; refresh_token: string }>(tokenResp);

      // The CF-resolved subject (sub) reaches /mcp through the entry wiring.
      await callProtectedMcp(app, config.resource, accessToken, "cf-operator");

      const refreshed = await app.inject({ method: "POST", url: "/oauth/token", headers: { "content-type": "application/x-www-form-urlencoded" }, payload: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId }).toString() });
      assert.equal(refreshed.statusCode, 200);
      assert.notEqual(json<{ refresh_token: string }>(refreshed).refresh_token, refreshToken);

      // A WRONG-audience CF JWT is rejected (the CF port's own gate, through the entry).
      const badAud = await new SignJWT({ email: "operator@cf.test", sub: "cf-operator" }).setProtectedHeader({ alg: "RS256", typ: "JWT", kid: "cf-test-key" }).setIssuer(CF_ISSUER).setAudience("https://evil.test").setIssuedAt(now).setExpirationTime(now + 3600).sign(privateKey);
      const rejected = await app.inject({ method: "GET", url: `/oauth/authorize?${q}`, headers: { "cf-access-jwt-assertion": badAud } });
      assert.equal(rejected.statusCode, 401, "CF JWT with the wrong audience is rejected (fail-closed)");
    } finally {
      await app.close();
      await store.close();
    }
  } finally {
    globalThis.fetch = realFetch;
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — /mcp Origin gate (MCP Streamable HTTP DNS-rebinding MUST): foreign Origin ⇒ 403 before parsing/auth on ALL methods; absent/allowlisted ⇒ proceed", async () => {
  // The MCP Streamable HTTP transport says servers MUST validate `Origin` on every
  // connection. The example enforces it in an onRequest hook scoped to /mcp — BEFORE
  // body parsing and for EVERY method (POST/GET/DELETE) — so a foreign Origin is
  // 403'd before authorize() AND before Fastify's body parser (a malformed/oversized
  // body with a foreign Origin still gets 403, not 400/413), while an absent Origin
  // (MCP clients are not browsers) or an allowlisted Origin proceeds to 401 (no token).
  const ORIGIN = "http://localhost:3000";
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-origin-"));
  const dir = join(base, "state");
  const init = JSON.stringify({ jsonrpc: "2.0", method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "0" } }, id: 1 });
  try {
    const { app, store } = await buildExample({ MCP_SSO_DIR: dir, OAUTH_ISSUER: ORIGIN, OAUTH_RESOURCE: `${ORIGIN}/mcp` });
    try {
      // Foreign Origin ⇒ 403, and the resource-server challenge is NOT emitted
      // (authorize() never ran).
      const evil = await app.inject({ method: "POST", url: "/mcp", headers: { "content-type": "application/json", origin: "https://evil.test" }, payload: init });
      assert.equal(evil.statusCode, 403, "foreign Origin rejected before authorization");
      assert.doesNotMatch(evil.headers["www-authenticate"] ?? "", /resource_metadata=/, "Origin gate fires before the authorize leg — no challenge");

      // Foreign Origin on GET and DELETE ⇒ 403 too — the hook is method-agnostic, not
      // a POST-handler-only check.
      const evilGet = await app.inject({ method: "GET", url: "/mcp", headers: { origin: "https://evil.test" } });
      assert.equal(evilGet.statusCode, 403, "foreign Origin rejected on GET (method coverage)");
      const evilDelete = await app.inject({ method: "DELETE", url: "/mcp", headers: { origin: "https://evil.test" } });
      assert.equal(evilDelete.statusCode, 403, "foreign Origin rejected on DELETE (method coverage)");

      // Foreign Origin beats body parsing: malformed JSON with a foreign Origin gets
      // 403, not Fastify's 400 body-parse error.
      const evilBadBody = await app.inject({ method: "POST", url: "/mcp", headers: { "content-type": "application/json", origin: "https://evil.test" }, payload: "{not valid json" });
      assert.equal(evilBadBody.statusCode, 403, "foreign Origin rejected before body parsing (malformed JSON ⇒ 403, not 400)");

      // Allowlisted Origin ⇒ proceeds to the bearer check ⇒ 401 + challenge.
      const allowlisted = await app.inject({ method: "POST", url: "/mcp", headers: { "content-type": "application/json", origin: ORIGIN }, payload: init });
      assert.equal(allowlisted.statusCode, 401, "allowlisted Origin proceeds to the bearer check");
      assert.match(allowlisted.headers["www-authenticate"] ?? "", /^Bearer resource_metadata=/, "reached the resource-server leg");

      // Absent Origin (non-browser client — the normal MCP case) ⇒ proceeds ⇒ 401.
      const absent = await app.inject({ method: "POST", url: "/mcp", headers: { "content-type": "application/json" }, payload: init });
      assert.equal(absent.statusCode, 401, "absent Origin proceeds to the bearer check");
      assert.match(absent.headers["www-authenticate"] ?? "", /^Bearer resource_metadata=/, "reached the resource-server leg");
    } finally {
      await app.close();
      await store.close();
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — runnable example rejects duplicate /mcp Origin occurrences before allowlist matching", async () => {
  const issuer = "http://localhost:3000";
  const allowed = "https://allowed.test";
  const foreign = "https://evil.test";
  const config = createBridgeConfig({
    issuer,
    resource: `${issuer}/mcp`,
    consentSigningSecret: "x".repeat(40),
    signingPrivateJwk: jwk(),
    redirectAllowlist: [],
    scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"],
    allowedOrigins: [`${allowed}, ${foreign}`, `${foreign}, ${allowed}`],
    dcr: { mode: "stateless" },
    dev: { allowInsecureLocalhost: true },
    accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000,
    consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });
  const built = await buildApp({
    config,
    identity: { async verify() { return { ok: false, reason: "unused" }; } },
    acknowledgeUnsafeStatelessDefaults: true,
  });
  await built.app.listen({ port: 0, host: "127.0.0.1" });
  const port = (built.app.server.address() as AddressInfo).port;
  try {
    for (const origins of [
      [["Origin", allowed], ["origin", foreign]],
      [["origin", foreign], ["Origin", allowed]],
    ] as const) {
      const response = await rawOccurrenceCall(
        port, "POST", "/mcp", [["Content-Type", "application/json"], ...origins], "{}",
      );
      assert.equal(response.status, 403, "raw duplicate fields reject even when their coalesced string is allowlisted");
      assert.doesNotMatch(response.headers["www-authenticate"] ?? "", /resource_metadata=/, "bearer authorization did not run");
    }
  } finally {
    await built.app.close();
    await built.close();
  }
});

test("integration — pairing POST rejects last-wins redirect_uri and foreign Origin before consent", async () => {
  const issuer = "http://127.0.0.1:9";
  const good = "http://127.0.0.1/cb";
  const evil = "https://evil.test/cb";
  const config = createBridgeConfig({
    issuer, resource: `${issuer}/mcp`,
    consentSigningSecret: "x".repeat(40), signingPrivateJwk: jwk(),
    redirectAllowlist: [good, evil], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: [issuer], dcr: { mode: "stateless" },
    dev: { allowInsecureLocalhost: true },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 600,
    consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  const built = await buildApp({
    config, pairing: { output: { write() {} } }, acknowledgeUnsafeStatelessDefaults: true,
  });
  await built.app.listen({ port: 0, host: "127.0.0.1" });
  const port = (built.app.server.address() as AddressInfo).port;
  try {
    const challenge = pkceChallenge("v-12345678901234567890123456789012345678");
    const lastWins = new URLSearchParams([
      ["response_type", "code"], ["client_id", "c"],
      ["code_challenge", challenge], ["code_challenge_method", "S256"],
      ["scope", "mcp:read"], ["redirect_uri", good], ["redirect_uri", evil],
    ]).toString();
    const dup = await rawOccurrenceCall(
      port, "POST", "/oauth/authorize",
      [["Content-Type", "application/x-www-form-urlencoded"], ["Origin", issuer]],
      lastWins,
    );
    const csrf = await rawOccurrenceCall(
      port, "POST", "/oauth/authorize",
      [["Content-Type", "application/x-www-form-urlencoded"], ["Origin", "https://attacker.test"]],
      new URLSearchParams({ response_type: "code", client_id: "c", redirect_uri: evil, code_challenge: challenge, code_challenge_method: "S256" }).toString(),
    );
    assert.equal(dup.status, 400);
    assert.match(dup.body, /"error":"invalid_request"/);
    assert.doesNotMatch(dup.body, /Pair this device|Authorize access/);
    assert.equal(csrf.status, 403);
    assert.match(csrf.body, /"error":"invalid_origin"/);
  } finally {
    await built.app.close();
    await built.close();
  }
});

test("integration — /mcp Origin gate admits the issuer origin even when allowedOrigins carries the raw (un-normalized) issuer (trailing slash)", async () => {
  // Regression for the normalization gap: allowedOrigins defaults to the RAW
  // OAUTH_ISSUER string, but a browser serializes Origin to scheme://host[:port]
  // (no trailing slash/path). An issuer set with a trailing slash would make the
  // gate 403 a same-origin browser request on a string mismatch — while the
  // consent approve flow (src/authorize.ts assertOrigin) admits it via
  // originOf(issuer). The gate mirrors assertOrigin: originOf(issuer) is admitted.
  const ISSUER = "http://localhost:3000/"; // trailing slash — a common misconfig
  const BROWSER_ORIGIN = "http://localhost:3000"; // what a browser sends (== originOf(issuer))
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-origin-norm-"));
  const dir = join(base, "state");
  const init = JSON.stringify({ jsonrpc: "2.0", method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "x", version: "0" } }, id: 1 });
  try {
    // allowedOrigins defaults to [ISSUER] = ["http://localhost:3000/"] (raw, slash).
    const { app, store, config } = await buildExample({ MCP_SSO_DIR: dir, OAUTH_ISSUER: ISSUER, OAUTH_RESOURCE: "http://localhost:3000/mcp" });
    assert.deepEqual(config.allowedOrigins, [ISSUER], "allowedOrigins is the raw, trailing-slash issuer (not normalized)");
    try {
      // Browser sends the normalized origin. Without originOf(issuer) admission this
      // is 403 (string mismatch); with it, the gate admits it → proceeds to the
      // bearer check → 401 (no token).
      const res = await app.inject({ method: "POST", url: "/mcp", headers: { "content-type": "application/json", origin: BROWSER_ORIGIN }, payload: init });
      assert.equal(res.statusCode, 401, "issuer origin admitted despite the raw allowedOrigins mismatch (originOf normalization) → reached the bearer check");
      assert.match(res.headers["www-authenticate"] ?? "", /^Bearer resource_metadata=/, "reached the resource-server leg, not the 403 Origin gate");
    } finally {
      await app.close();
      await store.close();
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("integration — runnable /mcp budget denies before bearer audit and does not charge a rejected Origin", async () => {
  const issuer = "http://localhost:3000";
  const config = createBridgeConfig({
    issuer, resource: `${issuer}/mcp`, consentSigningSecret: "x".repeat(40),
    signingPrivateJwk: jwk(), redirectAllowlist: [], scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"], allowedOrigins: [issuer], dcr: { mode: "stateless" },
    dev: { allowInsecureLocalhost: true }, accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });
  const auditEvents: string[] = [];
  let limiterIncrements = 0;
  class CountingStore implements FastifyRateLimitStore {
    constructor(_options: FastifyRateLimitOptions) {}
    incr(
      _key: string,
      callback: (error: Error | null, result?: { current: number; ttl: number }) => void,
      timeWindow: number,
    ): void {
      limiterIncrements += 1;
      callback(null, { current: limiterIncrements, ttl: timeWindow });
    }
    child(): FastifyRateLimitStore { return this; }
  }
  const built = await buildApp({
    config,
    identity: { async verify() { return { ok: false, reason: "unused" }; } },
    audit: { async writeAuthEvent(event) { auditEvents.push(event.event); } },
    protectedResourceRateLimit: { max: 1, timeWindowMs: 60_000, store: CountingStore },
    acknowledgeUnsafeStatelessDefaults: true,
  });
  const request = { method: "POST" as const, url: "/mcp", headers: { "content-type": "application/json" }, payload: "{}" };
  try {
    const foreign = await built.app.inject({ ...request, headers: { ...request.headers, origin: "https://evil.test" } });
    assert.equal(foreign.statusCode, 403, "Origin rejects before the limiter and does not consume its budget");
    assert.equal(limiterIncrements, 0, "foreign Origin causes zero limiter-store increments");
    const admitted = await built.app.inject(request);
    assert.equal(admitted.statusCode, 401, "the first allowed request reaches bearer verification");
    assert.equal(limiterIncrements, 1, "the admitted request consumes exactly one limiter-store increment");
    assert.equal(auditEvents.filter((event) => event === "auth.request").length, 1);
    const denied = await built.app.inject(request);
    assert.equal(denied.statusCode, 429);
    assert.equal(auditEvents.filter((event) => event === "auth.request").length, 1,
      "over-budget denial occurs before RequestAuthorizer audit effects");
  } finally {
    await built.app.close();
    await built.close();
  }
});

test("integration — example proxy trust keeps untrusted forwarded IPs in one bucket and separates trusted clients", async () => {
  const issuer = "http://localhost:3000";
  const config = createBridgeConfig({
    issuer, resource: `${issuer}/mcp`, consentSigningSecret: "x".repeat(40),
    signingPrivateJwk: jwk(), redirectAllowlist: [], scopeCatalog: ["mcp:read"],
    defaultScopes: ["mcp:read"], allowedOrigins: [issuer], dcr: { mode: "stateless" },
    dev: { allowInsecureLocalhost: true }, accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300,
    authorizationCodeTtlSeconds: 300,
  });
  const identity = { async verify() { return { ok: false as const, reason: "unused" }; } };
  const factories = [
    {
      name: "fastify-sqlite",
      build: (trustedProxies?: readonly string[]) => buildApp({
        config, identity, trustedProxies,
        protectedResourceRateLimit: { max: 1, timeWindowMs: 60_000 },
        acknowledgeUnsafeStatelessDefaults: true,
      }),
    },
    {
      name: "api-key-gateway",
      build: (trustedProxies?: readonly string[]) => buildGateway({
        config, identity, trustedProxies,
        backendUrl: "http://127.0.0.1:1/mcp",
        getBackendCredential: () => { throw new Error("bearer gate was bypassed"); },
        protectedResourceRateLimit: { max: 1, timeWindowMs: 60_000 },
        acknowledgeUnsafeStatelessDefaults: true,
      }),
    },
  ];
  const remoteAddress = "203.0.113.10";
  const request = (forwarded: string) => ({
    method: "POST" as const, url: "/mcp", remoteAddress,
    headers: { "content-type": "application/json", "x-forwarded-for": forwarded },
    payload: "{}",
  });

  for (const factory of factories) {
    for (const [mode, trustedProxies] of [
      ["default-off", undefined],
      ["untrusted-socket", ["192.0.2.10"]],
    ] as const) {
      const built = await factory.build(trustedProxies);
      try {
        assert.equal((await built.app.inject(request("198.51.100.1"))).statusCode, 401);
        assert.equal(
          (await built.app.inject(request("198.51.100.2"))).statusCode,
          429,
          `${factory.name}/${mode}: an untrusted socket cannot rotate X-Forwarded-For into a fresh bucket`,
        );
      } finally {
        await built.app.close();
        await built.close();
      }
    }

    const built = await factory.build(["203.0.113.0/24"]);
    try {
      assert.equal((await built.app.inject(request("198.51.100.1"))).statusCode, 401);
      assert.equal(
        (await built.app.inject(request("198.51.100.2"))).statusCode,
        401,
        `${factory.name}: distinct clients behind the configured proxy receive distinct buckets`,
      );
      assert.equal(
        (await built.app.inject(request("198.51.100.1"))).statusCode,
        429,
        `${factory.name}: the first trusted client remains bounded in its own bucket`,
      );
    } finally {
      await built.app.close();
      await built.close();
    }
  }
});

test("integration — malformed trusted-proxy config fails before example state and SQLite effects", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-int-trusted-proxy-invalid-"));
  const throwing = new Proxy(["127.0.0.1"], {
    get(target, property, receiver) {
      if (property === "0") throw new Error("raw proxy getter detail");
      return Reflect.get(target, property, receiver) as unknown;
    },
  });
  const malformed: unknown[] = [true, [], ["loopback"], ["0.0.0.0/0"], ["127.0.0.1", "127.0.0.1"], throwing];
  const config = createBridgeConfig({
    issuer: "http://localhost:3000", resource: "http://localhost:3000/mcp",
    consentSigningSecret: "x".repeat(40), signingPrivateJwk: jwk(), redirectAllowlist: [],
    scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"], allowedOrigins: ["http://localhost:3000"],
    dcr: { mode: "stateless" }, dev: { allowInsecureLocalhost: true }, accessTokenTtlSeconds: 600,
    refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
  try {
    for (const [index, trustedProxies] of malformed.entries()) {
      for (const target of ["fastify", "gateway"] as const) {
        const sqliteFile = join(base, `${target}-${index}.db`);
        const common = {
          config, sqliteFile, trustedProxies: trustedProxies as readonly string[],
          identity: { async verify() { return { ok: false as const, reason: "unused" }; } },
          acknowledgeUnsafeStatelessDefaults: true as const,
        };
        const boot = target === "fastify"
          ? buildApp(common)
          : buildGateway({
            ...common, backendUrl: "http://127.0.0.1:1/mcp",
            getBackendCredential: () => "unused",
          });
        await assert.rejects(boot, /trusted proxies must be 1\.\.32 unique IP or CIDR entries/);
        assert.equal(existsSync(sqliteFile), false, `${target}/${index}: rejected config did not open SQLite`);
      }
    }

    for (const target of ["fastify", "gateway"] as const) {
      const sqliteFile = join(base, `${target}-option-getter.db`);
      const options = {
        config, sqliteFile,
        identity: { async verify() { return { ok: false as const, reason: "unused" }; } },
        acknowledgeUnsafeStatelessDefaults: true as const,
        ...(target === "gateway" ? {
          backendUrl: "http://127.0.0.1:1/mcp", getBackendCredential: () => "unused",
        } : {}),
      };
      Object.defineProperty(options, "trustedProxies", {
        get() { throw new Error("raw option getter detail"); },
      });
      const boot = target === "fastify"
        ? buildApp(options)
        : buildGateway(options as Parameters<typeof buildGateway>[0]);
      await assert.rejects(boot, /trusted proxies must be 1\.\.32 unique IP or CIDR entries/);
      assert.equal(existsSync(sqliteFile), false, `${target}: throwing option getter did not open SQLite`);
    }

    for (const [index, raw] of ["", "not-an-ip", "127.0.0.1,", "0.0.0.0/0"].entries()) {
      for (const target of ["fastify", "gateway"] as const) {
        const dir = join(base, `env-${target}-${index}`);
        const env = { MCP_SSO_DIR: dir, [TRUSTED_PROXIES_ENV]: raw };
        const boot = target === "fastify"
          ? buildExample(env)
          : buildGatewayExample(env, {
            backendUrl: "http://127.0.0.1:1/mcp", getBackendCredential: () => "unused",
          });
        await assert.rejects(boot, /trusted proxies must be 1\.\.32 unique IP or CIDR entries/);
        assert.equal(existsSync(dir), false, `${target}/${index}: malformed env created no state directory`);
      }
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
