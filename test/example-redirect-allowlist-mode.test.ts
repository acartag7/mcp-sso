// The `OAUTH_REDIRECT_ALLOWLIST_MODE` seam in the SHIPPED composition roots
// (contracts §5, §10.1). `redirectAllowlistMode` reached `BridgeConfig` with no
// way to set it from the deployment configs the docs point operators at, so an
// operator who narrowed `OAUTH_REDIRECT_ALLOWLIST` to private origins still had
// the hosted defaults trusted underneath.
//
// The sibling axis here is composition root, not adapter: fastify-sqlite's
// production `configFromEnv` (which the api-key-gateway production branch also
// calls) plus the TWO zero-setup quickstart branches. Threading an option into
// the deployment branch and missing the quickstart branch is this repo's
// recurring defect, so each root is proved separately.
//
// Every proof goes through `resolveOpaqueRedirect` — the real authorize-path
// reader of the global allowlist — rather than reading the config field back.
// A field assertion would pass even if nothing consumed the value.
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { JWK } from "jose";

import { AuthConfigError } from "../src/config.ts";
import { resolveOpaqueRedirect } from "../src/authorize-internals.ts";
import { buildExample, configFromEnv } from "../examples/fastify-sqlite/app.ts";
import { buildGatewayExample } from "../examples/api-key-gateway/app.ts";

const HOSTED = "https://claude.ai/callback";
const PRIVATE_CALLBACK = "https://client.test/callback";
const GATEWAY_DEPS = { backendUrl: "http://127.0.0.1:1/mcp", getBackendCredential: () => "unused" };

function jwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }) } as JWK;
}

/** Minimum env for the production root. https issuer/resource keep the dev
 *  escape hatch — and its boot warning — out of these cases entirely. */
function productionEnv(extra: Record<string, string> = {}): Record<string, string | undefined> {
  return {
    OAUTH_ISSUER: "https://auth.test",
    OAUTH_RESOURCE: "https://api.test/mcp",
    OAUTH_CONSENT_SIGNING_SECRET: "x".repeat(40),
    OAUTH_SIGNING_PRIVATE_JWK: JSON.stringify(jwk()),
    OAUTH_REDIRECT_ALLOWLIST: PRIVATE_CALLBACK,
    ...extra,
  };
}

/** Stateless roots send every opaque client through the global allowlist, so
 *  this is the exact call an authorize request makes. */
async function redirectAccepted(config: Parameters<typeof resolveOpaqueRedirect>[0], uri: string): Promise<boolean> {
  try {
    await resolveOpaqueRedirect(config, "opaque-client", uri);
    return true;
  } catch {
    return false;
  }
}

test("examples — production configFromEnv: unset mode keeps the built-in hosted origins", async () => {
  const config = configFromEnv(productionEnv());
  assert.equal(await redirectAccepted(config, HOSTED), true, "omitting the env var must not change published behavior");
  assert.equal(await redirectAccepted(config, PRIVATE_CALLBACK), true, "configured entry still accepted");
});

test("examples — production configFromEnv: replace drops the built-in hosted origins", async () => {
  const config = configFromEnv(productionEnv({ OAUTH_REDIRECT_ALLOWLIST_MODE: "replace" }));
  assert.equal(await redirectAccepted(config, HOSTED), false, "replace must reach the authorize-path allowlist reader");
  assert.equal(await redirectAccepted(config, PRIVATE_CALLBACK), true, "the operator's own callback still authorizes");
});

test("examples — production configFromEnv: a malformed mode is a boot failure, never a fallback to extend", async () => {
  // The fail-closed half. If the seam mapped an unrecognized value onto
  // "extend", each of these would boot with the hosted origins silently
  // restored — the exact outcome the operator set the variable to prevent.
  for (const bad of ["Replace", "REPLACE", "", " replace", "true", "extend,replace"]) {
    assert.throws(
      () => configFromEnv(productionEnv({ OAUTH_REDIRECT_ALLOWLIST_MODE: bad })),
      AuthConfigError,
      `mode ${JSON.stringify(bad)} must fail at boot`,
    );
  }
});

test("examples — production configFromEnv: replace with no allowlist entries is a boot failure", async () => {
  assert.throws(
    () => configFromEnv(productionEnv({ OAUTH_REDIRECT_ALLOWLIST: "", OAUTH_REDIRECT_ALLOWLIST_MODE: "replace" })),
    AuthConfigError,
    "replace + empty allowlist accepts no redirect_uri at all, so it is a misconfiguration",
  );
});

test("examples — fastify-sqlite zero-setup branch honors the mode", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-zs-mode-"));
  try {
    const extend = await buildExample({ MCP_SSO_DIR: join(base, "extend") });
    assert.equal(await redirectAccepted(extend.config, HOSTED), true, "quickstart default keeps the hosted origins");
    await extend.app.close();
    await extend.store.close();

    const replace = await buildExample({
      MCP_SSO_DIR: join(base, "replace"),
      OAUTH_REDIRECT_ALLOWLIST_MODE: "replace",
    });
    assert.equal(await redirectAccepted(replace.config, HOSTED), false, "quickstart branch must read the same env seam");
    assert.equal(
      await redirectAccepted(replace.config, "http://localhost/cb"),
      true,
      "the branch's own loopback composition default survives replace",
    );
    await replace.app.close();
    await replace.store.close();
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("examples — api-key-gateway zero-setup branch honors the mode", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-gw-mode-"));
  try {
    const extend = await buildGatewayExample({ MCP_SSO_DIR: join(base, "extend") }, GATEWAY_DEPS);
    assert.equal(await redirectAccepted(extend.config, HOSTED), true, "gateway default keeps the hosted origins");
    await extend.app.close();
    await extend.store.close();

    const replace = await buildGatewayExample(
      { MCP_SSO_DIR: join(base, "replace"), OAUTH_REDIRECT_ALLOWLIST_MODE: "replace" },
      GATEWAY_DEPS,
    );
    assert.equal(await redirectAccepted(replace.config, HOSTED), false, "the gateway sibling must not be the missed one");
    await replace.app.close();
    await replace.store.close();
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
