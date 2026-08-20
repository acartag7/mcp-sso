// F9 regression — §17.8: "a composition root builds and validates its complete
// configuration from `secrets`, then invokes the one-shot persist() capability."
// The examples' zero-setup branch used the immediate loadOrCreateQuickstartSecrets
// wrapper, so a boot whose remaining config was invalid (e.g. a malformed
// OAUTH_SCOPE_CATALOG) had ALREADY written the state dir, .gitignore, and a
// fresh signing keypair — durable secret material from a boot that never came
// up, which the next boot then silently adopts. The init template
// (src/bin/templates.ts) already composes prepare → validate → persist; these
// tests pin the examples to the same order.

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { buildExample } from "../examples/fastify-sqlite/app.ts";
import { buildGatewayExample } from "../examples/api-key-gateway/app.ts";

const GATEWAY_DEPS = { backendUrl: "http://127.0.0.1:1/mcp", getBackendCredential: () => "unused" };
// A scope with a space is not an RFC 6749 scope token; createBridgeConfig
// rejects it, but only AFTER the quickstart material exists in the old order.
const BAD_SCOPE_CATALOG = "mcp: read";

type Boot = (dir: string) => Promise<{ app: { close(): Promise<void> }; store: { close(): Promise<void> } }>;

const TARGETS: Array<[string, Boot]> = [
  ["fastify-sqlite", (dir) => buildExample({ MCP_SSO_DIR: dir, OAUTH_SCOPE_CATALOG: BAD_SCOPE_CATALOG })],
  ["api-key-gateway", (dir) => buildGatewayExample({ MCP_SSO_DIR: dir, OAUTH_SCOPE_CATALOG: BAD_SCOPE_CATALOG }, GATEWAY_DEPS)],
];

for (const [name, boot] of TARGETS) {
  test(`${name}: invalid config rejects BEFORE any quickstart state exists`, async () => {
    const base = mkdtempSync(join(tmpdir(), `mcp-sso-f9-${name}-`));
    const dir = join(base, "state"); // must NOT pre-exist
    try {
      await assert.rejects(boot(dir), /scope/, "the malformed scope catalog fails the boot");
      assert.equal(existsSync(dir), false, "no state dir on a failed boot");
      assert.equal(existsSync(join(dir, "secrets.json")), false, "no secrets.json on a failed boot");
      assert.equal(existsSync(join(dir, ".gitignore")), false, "no .gitignore on a failed boot");
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  });
}

test("valid boots still persist quickstart state (the failed-boot assertions are a real differential)", async () => {
  const base = mkdtempSync(join(tmpdir(), "mcp-sso-f9-control-"));
  try {
    const appDir = join(base, "app");
    const appBoot = await buildExample({ MCP_SSO_DIR: appDir });
    assert.ok(existsSync(join(appDir, "secrets.json")), "example: valid boot persists secrets.json");
    await appBoot.app.close();
    await appBoot.store.close();

    const gatewayDir = join(base, "gateway");
    const gatewayBoot = await buildGatewayExample({ MCP_SSO_DIR: gatewayDir }, GATEWAY_DEPS);
    assert.ok(existsSync(join(gatewayDir, "secrets.json")), "gateway: valid boot persists secrets.json");
    await gatewayBoot.app.close();
    await gatewayBoot.store.close();
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
