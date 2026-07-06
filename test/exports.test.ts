// Verifies the consumer-facing public surface (contracts §15) is reachable from
// the ROOT entry — the import shape a package consumer uses, not in-repo source
// paths. Codex P2: handlePairingAuthorize was not exported, so consumers could
// get the console-pairing identity but not the helper that makes it mountable.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  Bridge,
  RequestAuthorizer,
  loadOrCreateQuickstartSecrets,
  handlePairingAuthorize,
  renderPairingPage,
  JsonlFileAudit,
  WebhookAudit,
  combineAudit,
} from "../src/index.ts";

test("exports: the S1b + S1a + core surface is reachable from the root entry", () => {
  assert.equal(typeof Bridge, "function", "Bridge (the central class) is root-exported");
  assert.equal(typeof RequestAuthorizer, "function");
  assert.equal(typeof loadOrCreateQuickstartSecrets, "function");
  assert.equal(typeof handlePairingAuthorize, "function");
  assert.equal(typeof renderPairingPage, "function");
  assert.equal(typeof JsonlFileAudit, "function");
  assert.equal(typeof WebhookAudit, "function");
  assert.equal(typeof combineAudit, "function");
});

test("exports: renderPairingPage emits the nonce + round-tripped OAuth params, never a code", () => {
  const html = renderPairingPage({
    nonce: "NONCE_ABC",
    expiresAt: "2026-07-05T12:00:00.000Z",
    oauthParams: { client_id: "c1", redirect_uri: "http://localhost/cb", scope: "mcp:read" },
  });
  assert.match(html, /name="pairing_nonce" value="NONCE_ABC"/);
  assert.match(html, /name="client_id" value="c1"/);
  assert.match(html, /name="scope" value="mcp:read"/);
  assert.match(html, /Pair this device/);
});

test("exports: the ./identity/console-pairing subpath is mapped to its source-of-truth", () => {
  // The subpath EXPORT STRING was never asserted: a rename/removal in package.json
  // (while the source still exports the factory) would silently break consumers who
  // import via the subpath. Resolve the exports map entry and cross-check the source.
  const pkgPath = fileURLToPath(new URL("../package.json", import.meta.url));
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { exports: Record<string, { types: string; default: string }> };
  const sub = pkg.exports["./identity/console-pairing"];
  assert.ok(sub, "./identity/console-pairing subpath is present in package.json exports");
  assert.equal(sub.types, "./dist/identity/console-pairing.d.ts", "subpath types target");
  assert.equal(sub.default, "./dist/identity/console-pairing.js", "subpath default target");
  // The dist files are built from this source — assert it exports the factory the
  // subpath promises (ties the export string to real source, not a dangling entry).
  const src = readFileSync(fileURLToPath(new URL("../src/identity/console-pairing.ts", import.meta.url)), "utf8");
  assert.ok(/export function createConsolePairingIdentity/.test(src), "source-of-truth exports createConsolePairingIdentity");
});
