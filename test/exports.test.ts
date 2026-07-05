// Verifies the consumer-facing public surface (contracts §15) is reachable from
// the ROOT entry — the import shape a package consumer uses, not in-repo source
// paths. Codex P2: handlePairingAuthorize was not exported, so consumers could
// get the console-pairing identity but not the helper that makes it mountable.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  loadOrCreateQuickstartSecrets,
  handlePairingAuthorize,
  renderPairingPage,
  JsonlFileAudit,
  WebhookAudit,
  combineAudit,
} from "../src/index.ts";

test("exports: the S1b + S1a surface is reachable from the root entry", () => {
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
