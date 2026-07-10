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
  createUpstreamRedirectFlow,
  isMcpPath,
  type UpstreamRedirectFlow,
  type RedirectIdentityPort,
} from "../src/index.ts";

const pkgPath = fileURLToPath(new URL("../package.json", import.meta.url));

test("exports: the S1b + S1a + core surface is reachable from the root entry", () => {
  assert.equal(typeof Bridge, "function", "Bridge (the central class) is root-exported");
  assert.equal(typeof RequestAuthorizer, "function");
  assert.equal(typeof loadOrCreateQuickstartSecrets, "function");
  assert.equal(typeof handlePairingAuthorize, "function");
  assert.equal(typeof renderPairingPage, "function");
  assert.equal(typeof JsonlFileAudit, "function");
  assert.equal(typeof WebhookAudit, "function");
  assert.equal(typeof combineAudit, "function");
  assert.equal(typeof createUpstreamRedirectFlow, "function", "createUpstreamRedirectFlow (§17.11) is root-exported");
  assert.equal(typeof isMcpPath, "function", "isMcpPath (/mcp Origin-gate path check) is root-exported");
  void (null as unknown as UpstreamRedirectFlow); // type reachable
  void (null as unknown as RedirectIdentityPort); // type reachable
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

test("exports: the §17.11 redirect-flow identity is re-exported from the ./identity/entra subpath source", () => {
  // createEntraRedirectIdentity lives in entra-redirect.ts but must be importable
  // via the ./identity/entra subpath (entra.ts re-exports it). Ties the re-export
  // line to real source so a rename/removal can't silently break consumers.
  const entraSrc = readFileSync(fileURLToPath(new URL("../src/identity/entra.ts", import.meta.url)), "utf8");
  assert.ok(/createEntraRedirectIdentity/.test(entraSrc), "entra.ts re-exports createEntraRedirectIdentity for the subpath");
  const redirectSrc = readFileSync(fileURLToPath(new URL("../src/identity/entra-redirect.ts", import.meta.url)), "utf8");
  assert.ok(/export function createEntraRedirectIdentity/.test(redirectSrc), "source-of-truth exports createEntraRedirectIdentity");
});

test("exports: the ./identity/generic-oidc subpath is mapped to its source-of-truth (S4a)", () => {
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { exports: Record<string, { types: string; default: string }> };
  const sub = pkg.exports["./identity/generic-oidc"];
  assert.ok(sub, "./identity/generic-oidc subpath is present in package.json exports");
  assert.equal(sub.types, "./dist/identity/generic-oidc.d.ts", "subpath types target");
  assert.equal(sub.default, "./dist/identity/generic-oidc.js", "subpath default target");
  const src = readFileSync(fileURLToPath(new URL("../src/identity/generic-oidc.ts", import.meta.url)), "utf8");
  assert.ok(/export async function createGenericOidcIdentity/.test(src), "source-of-truth exports createGenericOidcIdentity");
  assert.ok(/createGenericOidcRedirectIdentity/.test(src), "generic-oidc.ts re-exports createGenericOidcRedirectIdentity for the subpath");
});

test("exports: the ./identity/google subpath is mapped to its source-of-truth (S4a)", () => {
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { exports: Record<string, { types: string; default: string }> };
  const sub = pkg.exports["./identity/google"];
  assert.ok(sub, "./identity/google subpath is present in package.json exports");
  assert.equal(sub.types, "./dist/identity/google.d.ts", "subpath types target");
  assert.equal(sub.default, "./dist/identity/google.js", "subpath default target");
  const src = readFileSync(fileURLToPath(new URL("../src/identity/google.ts", import.meta.url)), "utf8");
  assert.ok(/export async function createGoogleIdentity/.test(src), "source-of-truth exports createGoogleIdentity");
  assert.ok(/export async function createGoogleRedirectIdentity/.test(src), "source-of-truth exports createGoogleRedirectIdentity");
});
