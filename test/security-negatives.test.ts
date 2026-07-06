// Adversarial negatives a 2026-07-06 threat-model×tests mapping found missing:
// shipped behavior, testable, untested. Each maps to a threat-model row whose
// control is in src but never adversarially exercised. TEST-ONLY.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { execSync, spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { SignJWT, type JWK } from "jose";
import { createBridgeConfig, type BridgeConfig } from "../src/config.ts";
import { signAccessToken } from "../src/crypto.ts";
import { OAuthError } from "../src/errors.ts";
import { RequestAuthorizer } from "../src/verifier.ts";
import { SystemClock } from "../src/ports/clock.ts";
import { noopAudit } from "../src/ports/audit.ts";

const REPO = fileURLToPath(new URL("..", import.meta.url));

function ecJwk(): JWK {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }), alg: "ES256", kid: "k" } as JWK;
}

/** https config (no dev flag needed). Same signing key across A/B isolates the
 *  audience check: a token's signature verifies under either verifier, so ONLY the
 *  audience binding can reject a cross-resource token. */
function httpsConfig(resource: string, signingPrivateJwk: JWK): BridgeConfig {
  return createBridgeConfig({
    issuer: "https://auth.test", resource,
    consentSigningSecret: "c".repeat(40), signingPrivateJwk, signingKeyId: "k",
    redirectAllowlist: [], scopeCatalog: ["mcp:read"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["https://auth.test"], dcr: { mode: "stateless" },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 600, consentTokenTtlSeconds: 600, authorizationCodeTtlSeconds: 600,
  });
}

function authorizer(config: BridgeConfig): RequestAuthorizer {
  return new RequestAuthorizer({ config, clock: new SystemClock(), audit: noopAudit });
}

function isInvalidToken(e: unknown): boolean {
  return e instanceof OAuthError && e.code === "invalid_token";
}

test("security — cross-resource audience fail-closed (RFC 8707 §7.2): a token minted for resource A is rejected by resource B", async () => {
  // threat-model row 6. Only the positive path (same resource) is tested elsewhere.
  const key = ecJwk();
  const configA = httpsConfig("https://api-a.test/mcp", key);
  const configB = httpsConfig("https://api-b.test/mcp", key);
  const clock = new SystemClock();
  const tokenA = await signAccessToken({ subject: "subj-a", clientId: "c", scopes: ["mcp:read"] }, configA, clock);

  // Positive contrast: A's own authorizer accepts its token.
  const ok = await authorizer(configA).authorize({ authorization: `Bearer ${tokenA}` });
  assert.equal(ok.subject, "subj-a");

  // Negative: B rejects the A-audience token even though the signature is valid
  // under B's verifier (same key) — audience fail-closed is the core RFC 8707 promise.
  await assert.rejects(authorizer(configB).authorize({ authorization: `Bearer ${tokenA}` }), isInvalidToken);
});

test("security — alg:none and HS256(consent-secret) token forgeries are rejected by the ES256 verifier (threat-model row 3)", async () => {
  // alg pinning (algorithms:["ES256"]) + consent/access key separation are in
  // src/crypto.ts but never adversarially exercised.
  const config = httpsConfig("https://api.test/mcp", ecJwk());
  const auth = authorizer(config);
  const now = Math.floor(Date.now() / 1000);

  // alg:none — no signature. The verifier's alg pin must reject it outright.
  const b64u = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString("base64url");
  const noneToken = `${b64u({ alg: "none", typ: "JWT", kid: "k" })}.${b64u({ sub: "forgger", client_id: "c", scope: "mcp:read", iss: config.issuer, aud: config.resource, iat: now, exp: now + 600 })}.`;
  await assert.rejects(auth.authorize({ authorization: `Bearer ${noneToken}` }), isInvalidToken, "alg:none rejected");

  // HS256 signed with the CONSENT secret (the symmetric consent-token key) — a
  // classic algorithm-confusion attack IF the access-token verifier ever honored
  // HS256. Key separation (access = EC ES256, consent = HMAC) + the alg pin reject it.
  const hs256Token = await new SignJWT({ sub: "forgger", client_id: "c", scope: "mcp:read" })
    .setProtectedHeader({ alg: "HS256", typ: "JWT", kid: "k" })
    .setIssuer(config.issuer).setSubject("forgger").setAudience(config.resource)
    .setIssuedAt(now).setExpirationTime(now + 600)
    .sign(new TextEncoder().encode(config.consentSigningSecret));
  await assert.rejects(auth.authorize({ authorization: `Bearer ${hs256Token}` }), isInvalidToken, "HS256-with-consent-secret rejected");
});

test("security — openSqliteStore on a FIFO fails closed without hanging (threat-model row 26, the unswept sqlite sibling)", async () => {
  if (process.platform === "win32") return; // no mkfifo
  // The quickstart + JSONL-audit FIFO no-hang tests exist (rows 23/24); the sqlite
  // sibling was never swept. openSqliteStore is SYNC, so a hang would stall the event
  // loop — run it in a SUBPROCESS with a hard deadline so a regression is observable
  // + killable, not a frozen test run. The row-26 claim: opens O_RDWR (no block) and
  // fails closed (SQLITE_IOERR) on a FIFO — the test proves BOTH throw AND promptness.
  const dir = await mkdtemp(join(tmpdir(), "mcp-sso-fifo-sqlite-"));
  const fifo = join(dir, "auth.fifo");
  execSync(`mkfifo '${fifo}'`);
  const sqliteUrl = pathToFileURL(join(REPO, "src", "store", "sqlite.ts")).href;
  const script = [
    `import { openSqliteStore } from ${JSON.stringify(sqliteUrl)};`,
    `const t0 = Date.now();`,
    `try { openSqliteStore(${JSON.stringify(fifo)}); process.stdout.write("open-ok " + (Date.now()-t0) + "ms\\n"); process.exit(0); }`,
    `catch (e) { process.stderr.write(String((e && e.message) || e) + " @" + (Date.now()-t0) + "ms\\n"); process.exit(1); }`,
  ].join("\n");
  const child = spawn("node", ["--input-type=module", "-e", script], { cwd: REPO, stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });
  const result = await new Promise<number | "HUNG">((resolve) => {
    const to = setTimeout(() => { child.kill("SIGKILL"); resolve("HUNG"); }, 3000);
    child.on("exit", (code) => { clearTimeout(to); resolve(code ?? -1); });
  });
  try {
    assert.notEqual(result, "HUNG", "openSqliteStore must NOT hang on a FIFO (row 26)");
    assert.equal(result, 1, "openSqliteStore must throw (fail closed) on a FIFO");
    assert.match(stderr, /I\/O error|disk|unable to open/i, "a disk/IO error (fail-closed), not a silent open");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
