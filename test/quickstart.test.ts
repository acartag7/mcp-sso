// Quickstart secret persistence (contracts §17.8, threat-model row 23).
// Verification rows S1b.1–S1b.4 + O_EXCL non-clobber + the "never ephemeral" rule.

import assert from "node:assert/strict";
import { chmod, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import type { JWK } from "jose";
import { AuthConfigError, createBridgeConfig } from "../src/config.ts";
import { loadOrCreateQuickstartSecrets } from "../src/quickstart.ts";
import { signAccessToken, verifyAccessToken } from "../src/crypto.ts";
import { SystemClock } from "../src/ports/clock.ts";
import { MemoryStore } from "../src/store/memory.ts";
import { OAuthTokenUseCase } from "../src/token.ts";
import { pkceChallenge } from "../src/crypto.ts";

const REDIRECT = "http://localhost:4321/callback";

function configFrom(secrets: { signingPrivateJwk: JWK; consentSigningSecret: string }) {
  return createBridgeConfig({
    issuer: "http://localhost", resource: "http://localhost/mcp",
    consentSigningSecret: secrets.consentSigningSecret,
    signingPrivateJwk: secrets.signingPrivateJwk, signingKeyId: "k",
    redirectAllowlist: [REDIRECT], scopeCatalog: ["mcp:read", "mcp:write"], defaultScopes: ["mcp:read"],
    allowedOrigins: ["http://localhost"], dcr: { mode: "stateless" }, dev: { allowInsecureLocalhost: true },
    accessTokenTtlSeconds: 600, refreshTokenTtlSeconds: 2_592_000, consentTokenTtlSeconds: 300, authorizationCodeTtlSeconds: 300,
  });
}

async function withDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtempUnique();
  try { return await fn(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}
async function mkdtempUnique(): Promise<string> {
  const { mkdtemp } = await import("node:fs/promises");
  return mkdtemp(join(tmpdir(), "mcp-sso-qs-"));
}

test("S1b.1: first boot with an empty dir — 0700 dir, 0600 file, .gitignore *, valid JWK + consent secret", async () => {
  await withDir(async (dir) => {
    const target = join(dir, "state");
    const secrets = await loadOrCreateQuickstartSecrets({ dir: target });

    // Directory 0700, secrets file 0600 (POSIX).
    if (process.platform !== "win32") {
      assert.equal((await stat(target)).mode & 0o777, 0o700, "dir is 0700");
      assert.equal((await stat(join(target, "secrets.json"))).mode & 0o777, 0o600, "file is 0600");
    }
    // .gitignore contains "*" so the dir can never be committed.
    assert.equal(await readFile(join(target, ".gitignore"), "utf8"), "*\n");

    // Valid EC P-256 JWK shape (passes createBridgeConfig — no throw).
    const jwk = secrets.signingPrivateJwk;
    assert.equal(jwk.kty, "EC");
    assert.equal(jwk.crv, "P-256");
    assert.ok(typeof jwk.d === "string" && jwk.d.length > 0);
    assert.ok(typeof jwk.x === "string" && jwk.x.length > 0);
    assert.ok(typeof jwk.y === "string" && jwk.y.length > 0);
    assert.ok(secrets.consentSigningSecret.length >= 32, "consent secret >= 32 chars");
    assert.doesNotThrow(() => configFrom(secrets));
  });
});

test("S1b.2: token survives restart — reload yields identical secrets and a pre-restart token still validates", async () => {
  await withDir(async (dir) => {
    const target = join(dir, "state");
    const first = await loadOrCreateQuickstartSecrets({ dir: target });
    // Mint a token with the first-boot material.
    const config1 = configFrom(first);
    const token = await signAccessToken({ subject: "agent@test", clientId: "c1", scopes: ["mcp:read"] }, config1, new SystemClock());

    // "Restart": reload from the same dir.
    const second = await loadOrCreateQuickstartSecrets({ dir: target });
    assert.deepEqual(second, first, "reloaded secrets are byte-identical to the generated ones");

    // The pre-restart token still validates against the reloaded config.
    const config2 = configFrom(second);
    const verified = await verifyAccessToken(token, config2, new SystemClock());
    assert.equal(verified.subject, "agent@test");
  });
});

test("S1b.2b: the quickstart key drives the full token use-case (sign → exchange → verify)", async () => {
  await withDir(async (dir) => {
    const secrets = await loadOrCreateQuickstartSecrets({ dir: join(dir, "state") });
    const config = configFrom(secrets);
    const clock = new SystemClock();
    const store = new MemoryStore();
    const token = new OAuthTokenUseCase({ config, store, clock, audit: { async writeAuthEvent() {} } });
    const verifier = "correct-horse-battery-staple-0123456789abcdef0123";
    const { code } = await (async () => {
      // minimal prepare+approve to mint an auth code, then exchange
      const { OAuthAuthorizationUseCase } = await import("../src/authorize.ts");
      const auth = new OAuthAuthorizationUseCase({ config, store, clock, audit: { async writeAuthEvent() {} } });
      const prepared = await auth.prepare({
        clientId: "c1", redirectUri: REDIRECT, responseType: "code",
        codeChallenge: pkceChallenge(verifier), codeChallengeMethod: "S256", scope: "mcp:read", subject: "agent@test",
      });
      const approved = await auth.approve({ consentToken: prepared.consentToken, approved: true, origin: "http://localhost" });
      return { code: approved.code };
    })();
    const tokens = await token.exchangeAuthorizationCode({
      grantType: "authorization_code", code: code as string, redirectUri: REDIRECT, clientId: "c1", codeVerifier: verifier,
    });
    assert.ok(tokens.access_token);
  });
});

test("S1b.3: POSIX group/other-readable secrets file fails closed with chmod 600 remediation", async () => {
  if (process.platform === "win32") return; // POSIX mode bits are meaningless on Windows
  await withDir(async (dir) => {
    const target = join(dir, "state");
    await loadOrCreateQuickstartSecrets({ dir: target });
    await chmod(join(target, "secrets.json"), 0o644);
    await assert.rejects(
      () => loadOrCreateQuickstartSecrets({ dir: target }),
      (err: unknown) => err instanceof AuthConfigError && /chmod 600/.test((err as Error).message),
    );
  });
});

test("S1b.4: corrupt / partial / bad-shape secrets fail closed — never an ephemeral fallback", async () => {
  await withDir(async (dir) => {
    const target = join(dir, "state");
    await mkdir(target, { recursive: true });
    const file = join(target, "secrets.json");

    // Unparseable JSON.
    await writeFile(file, "{not json", { mode: 0o600 });
    await assert.rejects(() => loadOrCreateQuickstartSecrets({ dir: target }), AuthConfigError);

    // Valid JSON, wrong shape (not an object).
    await writeFile(file, JSON.stringify([1, 2, 3]), { mode: 0o600 });
    await assert.rejects(() => loadOrCreateQuickstartSecrets({ dir: target }), AuthConfigError);

    // Consent secret too short.
    await writeFile(file, JSON.stringify({ signingPrivateJwk: badJwk(), consentSigningSecret: "short" }), { mode: 0o600 });
    await assert.rejects(() => loadOrCreateQuickstartSecrets({ dir: target }), AuthConfigError);

    // JWK wrong curve / missing d.
    await writeFile(file, JSON.stringify({ signingPrivateJwk: { kty: "EC", crv: "P-384", x: "x", y: "y" }, consentSigningSecret: "x".repeat(40) }), { mode: 0o600 });
    await assert.rejects(() => loadOrCreateQuickstartSecrets({ dir: target }), AuthConfigError);
  });
});

test("O_EXCL: an existing secrets.json is loaded, never overwritten (no silent key rotation)", async () => {
  await withDir(async (dir) => {
    const target = join(dir, "state");
    const first = await loadOrCreateQuickstartSecrets({ dir: target });
    // Stamp a sentinel by re-writing the file with a known consent secret + the same JWK.
    const stamped = { signingPrivateJwk: first.signingPrivateJwk, consentSigningSecret: "SENTINEL".repeat(8) };
    await writeFile(join(target, "secrets.json"), JSON.stringify(stamped), { mode: 0o600 });
    const reloaded = await loadOrCreateQuickstartSecrets({ dir: target });
    assert.equal(reloaded.consentSigningSecret, stamped.consentSigningSecret, "existing file loaded verbatim");
    assert.deepEqual(reloaded.signingPrivateJwk, first.signingPrivateJwk, "JWK untouched");
  });
});

test("§17.8: a pre-existing non-covering .gitignore fails closed; a covering one is accepted", async () => {
  await withDir(async (dir) => {
    const target = join(dir, "state");
    await mkdir(target, { recursive: true });

    // Non-covering .gitignore → fail closed (secrets.json would be committable).
    await writeFile(join(target, ".gitignore"), "*.log\n", { mode: 0o600 });
    await assert.rejects(() => loadOrCreateQuickstartSecrets({ dir: target }), AuthConfigError);

    // Covering .gitignore (exact secrets.json) → accepted, secrets written.
    await writeFile(join(target, ".gitignore"), "secrets.json\n", { mode: 0o600 });
    const covered = await loadOrCreateQuickstartSecrets({ dir: target });
    assert.ok(covered.consentSigningSecret.length >= 32);

    // A blanket `*` is also accepted.
    await rm(join(target, "secrets.json"), { force: true });
    await writeFile(join(target, ".gitignore"), "*\n", { mode: 0o600 });
    await loadOrCreateQuickstartSecrets({ dir: target });

    // A fresh dir (no .gitignore) → writes `*` (the default path).
    const fresh = join(dir, "fresh");
    await loadOrCreateQuickstartSecrets({ dir: fresh });
    assert.equal(await readFile(join(fresh, ".gitignore"), "utf8"), "*\n");
  });
});

test("unwritable directory fails closed (no ephemeral fallback)", async () => {
  await withDir(async (dir) => {
    const target = join(dir, "state");
    await mkdir(target, { recursive: true, mode: 0o500 }); // read+execute, no write
    if (process.platform !== "win32") {
      await assert.rejects(() => loadOrCreateQuickstartSecrets({ dir: join(target, "sub") }), AuthConfigError);
    }
  });
});

function badJwk(): JWK {
  // A real P-256 key but we only use it as a shape reference for the "wrong shape" cases above.
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { ...privateKey.export({ format: "jwk" }) } as JWK;
}
