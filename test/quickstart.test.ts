// Quickstart secret persistence (contracts §17.8, threat-model row 23).
// Verification rows S1b.1–S1b.4 + O_EXCL non-clobber + the "never ephemeral" rule.

import assert from "node:assert/strict";
import { chmod, mkdir, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
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

test("§17.8: fresh dir writes `*\n`; pre-existing .gitignore must be exactly ours (else fail closed)", async () => {
  // We never parse arbitrary gitignore (negations, anchoring, globs, symlinks) —
  // only the exact `*\n` we manage is trusted. Anything else fails closed.
  await withDir(async (dir) => {
    const target = join(dir, "state");
    await mkdir(target, { recursive: true });

    // Non-matching content → fail closed.
    await writeFile(join(target, ".gitignore"), "*.log\n", { mode: 0o600 });
    await assert.rejects(() => loadOrCreateQuickstartSecrets({ dir: target }), AuthConfigError);

    // "Covering" by exact name but not our content → fail closed.
    await writeFile(join(target, ".gitignore"), "secrets.json\n", { mode: 0o600 });
    await assert.rejects(() => loadOrCreateQuickstartSecrets({ dir: target }), AuthConfigError);

    // A negation that un-ignores the secret → fail closed.
    await writeFile(join(target, ".gitignore"), "*\n!secrets.json\n", { mode: 0o600 });
    await assert.rejects(() => loadOrCreateQuickstartSecrets({ dir: target }), AuthConfigError);

    // Our exact content (`*\n`) from a prior partial run → accepted (recovery).
    await writeFile(join(target, ".gitignore"), "*\n", { mode: 0o600 });
    await loadOrCreateQuickstartSecrets({ dir: target });

    // A fresh dir (no .gitignore) → writes `*` and succeeds.
    const fresh = join(dir, "fresh");
    await loadOrCreateQuickstartSecrets({ dir: fresh });
    assert.equal(await readFile(join(fresh, ".gitignore"), "utf8"), "*\n");
  });
});

test("§17.8 (Codex): a symlinked .gitignore fails closed (git does not follow symlinks)", async () => {
  if (process.platform === "win32") return; // symlink creation needs elevated perms on Windows
  await withDir(async (dir) => {
    const target = join(dir, "state");
    await mkdir(target, { recursive: true });
    await writeFile(join(dir, "fake-gitignore"), "*\n", { mode: 0o600 });
    await symlink(join(dir, "fake-gitignore"), join(target, ".gitignore"));
    await assert.rejects(() => loadOrCreateQuickstartSecrets({ dir: target }), AuthConfigError);
  });
});

test("§17.8 (Codex): reload requires our exact .gitignore present (deleted or tampered → fail closed)", async () => {
  // We never CREATE a .gitignore in a dir we didn't make this process — a stray
  // secrets.json in a repo root must not trigger a `*` write. Reload requires it
  // already present and exact.
  await withDir(async (dir) => {
    const target = join(dir, "state");
    const first = await loadOrCreateQuickstartSecrets({ dir: target });

    // Normal reload (our .gitignore present) → loads the key.
    const reloaded = await loadOrCreateQuickstartSecrets({ dir: target });
    assert.deepEqual(reloaded, first);

    // Deleted after first boot → fail closed (no auto-recreate; can't prove ownership).
    await rm(join(target, ".gitignore"), { force: true });
    await assert.rejects(() => loadOrCreateQuickstartSecrets({ dir: target }), AuthConfigError);

    // Tampered → fail closed.
    await writeFile(join(target, ".gitignore"), "*.log\n", { mode: 0o600 });
    await assert.rejects(() => loadOrCreateQuickstartSecrets({ dir: target }), AuthConfigError);
  });
});

test("§17.8 (Codex round 7): a pre-existing dir with a stray secrets.json and no .gitignore fails closed (no write)", async () => {
  // The load path must not write `*` into a pre-existing dir just because a
  // (possibly malformed) secrets.json is there — that could hide a repo's tree.
  await withDir(async (dir) => {
    const target = join(dir, "state");
    await mkdir(target, { recursive: true });
    await writeFile(join(target, "secrets.json"), "{not json", { mode: 0o600 });
    await assert.rejects(() => loadOrCreateQuickstartSecrets({ dir: target }), AuthConfigError);
    await assert.rejects(stat(join(target, ".gitignore")), /ENOENT/, "did not create a .gitignore");
  });
});

test("§17.8 (Codex round 6): a pre-existing dir without .gitignore fails closed (won't nuke a repo)", async () => {
  // Writing a fresh `*` .gitignore into an existing repo/shared dir would ignore
  // the operator's whole tree. Refuse: only a dir we created (or our reload dir)
  // may have its .gitignore created.
  await withDir(async (dir) => {
    const target = join(dir, "state");
    await mkdir(target, { recursive: true }); // pre-existing, no .gitignore
    await assert.rejects(() => loadOrCreateQuickstartSecrets({ dir: target }), AuthConfigError);
    await assert.rejects(stat(join(target, ".gitignore")), /ENOENT/, "did not create a .gitignore");
    await assert.rejects(stat(join(target, "secrets.json")), /ENOENT/, "did not write secrets");
  });
});

test("§17.8 (Codex): a rejected pre-existing directory is not chmod-mutated", async () => {
  // MCP_SSO_DIR may target an existing shared/project dir. chmodding it to 0700
  // before later checks reject it would leave that path inaccessible. Only a dir
  // we just created gets chmod'd; a pre-existing one is left untouched.
  if (process.platform === "win32") return;
  await withDir(async (dir) => {
    const target = join(dir, "state");
    await mkdir(target, { recursive: true, mode: 0o755 });
    await chmod(target, 0o755); // umask-neutral
    await writeFile(join(target, ".gitignore"), "*.log\n", { mode: 0o600 }); // forces rejection
    await assert.rejects(() => loadOrCreateQuickstartSecrets({ dir: target }), AuthConfigError);
    assert.equal((await stat(target)).mode & 0o777, 0o755, "pre-existing dir perms not mutated");
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
