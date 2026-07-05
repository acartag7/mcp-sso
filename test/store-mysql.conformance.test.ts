// MysqlStore integration: runs the shared StorePort conformance suite (contracts
// §12) against a real MySQL, plus MySQL-specific proofs the sequential suite
// cannot cover: concurrent-rotation serialization (FOR UPDATE — review H3), the
// consumeConsentJti ODKU no-op across differing timestamps (M7), and the
// no-raw-secrets / only-OAuth-tables assertions.
//
// Gated on MYSQL_URL: locally absent -> tests are not registered (local `pnpm test`
// stays green). In CI, MYSQL_URL MUST be set — a missing value hard-fails the file
// (review B3) so a wiring typo cannot silently skip coverage and print a green CI.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { before, after, beforeEach, test } from "node:test";
import { createPool, type Pool, type RowDataPacket } from "mysql2/promise";
import type { StorePort } from "../src/ports/store.ts";
import { MysqlStore, createMysqlStore } from "../src/store/mysql.ts";
import { MYSQL_OAUTH_TABLES } from "../src/store/mysql-schema.ts";
import { runStoreConformance } from "./lib/store-conformance.ts";

const RUN_INTEGRATION = process.env.RUN_INTEGRATION === "true";
const MYSQL_URL = process.env.MYSQL_URL;
const RUN = !!MYSQL_URL;

if (RUN_INTEGRATION && !MYSQL_URL) {
  // B3: in the integration CI job (RUN_INTEGRATION set), a missing MYSQL_URL must RED,
  // not silently skip. Keyed on RUN_INTEGRATION (not the ambient CI var) because
  // publish.yml also runs `pnpm test` under CI=true without the service containers —
  // gating on CI would block every release.
  throw new Error("MYSQL_URL is required when RUN_INTEGRATION is set — the MysqlStore adapter must be exercised.");
}

const NOW = "2026-07-03T12:00:00.000Z";
const LATER = "2026-07-03T12:05:00.000Z";
const FUTURE = "2026-07-03T13:00:00.000Z";

let admin: Pool | undefined;

before(async () => {
  if (!RUN) return;
  admin = createPool(MYSQL_URL as string);
  // Migrate once (also runs the boot-time strict-mode + collation assertions).
  const setupStore = await createMysqlStore(MYSQL_URL as string);
  await setupStore.close();
});

beforeEach(async () => {
  if (!admin) return;
  // Delete in FK-safe order (children first); CASCADE already empties tokens when a
  // family goes, but explicit child-first DELETE avoids any FK check friction.
  await admin.query("DELETE FROM oauth_refresh_tokens");
  await admin.query("DELETE FROM oauth_refresh_token_families");
  await admin.query("DELETE FROM oauth_auth_codes");
  await admin.query("DELETE FROM oauth_consent_jtis");
});

after(async () => {
  if (admin) await admin.end();
});

// Fresh pool/store per test (lazy pool; close() ends it). Tables already exist.
function make(): StorePort {
  return new MysqlStore(createPool(MYSQL_URL as string));
}

if (RUN) {
  runStoreConformance("MysqlStore", make);

  test("MysqlStore: concurrent rotation serializes (FOR UPDATE prevents double-spend) — review H3", async () => {
    const store = make();
    try {
      await store.saveRefreshToken(refresh("conc", "fam-conc", null, FUTURE));
      const a = refresh("nextA", "fam-conc", sha256Hex("conc"), FUTURE);
      const b = refresh("nextB", "fam-conc", sha256Hex("conc"), FUTURE);
      const [ra, rb] = await Promise.all([
        store.rotateRefreshToken(sha256Hex("conc"), a, NOW),
        store.rotateRefreshToken(sha256Hex("conc"), b, NOW),
      ]);
      assert.equal([ra, rb].filter((r) => r !== null).length, 1, "exactly one concurrent rotation wins");
      const [rows] = await admin!.query<RowDataPacket[]>(
        "SELECT COUNT(*) AS c FROM oauth_refresh_tokens WHERE previous_token_hash = ?",
        [sha256Hex("conc")],
      );
      assert.equal((rows[0] as { c: number }).c, 1, "exactly one successor row exists");
      // The losing rotation observed consumed_at set and revoked the family -> replay is null.
      assert.equal(await store.rotateRefreshToken(sha256Hex("conc"), refresh("nextC", "fam-conc", sha256Hex("conc"), FUTURE), LATER), null);
    } finally {
      await store.close();
    }
  });

  test("MysqlStore: 20 concurrent rotations yield exactly one successor", async () => {
    const store = make();
    try {
      await store.saveRefreshToken(refresh("race", "fam-race", null, FUTURE));
      const results = await Promise.all(Array.from({ length: 20 }, (_, i) =>
        store.rotateRefreshToken(sha256Hex("race"), refresh(`r${i}`, "fam-race", sha256Hex("race"), FUTURE), NOW),
      ));
      assert.equal(results.filter((r) => r !== null).length, 1, "exactly one of 20 wins");
      const [rows] = await admin!.query<RowDataPacket[]>(
        "SELECT COUNT(*) AS c FROM oauth_refresh_tokens WHERE previous_token_hash = ?",
        [sha256Hex("race")],
      );
      assert.equal((rows[0] as { c: number }).c, 1, "exactly one successor row exists");
    } finally {
      await store.close();
    }
  });

  test("MysqlStore: consumeConsentJti returns false on replay even with a different timestamp — review M7", async () => {
    const store = make();
    try {
      assert.equal(await store.consumeConsentJti("jti-m7", "2026-07-03T13:00:00.000Z"), true);
      // INSERT IGNORE returns affectedRows=1 on first insert and 0 on every replay,
      // independent of the supplied timestamp. (The earlier ODKU expires_at=expires_at
      // form was empirically verified to return affectedRows=1 on replay under MySQL 8.4,
      // making replays indistinguishable from first use — hence INSERT IGNORE.)
      assert.equal(await store.consumeConsentJti("jti-m7", "2026-07-03T14:00:00.000Z"), false);
    } finally {
      await store.close();
    }
  });

  test("MysqlStore: a successor-hash collision returns null and leaves the predecessor unconsumed (parity)", async () => {
    const store = make();
    try {
      await store.saveRefreshToken(refresh("orig", "fam-col", null, FUTURE));
      await store.saveRefreshToken(refresh("existing", "fam-other", null, FUTURE)); // hash collides with the successor below
      // Rotate "orig" but supply a successor tokenHash that already exists -> null.
      const rotated = await store.rotateRefreshToken(sha256Hex("orig"), {
        ...refresh("next", "fam-col", sha256Hex("orig"), FUTURE), tokenHash: sha256Hex("existing"),
      }, NOW);
      assert.equal(rotated, null, "collision -> null");
      // The predecessor must STILL be consumable: the failed rotation did not consume it
      // (matches sqlite's check-before-update; Codex P2). Would fail if UPDATE preceded INSERT.
      const retry = await store.rotateRefreshToken(sha256Hex("orig"), refresh("ok", "fam-col", sha256Hex("orig"), FUTURE), LATER);
      assert.ok(retry, "predecessor survives the failed rotation");
    } finally {
      await store.close();
    }
  });

  test("MysqlStore: sweep concurrent with rotation keeps the live successor (H1)", async () => {
    const store = make();
    try {
      await store.saveRefreshToken(refresh("src", "fam-h1", null, FUTURE));
      // At NOW the family is still valid (FUTURE > NOW), so sweep must delete nothing.
      // Run several sweeps concurrently with a rotation; the two-step sweep must not
      // delete the freshly-rotated live successor under READ COMMITTED.
      await Promise.all([
        store.sweepExpired(NOW), store.sweepExpired(NOW), store.sweepExpired(NOW),
        store.rotateRefreshToken(sha256Hex("src"), refresh("h1succ", "fam-h1", sha256Hex("src"), FUTURE), NOW),
      ]);
      assert.ok(await store.findRefreshToken(sha256Hex("h1succ")), "live successor survives concurrent sweep (H1)");
    } finally {
      await store.close();
    }
  });

  test("MysqlStore: stores no raw secrets and only OAuth tables", async () => {    const store = make();
    try {
      const rawCode = "raw-secret-mysql-code-xyz";
      const rawRefresh = "rt.rawsecret-mysql-token-aaa";
      await store.saveAuthCode({
        codeHash: sha256Hex(rawCode), clientId: "c", subject: "s",
        redirectUri: "https://client.test/callback", resource: "https://api.test/mcp",
        scopes: ["mcp:read"], codeChallenge: "x", codeChallengeMethod: "S256", expiresAt: FUTURE,
      });
      await store.saveRefreshToken({
        tokenHash: sha256Hex(rawRefresh), familyId: "famx", previousTokenHash: null,
        clientId: "c", subject: "s", scopes: ["mcp:read"], expiresAt: FUTURE,
      });
    } finally {
      await store.close();
    }
    // No hash-bearing column equals the raw secret. (Strictly weaker than sqlite's
    // full-file byte scan — cannot see index pages / redo / binlog — but covers every
    // hash column the adapter writes.)
    const probes = [
      ["SELECT COUNT(*) AS c FROM oauth_auth_codes WHERE code_hash = ?", "raw-secret-mysql-code-xyz"],
      ["SELECT COUNT(*) AS c FROM oauth_refresh_tokens WHERE token_hash = ?", "rt.rawsecret-mysql-token-aaa"],
      ["SELECT COUNT(*) AS c FROM oauth_refresh_tokens WHERE previous_token_hash = ?", "rt.rawsecret-mysql-token-aaa"],
    ] as const;
    for (const [sql, val] of probes) {
      const [rows] = await admin!.query<RowDataPacket[]>(sql, [val]);
      assert.equal((rows[0] as { c: number }).c, 0, `raw secret matched a hash column: ${sql}`);
    }
    // The schema contains exactly the four OAuth tables.
    const [rows] = await admin!.query<RowDataPacket[]>(
      "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME",
    );
    const tables = (rows as { TABLE_NAME: string }[]).map((r) => r.TABLE_NAME);
    assert.deepEqual(tables, [...MYSQL_OAUTH_TABLES].sort());
  });

  test("MysqlStore: migrate fails closed on a non-InnoDB oauth table (Codex P2)", async () => {
    // CREATE TABLE IF NOT EXISTS does not change a pre-existing table's engine, so a
    // MyISAM oauth_* table would pass the strict-mode + collation guards while breaking
    // FOR UPDATE row locking. Convert oauth_auth_codes to MyISAM and assert migrate
    // rejects; restore InnoDB + re-migrate in finally so later tests see a clean schema.
    await admin!.query("ALTER TABLE oauth_auth_codes ENGINE=MyISAM");
    try {
      await assert.rejects(createMysqlStore(MYSQL_URL as string), /InnoDB/);
    } finally {
      await admin!.query("ALTER TABLE oauth_auth_codes ENGINE=InnoDB");
      const restore = await createMysqlStore(MYSQL_URL as string);
      await restore.close();
    }
  });
}

function refresh(rawToken: string, familyId: string, previousTokenHash: string | null, expiresAt: string) {
  return {
    tokenHash: sha256Hex(rawToken), familyId, previousTokenHash,
    clientId: "client-1", subject: "subject-1", scopes: ["mcp:read"], expiresAt,
  };
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
