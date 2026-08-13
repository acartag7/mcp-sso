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
import { createPool, type Pool, type PoolConnection, type ResultSetHeader, type RowDataPacket } from "mysql2/promise";
import type { StorePort } from "../src/ports/store.ts";
import { MysqlStore, createMysqlStore } from "../src/store/mysql.ts";
import { MYSQL_OAUTH_TABLES } from "../src/store/mysql-schema.ts";
import { MYSQL_SUBJECT_CAPACITY } from "../src/store/mysql-subject-schema.ts";
import { entraIssuer, validateEntraIdToken } from "../src/identity/entra.ts";
import { runStoreConformance } from "./lib/store-conformance.ts";

const RUN_INTEGRATION = process.env.RUN_INTEGRATION === "true";
const MYSQL_URL = process.env.MYSQL_URL;
const RUN = !!MYSQL_URL;

// node --test runs test files CONCURRENTLY in separate processes against this SAME
// CI database. integration-full-flow.test.ts runs a full /mcp round-trip through a
// real express mount against MysqlStore here too; this file's beforeEach DELETE-all
// could wipe that flow's rows mid-flight. Both files take this named advisory lock
// for their whole lifetime so they serialize (CI is sacred — no cross-file flakes).
const OAUTH_LOCK_NAME = "mcp_sso_oauth_lock";

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
let lockConn: PoolConnection | undefined;

before(async () => {
  if (!RUN) return;
  admin = createPool(MYSQL_URL as string);
  // Hold the named lock on a DEDICATED connection for this file's lifetime so the
  // concurrent integration-full-flow mysql round-trip can't race this file's
  // beforeEach DELETE-all (and vice versa). GET_LOCK is per-connection, so the
  // connection is kept (not released) until `after`.
  lockConn = await admin.getConnection();
  // 120s must exceed the worst-case runtime of the sibling integration-full-flow
  // mysql test (it waits for THIS file's whole-suite duration under the same lock).
  const [rows] = await lockConn.query<RowDataPacket[]>("SELECT GET_LOCK(?, 120) AS ok", [OAUTH_LOCK_NAME]);
  assert.equal((rows[0] as { ok: number }).ok, 1, `could not acquire ${OAUTH_LOCK_NAME}`);
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
  if (lockConn) {
    try { await lockConn.query("SELECT RELEASE_LOCK(?)", [OAUTH_LOCK_NAME]); } catch { /* pool ending below anyway */ }
    lockConn.release();
  }
  if (admin) await admin.end();
});

// Fresh pool/store per test (lazy pool; close() ends it — the test owns the pool it
// creates, so ownsPool=true). Tables already exist.
function make(): StorePort {
  return new MysqlStore(createPool(MYSQL_URL as string), true);
}

if (RUN) {
  test("MysqlStore/MySQL 8.4: migrates VARCHAR(255) subjects and persists max Entra authorization/refresh", async () => {
    await admin!.query("ALTER TABLE oauth_auth_codes MODIFY COLUMN subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL");
    await admin!.query("ALTER TABLE oauth_refresh_tokens MODIFY COLUMN subject VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL");
    const store = await createMysqlStore(MYSQL_URL as string);
    try {
      await store.migrate();
      const [columns] = await admin!.query<RowDataPacket[]>(
        `SELECT TABLE_NAME, CHARACTER_MAXIMUM_LENGTH
         FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE() AND COLUMN_NAME = 'subject'
           AND TABLE_NAME IN ('oauth_auth_codes', 'oauth_refresh_tokens')
         ORDER BY TABLE_NAME`,
      );
      assert.deepEqual(
        (columns as { TABLE_NAME: string; CHARACTER_MAXIMUM_LENGTH: number }[]).map((column) => ({
          table: column.TABLE_NAME, width: column.CHARACTER_MAXIMUM_LENGTH,
        })),
        [
          { table: "oauth_auth_codes", width: MYSQL_SUBJECT_CAPACITY },
          { table: "oauth_refresh_tokens", width: MYSQL_SUBJECT_CAPACITY },
        ],
      );

      const tenantId = "11111111-2222-3333-4444-555555555555";
      const issuer = entraIssuer(tenantId);
      const result = validateEntraIdToken({
        iss: issuer, aud: "mysql-max-subject-client", tid: tenantId,
        sub: "s".repeat(255), exp: Math.floor(Date.parse(FUTURE) / 1000),
      }, {
        tenantId, clientId: "mysql-max-subject-client", redirectUri: "https://bridge.test/oauth/entra/callback",
      });
      assert.ok(result.ok);
      const subject = result.identity.subject;
      assert.equal(issuer.length, 75);
      assert.equal(subject.length, 331);

      const codeHash = sha256Hex("max-entra-subject-code");
      await store.saveAuthCode({
        codeHash, clientId: "mysql-max-subject-client", subject,
        redirectUri: "https://client.test/callback", resource: "https://api.test/mcp",
        scopes: ["mcp:read"], codeChallenge: "challenge", codeChallengeMethod: "S256", expiresAt: FUTURE,
      });
      assert.equal((await store.consumeAuthCode(codeHash, NOW))?.subject, subject);

      const predecessorHash = sha256Hex("max-entra-subject-refresh");
      const successorHash = sha256Hex("max-entra-subject-successor");
      await store.saveRefreshToken({
        tokenHash: predecessorHash, familyId: "max-entra-subject-family", previousTokenHash: null,
        clientId: "mysql-max-subject-client", subject, resource: "https://api.test/mcp",
        scopes: ["mcp:read"], expiresAt: FUTURE,
      });
      const rotated = await store.rotateRefreshToken(predecessorHash, {
        tokenHash: successorHash, familyId: "max-entra-subject-family", previousTokenHash: predecessorHash,
        clientId: "attacker-client", subject: "attacker-subject", resource: "https://api.test/mcp",
        scopes: ["mcp:write"], expiresAt: FUTURE,
      }, NOW);
      assert.equal(rotated?.subject, subject);
      assert.equal((await store.findRefreshToken(successorHash))?.subject, subject);
      assert.deepEqual(
        await store.findGrantedScopes(subject, "mysql-max-subject-client", NOW),
        ["mcp:read"],
      );
    } finally {
      await store.close();
    }
  });

  test("MysqlStore: fresh schema has non-null exact resource columns", async () => {
    const [columns] = await admin!.query<RowDataPacket[]>(
      `SELECT TABLE_NAME, IS_NULLABLE, COLUMN_TYPE, COLLATION_NAME
       FROM information_schema.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE() AND COLUMN_NAME = 'resource'
         AND TABLE_NAME IN ('oauth_refresh_token_families', 'oauth_refresh_tokens')
       ORDER BY TABLE_NAME`,
    );
    assert.deepEqual(
      (columns as { TABLE_NAME: string; IS_NULLABLE: string; COLUMN_TYPE: string; COLLATION_NAME: string }[])
        .map((column) => ({
          table: column.TABLE_NAME,
          nullable: column.IS_NULLABLE,
          type: column.COLUMN_TYPE,
          collation: column.COLLATION_NAME,
        })),
      [
        { table: "oauth_refresh_token_families", nullable: "NO", type: "varchar(2048)", collation: "utf8mb4_bin" },
        { table: "oauth_refresh_tokens", nullable: "NO", type: "varchar(2048)", collation: "utf8mb4_bin" },
      ],
    );
    await assert.rejects(
      admin!.query(
        "INSERT INTO oauth_refresh_token_families (family_id, resource, revoked_at, grant_generation) VALUES (?, NULL, NULL, ?)",
        ["fresh-null-resource-family", 1],
      ),
      (error: unknown) => (error as { code?: unknown }).code === "ER_BAD_NULL_ERROR",
    );
    await admin!.query(
      "INSERT INTO oauth_refresh_token_families (family_id, resource, revoked_at, grant_generation) VALUES (?, ?, NULL, ?)",
      ["fresh-null-resource-token-family", "https://api-a.test/mcp", 1],
    );
    await assert.rejects(
      admin!.query(
        `INSERT INTO oauth_refresh_tokens
         (token_hash, family_id, previous_token_hash, client_id, subject, resource, scopes_json, expires_at, consumed_at, grant_generation)
         VALUES (?, ?, NULL, ?, ?, NULL, ?, ?, NULL, ?)`,
        [sha256Hex("fresh-null-resource-token"), "fresh-null-resource-token-family", "client-1", "subject-1", "[\"mcp:read\"]", FUTURE, 1],
      ),
      (error: unknown) => (error as { code?: unknown }).code === "ER_BAD_NULL_ERROR",
    );
  });

  runStoreConformance("MysqlStore", make);

  test("MysqlStore: two store instances serialize matching and mismatching resource consumes", async () => {
    const wrongResourceStore = make();
    const matchingResourceStore = make();
    const rawCode = "two-store-resource-code";
    const resourceA = "https://resource-a.test/mcp";
    const resourceB = "https://resource-b.test/mcp";
    try {
      await matchingResourceStore.saveAuthCode({
        codeHash: sha256Hex(rawCode), clientId: "client-1", subject: "subject-1",
        redirectUri: "https://client.test/callback", resource: resourceA,
        scopes: ["mcp:read"], codeChallenge: "challenge", codeChallengeMethod: "S256",
        expiresAt: FUTURE,
      });
      const [wrong, matching] = await Promise.all([
        wrongResourceStore.consumeAuthCode(sha256Hex(rawCode), NOW, undefined, resourceB),
        matchingResourceStore.consumeAuthCode(sha256Hex(rawCode), NOW, undefined, resourceA),
      ]);
      assert.equal(wrong, null);
      assert.equal(matching?.resource, resourceA);
      assert.equal(await matchingResourceStore.consumeAuthCode(sha256Hex(rawCode), NOW, undefined, resourceA), null);
    } finally {
      await wrongResourceStore.close();
      await matchingResourceStore.close();
    }
  });

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
        clientId: "c", subject: "s", resource: "https://api.test/mcp", scopes: ["mcp:read"], expiresAt: FUTURE,
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

  test("MysqlStore: close() does not end a caller-owned pool (Codex P2)", async () => {
    const pool = createPool(MYSQL_URL as string);
    const store = new MysqlStore(pool, false); // caller owns the pool
    await store.close();
    try {
      // Store is closed (ops throw)...
      await assert.rejects(store.findRefreshToken(sha256Hex("x")), /Store is closed/);
      // ...but the pool is still alive: a query through it succeeds.
      const [rows] = await pool.query<RowDataPacket[]>("SELECT 1 AS ok");
      assert.equal((rows[0] as { ok: number }).ok, 1);
    } finally {
      await pool.end();
    }
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

  test("MysqlStore: migrate rejects a consent-JTI table without JTI-only uniqueness", async () => {
    await admin!.query("DROP TABLE oauth_consent_jtis");
    await admin!.query(`CREATE TABLE oauth_consent_jtis (
      jti VARCHAR(255) NOT NULL,
      expires_at VARCHAR(24) NOT NULL,
      UNIQUE KEY uq_oauth_consent_jtis_jti_expiry (jti, expires_at),
      INDEX idx_oauth_consent_jtis_expires_at (expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`);
    try {
      const [first] = await admin!.query<ResultSetHeader>(
        "INSERT IGNORE INTO oauth_consent_jtis (jti, expires_at) VALUES (?, ?)",
        ["malformed-schema-jti", FUTURE],
      );
      const [replay] = await admin!.query<ResultSetHeader>(
        "INSERT IGNORE INTO oauth_consent_jtis (jti, expires_at) VALUES (?, ?)",
        ["malformed-schema-jti", "2026-07-03T14:00:00.000Z"],
      );
      assert.equal(first.affectedRows, 1);
      assert.equal(replay.affectedRows, 1, "malformed schema admits a replay with another expiry");
      await assert.rejects(createMysqlStore(MYSQL_URL as string), /full-column JTI PRIMARY or UNIQUE index/);
    } finally {
      await admin!.query("DROP TABLE oauth_consent_jtis");
      const restore = await createMysqlStore(MYSQL_URL as string);
      await restore.close();
    }
  });

  test("MysqlStore: actual pre-resource schema migrates legacy null rows that fail closed", async () => {
    // This is the exact refresh-table shape at the parent of this change. It exercises
    // the production ALTER path, rather than merely asserting the intended ALTER text.
    await admin!.query("DROP TABLE IF EXISTS oauth_refresh_tokens");
    await admin!.query("DROP TABLE IF EXISTS oauth_refresh_token_families");
    await admin!.query(`CREATE TABLE oauth_refresh_token_families (
      family_id VARCHAR(64) NOT NULL,
      revoked_at VARCHAR(24),
      grant_generation BIGINT UNSIGNED,
      PRIMARY KEY (family_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`);
    await admin!.query(`CREATE TABLE oauth_refresh_tokens (
      token_hash VARCHAR(64) NOT NULL,
      family_id VARCHAR(64) NOT NULL,
      previous_token_hash VARCHAR(64),
      client_id VARCHAR(255) NOT NULL,
      subject VARCHAR(255) NOT NULL,
      scopes_json TEXT NOT NULL,
      expires_at VARCHAR(24) NOT NULL,
      consumed_at VARCHAR(24),
      grant_generation BIGINT UNSIGNED,
      PRIMARY KEY (token_hash),
      INDEX idx_oauth_refresh_tokens_family_id (family_id),
      INDEX idx_oauth_refresh_tokens_expires_at (expires_at),
      INDEX idx_oauth_refresh_tokens_subject_client (subject, client_id),
      CONSTRAINT fk_oauth_refresh_tokens_family FOREIGN KEY (family_id)
        REFERENCES oauth_refresh_token_families (family_id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`);
    const familyId = "legacy-resource-family";
    const tokenHash = sha256Hex("legacy-resource-token");
    await admin!.query(
      "INSERT INTO oauth_refresh_token_families (family_id, revoked_at, grant_generation) VALUES (?, NULL, ?)",
      [familyId, 1],
    );
    await admin!.query(
      `INSERT INTO oauth_refresh_tokens
       (token_hash, family_id, previous_token_hash, client_id, subject, scopes_json, expires_at, consumed_at, grant_generation)
       VALUES (?, ?, NULL, ?, ?, ?, ?, NULL, ?)`,
      [tokenHash, familyId, "client-1", "subject-1", "[\"mcp:read\"]", FUTURE, 1],
    );

    let migrated: MysqlStore | undefined;
    try {
      migrated = await createMysqlStore(MYSQL_URL as string);
      const [columns] = await admin!.query<RowDataPacket[]>(
        `SELECT TABLE_NAME, IS_NULLABLE FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE() AND COLUMN_NAME = 'resource'
           AND TABLE_NAME IN ('oauth_refresh_token_families', 'oauth_refresh_tokens')
         ORDER BY TABLE_NAME`,
      );
      assert.deepEqual(
        (columns as { TABLE_NAME: string; IS_NULLABLE: string }[]).map((column) => ({
          table: column.TABLE_NAME, nullable: column.IS_NULLABLE,
        })),
        [
          { table: "oauth_refresh_token_families", nullable: "YES" },
          { table: "oauth_refresh_tokens", nullable: "YES" },
        ],
      );
      assert.equal((await migrated.findRefreshToken(tokenHash))?.resource, null, "legacy NULL resource is projected as unbound");
      assert.equal(
        await migrated.rotateRefreshToken(
          tokenHash,
          refresh("legacy-resource-successor", familyId, tokenHash, FUTURE),
          NOW,
          undefined,
          "https://api-b.test/mcp",
        ),
        null,
        "legacy NULL resource fails closed as invalid_grant",
      );
      const [state] = await admin!.query<RowDataPacket[]>(
        `SELECT t.consumed_at, f.revoked_at
         FROM oauth_refresh_tokens t JOIN oauth_refresh_token_families f ON f.family_id = t.family_id
         WHERE t.token_hash = ?`,
        [tokenHash],
      );
      assert.deepEqual(state[0], { consumed_at: null, revoked_at: null }, "rejected legacy rotation leaves state untouched");
      assert.equal(await migrated.findRefreshToken(sha256Hex("legacy-resource-successor")), null, "no successor was inserted");
    } finally {
      try {
        await migrated?.close();
      } finally {
        await admin!.query("DROP TABLE IF EXISTS oauth_refresh_tokens");
        await admin!.query("DROP TABLE IF EXISTS oauth_refresh_token_families");
        const restore = await createMysqlStore(MYSQL_URL as string);
        await restore.close();
      }
    }
  });
}

function refresh(rawToken: string, familyId: string, previousTokenHash: string | null, expiresAt: string) {
  return {
    tokenHash: sha256Hex(rawToken), familyId, previousTokenHash,
    clientId: "client-1", subject: "subject-1", resource: "https://api.test/mcp", scopes: ["mcp:read"], expiresAt,
  };
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
