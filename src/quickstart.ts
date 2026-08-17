// Quickstart secret persistence (contracts §17.8, threat-model row 23).
// Existing state is admitted read-only; missing material can be prepared in
// memory, validated as part of a complete config, then persisted exactly once.
//
// SECURITY POSTURE — fail-closed, never ephemeral at runtime:
//   - Dir 0700, secrets file 0600, exclusive/no-follow writes, managed `*` ignore.
//   - Supported POSIX reads use open(O_NOFOLLOW)+fstat+read-fd.
//   - Windows/no-O_NOFOLLOW relies on a private ACL and emits the shared warning.
//   - Any filesystem/shape/permission failure is AuthConfigError; no silent key
//     rotation or fallback after persistence is attempted.

import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { exportJWK, generateKeyPair } from "jose";
import { AuthConfigError } from "./config.ts";
import {
  assertRealDir, ensureGitignore, loadQuickstartSecrets, pathExists,
  persistQuickstartSecrets,
} from "./quickstart-fs.ts";
import type { QuickstartSecrets } from "./quickstart-shape.ts";
import { warnWindowsPermissionGap } from "./windows-permission-warning.ts";

export { assertRealDir, ensureGitignore } from "./quickstart-fs.ts";
export type { QuickstartSecrets } from "./quickstart-shape.ts";

export interface QuickstartOptions {
  /** Directory holding `secrets.json` + `.gitignore`. Default `./.mcp-sso`. */
  dir?: string;
}

export interface PreparedQuickstartSecrets {
  /** Existing admitted material or newly generated in-memory material. */
  readonly secrets: QuickstartSecrets;
  /** Persist missing material once. Existing admitted material is not rewritten. */
  persist(): Promise<void>;
}

const SECRETS_FILE = "secrets.json";

/** Prepare secrets without creating or changing quickstart state. */
export async function prepareQuickstartSecrets(
  opts: QuickstartOptions = {},
): Promise<PreparedQuickstartSecrets> {
  const dir = opts.dir ?? "./.mcp-sso";
  const secretsPath = join(dir, SECRETS_FILE);
  warnWindowsPermissionGap();

  if (await pathExists(secretsPath)) {
    const secrets = await loadQuickstartSecrets(dir, secretsPath);
    return oneShotPreparation(secrets, async () => {});
  }
  if (await pathExists(dir)) {
    await assertRealDir(dir);
    await ensureGitignore(dir, false);
  }
  const secrets = await generateQuickstartSecrets();
  return oneShotPreparation(
    secrets,
    () => persistQuickstartSecrets(dir, secretsPath, secrets),
  );
}

/** Immediate-persistence convenience wrapper retained for existing consumers. */
export async function loadOrCreateQuickstartSecrets(
  opts: QuickstartOptions = {},
): Promise<QuickstartSecrets> {
  const prepared = await prepareQuickstartSecrets(opts);
  await prepared.persist();
  return prepared.secrets;
}

async function generateQuickstartSecrets(): Promise<QuickstartSecrets> {
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  return {
    signingPrivateJwk: await exportJWK(privateKey),
    consentSigningSecret: randomBytes(48).toString("base64url"),
  };
}

function oneShotPreparation(
  secrets: QuickstartSecrets,
  persist: () => Promise<void>,
): PreparedQuickstartSecrets {
  let used = false;
  return Object.freeze({
    secrets,
    async persist(): Promise<void> {
      if (used) {
        throw new AuthConfigError("quickstart: prepared secrets persist() may be called only once");
      }
      used = true;
      await persist();
    },
  });
}
