// Place the tunnel connector credentials fetch-bundle.mjs wrote where
// serve.sh expects them: $HOME/.cloudflared/<TunnelID>.json, owner-only. An
// absent bundle file is reported and is not an error here; the rows that need
// a served leg report BLOCKED with that reason.
import { closeSync, constants, existsSync, mkdirSync, openSync, realpathSync, writeSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { readPrivateJson } from "./bundle-support.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function installTunnelCredentials({ bundleDir, home }) {
  const source = join(bundleDir, "tunnel-credentials.json");
  if (!existsSync(source)) return { installed: false };
  const credentials = readPrivateJson(source);
  if (typeof credentials.TunnelID !== "string" || !UUID.test(credentials.TunnelID)) throw new Error("tunnel credentials name no tunnel");
  const dir = join(home, ".cloudflared");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const target = join(dir, `${credentials.TunnelID}.json`);
  const fd = openSync(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    writeSync(fd, `${JSON.stringify(credentials)}\n`);
  } finally {
    closeSync(fd);
  }
  return { installed: true, tunnelId: credentials.TunnelID };
}

const invokedAsMain = () => {
  try {
    return realpathSync(process.argv[1] ?? "") === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
};

if (invokedAsMain()) {
  const bundleDir = process.env.MCP_SSO_BUNDLE_DIR;
  const home = process.env.HOME;
  if (!bundleDir || !home) {
    process.stderr.write("install-tunnel: MCP_SSO_BUNDLE_DIR and HOME are required\n");
    process.exitCode = 1;
  } else {
    try {
      const result = installTunnelCredentials({ bundleDir, home });
      process.stdout.write(result.installed ? "tunnel credentials installed\n" : "tunnel credentials absent\n");
    } catch {
      process.stderr.write("install-tunnel: tunnel credentials could not be installed\n");
      process.exitCode = 1;
    }
  }
}
