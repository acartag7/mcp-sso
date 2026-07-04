// Standalone entry point: `node examples/fastify-sqlite/index.ts`.
// Production: CF Access sits in front and injects Cf-Access-Jwt-Assertion, verified
// by the /identity/cloudflare-access port. For local dev without CF Access, set
// DEV_STUB_SUBJECT to a fixed subject (the identity port accepts any non-empty
// assertion). See README for the full quickstart.

import { createCloudflareAccessIdentity } from "../../src/identity/cloudflare-access.ts";
import { buildApp, configFromEnv } from "./app.ts";

async function main(): Promise<void> {
  const config = configFromEnv();
  const identity = process.env.DEV_STUB_SUBJECT
    ? stubIdentity(process.env.DEV_STUB_SUBJECT)
    : createCloudflareAccessIdentity({
        audience: mustEnv("CF_ACCESS_AUDIENCE"),
        certsUrl: mustEnv("CF_ACCESS_CERTS_URL"),
        issuer: mustEnv("CF_ACCESS_ISSUER"),
        emailAllowlist: listEnv("CF_ACCESS_EMAIL_ALLOWLIST"),
      });
  const { app } = await buildApp({ config, identity, sqliteFile: process.env.OAUTH_SQLITE_FILE });
  const port = Number(process.env.PORT ?? 3000);
  await app.listen({ port, host: "0.0.0.0" });
  console.error(`mcp-sso example listening on :${port}`);
  console.error(`  issuer=${config.issuer}  resource=${config.resource}`);
}

// DEV ONLY (DEV_STUB_SUBJECT): bypasses identity entirely so MCP clients — which do
// NOT send a Cf-Access-Jwt-Assertion header — can complete the OAuth dance locally
// without Cloudflare Access. Every authorize resolves to `subject`. Never use in
// production; production uses the real CF Access identity port (header-injected by CF).
function stubIdentity(subject: string) {
  return {
    async verify(_input: unknown) {
      return { ok: true as const, identity: { subject } };
    },
  };
}
function mustEnv(k: string): string { const v = process.env[k]; if (!v) throw new Error(`Missing env: ${k}`); return v; }
function listEnv(k: string): string[] | undefined { const v = process.env[k]; return v ? v.split(",").map((s) => s.trim()).filter(Boolean) : undefined; }

main().catch((error) => { console.error(error); process.exit(1); });
