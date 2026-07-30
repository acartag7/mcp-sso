// Entrypoint for the two-resource example. Boot fails loudly on missing config:
// every required value is read before any listener binds, so a misconfigured
// deployment never serves a partially-configured surface.

import { buildApp, buildConfig, buildIdentity, RESOURCE_PATHS } from "./app.ts";

const config = buildConfig(process.env);
const identity = buildIdentity(process.env);
const app = await buildApp({ config, identity, sqliteFile: process.env.SQLITE_FILE });

const port = Number(process.env.PORT ?? 8787);
const host = process.env.HOST ?? "127.0.0.1";
await app.listen({ port, host });

const origin = new URL(config.issuer).origin;
console.log(`mcp-sso multi-resource example listening on ${host}:${port}`);
for (const path of RESOURCE_PATHS) {
  console.log(`  resource ${origin}${path}`);
  console.log(`    PRM   ${origin}/.well-known/oauth-protected-resource${path}`);
}
