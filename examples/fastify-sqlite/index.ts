// Standalone entry: `node examples/fastify-sqlite/index.ts`.
//
// The wiring lives in buildExample() (in app.ts) so it is integration-tested
// (test/integration-example.test.ts) without app.listen(). This entry just adds
// the listen step. Two paths, selected by env — NOT one routed into the other:
//
//  - PRODUCTION (Cloudflare Access): CF_ACCESS_AUDIENCE set -> env signing
//    material + the Cloudflare Access identity port (header-injected by CF).
//  - ZERO-SETUP (console pairing): otherwise -> quickstart secrets (§17.8) +
//    console pairing (§17.5); an operator pastes a one-time code from the
//    console. Replaces the old DEV_STUB_SUBJECT dev bypass.

import { buildExample } from "./app.ts";

async function main(): Promise<void> {
  const { app, config } = await buildExample(process.env);
  const port = Number(process.env.PORT ?? 3000);
  await app.listen({ port, host: "0.0.0.0" });
  const mode = process.env.CF_ACCESS_AUDIENCE ? "Cloudflare Access" : "console pairing";
  console.error(`mcp-sso example listening on :${port}  (identity: ${mode})`);
  console.error(`  issuer=${config.issuer}  resource=${config.resource}`);
}

main().catch((error) => { console.error(error); process.exit(1); });
