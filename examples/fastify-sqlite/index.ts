// Standalone entry: `node examples/fastify-sqlite/index.ts`.
//
// The wiring lives in buildExample() (in app.ts) so it is integration-tested
// (test/integration-example.test.ts) without app.listen(). This entry just adds
// the listen step. Two paths, selected by env — NOT one routed into the other:
//
//  - PRODUCTION: env signing material + Cloudflare Access, Entra redirect,
//    Google, or a generic OIDC identity port.
//  - ZERO-SETUP (console pairing): otherwise -> quickstart secrets (§17.8) +
//    console pairing (§17.5); an operator pastes a one-time code from the
//    console. Replaces the old DEV_STUB_SUBJECT dev bypass.

import { buildExample, defaultListenHost } from "./app.ts";

async function main(): Promise<void> {
  const { app, config } = await buildExample(process.env);
  const port = Number(process.env.PORT ?? 3000);
  const host = process.env.HOST ?? defaultListenHost(process.env);
  await app.listen({ port, host });
  const mode = process.env.ENTRA_TENANT_ID !== undefined ? "Entra redirect" : process.env.CF_ACCESS_AUDIENCE !== undefined ? "Cloudflare Access" : process.env.GOOGLE_CLIENT_ID !== undefined ? "Google" : process.env.OIDC_ISSUER !== undefined ? "generic OIDC" : "console pairing";
  console.error(`mcp-sso example listening on ${host}:${port}  (identity: ${mode})`);
  console.error(`  issuer=${config.issuer}  resource=${config.resource}`);
}

main().catch((error) => { console.error(error); process.exit(1); });
