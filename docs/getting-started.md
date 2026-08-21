# Get started

This tutorial gets one MCP client through a complete authorization flow. Choose the local path for one operator on one computer. Choose the identity-provider path when other users must sign in.

## Run the local tutorial

The generated server uses console pairing, listens on loopback, and stores state in SQLite. It rejects a non-loopback host, issuer, or resource before it creates persistent state.

```bash
# Keep this server on localhost.
npx mcp-sso init my-mcp-server
cd my-mcp-server
npm install
npm start
```

In another terminal, add the server to Claude Code:

```bash
claude mcp add --transport http my-bridge http://127.0.0.1:3000/mcp
```

The server prints a one-time code. Paste the code into the browser, approve the request, and call a tool from the MCP client.

> [!WARNING]
> Console output is the identity channel for this tutorial. Anyone who can read the pairing code can become the shared `console-operator` identity. Keep the process on loopback and keep its output private. The generated server is not a production template.

## Run the identity-provider tutorial

Start from an `mcp-sso` repository checkout. The `examples/fastify-sqlite/` example uses SQLite, so this path proves the identity flow but does not demonstrate a multi-replica production topology.

```bash
corepack pnpm install --frozen-lockfile
cp docs/.env.example .env
```

Before you configure an identity provider, replace all four bridge placeholders in `.env`. `OAUTH_ISSUER` is the origin that users and MCP clients can reach. `OAUTH_RESOURCE` is that deployment's protected `/mcp` URL. The two signing values must be newly generated secrets.

For a reachable HTTPS deployment, use your public origin and resource:

```dotenv
OAUTH_ISSUER=https://bridge.example.com
OAUTH_RESOURCE=https://bridge.example.com/mcp
```

For a local development flow on the same computer, use the explicit loopback profile:

```dotenv
OAUTH_ISSUER=http://127.0.0.1:3000
OAUTH_RESOURCE=http://127.0.0.1:3000/mcp
OAUTH_ALLOW_INSECURE_LOCALHOST=true
```

> [!IMPORTANT]
> Use the HTTPS profile when the identity provider or MCP client cannot reach a loopback URL. Cloudflare Access needs the HTTPS profile in practice, because Cloudflare must front the browser authorization route; the library does not enforce that pairing, so a loopback profile with Cloudflare Access boots and then fails at sign-in. `OAUTH_ALLOW_INSECURE_LOCALHOST=true` is for local development only.

Generate the consent secret and private ES256 JWK from the repository checkout:

```bash
openssl rand -hex 32
node --input-type=module -e 'import { exportJWK, generateKeyPair } from "jose"; const { privateKey } = await generateKeyPair("ES256", { extractable: true }); console.log(JSON.stringify(await exportJWK(privateKey)))'
```

Copy the first output into `OAUTH_CONSENT_SIGNING_SECRET` and the one-line JSON output into `OAUTH_SIGNING_PRIVATE_JWK`. Do not add shell syntax such as `$(...)` to `.env`; Node reads the file without shell expansion.

> [!WARNING]
> Both generated values are credentials. Do not commit `.env`, paste either value into an issue, or reuse them across deployments. Anyone with the private JWK can mint access tokens. Anyone with the consent secret can forge consent and upstream-flow state.

Now configure exactly one identity provider. The [identity-provider index](identity/README.md) links to the required values for Cloudflare Access, Microsoft Entra ID, Google, and generic OIDC. For Entra, Google, or generic OIDC, register the exact callback `${OAUTH_ISSUER}/oauth/callback` with the provider and put that same URL in `ENTRA_REDIRECT_URI`, `GOOGLE_REDIRECT_URI`, or `OIDC_REDIRECT_URI`. If the provider refuses a loopback HTTP callback, use a reachable HTTPS origin instead.

Start the example with the environment file loaded explicitly:

```bash
node --env-file=.env examples/fastify-sqlite/index.ts
```

Point an MCP client at the `/mcp` URL printed by the example. Complete the identity-provider login, approve the requested scopes, and call a tool.

Before exposing the service, follow the [gateway deployment procedure](gateway-deployment.md), choose a store for the deployment topology, configure a shared rate-limit store or a trusted edge limit for multiple replicas, and run the [live client verification procedure](live-verification.md).
