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

> [!WARNING] Console output is the identity channel for this tutorial. Anyone who can read the pairing code can become the shared `console-operator` identity. Keep the process on loopback and keep its output private. The generated server is not a production template.

## Run the identity-provider tutorial

Start from an `mcp-sso` repository checkout. The `examples/fastify-sqlite/` example uses SQLite, so this path proves the identity flow but does not demonstrate a multi-replica production topology.

```bash
corepack pnpm install --frozen-lockfile
cp docs/.env.example.env
```

Edit `.env` and configure one identity provider. The [identity-provider index](identity/README.md) links to the required values for Cloudflare Access, Microsoft Entra ID, Google, and generic OIDC.

Start the example with the environment file loaded explicitly:

```bash
node --env-file=.env examples/fastify-sqlite/index.ts
```

Point an MCP client at the `/mcp` URL printed by the example. Complete the identity-provider login, approve the requested scopes, and call a tool.

Before exposing the service, follow the [gateway deployment procedure](gateway-deployment.md), choose a store for the deployment topology, configure a shared rate-limit store or a trusted edge limit for multiple replicas, and run the [live client verification procedure](live-verification.md).
