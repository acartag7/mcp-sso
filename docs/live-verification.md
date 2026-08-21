# Run live client verification

Use this procedure to verify a release candidate with a real MCP client and a real identity provider. Read the [harness reference](reference/live-harness.md) for the checks each probe can establish.

## Run an automated provider probe

Start from a clean checkout at the release candidate commit.

Run the named provider leg through `scripts/live/run.sh`. The exact arguments and private infrastructure variables are in `scripts/live/README.md`.

Confirm that the probe prints the runtime commit and reports every required check as passed. A run with `MCP_SSO_ALLOW_DIRTY=true` is not release evidence.

Record the date, runtime commit, provider, probe result, and any limitation in [Verification status](verification-status.md). Move the previous result to the [verification archive](archive/verification-history.md) when the new run supersedes it.

## Serve provider legs for MCP clients

Use `scripts/live/serve.sh` to start the configured legs and the named Cloudflare tunnel. Do not use `cloudflared tunnel --url` for release evidence.

Wait for `serve.sh` to report readiness for each leg. The script stops if a child process dies or if another process takes a configured port.

Run the matching rows in `scripts/live/CHECKLIST.md` from the MCP client. For each row, complete authorization, consent, a protected tool call, and the negative case named by the checklist.

Record the client version, identity provider, registration method, DCR mode, runtime commit, result, and limitation in the [client compatibility reference](client-compatibility.md).

## Verify Cloudflare Access

Create a Cloudflare Access application for `/oauth/authorize*`. Keep `/.well-known/*`, `POST /oauth/register`, `POST /oauth/token`, `POST /oauth/revoke`, and `/mcp` outside the Access application. The MCP client calls those endpoints without a Cloudflare browser session.

Set `CF_ACCESS_ISSUER` to `https://<team>.cloudflareaccess.com` without a trailing slash. Set `CF_ACCESS_AUDIENCE` to the application's Access AUD tag, not its hostname.

Start the Fastify and SQLite example:

```bash
OAUTH_ISSUER=https://<your-host> \
OAUTH_RESOURCE=https://<your-host>/mcp \
OAUTH_CONSENT_SIGNING_SECRET=$(openssl rand -hex 32) \
OAUTH_SIGNING_PRIVATE_JWK='{"kty":"EC","crv":"P-256",...}' \
CF_ACCESS_AUDIENCE=<your-app-aud> \
CF_ACCESS_CERTS_URL=https://<team>.cloudflareaccess.com/cdn-cgi/access/certs \
CF_ACCESS_ISSUER=https://<team>.cloudflareaccess.com \
CF_ACCESS_EMAIL_ALLOWLIST=you@example.com \
node examples/fastify-sqlite/index.ts
```

Expose the server through the named tunnel:

```bash
cloudflared tunnel route dns <tunnel-id> <your-host>
cloudflared tunnel --config tunnel-config.yml run
```

Point the MCP client at `https://<your-host>/mcp`. Complete the Access login, approve the `mcp-sso` consent request, and call a tool.

Repeat the request with an account outside the Access policy or with a wrong-audience assertion. The request must stop before consent.

## Verify Microsoft Entra ID

Register an Entra application. Set `ENTRA_REDIRECT_URI` to `https://<your-host>/<callback-path>`. The callback path must match the path mounted by `createUpstreamRedirectFlow`.

Start either runnable example with `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`, and `ENTRA_REDIRECT_URI`.

Point the MCP client at `https://<your-host>/mcp`. Complete the Entra login, approve the `mcp-sso` consent request, and call a tool.

Run the wrong-tenant, subject-allowlist, group-overage, no-group, and no-mapped-group cases from `scripts/live/CHECKLIST.md`. Record the audit reason for each denial.

## Verify ChatGPT

Serve either the Cloudflare Access or Entra leg on a public HTTPS origin. Do not use console pairing on a public URL.

Add a ChatGPT custom connector for `https://<your-host>/mcp`. Complete authorization and call a tool.

Record whether ChatGPT used CIMD or `POST /oauth/register`. Also record the identity provider and the DCR mode.

## Verify the API-key gateway

Start the gateway with a generated backend credential:

```bash
BACKEND_API_KEY=$(openssl rand -hex 32) node examples/api-key-gateway/index.ts
```

Add it to Claude Code:

```bash
claude mcp add --transport http gw http://localhost:3000/mcp
```

Complete console pairing and consent. Call the `status` tool and confirm that the response contains the backend marker.

Search the client output, responses, and `./.mcp-sso/audit.jsonl` for the backend credential. The credential must not appear.

For a multi-user run, configure Cloudflare Access, Entra, Google, or generic OIDC instead of console pairing.
