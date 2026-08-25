# Run live client verification

Use this procedure to verify a release candidate with a real MCP client and a real identity provider. Read the [harness reference](reference/live-harness.md) for the checks each probe can establish.

## Run an automated provider probe

Start from a clean checkout at the release candidate commit.

Run the named provider leg through `scripts/live/run.sh`. The exact arguments and private infrastructure variables are in `scripts/live/README.md`.

Confirm that the probe prints the runtime commit and reports every required check as passed. A run with `MCP_SSO_ALLOW_DIRTY=true` is not release evidence.

Record the date, runtime commit, provider, probe result, and any limitation in [Verification status](verification-status.md). Move the previous result to the [verification archive](archive/verification-history.md) when the new run supersedes it.

## Run the rehearsal

Run every automated probe at once and get one receipt:

```bash
REDIS_URL=redis://127.0.0.1:6379 node scripts/live/rehearsal.mjs
```

Read the summary. A `PASS` row passed every check the probe reports. A `BLOCKED` row names what to arm before the run can count, for example `cloudflare_access_login_required`. A `FAIL` row names the failed check. The receipt at `.live-state/receipt.json` is evidence only when the command exited 0, which requires every row to pass on a clean tree.

To run it from CI instead:

```bash
gh workflow run live.yml
gh run watch
```

The `live` workflow runs the same command on a GitHub-hosted runner with the provider values fetched from the private secret store through the workflow's OIDC role. It also runs nightly from `main`, and on every push to a `rehearsal/*` branch after the owner approves that run in the `live-branch` environment. Download the `rehearsal-receipt-*` artifact for the receipt. `scripts/live/README.md` describes the credential path and the row rules.

Record a passing rehearsal the same way as a probe run: date, runtime commit, and the row results, in [Verification status](verification-status.md).

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

Run the wrong-tenant, subject-allowlist, group-overage, no-group, and no-mapped-group cases from `scripts/live/CHECKLIST.md`. Record the audit reason for each denial. The harness feeds the group mapping through `ENTRA_GROUP_AUTHORIZATION_JSON` as `{"mapping": …}` with no `baseScopes`; that empty `baseScopes` is why the no-group fixture produces `entra_no_groups` rather than a default grant, so record the mapping shape with the result. The guest or B2B rejection case is not in `CHECKLIST.md`; the checklist at the top of `src/identity/entra.ts` enumerates it, and [Verification status](verification-status.md) lists it as a remaining live gap until someone drives it.

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
