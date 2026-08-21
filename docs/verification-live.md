# Tier 3 evidence reference

Tier 3 records compatibility with real identity providers and MCP clients. Tier 1 remains the required security evidence.

## Evidence by area

| Area | Live target | Evidence |
| --- | --- | --- |
| Captatum dogfood | Deployed Captatum with mcp-sso | Date, mcp-sso commit or package, Captatum commit, client rows, and caveats |
| Entra groups | Real tenant with mapped groups | Date, sanitized tenant shape, and results for mapped, unmapped, and overage cases |
| Google identity | Real Google OAuth app | Stable subject, allowlist results, and hosted-domain behavior when configured |
| GitHub identity | Real GitHub OAuth app | Numeric subject, verified primary email behavior, and allowlist rejection |
| Device flow | Real terminal and browser | Code request, approval, denial, polling results, and protected `/mcp` call |
| CIMD | Owner-controlled HTTPS metadata URL | Document URL, cache behavior, client result, and exact runtime commit |
| MCP clients | curl, official MCP SDK, Claude Code, claude.ai, and ChatGPT when available | Date, client version when visible, and a caveat for every partial row |

README compatibility claims require a matching Tier 3 receipt.

## Required setup

| Area | Required setup |
| --- | --- |
| Common | Node 24, corepack and pnpm, a clean tree, the current package commit, an HTTPS issuer URL, a registered redirect URL, an audit log location, and a private browser session |
| Release smoke | A temporary directory outside the repository, the packed tarball, npm access when testing the published package, and a command transcript |
| Captatum dogfood | Access to the Captatum deployment repository, deploy credentials, the target environment, a production-like database path, a Cloudflare Access test identity, a rollback plan, and the MCP clients under test |
| Entra groups | An Azure tenant, an app registration, a client secret, a redirect URI, test users, mapped and unmapped group GUIDs, a scope map, and an overage test plan |
| Google identity | A Google Cloud project, an OAuth consent screen, a client ID and secret, a redirect URI, a test account, allowlist values, and an optional Workspace account for `hd` testing |
| GitHub identity | A GitHub OAuth App, a client ID and secret, a callback URL, a test account with a verified primary email, a numeric user ID, and a mutable-login case when enabled |
| Device flow | A terminal client, a browser session, an identity source, short expiry settings, and a transcript of approval, denial, and polling |
| CIMD | An owner-controlled HTTPS metadata document, a controlled redirect URI, cache-control variants, and a deployment that uses the guarded fetcher |
| MCP clients | The curl command, official MCP SDK version, Claude Code version, claude.ai test window, ChatGPT connector setup when available, and a caveat field for each client |

Tier 1 contains the CIMD SSRF rejection tests. Tier 3 does not replace them.

## Required fields for each result

Each live result contains:

1. The date and timezone.
2. The mcp-sso commit or npm version.
3. The provider or client name.
4. The provider or client version when visible.
5. The sanitized configuration shape.
6. A result for each named scenario.
7. Every skipped, simulated, or partial step.

A CIMD flow starts authorization with an HTTPS `client_id`. It does not call `POST /oauth/register`. A DCR flow calls `POST /oauth/register`.

Do not commit credentials, tenant identifiers, private URLs, or raw evidence that contains secrets.
