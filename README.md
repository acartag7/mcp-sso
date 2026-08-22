# mcp-sso

OAuth 2.1 for your MCP server, so nobody pastes a shared API key into a client config.

[![npm](https://img.shields.io/npm/v/mcp-sso)](https://www.npmjs.com/package/mcp-sso) [![CI](https://img.shields.io/github/actions/workflow/status/acartag7/mcp-sso/ci.yml?branch=main&label=CI)](https://github.com/acartag7/mcp-sso/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/acartag7/mcp-sso?label=openssf%20scorecard)](https://scorecard.dev/viewer/?uri=github.com/acartag7/mcp-sso) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13556/badge)](https://www.bestpractices.dev/projects/13556) [![license](https://img.shields.io/github/license/acartag7/mcp-sso)](LICENSE) [![node](https://img.shields.io/node/v/mcp-sso)](package.json) [![runtime deps](https://img.shields.io/badge/runtime%20deps-1%20(jose)-blue)](docs/dependency-ledger.md)

[Get started](docs/getting-started.md) · [Documentation](docs/README.md) · [Threat model](docs/threat-model.md) · [Conformance matrix](docs/contracts/16-spec-conformance-matrix.md) · [Verification status](docs/verification-status.md)

## The problem

A remote MCP server needs to know who is calling. The usual answer is a static API key pasted into every client configuration. One key gives every caller the same identity, never expires, and leaks in a `git add .` or a support screenshot. Revoking it means rotating it for everyone.

MCP's answer is OAuth 2.1. That leaves a gap. An MCP client must identify itself to an authorization server and obtain a token that is valid for exactly your server. Identity providers such as Microsoft Entra ID and Cloudflare Access prove who the user is, but they do not speak the MCP client-facing flow: client registration, PKCE, consent, and audience-bound tokens.

`mcp-sso` fills that gap. It is a TypeScript library in two halves:

- The authorization-server bridge accepts the client's identity (a Client ID Metadata Document, or `POST /oauth/register`), sends the user to your identity provider, shows a consent page, and mints its own access and refresh tokens for one MCP resource.
- The resource-server verifier checks the token's signature, audience, and scope on every `/mcp` request, and answers with the RFC 9728 `WWW-Authenticate` challenge when it rejects one.

Your identity provider's tokens stay between the provider and `mcp-sso`. The MCP client only ever holds a token that `mcp-sso` minted for your server.

## Install

```bash
npm install mcp-sso
```

Node 24 or later. `jose` is the only runtime dependency. Fastify, Express, Hono, `mysql2`, `ioredis`, and `@fastify/rate-limit` are optional peer dependencies: install the ones you use.

## Try it on one machine

This runs a local server that uses console pairing as the identity check. It listens on loopback and refuses a non-loopback host, issuer, or resource before it writes any state.

```bash
npx mcp-sso init my-mcp-server
cd my-mcp-server
npm install
npm start
```

In another terminal, add it to an MCP client. With Claude Code:

```bash
claude mcp add --transport http my-bridge http://127.0.0.1:3000/mcp
```

The server prints a one-time code. Paste it into the browser, approve, and call a tool.

> [!WARNING]
> Anyone who can read that code becomes the `console-operator` identity. Keep the server on loopback and its console private. This is a tutorial, not a production template. For real users, follow the [identity-provider tutorial](docs/getting-started.md#run-the-identity-provider-tutorial).

## What the flow looks like

Assume Alice connects an MCP client to `https://mcp.example/mcp`.

1. The client identifies itself with a Client ID Metadata Document (CIMD) or by calling `POST /oauth/register`.
2. `mcp-sso` sends Alice to your identity provider. The provider proves who she is.
3. Alice sees the client, the resource, and the requested scopes, and approves.
4. The client exchanges the authorization code and its PKCE verifier for tokens. The access token is valid for `https://mcp.example/mcp` and nothing else.
5. Your MCP server verifies the token's audience and required scope on every request. Refresh-token rotation detects a replayed refresh token and revokes the whole token family.

```mermaid
sequenceDiagram
    participant C as MCP client
    participant B as mcp-sso
    participant I as Identity provider
    participant S as MCP server
    C->>B: CIMD identity or POST /oauth/register
    C->>B: Authorization request with PKCE
    B->>I: Sign Alice in
    I-->>B: Verified identity
    B-->>C: Consent, then authorization code
    C->>B: Authorization code and PKCE verifier
    B-->>C: Tokens for mcp.example/mcp
    C->>S: MCP request with access token
    S->>S: Verify audience and required scope
```

[How the OAuth roles fit together](docs/explanation/oauth-roles-and-flow.md) explains each step and where a request can stop.

## Protect a route

The bridge issues tokens. The verifier is what your `/mcp` handler calls. This fragment shows the shape; the complete, tested composition is [`examples/fastify-sqlite/`](examples/fastify-sqlite/).

```ts
import { RequestAuthorizer, buildUnauthorizedChallenge, OAuthError, SystemClock, noopAudit } from "mcp-sso";

// `config` is the BridgeConfig you built with createBridgeConfig().
const authorizer = new RequestAuthorizer({ config, clock: new SystemClock(), audit: noopAudit });

app.post("/mcp", async (request, reply) => {
  let auth;
  try {
    auth = await authorizer.authorize({ authorization: request.headers.authorization, requiredScope: "mcp:read" });
  } catch (error) {
    const oe = error instanceof OAuthError ? error : new OAuthError("invalid_token", "Bearer token is invalid", 401);
    reply.header("www-authenticate", buildUnauthorizedChallenge(config, { scope: config.scopeCatalog, error: oe.code, errorDescription: oe.message }));
    return reply.code(oe.status).send({ jsonrpc: "2.0", error: { code: -32001, message: `${oe.code}: ${oe.message}` }, id: null });
  }
  // auth.subject, auth.scopes, and auth.credentialKind ("interactive" or "machine") are verified here.
});
```

`RequestAuthorizer.authorize` fails closed. A missing token, a wrong audience, an expired token, or a missing scope throws an `OAuthError` whose `status` is 401 or 403. There is no local or unauthenticated mode. The tested example reads the header through `headersFromDistinct` so that a duplicated `Authorization` header is rejected instead of silently collapsed; this fragment reads it the plain way. Start from the example when you wire your own route.

## What ships

| Area | Shipped in `mcp-sso@0.4.0` |
| --- | --- |
| Identity providers | Cloudflare Access, Microsoft Entra ID (redirect flow plus group-to-scope ceilings), Google, generic OIDC, console pairing for local use, and claims-only website login |
| Client registration | CIMD, and `POST /oauth/register` in stateless or stored mode |
| Frameworks | Fastify, Express, Hono. OAuth decisions stay in the framework-free core |
| Stores | `node:sqlite` (one host), MySQL (shared replicas), memory (one process). One shared conformance suite, also published as `mcp-sso/testing/*` |
| Grants | Authorization code with PKCE S256, refresh-token rotation with family revocation, `client_credentials` for machine clients |
| Operations | JSONL and webhook audit sinks, Redis or Valkey rate limiting, a Fastify `/mcp` rate-limit helper |
| Runtime dependency | `jose`, and nothing else |

Not shipped: a GitHub identity port and the device authorization grant are contract-only. Neither is a release claim. The [capability reference](docs/reference/capabilities.md) has the exact list and the deployment limits, including that one bridge protects one resource.

## Why you can trust it

Security products earn trust with artifacts, not adjectives. These are the ones this project publishes.

- A [STRIDE threat model](docs/threat-model.md) with 48 attacker-driven rows, the control for each, and the residual risk that remains.
- A [conformance matrix](docs/contracts/16-spec-conformance-matrix.md) against MCP Authorization `2026-07-28` and CIMD draft `-00`, row by row, with the two deviations recorded rather than hidden.
- A [release verification matrix](docs/verification.md) that binds every shipped feature to a test row, plus packed-artifact checks, plus a dated [live client matrix](docs/client-compatibility.md) against real identity providers and real MCP clients.
- A [dependency ledger](docs/dependency-ledger.md): `jose` is the only runtime dependency, every pin is recorded with its publish date, and ordinary updates wait 15 days. npm publishes run only from GitHub Actions with OIDC provenance, never from a laptop.
- Fail-closed defaults. Ambiguous configuration, a missing identity, an unknown audience, or a replayed refresh token is a hard failure, never a degraded default. Authorization codes and refresh tokens are stored as hashes and are single-use. A stolen access token is a bearer token and stays valid until `exp`, which is why it is short-lived ([threat model row 1](docs/threat-model.md#threats-attacker-driven)).

## When to use something else

Use `mcp-sso` when your identity provider authenticates users but does not expose MCP-compatible OAuth endpoints.

| Project | Choose it if |
| --- | --- |
| `mcp-sso` (this repo) | Your identity provider is not an MCP authorization server: Entra ID, Cloudflare Access, most enterprise SSO. |
| [`mcp-auth`](https://github.com/mcp-auth/js) | Your identity provider already exposes compatible OAuth 2.1 client registration and you only need resource-server wiring ([compatibility list](https://mcp-auth.dev/provider-list)). |
| [`mcp-oauth-server`](https://github.com/wille/mcp-oauth-server) | You need the device authorization grant today. `mcp-sso` ships `client_credentials`, not device flow. |
| [`workers-oauth-provider`](https://github.com/cloudflare/workers-oauth-provider) | Your MCP server is a Cloudflare Worker. |

## Documentation

The [documentation index](docs/README.md) routes by what you are trying to do. The short version:

- Learn: [Get started](docs/getting-started.md).
- Do: [configure client registration](docs/client-registration.md), [provision a machine client](docs/machine-clients.md), [put SSO in front of an API-key backend](docs/gateway-deployment.md), [ship audit events](docs/audit-deployment.md), [run live verification](docs/live-verification.md).
- Look up: [configuration](docs/configuration.md), [contracts](docs/contracts.md), [threat model](docs/threat-model.md), [verification status](docs/verification-status.md).
- Understand: [OAuth roles and flow](docs/explanation/oauth-roles-and-flow.md), [client registration choices](docs/explanation/client-registration-choices.md), [redirect URI trust](docs/explanation/redirect-uri-trust.md), [rate limits and client IP trust](docs/explanation/rate-limits-and-client-ip.md), [CIMD fetch safety](docs/explanation/cimd-fetch-safety.md).

## License

MIT
