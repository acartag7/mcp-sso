# Cloudflare Access identity (`createCloudflareAccessIdentity`)

Front the bridge's browser sign-in with **Cloudflare Access** (Zero Trust). Access
sits in front of the `/oauth/authorize` leg and injects a signed
`Cf-Access-Jwt-Assertion` header; mcp-sso verifies that assertion and mints its
**own** audience-bound token. The Cloudflare token never passes through to the MCP
client.

```ts
import { createCloudflareAccessIdentity } from "mcp-sso/identity/cloudflare-access";

const identity = createCloudflareAccessIdentity({
  audience: process.env.CF_ACCESS_AUDIENCE!,   // the app's hex AUD tag — NOT the hostname
  certsUrl: process.env.CF_ACCESS_CERTS_URL!,  // https://<team>.cloudflareaccess.com/cdn-cgi/access/certs
  issuer:   process.env.CF_ACCESS_ISSUER!,     // https://<team>.cloudflareaccess.com  (no trailing slash)
  emailAllowlist: [],                          // optional defense-in-depth — see "Who is allowed" below
});
```

Live-verified across five clients (Claude Code CLI, Codex CLI, claude.ai, ChatGPT,
official MCP SDK) on 2026-07-07. In every run the bridge-token `sub` is the
Cloudflare **opaque `sub` UUID**, not the email.

## How it works

1. The MCP client opens `/oauth/authorize` in a browser.
2. Cloudflare Access requires the user to sign in against your Zero Trust policy,
   then injects a `Cf-Access-Jwt-Assertion` JWT on that request.
3. mcp-sso verifies the assertion: **RS256 only**, exact `aud` match, exact `iss`
   match, keys fetched from `certsUrl` (JWKS, cached 5 min), 60 s clock tolerance.
4. The subject is keyed on the Cloudflare `sub` (opaque per-account UUID), and the
   bridge mints its own ES256 audience-bound access token.

## Cloudflare setup

1. In **Cloudflare Zero Trust → Access → Applications**, create an application
   **path-scoped to `/oauth/authorize*`** — **not** the whole hostname. Access
   injects `Cf-Access-Jwt-Assertion` only on the browser authorize leg.
2. Leave the server-side paths **public** (no Access app): `/.well-known/*`,
   `/oauth/register`, `/oauth/token`, `/oauth/revoke`, and `/mcp` (which the
   bridge's own token protects). A whole-hostname app gates these too, and the
   client's cookie-less server calls get a `302 → login` instead of reaching the
   verifier — the flow cannot complete.
3. Copy the application's **AUD tag** (hex) → `CF_ACCESS_AUDIENCE`. This is the
   app tag, **not** the hostname.
4. Set `CF_ACCESS_ISSUER` = `https://<team>.cloudflareaccess.com` with **no
   trailing slash** (the `iss` claim is matched exactly).
5. Set `CF_ACCESS_CERTS_URL` = `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`.
6. Configure the Access **policy** (allowed emails / identities). This is the
   primary "who is allowed" gate — see below.
7. Expose the origin via a **named** `cloudflared` tunnel with an explicit
   `ingress:` config. Anonymous quick tunnels (`cloudflared tunnel --url`) 404 at
   the edge and are unreliable for OAuth callbacks — see
   [`troubleshooting.md`](../troubleshooting.md).

## Configuration

| Env var | Maps to | Required | Notes |
|---|---|---|---|
| `CF_ACCESS_AUDIENCE` | `audience` | **required** — its presence selects the CF branch | The app's hex AUD tag, not the hostname. A blank value fails the boot. |
| `CF_ACCESS_CERTS_URL` | `certsUrl` | **required** | The JWKS URL. Must start with literal `https://`. |
| `CF_ACCESS_ISSUER` | `issuer` | **required** | The team URL, no trailing slash. Must start with `https://`. |
| `CF_ACCESS_EMAIL_ALLOWLIST` | `emailAllowlist` | optional | Comma-separated. Empty ⇒ delegated to the Access policy. |

The bridge's own signing material (`OAUTH_ISSUER`, `OAUTH_RESOURCE`,
`OAUTH_CONSENT_SIGNING_SECRET`, `OAUTH_SIGNING_PRIVATE_JWK`) is required and
independent of Cloudflare — the Cloudflare branch does not use the quickstart
secret helper.

## Who is allowed

Two gates, and only the first is mandatory:

1. **The Cloudflare Access policy is the primary gate.** It decides who can sign
   in at all; a denied user is stopped at the Cloudflare edge and never reaches
   the gateway (no gateway audit row is written — the block is upstream).
2. **`emailAllowlist` is optional defense-in-depth only.** When non-empty, the
   verified email must be a member (case-insensitive). When empty or unset, the
   "who" decision is delegated **entirely** to the Access policy — it is not a
   standalone gate.

## Fail-closed behavior

Two conditions fail the **boot** (a misconfiguration, not a degraded default):

- Empty `audience` → the factory throws. (An empty audience would let `jose`
  enforce audience *presence* but skip the value match — accepting any Cloudflare
  JWT regardless of app.)
- `certsUrl` or `issuer` not starting with literal `https://` → the factory
  throws (`http` trust roots allow key substitution).

At verify time, every failure returns `{ ok: false, reason }` with a fixed reason
code — never a bypass:

| Condition | Reason code |
|---|---|
| Missing / non-string / empty assertion | `access_jwt_missing` |
| No `exp` claim | `access_jwt_missing_expiry` |
| No `email` claim, or email not in `emailAllowlist` | `access_jwt_email_not_allowed` |
| Expired token | `access_jwt_expired` |
| Wrong `aud` or `iss` | `access_jwt_bad_claim` |
| Signature alg not RS256 | `access_jwt_unsupported_alg` |
| No matching key in the Cloudflare JWKS | `access_jwt_unknown_key` |
| Other `jose` error (incl. JWKS fetch/timeout) | `access_jwt_invalid` |
| Non-`jose` / unknown error | `access_jwt_verify_failed` |

## Gotchas

- **Path-scope the Access app to `/oauth/authorize*`.** A whole-hostname app also
  gates `/mcp` and `/oauth/token`, so the client's server-side requests get
  `302 → login` and the flow hangs. (Learned the hard way on 2026-07-07.)
- **`CF_ACCESS_ISSUER` has no trailing slash.** `jose` matches `iss` exactly; a
  trailing slash yields `access_jwt_bad_claim`.
- **`CF_ACCESS_AUDIENCE` is the hex AUD tag, not the hostname.** A wrong value is
  an `aud` mismatch; an *empty* value is worse (see fail-closed) — the factory
  throws on empty to prevent it.
- **Subject is the Cloudflare `sub` (opaque UUID), not the email.** Cloudflare puts
  a stable per-account UUID in `sub` and the email in a separate claim. Do not key
  authorization on the email.
- **Use a named tunnel.** Anonymous quick tunnels 404 at the edge. If you run other
  named tunnels on the same host, pass `--credentials-file` explicitly — a stray
  `~/.cloudflared/config.yml` can silently override which credentials are used.
- **The Cloudflare branch binds `0.0.0.0`** (network deployment), not loopback —
  the callback must be reachable by the edge. `HOST` overrides.

## Verify

- Direct `POST /mcp` with no token → `401` + `WWW-Authenticate` carrying the
  RFC 9728 `resource_metadata` pointer.
- `GET /oauth/authorize` with no `Cf-Access-Jwt-Assertion` → `access_jwt_missing`.
- A user outside the Access policy → stopped at the Cloudflare sign-in ("That
  account does not have access"); no OTP issued, request never reaches the gateway.
- An admitted email removed from `CF_ACCESS_EMAIL_ALLOWLIST` (but still in the
  policy) → `access_jwt_email_not_allowed` (audit-confirmed).

See [`live-verification.md`](../live-verification.md) for the full provider ×
client matrix and [`authorization.md`](../authorization.md) for how the Access
policy and the mcp-sso allowlist relate.
