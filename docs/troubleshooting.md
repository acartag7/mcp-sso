# Troubleshooting

Operational gotchas hit while reproducing this repo's own verification steps —
kept here because they cost real time to work out and aren't obvious from
`cloudflared --help`. The live client conformance results these relate to are
in [`live-verification.md`](live-verification.md).

Start from the symptom:

| Symptom | Go to |
| --- | --- |
| SQLite refuses to boot or migrate | [SQLite persistent-state boot rejection](#sqlite-persistent-state-boot-rejection) |
| DCR returns `invalid_redirect_uri` for an ephemeral localhost callback | [Native CLI registration](#native-cli-registration-needs-stored-dcr) |
| Entra returns `access_denied` after successful sign-in | [Entra group authorization denials](#entra-group-authorization-denials) |
| A client rejects the OAuth callback when `iss` is present | [Codex CLI callback regression](#codex-cli-01441-callback-regression) |
| A tunnel connects but the public URL returns an edge 404 | [Anonymous quick tunnels](#anonymous-quick-tunnels-404-at-the-edge) or [named-tunnel ingress](#named-tunnels-need-a-config-file-ingress-rule) |
| A named tunnel loops on authentication | [Default config credential selection](#default-configyml-can-hijack-your-credentials) |

For OAuth wire errors, configuration failures, and live-flow probes, also use
the [configuration reference](configuration.md) and
[live-verification checklist](live-verification.md).

## SQLite persistent-state boot rejection

`openSqliteStore` accepts exact `:memory:` or an ordinary filesystem path. A
`file:` URI is rejected deliberately; replace it with the underlying path and
remove URI query options. The parent directory must already exist and be
private. On POSIX, verify its provenance, then use owner-only permissions (for
example `chmod 700 <state-directory>`); an existing database must be the
service user's regular, single-link file with exact mode `0600` (for example
`chmod 600 <database>` only after verifying that it is the intended file).

The store never chmods, deletes, truncates, or migrates a rejected existing
object. A symlink, hard link, FIFO, socket, device, directory, unsafe ancestor,
or attacker-writable immediate directory must be replaced with a real private
directory and regular owner-only file. On Windows, apply an equivalent private
directory ACL. The library does not inspect that ACL and prints one shared,
fixed warning on the first call in each Windows Node worker/runtime instance to
`loadOrCreateQuickstartSecrets`, standalone `assertRealDir`, `ensureStateDir`,
or persistent `openSqliteStore`; exact `:memory:` does not consume it. The
warning does not claim POSIX permission enforcement there.

## Native CLI registration needs stored DCR

Codex CLI registers an ephemeral native callback such as
`http://localhost:1455/auth/callback`. An exact allowlist URI cannot predict its
runtime port and path, while the required portless `http://localhost` origin is
deliberately rejected in the stateless production composition. For
`examples/fastify-sqlite`, use its SQLite-backed stored mode and list both
loopback hosts explicitly:

```dotenv
OAUTH_DCR_MODE=stored
OAUTH_REDIRECT_ALLOWLIST=https://your-app.example/callback,http://localhost,http://127.0.0.1
```

Do not work around the boot guard or add a placeholder HTTPS callback. Stored
DCR preserves the broad admission needed at registration, then binds later
authorization to the concrete native callback saved for that client. The
API-key gateway example remains stateless unless its composition root supplies
a shared `ClientStore` and a bounded core `RateLimitPort`. The Fastify/SQLite
example supplies a finite process-local registration port automatically in
stored mode; multi-replica deployments use a shared port such as
`mcp-sso/rate-limit/redis`.

## Entra group authorization denials

After Entra has authenticated the user, the redirect may contain
`error=access_denied` and one of these fixed, library-authored descriptions:

| Exact `error_description` | Cause | Remedy |
| --- | --- | --- |
| `Entra returned no groups for this account` | The verified token contained no usable group IDs. The user may belong to zero groups, or the app registration may not emit group claims. | Assign the user to a mapped group and verify the app manifest's `groupMembershipClaims` setting. If every authenticated user should receive baseline scopes, configure `baseScopes` deliberately. |
| `Entra groups do not authorize this account for this resource` | Entra returned groups, but none of their object IDs matched `groupAuthorization.mapping`, and no `baseScopes` applied. | Add the intended group object ID to `mapping`, assign the user to an already-mapped group, or configure deliberate `baseScopes`. |
| `Entra group claims exceed the supported limit; operator configuration is required` | Entra emitted a group-overage marker instead of the group list, so mcp-sso failed closed rather than dereferencing `_claim_sources`. | Set `groupMembershipClaims` to `ApplicationGroup` for direct assignments (requires Entra P1), or reduce the user's group sprawl below the claim limit. |

Other identity failures retain `upstream identity verification failed`. Use the
closed reason code on the `identity.verify` audit event for the operator-only
detail; raw IdP `error` and `error_description` values are never copied to the
client or logs.

## Codex CLI 0.144.1 callback regression

On 2026-07-28 the installed Codex CLI 0.144.1 failed the OAuth callback when
the authorization response included the RFC 9207 `iss` parameter. Historical
Codex CLI verification remains valid, but current-version compatibility is
pending an upstream resolution and retest. mcp-sso continues to emit `iss`
through `redirectWithCode`; do not disable the protocol binding as a client
workaround.

## Cloudflare tunnels (claude.ai custom-connector check)

### Anonymous quick tunnels 404 at the edge

`cloudflared tunnel --url ...` with no account was unreliable, and is not what
was ultimately used. Three independent quick tunnels each registered cleanly
with Cloudflare's edge (zero errors in the connector log), and the same local
server answered correctly over plain `http://localhost` throughout. But every
public request through each tunnel's hostname returned a **404 straight from
Cloudflare's edge**, never reaching the app.

A healthy backend, a healthy connector log, and an edge-level 404 together fit
the anonymous quick tunnel's single-connector, no-redundancy design.
`cloudflared`'s own CLI disclaims "no uptime guarantee" for these on every
startup. This was **not** a bug in the OAuth/DCR code path — the Claude Code
check verified successfully against the identical server.

### Named tunnels need a config-file ingress rule

What actually worked: a named (account-backed) tunnel on a real domain, with an
explicit `ingress:` hostname rule in a config file — not the ad-hoc shortcut:

```text
cloudflared tunnel run --url <url> <tunnel>   # clean edge-level 404, even named + fresh DNS
```

The ad-hoc form produced clean edge-level 404s in this session even with a named
tunnel and a brand-new DNS record. Switching to a config file with an explicit
`hostname:` / `service:` rule (plus the required catch-all `http_status:404`)
fixed it immediately. Prefer this form from the start:

```yaml
tunnel: <your-tunnel-id>
credentials-file: /path/to/<your-tunnel-id>.json
ingress:
  - hostname: mcp-sso-verify.yourdomain.com
    service: http://localhost:3000
  - service: http_status:404
```

```bash
cloudflared tunnel route dns <your-tunnel-id> mcp-sso-verify.yourdomain.com
cloudflared tunnel --config tunnel-config.yml run
```

### Default config.yml can hijack your credentials

If you already run other named tunnels on the same machine, `cloudflared`'s
default `~/.cloudflared/config.yml` can silently override which credentials get
used — even when you pass a *different* tunnel ID on the command line. The
symptom is a confusing auth-retry loop (`control stream encountered a failure
while serving`) that looks like a network problem, not a wrong-credentials one.

Pass `--credentials-file` explicitly, or a full `--config`, to be sure which
tunnel you're authenticating as:

```bash
cloudflared tunnel --credentials-file /path/to/<your-tunnel-id>.json \
  run --url http://localhost:3000 <your-tunnel-id>
```
