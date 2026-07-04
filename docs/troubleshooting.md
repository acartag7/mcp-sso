# Troubleshooting

Operational gotchas hit while reproducing this repo's own verification steps,
kept here because they cost real time to work out and aren't obvious from
`cloudflared --help`. See [`README.md`](../README.md#live-client-verification)
for the live client conformance results these relate to.

## Cloudflare tunnels for the claude.ai custom-connector check

**Anonymous quick tunnels (`cloudflared tunnel --url ...`, no account) were
unreliable and are not what was ultimately used.** Three independent quick
tunnels each registered cleanly with Cloudflare's edge (zero errors in the
connector log), and the same local server answered correctly over plain
`http://localhost` throughout. But every public request through each
tunnel's hostname returned a `404` straight from Cloudflare's edge, never
reaching the app. That combination — a healthy backend, a healthy connector
log, and an edge-level 404 — is consistent with the anonymous quick tunnel's
single-connector, no-redundancy design; `cloudflared`'s own CLI disclaims "no
uptime guarantee" for these on every startup. This was not a bug in the
OAuth/DCR code path, which the Claude Code check verified successfully with
the identical server.

**What actually worked: a named (account-backed) tunnel on a real domain,
with an explicit `ingress:` hostname rule in a config file** — not the
ad-hoc `cloudflared tunnel run --url <url> <tunnel>` shortcut. The ad-hoc
form also produced clean edge-level `404`s in this session, even with a
named tunnel and a brand-new DNS record. Switching to a config file with an
explicit `hostname:`/`service:` ingress rule (plus the required catch-all
`http_status:404`) fixed the problem immediately. If you're setting this up
yourself, prefer the config-file form from the start:

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

**A sharp edge if you already run other named tunnels on the same
machine:** `cloudflared`'s default `~/.cloudflared/config.yml` can silently
override which credentials get used, even when you pass a *different*
tunnel ID on the command line. This produces a confusing auth-retry loop
(`control stream encountered a failure while serving`) that looks like a
network problem, not a wrong-credentials one. Pass `--credentials-file`
explicitly (or a full `--config`) to be sure which tunnel you're actually
authenticating as — for example:

```bash
cloudflared tunnel --credentials-file /path/to/<your-tunnel-id>.json \
  run --url http://localhost:3000 <your-tunnel-id>
```
