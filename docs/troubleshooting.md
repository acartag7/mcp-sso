# Troubleshooting

Operational gotchas hit while reproducing this repo's own verification steps —
kept here because they cost real time to work out and aren't obvious from
`cloudflared --help`. The live client conformance results these relate to are
in [`README.md`](../README.md#live-client-verification).

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
