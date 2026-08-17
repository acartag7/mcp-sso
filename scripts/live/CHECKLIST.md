# Live client verification checklist

The repeatable client×leg matrix. `scripts/live/README.md` covers the automated
probes; this covers the parts that need a real client and a human at a browser,
which is what `docs/live-verification.md` records as owner-run.

Hostnames, tenant identifiers, and test-account names are **not** in this
repository. They come from the OpenTofu stack outputs — see the README — and the
concrete substitutions live in the maintainer's project memory. Placeholders here:

| Placeholder | Meaning |
| --- | --- |
| `<CF_HOST>` | issuer origin for the `cloudflare_access` leg |
| `<ENTRA_HOST>` | issuer origin for the `entra` leg |
| `<GOOGLE_HOST>` | issuer origin for the `google` leg |
| `<ADMITTED_EMAIL>` | the single identity the Access policy admits |
| `<MEMBER>` | Entra test user in BOTH mapped groups |
| `<NOGROUPS>` / `<WRONGGROUP>` / `<OVERAGE>` | Entra deny-leg fixtures |

## Before you start

1. `aws sso login` — the only interactive login for the stacks.
2. `scripts/live/serve.sh <leg>` per leg, or run the three legs on their own
   gateway ports and one tunnel with all three hostnames.
3. All legs should run **stored DCR with loopback allowlisted**: that is the
   supported shape for CLI clients with ephemeral callback ports, and stored DCR
   requires a bounded limiter (the example supplies one).
4. Each leg needs its **own** state directory. A shared one means starting a leg
   deletes the previous leg's database, and every later store write fails as a
   generic `internal_error` that reads exactly like a product bug.
5. **A fresh private window for every row.** Entra and Cloudflare both reuse
   sessions; that has produced false failures more than once.

## Preflight — no browser needed

```sh
for h in <CF_HOST> <ENTRA_HOST> <GOOGLE_HOST>; do
  curl -s -o /dev/null -w "$h PRM=%{http_code}\n" "$h/.well-known/oauth-protected-resource"
  # a CLI client's loopback DCR registration must be accepted (201)
  curl -s -o /dev/null -w "$h DCR=%{http_code}\n" -X POST "$h/oauth/register" \
    -H 'content-type: application/json' \
    -d '{"redirect_uris":["http://localhost:1455/auth/callback"],"application_type":"native"}'
done
```

A CIMD `client_id` should reach `302` (dispatched to the IdP). A `400` or
`invalid_client` there means a document-validation or dispatch regression, and it
is worth resolving before spending a browser session.

## The matrix

| # | Client | Leg | Sign in as | Expected |
| --- | --- | --- | --- | --- |
| A1 | Claude Code | Cloudflare | `<ADMITTED_EMAIL>` | consent → tool round-trip |
| A2 | Claude Code | Entra | `<MEMBER>` | consent → tool round-trip |
| A3 | Claude Code | Google | any Google account | consent → tool round-trip |
| B1 | Codex CLI | Cloudflare | `<ADMITTED_EMAIL>` | consent → tool round-trip |
| B2 | Codex CLI | Entra | `<MEMBER>` | consent → tool round-trip |
| B3 | Codex CLI | Google | any Google account | consent → tool round-trip |
| C1 | ChatGPT connector | Cloudflare | `<ADMITTED_EMAIL>` | consent → tool round-trip |
| C2 | ChatGPT connector | Entra | `<MEMBER>` | consent → tool round-trip |
| D1 | any | Entra | `<NOGROUPS>` | `access_denied` — *Entra returned no groups for this account* |
| D2 | any | Entra | `<WRONGGROUP>` | `access_denied` — *Entra groups do not authorize this account for this resource* |
| D3 | any | Entra | `<OVERAGE>` | `access_denied` — *Entra group claims exceed the supported limit; operator configuration is required* |
| E1 | any | Cloudflare | any account that is **not** `<ADMITTED_EMAIL>` | Cloudflare's own denial page; **no** consent screen, **no** code mail, and **no audit row on our side** |
| F1–F3 | claude.ai connector | all three | as A1–A3 | consent → tool round-trip |

Client commands:

```sh
claude mcp add --transport http <name> <HOST>/mcp
codex  mcp add <name> --url <HOST>/mcp
# ChatGPT / claude.ai: add <HOST>/mcp as a custom connector
```

## Reading the results

Assert against the **audit trail**, not only the client UI. Each leg writes
`.live-state/<leg>/audit.jsonl`, and it is the authority when a client's message
is vague or absent:

```sh
python3 - <<'PY'
import json,glob,collections
for f in sorted(glob.glob('.live-state/*/audit.jsonl')):
    rows=[json.loads(l) for l in open(f) if l.strip()]
    print(f.split('/')[1], dict(collections.Counter(e.get('event') for e in rows)))
    print('  denials:', dict(collections.Counter(
        e.get('reason') for e in rows if e.get('status')=='failure' and e.get('reason'))))
PY
```

A full success leg shows `oauth.register` (or `oauth.cimd.fetch`) →
`identity.verify` → `oauth.authorize.prepare` → `oauth.upstream.callback` (redirect
legs) → `oauth.authorize.approve` → `oauth.token.authorization_code` →
`auth.request`.

Two things the trail catches that a client will not:

- **A client may swallow the denial.** ChatGPT reports the D3 overage case only
  as "connection setup was canceled" with no message, while the audit shows
  `entra_groups_overage` correctly emitted. Absence of a client-side error is not
  absence of a correct server decision.
- **E1's evidence is an absence.** The Cloudflare edge blocks before the request
  reaches the gateway, so the correct result is **no audit row at all**. Seeing
  nothing is the pass condition.

Also worth noticing: a matrix round usually exercises `oauth.token.refresh` and
sometimes `oauth.revoke` without anyone asking for them, because the clients
refresh on their own. Check for them before assuming those paths are unverified.
