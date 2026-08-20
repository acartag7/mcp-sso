# Live client verification checklist

The repeatable client × leg matrix. `scripts/live/README.md` covers the automated
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

1. `aws sso login` (and `az login` for the Entra stack) — the only interactive
   logins for the stacks.
2. `scripts/live/serve.sh cloudflare_access entra google` — one invocation
   serves every leg on its own gateway port behind one tunnel ingress; it
   prints the three URLs and the client commands. Starting legs in separate
   invocations does not work: a second connector with a different ingress
   would receive part of the traffic.
3. All legs run **stored DCR with loopback allowlisted** (the `run.sh` default):
   that is the supported shape for CLI clients with ephemeral callback ports,
   and stored DCR requires a bounded limiter (the example supplies one).
   For the #278 mode differential, set `MCP_SSO_DCR_MODE=stateless` while
   retaining loopback; the example now supplies the same bounded limiter and
   the preflight admits that composition. `probe-e2e.mjs` consumes the selected
   mode and proves the unknown-opaque-client differential; its machine-client
   rows run only under stored mode because that feature requires stored DCR.
4. Each leg gets its **own** state directory, `.live-state/<leg>`, from
   `run.sh`; at start the last run's state for that leg is rotated to
   `.live-state/<leg>.previous` when it holds an `audit.jsonl` (a failed start
   without one is discarded instead), so the last round's `audit.jsonl` is
   still there to compare against — even after a failed start and a retry. A shared
   directory would let one leg delete another's database, and every later
   store write would then fail as a generic `internal_error` that reads exactly
   like a product bug.
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

When a CIMD client (Claude Code, the ChatGPT and claude.ai connectors) connects,
its first `/oauth/authorize` should be a `302` to the identity provider on the
redirect legs, or the consent page on the Cloudflare leg. A `400` /
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
| D4 | any | Entra, served with `MCP_SSO_ENTRA_ALLOWED_TENANT_IDS` set to a tenant that is not yours (`run.sh` maps it onto `ENTRA_ALLOWED_TENANT_IDS`) | `<MEMBER>` | `access_denied`, audit reason `entra_bad_tid` |
| D5 | any | Entra, served with `MCP_SSO_ENTRA_SUBJECT_ALLOWLIST` set to a subject that is not the signer (`run.sh` maps it onto `ENTRA_SUBJECT_ALLOWLIST`) | `<MEMBER>` | `access_denied`, audit reason `entra_subject_not_allowed` |
| E1 | any | Cloudflare | any account that is **not** `<ADMITTED_EMAIL>` | Cloudflare's own denial page; **no** consent screen, **no** code mail, and the gateway audit count is unchanged from immediately before the attempt |
| F1–F3 | claude.ai connector | all three | as A1–A3 | consent → tool round-trip |

D4 and D5 change server configuration, so each needs its own `serve.sh entra`
invocation with the marked variable exported; they cannot ride the normal
matrix run. Read both outcomes from the audit trail like every other deny row.

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
node --input-type=module -e '
import { readFileSync } from "node:fs";
for (const leg of ["cloudflare_access", "entra", "google"]) {
  let rows = [];
  try { rows = readFileSync(`.live-state/${leg}/audit.jsonl`, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { continue; }
  const count = (key, filter = () => true) => Object.fromEntries([...rows.filter(filter).reduce((m, e) => m.set(e[key], (m.get(e[key]) ?? 0) + 1), new Map())]);
  console.log(leg, count("event"));
  console.log("  denials:", count("reason", (e) => e.status === "failure" && e.reason));
}'
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
- **E1's evidence is an unchanged audit count.** Pause every other matrix row,
  then record the current count immediately before the E1 attempt:

  ```sh
  E1_AUDIT=.live-state/cloudflare_access/audit.jsonl
  audit_count() { if [ -f "$1" ]; then wc -l < "$1"; else printf '0\n'; fi; }
  E1_BEFORE=$(audit_count "$E1_AUDIT")
  ```

  After Cloudflare shows its denial page, record the count again and require no
  new gateway event:

  ```sh
  E1_AFTER=$(audit_count "$E1_AUDIT")
  test "$E1_AFTER" -eq "$E1_BEFORE" || {
    printf 'FAIL: E1 added gateway audit rows (%s -> %s)\n' "$E1_BEFORE" "$E1_AFTER" >&2
    exit 1
  }
  ```

  The file may already contain earlier successful rows; absolute emptiness is
  not the claim. The invariant is that the E1 attempt adds nothing because the
  Cloudflare edge blocks it before the request reaches the gateway.

Also worth noticing: a matrix round usually exercises `oauth.token.refresh` and
sometimes `oauth.revoke` without anyone asking for them, because the clients
refresh on their own. Check for them before assuming those paths are unverified.
