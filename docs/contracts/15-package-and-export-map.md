# 15. Package & export map

Single package `mcp-sso`. Root/core runtime dep: **`jose` only**. Framework adapters,
identity ports, the MySQL/Redis adapters, and the Fastify protected-resource
rate-limit helper are optional `peerDependencies`
(the consumer installs only the ones it uses); `node:sqlite` is built-in (no
dep). No postinstall, no bundler. Dev runs on **Node 24 native TS** (`.ts`
imports, no build step); the published artifact is plain-`tsc` ESM + `.d.ts`.
The optional Hono peer range is **`>=4.12.34 <5`**: `4.12.34` is the minimum
version that fixes the published advisories recorded in the dependency ledger
and whose `bodyLimit` behavior this adapter verifies; the next major is
excluded until separately tested.

Dev/test does **not** consume the package via its own exports: Node 24 native TS
imports source files directly (e.g. `../src/index.ts`), so there is no build step
during development. The exports map is **consumer-facing and always points at
`./dist`**; a `prepublishOnly` hook runs `tsc` → `./dist` (ESM + `.d.ts`) before
the npm artifact is cut, so the published package is never broken by `.ts` paths:

```
"exports": {
  ".":                          { "types": "./dist/index.d.ts",                    "default": "./dist/index.js" },
  "./store/memory":             { "types": "./dist/store/memory.d.ts",             "default": "./dist/store/memory.js" },
  "./store/sqlite":             { "types": "./dist/store/sqlite.d.ts",             "default": "./dist/store/sqlite.js" },
  "./store/mysql":              { "types": "./dist/store/mysql.d.ts",              "default": "./dist/store/mysql.js" },
  "./rate-limit/redis":         { "types": "./dist/rate-limit/redis.d.ts",         "default": "./dist/rate-limit/redis.js" },
  "./fastify":                  { "types": "./dist/adapters/fastify.d.ts",         "default": "./dist/adapters/fastify.js" },
  "./fastify/protected-resource-rate-limit": { "types": "./dist/adapters/fastify-protected-resource-rate-limit.d.ts", "default": "./dist/adapters/fastify-protected-resource-rate-limit.js" },
  "./express":                  { "types": "./dist/adapters/express.d.ts",         "default": "./dist/adapters/express.js" },
  "./hono":                     { "types": "./dist/adapters/hono.d.ts",            "default": "./dist/adapters/hono.js" },
  "./identity/cloudflare-access": { "types": "./dist/identity/cloudflare-access.d.ts", "default": "./dist/identity/cloudflare-access.js" },
  "./identity/entra":             { "types": "./dist/identity/entra.d.ts",             "default": "./dist/identity/entra.js" },
  "./identity/console-pairing":   { "types": "./dist/identity/console-pairing.d.ts",   "default": "./dist/identity/console-pairing.js" },
  "./identity/generic-oidc":      { "types": "./dist/identity/generic-oidc.d.ts",      "default": "./dist/identity/generic-oidc.js" },
  "./identity/google":            { "types": "./dist/identity/google.d.ts",            "default": "./dist/identity/google.js" }
}
```

The v0.2 reference audit sinks — `JsonlFileAudit`, `WebhookAudit`,
`combineAudit` (§17.7) — are exported from the **root `.` entry**, not a subpath:
they carry no runtime dependency (`node:fs` is built-in; `fetch` is native to Node
24), so there is no optional peer dep to isolate and a single
`import { JsonlFileAudit } from "mcp-sso"` is the intended consumer shape.
Quickstart secret persistence (`loadOrCreateQuickstartSecrets`, §17.8) is
root-exported for the same reason (it depends only on `jose` + node builtins).
The `./store/sqlite` subpath exports both `openSqliteStore(path)` and the
`SqliteStore` constructor. Only `openSqliteStore` provides the §12.4 persistent
filesystem-admission guarantee; `new SqliteStore(callerDatabaseSync)` deliberately
leaves filesystem provenance, permissions, and directory trust with the caller.
The console-pairing identity (§17.5) ships as the `./identity/console-pairing`
subpath, parallel to the other identity ports; its framework-free authorize
helpers (`handlePairingAuthorize`, `renderPairingPage`) are root-exported so a
consumer can mount the pairing surface alongside the `skipAuthorize` adapter
option. A Hono consumer also imports `honoOAuthBodyLimit` from `mcp-sso/hono`
and mounts it before parsing the caller-owned pairing POST; the four built-in
Hono OAuth POST routes apply it automatically. The in-repo example imports the
framework-free helpers from source; package consumers import them from the root
entry. The framework-free `Bridge` class — the central object
a consumer constructs and passes to a framework adapter — is root-exported
(`import { Bridge, RequestAuthorizer } from "mcp-sso"`). `isMcpPath(requestUrl)` —
the `/mcp` Streamable-HTTP path check a consumer's `onRequest` Origin-gate hook uses
to scope DNS-rebinding protection to MCP paths (it robustly handles the
absolute-form request-target `POST http://host/mcp`, which a raw `=== "/mcp"` misses;
run before the bearer check, for every method — see `examples/fastify-sqlite`) — is
root-exported (`import { isMcpPath } from "mcp-sso"`) so adopters of the recommended
Origin-gate pattern need not import an internal adapter path. Deployer guidance for the audit sinks lives in
[`docs/audit-deployment.md`](../audit-deployment.md).

`assertRegistrationRedirectPolicy(value, applicationType)` is also exported
from the root entry. Custom persisted `ClientStore` implementations use this
existing §10.2 write-time check before saving native or web registrations,
without importing the internal `src/redirect.ts` module.

The two runnable Fastify examples apply that `/mcp` gate to Node's raw header
occurrence metadata before the allowlist decision: `headersFromDistinct` keeps
multiple `Origin` fields distinct and `readHeader` marks arrays,
case-duplicated fields, and comma-coalesced values ambiguous. An absent
`Origin` proceeds; exactly one comma-free string may be matched against
`allowedOrigins` or the issuer origin; ambiguity is a 403 before body parsing or
bearer authorization. The generated `server.ts` performs the same
exactly-one-occurrence decision inline from
`request.raw.headersDistinct.origin`. These are reference composition-root
controls, not automatic `/mcp` middleware in the framework adapters.

Those same three composition roots mount protected routes with the real
`@fastify/rate-limit` plugin via the isolated
`mcp-sso/fastify/protected-resource-rate-limit` subpath. The helper validates a
closed options object (`max` integer 1..10,000; `timeWindowMs` integer
1,000..3,600,000; defaults 60 / 60,000), registers `onRequest` admission with
`global: false` and `skipOnError: false`, and returns the snapshotted policy the
caller places in each protected route's `config.rateLimit`. The examples group
each method-specific route under the fixed `mcp-protected-resource` id; the
finite in-memory default is per process and per method route. A supplied custom store is wrapped so
synchronous throws, callback errors, duplicate callbacks, and malformed
counter results become one fixed 503 error before the route handler. A valid
increment result has a positive safe-integer `current` (the current request is
already counted) and a non-negative safe-integer `ttl`; zero, negative,
fractional, unsafe, wrongly typed, missing, or accessor-throwing values reject,
never a
fail-open request or a raw backend-error leak. A normal budget denial is 429.
The two runnable example factories take an optional `trustedProxies` array and
the production env compositions parse `MCP_SSO_TRUSTED_PROXIES` into that same
shape. Absence is explicit Fastify `trustProxy: false`: an untrusted socket
cannot make `X-Forwarded-For` select another bucket. A present value is a
snapshotted allowlist of 1..32 unique concrete IP or CIDR strings (each at most
64 characters; CIDR prefixes are 1..32 for IPv4 and 1..128 for IPv6). Blank,
wrongly typed, sparse/accessor-throwing, duplicate, malformed, or over-limit
configuration is a boot error before state-directory, SQLite, listener, or
protected-handler effects. Boolean trust-all, numeric hop-count, custom
function, and proxy-addr named-range forms are deliberately not exposed. The
validated array is passed to Fastify's `trustProxy`, so Fastify/proxy-addr walks
the chain from the socket and stops at the first untrusted address; it does not
trust a client-supplied forwarded address merely because the header exists.
The helper is a separate subpath so importing `mcp-sso/fastify` for OAuth route
wiring does not force the plugin on existing consumers; consumers of the new
subpath install its optional peer. This does not change the root package's
`jose`-only runtime graph.

**Consumer-facing example helpers (DX):** five symbols the in-repo example leans on
to implement the recommended patterns are root-exported, so a package consumer
replicating those patterns imports them from `mcp-sso` instead of reimplementing
them (and re-opening the footguns they centralize): the normalized request/response
shapes `NormRequest` and `NormResponse` (co-exported with `isMcpPath` — the types
the already-exported `handlePairingAuthorize` and `createUpstreamRedirectFlow`
take/return, so a consumer mounting the pairing surface or an upstream callback can
type-check them); the state-dir security controls `ensureStateDir` (the ATOMIC
helper — `mkdir 0o700` + `assertRealDir` + the managed `*` `.gitignore`, which a
consumer on the Cloudflare/Entra/gateway path — managing its own state dir — applies
for the SAME bar the example does; it derives whether the `.gitignore` may be created
from `mkdir`'s return, so a caller cannot drop a `*` ignore into a pre-existing tree)
and `assertRealDir` (the fs-trust bar alone — rejects a symlink or
group/other-accessible state dir so another local user cannot replace `auth.db`),
co-exported with `loadOrCreateQuickstartSecrets` (the raw `ensureGitignore(dir,
canCreate)` stays internal — its caller-asserted boolean is a footgun); and `assertCallbackPath` (the upstream callback-PATH
validator — a pure check that the pathname starts with `/`, is plain (no
query/fragment/whitespace/control or dot-segments), normalizes to itself under the
issuer origin, and is not a reserved OAuth route or the resource path), co-exported
with `createUpstreamRedirectFlow`. It validates the PATH only — the
`identity.redirectUri === issuerOrigin + callbackPath` equality is enforced
separately, at mount, by `createUpstreamRedirectFlow` (and mirrored by the example's
`assertUpstreamConfigBeforeState`); a consumer doing early-fail boot validation
pairs `assertCallbackPath` with its own redirectUri equality check. All five are
dep-free (node builtins / pure string logic), so root-exporting them does not widen
the `jose`-only runtime posture.

**Init CLI (`npx mcp-sso init`):** the package ships a `bin` — `mcp-sso init [target]`
(default `.`) — that scaffolds a working zero-setup MCP server a stranger can boot with
`npm install && npm start` and pair with via a console-printed one-time code (then
`claude mcp add --transport http my-bridge http://127.0.0.1:3000/mcp`). It generates:
`package.json` (`"type": "module"`, `"start": "node server.ts"`, exact-pinned deps —
`mcp-sso` at the running version + `fastify` + `@fastify/rate-limit` +
`@modelcontextprotocol/sdk` at the
versions mcp-sso is tested against, recorded in `docs/dependency-ledger.md`; Node
`>=24`, native TS, no build step); `server.ts` (the composition root, built from the
root exports + the `./fastify`, `./store/sqlite`, `./identity/console-pairing` subpaths
— quickstart secrets + console pairing + sqlite + the `/mcp` Streamable-HTTP Origin
gate + mandatory fail-closed protected-resource rate limiting + a protected `/mcp`,
zero-setup loopback by default). The generated localhost-only server fixes
Fastify `trustProxy: false` and has no forwarded-IP env escape; production proxy
trust belongs to the env-driven examples above. The same SQLite instance
implements both OAuth state and stored user DCR, so a generated client registration
survives a server restart; the shipped-entrypoint integration test restarts between
registration and authorization before completing pairing, token exchange, and an
official-SDK tool call. The generated composition rejects a non-loopback `HOST` before
creating keys or opening SQLite: stored DCR is intentionally confined to the starter's
single-operator localhost envelope, where an unauthenticated network caller cannot grow
the persistent client table. Internet-facing deployments use the production composition
with a real rate limiter and identity provider. `.gitignore`
(`node_modules/` + the `.mcp-sso/` state dir); `.npmrc` (`ignore-scripts=true` —
dependency lifecycle scripts disabled unless the operator vets one, the project's
supply-chain posture); and `README.md` (the run steps +
pointers to `docs/gateway-deployment.md` / `docs/live-verification.md` for production
identity providers). The init binary itself is **dep-free** (node builtins only) — it
adds nothing to the `jose`-only runtime. It refuses to overwrite an existing file or
follow a symlink (atomic `O_NOFOLLOW|O_EXCL|O_CREAT`; it refuses to write through any
path component an attacker could swap — a symlinked target/ancestor, a missing segment
raced in before `mkdir`, or an existing real dir NOT owned by you — when its *real*
(symlink-followed) parent is group/other-writable; sticky + victim-owned paths, e.g.
`mkdtemp` under `/tmp`, and system symlinks like macOS `/tmp`→`/private/tmp`, are allowed
so a normal temp-dir scaffold isn't a false positive). **Filesystem-trust boundary (inherent
Node limit):** the check covers the common write-redirection paths, but a fully race-free
secure `mkdir` needs `mkdirat`/`openat` — resolve-and-create relative to a held directory
fd — which Node's `fs` does not expose. A residual TOCTOU therefore remains in exotic cases
(a trusted symlink whose *destination's real ancestry* is attacker-swappable, on a
multi-user host where an attacker has write access to the user's own path); the realistic
cases are refused, and this residual is inherent to Node, not a logic gap. **Dependency posture:** the generated
`package.json` pins the top-level deps **exactly** (the versions mcp-sso is tested
against); the scaffold cannot ship a curated transitive lockfile (that needs network
resolution at scaffold time), so the operator's `npm install` creates
`package-lock.json` (to commit) — locking the transitive graph at first install. The
server is the zero-setup pairing path; a real IdP (Cloudflare Access / Entra / Google /
OIDC) is a documented graduation (see `examples/fastify-sqlite`), not a scaffolded
default — the done-bar is the pairing round-trip, not a production deploy. **Config-
validation ordering (benign residual):** the generated server pre-validates the
`OAUTH_ISSUER`/`OAUTH_RESOURCE` URLs before the state-creating helper, but the deeper
config validation (`createBridgeConfig` — scheme, scope shapes) runs *after*
`loadOrCreateQuickstartSecrets`, so a malformed env value leaves a `secrets.json`. That
file is owner-only (`0600` in a `0700` gitignored dir), holds secrets generated
independently of the rejected config (so they are valid, not bad), and is reused verbatim
on the next (fixed) boot — no leak, no exposed/bad/committed state; full pre-validation
would need a library secret-free `validateConfig` (deferred).

**Supply-chain settings:** `packageManager` is the single pnpm version pin;
`pnpm/action-setup` reads it and workflow steps MUST NOT override it with a
second `with.version` value. `pnpm-workspace.yaml` sets
`minimumReleaseAge: 21600` (**minutes** = 15 days — the install-time floor and
the `docs/dependency-ledger.md` ordinary-pin curation rule are the same
standard). A published GHSA/CVE fix for a direct npm pin may use only the
ledger's verified per-package exception; it does not lower the global floor;
the dependency-policy gate requires that value to equal the machine-readable
`minimumAgeDays * 1440`. CI actions are pinned by SHA; npm publish uses
`--provenance` from GitHub Actions OIDC only (no local publishes). Every pin is
recorded in `docs/dependency-ledger.md` with version + publish date.

**Dependency-policy gate:** the ledger contains one machine-readable record
for every direct npm package and GitHub Action pin.
`check:deps` compares those records with `package.json` and every workflow
`uses:` entry: missing, extra, unpinned, or mismatched entries reject. Each
third-party Action record binds its immutable commit SHA to the recorded
release tag and publication date and must be at least 15 days old; the
first-party `acartag7/engineering-os` exception remains explicit and
SHA-pinned. CI runs the same gate, including the upstream tag/date check, so a
manual workflow edit cannot bypass the quarantine or leave the prose ledger
describing different code. The quarantine age is the upstream release's
`published_at`, while immutable SHA pins prevent a later tag move from changing
executed code; the remote check rejects a moved tag until a deliberate local
pin and ledger change is reviewed. Git author/committer timestamps are not used
as independent age evidence because the commit creator controls them.

**Release-authority boundary:** `.github/workflows/publish.yml` has four
separate jobs. A read-only build job checks out with persisted credentials
disabled, validates a tag as exactly `v${package.version}` when the event is a
tag push, runs the source gates, builds once, and uploads the packed tarball
plus its SHA-256 digest. `workflow_dispatch` has no real-publish input and can
only invoke a no-OIDC dry-run job against that artifact. The real publish job
runs only for a matching tag push, receives `id-token: write` but no checkout,
install, repository scripts, or `contents: write`, verifies the artifact
digest, and publishes that tarball with provenance and scripts disabled. A
separate post-publish job receives `contents: write` but no OIDC permission and
creates the GitHub Release. Before any real tag, the `publish` GitHub
Environment MUST provide the external second gate: required reviewer approval,
no admin bypass, and a custom deployment tag policy restricted to `v*.*.*`.
