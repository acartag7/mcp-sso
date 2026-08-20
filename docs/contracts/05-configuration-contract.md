# 5. Configuration contract

`BridgeConfig` is the complete security configuration for one bridge. The
library checks it when the bridge starts. Missing, malformed, ambiguous, or
insecure values stop startup with `AuthConfigError`; they do not silently turn
off authentication or another security gate. Local development still uses the
same authenticated OAuth flow as an internet-facing deployment.

```ts
interface BridgeConfig {
  // --- identities (both REQUIRED, validated) ---
  issuer: string;            // AS issuer URL, e.g. "https://auth.example.com"
  resource: string;          // RS resource URL, e.g. "https://api.example.com/mcp"

  // --- signing material (REQUIRED, validated for shape + strength) ---
  consentSigningSecret: string;   // >=32 chars; HS256 for consent tokens
  signingPrivateJwk: JWK;         // EC P-256 (crv "P-256") private key with d,x,y
  signingKeyId?: string;          // optional; else derived from the JWK kid

  // --- redirect policy (stateless-DCR backstop; see §10) ---
  // Every entry MUST satisfy the §10.0 redirect-entry grammar (canonical origin
  // or exact-URI form). Enforced at boot by createBridgeConfig (§5): the array
  // is snapshotted once, validated, frozen, and published as the same copy.
  // An EMPTY array is valid under the default mode — only the hosted-client
  // defaults remain enabled. Loopback redirects require an explicit entry here.
  redirectAllowlist: string[];    // ADDS to the hosted defaults under "extend"
                                  // (the default); under "replace" it IS the whole list

  // How the array above composes with the §10.1 built-in hosted-client origins.
  // Omitted => "extend" (the published default: built-ins PLUS the entries).
  // "replace" trusts ONLY the entries above, dropping https://claude.ai and
  // https://chatgpt.com — for OPAQUE/DCR client ids, the only ids that read
  // this allowlist. A CIMD client is matched against its fetched document
  // instead and is unaffected by the mode (§10.1 scope limit), so refusing the
  // hosted clients entirely also needs cimd.enabled off or a deployer CIMD host
  // policy. Any other value is a
  // boot failure — a typo must never fall back to trusting the built-ins.
  // "replace" with an EMPTY redirectAllowlist is a boot failure: no redirect_uri
  // could ever be accepted, so it is a misconfiguration, not a deny-all posture.
  redirectAllowlistMode?: "extend" | "replace";

  // --- scope contract (see §11); REQUIRED, fail-closed ---
  scopeCatalog: string[];         // the complete set of scopes this resource honors
  defaultScopes: string[];        // granted when a request omits scope; MUST be ⊆ catalog
  scopeHierarchy?: {              // omitted => exact membership only
    resource: string;             // MUST equal this BridgeConfig.resource byte-for-byte
    implications: Array<{
      granted: string;            // a broader granted scope
      implies: string[];          // directly implied narrower scopes
    }>;
  };

  // --- CSRF/Origin policy for the consent approve step (see §9) ---
  // Every entry is an exact canonical browser origin (scheme://host[:port]).
  // Opaque `null` and URL spellings carrying any non-origin component reject
  // at boot. Runnable defaults derive originOf(issuer), never copy its raw URL.
  allowedOrigins: string[];       // same-origin issuer + any explicitly allowed origins

  // --- DCR mode (fix #4; see §9) ---
  dcr:
    | { mode: "stateless" }
    | { mode: "stored"; store: ClientStore };

  // --- local-dev escape hatch (see boot validation below) ---
  dev?: { allowInsecureLocalhost: boolean };

  // --- machine-client grant (opt-in; see §17.2) ---
  // enabled:true requires stored DCR so machine clients have a ClientStore.
  clientCredentials?: { enabled: boolean };

  // --- CIMD (opt-in; Client ID Metadata Documents; see §17.1 + §17.1.5) ---
  cimd?: {
    enabled: true;
    // No `fetcher` knob (§17.1.6 decision 5): the core constructs the branded
    // guarded fetcher from these caps + allowLoopback derived SOLELY from
    // dev.allowInsecureLocalhost. Tests inject only below-guard cimdTransport/
    // cimdResolver deps (never a whole GuardedFetcher).
    maxDocumentBytes?: number;    // integer [1024, 65536], default 5120 (§17.1.5 rule 21)
    fetchTimeoutMs?: number;      // integer [1000, 30000], default 5000
    cacheTtlCapSeconds?: number;  // integer [60, 86400], default 3600
    maxInFlight?: number;         // integer [1, 64], default 8 (global in-flight cap)
    maxWaitersPerFetch?: number;  // integer [1, 4096], default 256 (followers parked on ONE fetch; §17.1.6 dec 7)
  };

  // --- TTLs (seconds); each MUST be a positive integer ---
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  consentTokenTtlSeconds: number;
  authorizationCodeTtlSeconds: number;
}
```

**Boot validation (all throw `AuthConfigError`, never warn):**

- The input admits **only** the `BridgeConfig` fields enumerated above — no
  other own property (string- or symbol-keyed). Any extra key is a boot
  `AuthConfigError` **naming the offending key**. The frozen `bridge.config`
  object is the thing passed to every adapter and consent renderer, so a value a
  JS/cast-TS caller parked on the input — e.g. a backend API key, or a typo like
  `issuers` — would otherwise ship on that public object. Park secrets in your
  own closure; do not put them in the `createBridgeConfig` input.
- `issuer` and `resource` are absolute `https://` URLs (the bridge does not run
  over plain http in production); every other scheme is rejected at boot. Their
  **origins** are computed once and reused. Each raw spelling must also
  **byte-equal its own WHATWG serialization**: `createBridgeConfig` rejects any
  string `new URL(value).href` would rewrite — an embedded CR/LF/TAB the parser
  silently strips (the raw value is emitted verbatim into the RFC 7617 `realm`
  challenge and the AS metadata `issuer`), an uppercase or percent-encoded
  host, a query WHATWG moves behind the root path — with an `AuthConfigError`
  naming the canonical form, exactly as §10.0 requires for redirect entries
  and this section requires for `allowedOrigins`. The one permitted deviation
  is the root slash WHATWG appends to an origin-form value
  (`https://auth.example.com`). The spelling the deployer wrote is stored and
  emitted **verbatim, never silently normalized** — it is byte-copied into JWT
  `iss` claims, so a normalized copy would issue tokens under an issuer
  nobody configured (owner decision 2026-08-19).
  **Local-dev escape hatch:** `dev.allowInsecureLocalhost` permits `http://`
  `issuer`/`resource` **only on loopback** (`localhost`/`127.0.0.1`/`[::1]`); it is
  rejected at boot if either origin is not loopback and it emits a loud warning.
  This exists for the Phase 4 local example (Claude Code expects `http://localhost`);
  it can never weaken a real (non-loopback) deployment. Deployers who want zero http
  anywhere can use a tunnel (cloudflared / mkcert) instead — no flag required.
- `consentSigningSecret.trim().length >= 32`.
- `signingPrivateJwk` parses to an EC P-256 key with `d`, `x`, `y` present. (jose
  rejects zero-length keys; we validate shape explicitly so a misconfigured boot
  fails closed independent of jose upgrades.)
- `scopeCatalog`, `defaultScopes`, `allowedOrigins`, and `redirectAllowlist` are
  arrays of strings. A non-array or non-string entry is an `AuthConfigError` at
  boot; a bare string is not treated as a one-element list. Every configuration
  array, including `signingPrivateJwk.key_ops`, is capped at 4096 entries before
  iteration so a hostile runtime `length` cannot make boot unbounded.
- `scopeCatalog` and `defaultScopes` are additionally bounded scope lists:
  **at most 128** RFC 6749 `scope-token` entries, each at most **256 UTF-8
  bytes** (and therefore at most 32,895 UTF-8 bytes when space-joined).
  `defaultScopes ⊆ scopeCatalog` and `scopeCatalog` is non-empty. An empty
  catalog means the resource honors no scopes and every authorize fails closed —
  the deployer MUST declare scopes explicitly. These boot limits ensure a
  server-generated consent token always fits the approval-form transport bound.
- An optional `scopeHierarchy` is one implication graph for the exact configured
  `resource`; the repeated resource binding MUST equal `BridgeConfig.resource`
  byte-for-byte. The graph has at most 128 `granted` rows and 4,096 direct
  edges. Every row has exactly the string key `granted` and array key `implies`;
  each scope is a member of `scopeCatalog`. Empty graphs are accepted and mean
  exact membership. Empty `implies` rows, duplicate `granted` rows, duplicate
  targets within a row, self-references, cycles, unknown scopes, extra string
  keys, symbol keys, malformed containers, and over-bound graphs are boot
  `AuthConfigError`s. The validated graph is snapshotted and deeply frozen.
  `BridgeConfig.resource` remains singular; this explicit binding makes the
  policy shape ready to become one graph per resource without claiming that a
  multi-resource bridge ships today.
- Every TTL is a positive integer.
- `dcr.mode` is `"stateless"` or `"stored"`; stored mode requires a `ClientStore`.
- `redirectAllowlistMode`, when present, is exactly `"extend"` or `"replace"`;
  any other value — including a near-miss such as `"Replace"` or `""` — is an
  `AuthConfigError` at boot rather than a silent fall back to `"extend"`.
  `"replace"` additionally requires at least one `redirectAllowlist` entry.
  Every shipped zero-setup composition root computes the redirect-entry list,
  validates every entry with the same §10.0 parser, and applies both mode checks
  **before** `loadOrCreateQuickstartSecrets`; a rejected entry or mode therefore
  creates no state directory, ignore file, signing material, or listener.
  `createBridgeConfig` repeats the authoritative checks after secrets are loaded.
- `redirectAllowlist` is an array, and **every entry satisfies the §10.0
  redirect-entry grammar**. `createBridgeConfig` snapshots the array once,
  validates that copy, and publishes the same frozen copy — origin form or canonical exact-URI form, `https`/
  `http` only, no wildcard, userinfo, query, fragment, whitespace, control
  character, backslash, or malformed percent-escape. Each rule is checked on the
  RAW entry as well as any parsed field (§10.0 explains why: WHATWG
  normalization erases the syntax the decision depends on). An empty array is
  valid **only under omitted/`"extend"` mode**; with `"replace"` it is a boot
  failure, per the mode rule above (no built-ins remain, so no redirect_uri
  could ever be accepted). The error **names the offending entry** and, for a non-canonical one,
  shows its canonical form — a deployer with several origins configured must not
  have to bisect.
- `allowedOrigins` is an array of exact canonical WHATWG origin serializations:
  `http://host[:port]` or `https://host[:port]`, with no trailing slash, path,
  query, fragment, userinfo, wildcard, whitespace, control character,
  backslash, or non-canonical spelling. The opaque browser origin string
  `"null"` is rejected explicitly. Each entry is capped at 2,048 UTF-8 bytes
  before URL parsing. HTTP origins remain an explicit deployer choice; this
  grammar does not silently broaden them from an insecure issuer. An empty
  array is valid because the exact `originOf(issuer)` is always admitted by the
  request-time gate. Runnable example and generated-starter defaults use that
  derived issuer origin rather than copying the raw issuer URL, which may carry
  a path or trailing slash and therefore is not an Origin value. Their
  `OAUTH_ALLOWED_ORIGINS` parser preserves every comma-separated raw spelling —
  it never trims whitespace or drops an empty member before this grammar runs.
  The one explicit exception is a wholly empty environment value, which maps to
  the supported empty array rather than one empty entry.
  `validateAllowedOrigins(value)` exposes this exact array snapshot + grammar
  check for composition roots that must reject env-derived origin policy before
  signing material or other state exists. It returns the same frozen string
  shape that `createBridgeConfig` publishes and throws `AuthConfigError` for
  every malformed container or entry; it does not perform request matching.

**Publication (what boot approves is what requests read).**
`createBridgeConfig` publishes frozen snapshots of every caller-provided
container it validates: `signingPrivateJwk`, `redirectAllowlist`,
`scopeCatalog`, `defaultScopes`, `allowedOrigins`, `dcr`, `dev`,
`clientCredentials`, `cimd`, and every nested `scopeHierarchy` container. The
published containers are never the
caller's objects or arrays, so later caller mutation cannot change the validated
configuration. Copies use explicit member allowlists and single reads. The
`dcr` wrapper is copied and frozen, but a stored-mode wrapper retains the exact
`ClientStore` object as a live port; the store implementation itself is neither
cloned nor frozen.

A config object is constructed via `createBridgeConfig(input)` (validates +
freezes). The frozen object is the only thing passed to use-cases.

**Bridge composition boot guard.** Stored DCR is admitted only when the bridge
receives a callable, contractually bounded `RateLimitPort` that bounds
`register:<ip>` admission. An absent limiter and the exported `noopRateLimit`
singleton both fail boot in stored mode because each anonymous registration is a
durable write. This rule applies to loopback and internet-facing deployments
alike, before any stateless-only carve-out.

This is a **boot** rule, and boot admission alone is not a runtime guarantee: a
port that is bounded at startup can become unavailable later. §6.7 carries the
matching runtime rule — a `register:<ip>` check that throws under stored DCR
fails closed with a fixed 503 rather than restoring the unbounded anonymous
durable-write path this rule exists to close. Read the two together; neither is
sufficient alone. `Bridge.handleRegister` enforces the runtime half before body
selection or registration work; stateless registration retains fail-open outage
handling because it persists nothing.

Stateless DCR retains its existing composition rule. `Bridge` rejects the shape
where all three conditions hold: DCR is stateless, no bounded `RateLimitPort` was
supplied, and `redirectAllowlist` adds no application-specific HTTPS redirect
trust beyond the hosted defaults and the retained loopback starter entries. A
loopback entry is starter trust regardless of its path, port, or scheme: any
redirect entry whose host is `localhost`, `127.0.0.1`, or `[::1]` — root,
`http://localhost:4321/callback`, `https://localhost/callback`, any spelling
those hosts admit without a query or fragment — counts as retained starter
trust and never as application-specific trust. The §10.0 grammar admits
loopback entries with paths because native CLI clients choose their callback
path at runtime; this guard is what keeps that admitted shape from silently
re-widening the starter trust. An `https` loopback entry is not an
application-specific HTTPS callback: its host is the developer's own machine,
and its authority is the starter's, not an application's. A bridge whose issuer
and resource are both loopback URLs under `dev.allowInsecureLocalhost` is
local-only and does not need that internet-facing mitigation. Each stateless
choice remains available separately; the unbounded, broadly reusable starter
combination is not a valid composition. Adding an application callback does not
mitigate a generic loopback entry that remains in the same additive allowlist;
that mixed allowlist is still rejected.
`Bridge` snapshots `config`, `rateLimit`, the acknowledgement, and its remaining
dependencies once, then runs the check and constructs every use-case from that
same snapshot. Accessor-backed input therefore cannot present one composition to
the guard and another to runtime initialization. The validated limiter's `check`
method is also read and bound once; request handling invokes that bound function
rather than re-reading an accessor-backed method. The check runs before the
bridge constructs a CIMD resolver or any use-case.
The root-exported `assertSafeDeploymentCombination` applies the same rule to its
own input: it reads `config`, `rateLimit`, and the acknowledgement once and
returns the bound limiter snapshot. A composition root that preflights before a
stateful factory passes that returned value to `Bridge`, rather than re-reading
the original dependency after creating state.
`acknowledgeUnsafeStatelessDefaults: true` on `BridgeDeps` is an explicit,
temporary stateless-only escape hatch for the localhost-only starter and emits a
loud boot warning. Any other value is treated as absent. Internet-facing
compositions do not set it. The acknowledgement is accepted only when both
`issuer` and `resource` are loopback URLs. It never admits stored DCR without a
bounded limiter. A supplied limiter must expose a callable `check` method;
malformed limiter values fail at boot rather than counting as a bound. The guard
can distinguish the exported no-op singleton but cannot prove the behavior of a
custom implementation; a custom port that always allows registration is
nonconforming.
Composition roots run this guard before creating a state directory, persisting
signing keys, creating an audit file or state store, or starting OIDC discovery.
The generated starter first prepares new signing material in memory, validates
the complete `BridgeConfig`, retains the guard's bound limiter, and only then
persists that material. The console-pairing branches perform their
loopback-only preflight from issuer/resource strings before the signing-key
helper needed to build a complete `BridgeConfig`. Exported factories snapshot
their config, limiter, and acknowledgement once and reuse those exact values
after preflight, including for store and bridge construction.
The two runnable repository examples do not set the acknowledgement: their
loopback issuer/resource composition is already admitted by the local-only rule
above. When no production identity-provider selector is present, they also
preflight the effective listen host before the signing-key helper or any other
state side effect. Only exact `localhost`, `127.0.0.1`, and `::1` binds are
admitted by default. A non-loopback bind is a boot error unless the deployer sets
the deliberately unsafe, example-only escape hatch
`MCP_SSO_UNSAFE_ALLOW_NON_LOOPBACK_PAIRING=true`; using that exact value emits a
loud warning before state creation. The escape hatch changes only the listen-host
decision. It never relaxes the issuer/resource loopback preflight, and it is
ignored by real-IdP branches.
After that pure listen-host preflight, the API-key gateway binds its backend
listener before invoking the stateful gateway builder. An invalid or occupied
backend bind therefore leaves no quickstart state behind.
The generated starter additionally rejects non-loopback issuer or resource URLs
before creating its state directory, signing keys, audit file, or SQLite database.

**Fastify/SQLite production DCR selection.** The
`examples/fastify-sqlite` production branches accept an exact
`OAUTH_DCR_MODE` value of `"stateless"` or `"stored"`; omission preserves the
published stateless default, while a blank or unknown value is a pre-state boot
failure. Stored mode binds `dcr.store` to a `ClientStore` adapter backed by the
same `SqliteStore` instance that owns the bridge's OAuth state. Both example
modes support native CLI clients whose ephemeral callback needs a portless
loopback origin in `OAUTH_REDIRECT_ALLOWLIST`: the stateless-DCR composition
guard remains unchanged, but the example's unconditional bounded limiter is
the guard's documented escape. Choose stored mode when registrations must
survive restart; stateless mode carries the signed registration in the client
identifier. The API-key gateway example retains stateless-only environment
wiring and supplies the same bounded limiter.

**Fastify/SQLite registration admission.** Every `POST /oauth/register` mounted
by `examples/fastify-sqlite` carries a fixed Fastify `onRequest` budget of 30
requests per 60 seconds per derived client IP, under the separate
`oauth-client-registration` group. The route uses the same installed
`@fastify/rate-limit` instance and optional custom store as the example's
mandatory `/mcp` limiter, but its finite max/window are not inherited from or
disabled by the `/mcp` route options. The budget applies in both stateless and
stored DCR modes. Normal exhaustion returns 429; a custom limiter-store throw,
rejection, callback error, or malformed counter fails closed with the helper's
fixed 503 before body parsing, `Bridge.handleRegister`, `ClientStore.save`, or a
registration success audit. The example's validated Fastify proxy trust policy
selects the IP used for both route budgets. The built-in store remains
per-process, so a public multi-replica deployment needs a conforming shared
Fastify limiter store or equivalent trusted-edge admission control.

The same example also supplies both DCR modes a process-local `RateLimitPort`
with a fixed aggregate registration budget; in stored mode this additionally
satisfies the stored-DCR boot contract. The
Fastify per-IP route budget remains a separate earlier control: it rejects before
body parsing and can use a shared Fastify limiter store, while the core port
bounds the aggregate registrations that reach `Bridge` in one process. The
generated starter supplies the same finite process-local registration budget.
Custom and multi-replica production compositions supply their own bounded port;
`mcp-sso/rate-limit/redis` is the shipped distributed implementation.

**Runnable-example OAuth admission (owner decision, 2026-08-21).** Both
`examples/fastify-sqlite` and `examples/api-key-gateway` construct their finite
process-local core `RateLimitPort` unconditionally when the caller does not
supply one, in stateless as well as stored DCR mode. The port retains one
aggregate registration bucket (30 requests per 60 seconds per process) and
adds a separate `upstream:<ip>` bucket with the same fixed window for each
derived client IP. At most 1,024 upstream buckets exist per process; when that
set is full the port removes expired windows, then fails closed for a new key
rather than growing memory without a bound. Both upstream authorize and
callback charge that one per-IP bucket through the exact port passed to
`createUpstreamRedirectFlow`; the callback does not receive a second default
or the library's `noopRateLimit`.
An operator-supplied port still replaces this example default; the same bound
boot snapshot is passed to the Bridge and redirect flow.

The unconditional shape is deliberate: one runnable example has one admission
posture, and a stateless composition must not silently lose the limiter merely
because registration itself is non-durable. It also means stateless DCR with a
generic loopback redirect now passes `assertSafeDeploymentCombination` in both
example factories. That boot change is intended—the guard's escape is a
bounded port because it converts unbounded anonymous work into a finite
per-process budget. This does not change `Bridge`,
`assertSafeDeploymentCombination`, or custom library compositions: an omitted
library `RateLimitPort` still becomes `noopRateLimit` wherever §5 otherwise
admits it. Multi-replica public deployments still replace the process-local
example port with a conforming shared limiter.

This is a deliberate boot-breaking change approved by owner decision **B1** on
2026-08-17. Existing stored-DCR compositions that omit `rateLimit` or pass
`noopRateLimit` must add a bounded port before upgrading. There is no
acknowledgement escape hatch and the existing stateless acknowledgement is not
widened.

**Loopback starter trust is path-independent** (owner decision, 2026-08-19).
The guard's loopback predicate previously matched only root-path entries, so
two compositions booted that the rule's own wording did not intend to admit:
an application-specific HTTPS callback sitting alongside a loopback entry with
a path (the exact native-CLI callback shape
`http://localhost:4321/callback`), and an `https` loopback entry with a path
as the only entry, which the predicate mis-filed as application-specific HTTPS
trust. Both now fail the stateless guard until a bounded limiter is supplied
or the starter risk is acknowledged. Existing stateless compositions whose
allowlists mix an application callback with a loopback entry carrying a path
must add a limiter before upgrading; the acknowledgement escape hatch and its
loopback-only restriction are unchanged.
