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
  // An EMPTY array is valid — only the hosted-client defaults remain enabled.
  // Loopback redirects require an explicit entry here.
  redirectAllowlist: string[];    // ADDS to the hosted MCP-client defaults

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
  **origins** are computed once and reused.
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
- `redirectAllowlist` is an array, and **every entry satisfies the §10.0
  redirect-entry grammar**. `createBridgeConfig` snapshots the array once,
  validates that copy, and publishes the same frozen copy — origin form or canonical exact-URI form, `https`/
  `http` only, no wildcard, userinfo, query, fragment, whitespace, control
  character, backslash, or malformed percent-escape. Each rule is checked on the
  RAW entry as well as any parsed field (§10.0 explains why: WHATWG
  normalization erases the syntax the decision depends on). An empty array is
  valid. The error **names the offending entry** and, for a non-canonical one,
  shows its canonical form — a deployer with several origins configured must not
  have to bisect.

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

**Bridge composition boot guard.** `Bridge` rejects the combined deployment
shape where all three conditions hold: DCR is stateless, no `RateLimitPort` was
supplied, and `redirectAllowlist` adds no application-specific HTTPS redirect
trust beyond the hosted defaults and the explicit loopback starter origins
(`localhost`, `127.0.0.1`, `[::1]`). A bridge whose issuer and resource are both
loopback URLs under `dev.allowInsecureLocalhost` is local-only and does not need
that internet-facing mitigation. Each choice remains available separately;
the unbounded, broadly reusable starter combination is not a valid composition.
Adding an application callback does not mitigate a generic loopback origin that
remains in the same additive allowlist; that mixed allowlist is still rejected.
`Bridge` snapshots `config`, `rateLimit`, the acknowledgement, and its remaining
dependencies once, then runs the check and constructs every use-case from that
same snapshot. Accessor-backed input therefore cannot present one composition to
the guard and another to runtime initialization. The validated limiter's `check`
method is also read and bound once; request handling invokes that bound function
rather than re-reading an accessor-backed method. The check runs before the
bridge constructs a CIMD resolver or any use-case.
`acknowledgeUnsafeStatelessDefaults: true` on `BridgeDeps` is an explicit,
temporary escape hatch for the localhost-only starter and emits a loud boot
warning. Any other value is treated as absent. Internet-facing compositions do
not set it. The acknowledgement is accepted only when both `issuer` and
`resource` are loopback URLs. A supplied limiter must expose a callable `check`
method; malformed limiter values fail at boot rather than counting as a bound.
Composition roots run this guard before creating a state directory, signing
keys, audit file, state store, or starting OIDC discovery. The console-pairing branches perform their
loopback-only preflight from issuer/resource strings before the signing-key
helper needed to build a complete `BridgeConfig`. Exported factories snapshot
their config and acknowledgement once and reuse those exact values after
preflight, including for store and bridge construction.
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
