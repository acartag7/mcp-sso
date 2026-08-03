# 5. Configuration contract

All runtime behavior derives from a validated `BridgeConfig`. **Configuration is
fail-closed**: ambiguous, incomplete, or insecure configuration is a boot
`AuthConfigError`, never a degraded default. There is intentionally **no
unauthenticated/local-bypass flavor** (Captatum's `local-binary` bypass is
dropped — this is a library that enforces real auth everywhere it is used).

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
  // An EMPTY array is valid — the built-in defaults cover the common case.
  redirectAllowlist: string[];    // ADDS to the built-in MCP-client defaults

  // --- scope contract (see §11); REQUIRED, fail-closed ---
  scopeCatalog: string[];         // the complete set of scopes this resource honors
  defaultScopes: string[];        // granted when a request omits scope; MUST be ⊆ catalog

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
  over plain http in production). Their **origins** are computed once and reused.
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
`clientCredentials`, and `cimd`. The published containers are never the
caller's objects or arrays, so later caller mutation cannot change the validated
configuration. Copies use explicit member allowlists and single reads. The
`dcr` wrapper is copied and frozen, but a stored-mode wrapper retains the exact
`ClientStore` object as a live port; the store implementation itself is neither
cloned nor frozen.

A config object is constructed via `createBridgeConfig(input)` (validates +
freezes). The frozen object is the only thing passed to use-cases.
