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

### 5.1 Multi-resource configuration (PENDING 0.4.0)

> **NOT ENFORCED at this commit.** The singleton form above remains shipped.

One issuer and signing-key set may serve a finite configured resource catalog.
The existing `{ resource, scopeCatalog, defaultScopes }` trio and a new
`resources` form are mutually exclusive:

```ts
interface ResourceDefinition {
  resource: string;
  scopeCatalog: string[];
  defaultScopes: string[];
}

interface MultiResourceBridgeConfig {
  resources: ResourceDefinition[]; // non-empty
  // all existing common BridgeConfig fields; no singleton trio
}

type ResourceConfiguration =
  | { resource: string; scopeCatalog: string[]; defaultScopes: string[];
      legacySingletonResource?: string; resources?: never }
  | { resources: ResourceDefinition[]; resource?: never;
      scopeCatalog?: never; defaultScopes?: never;
      legacySingletonResource?: never };
```

At activation the common fields from the shipped interface above and
`ResourceConfiguration` form the public `BridgeConfig` union; the first member
is the existing singleton shape.

An empty `resources` array, a partial singleton trio, both forms, or neither
form is a boot `AuthConfigError`. `createBridgeConfig` snapshots each selected
definition and nested scope array once, validates them, freezes the published
copies, and normalizes the singleton form to a one-entry internal catalog. It
does not introduce dynamic resources, wildcard entries, aliases, or a policy
callback.

`legacySingletonResource` is an optional, explicit upgrade attestation, not a
resource selector. It is accepted only in the singleton form and must
canonicalize exactly to `resource`. When present, it states that every
pre-0.4 stored record with null/missing resource lineage was issued for that
same resource and permits the one-time lazy binding in §§6–7/12/17. Omitting it
keeps new and already-bound singleton flows source-compatible but rejects
unbound legacy refresh and machine state. A deployment changing A to B cannot
set the field to A because it disagrees with B, and must not attest B for
A-originated records. The multi-resource form always rejects the field. There
is deliberately no automatic default to the current resource: the library
cannot distinguish an A→A upgrade from an A→B replacement by inspecting a null
legacy row. The 0.4.0 migration guide and release notes must call out the
attestation before upgrade; omission is the fail-closed choice, not silent
resource inference.

One `canonicalResource(value)` parser owns configuration and request equality:
the input is a primitive non-empty absolute URL; production requires `https`
and the existing loopback-only development exception applies; userinfo, query,
and fragment are rejected. URL parsing lower-cases scheme/host, removes an
ordinary default port, and resolves dot segments. An origin-only resource
canonicalizes without a trailing slash; non-root paths retain their
trailing-slash distinction. The canonical value is stored in grant records and
JWT `aud`. Duplicate canonical resources are a boot error.

Each resource's catalog is non-empty and duplicate-free, contains only RFC 6749
scope tokens, and owns a duplicate-free defaults subset. Different resources
may use the same scope string without sharing grant state. This amendment
narrows previously accepted query/userinfo resource URLs because they cannot
produce an unambiguous RFC 9728 PRM route.

The catalog represents independently addressable MCP endpoints. For example,
one Atesaki deployment may configure
`https://atesaki.dev/grafana/mcp`,
`https://atesaki.dev/captatum/mcp`, and
`https://atesaki.dev/memory/mcp`, while each client selects only the endpoint
it needs. It does not turn one MCP connection into a tool multiplexer. A local
Atesaki process may expose the same paths on loopback without requiring inbound
OAuth; Atesaki's separate role as an OAuth client of protected remote MCP
servers is outside mcp-sso.

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
- `defaultScopes ⊆ scopeCatalog` and `scopeCatalog` is non-empty. An empty
  catalog means the resource honors no scopes and every authorize fails closed —
  the deployer MUST declare scopes explicitly.
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

A config object is constructed via `createBridgeConfig(input)` (validates +
freezes). The frozen object is the only thing passed to use-cases.
