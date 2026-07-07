# Authorization model — the two gates

Who can use a `mcp-sso`-protected MCP server, and **where** each part of that
decision is enforced. [`docs/contracts.md`](contracts.md) defines the schemas;
this document explains the model so you can pick the right knob.

## The chain, end to end

A request only reaches your MCP tools after passing four independent checks,
enforced at three different places:

```
who can authenticate?          Gate 1 — your IdP (Entra / Cloudflare Access)
who does the bridge accept?    Gate 2 — mcp-sso allowlists (+ Entra group→scope mapping, shipped §17.4)
what does this client get?     consent — the user approves requested scopes
what does this token allow?    RS check — requireScope on each /mcp call
```

mcp-sso does **not** replace Gate 1. The upstream IdP owns enterprise identity
— MFA, device posture, session policies, group management. The bridge's own
checks are **defense-in-depth on top**: a second gate, never the only gate.

## Gate 1 — IdP-side access control (primary)

Enforced entirely **outside** mcp-sso, before the bridge sees a subject. A
Gate 1 rejection means the identity port never resolves and the authorize
request **fails closed** — `access_denied` as a direct 401 (contracts §9.3).

**Microsoft Entra ID** — two controls on the bridge's app registration:

- **Assignment required.** Enterprise application → Properties →
  *"Assignment required?" = Yes*, then add permitted users/groups under
  *Users and groups*. Anyone not assigned **cannot complete the Entra sign-in**
  for this app.
- **Conditional Access.** Tenant policies (MFA, compliant device, named
  locations, sign-in risk) apply to the bridge's app like any other app.

**Cloudflare Access** — the Zero Trust **Access policy** in front of the bridge
decides who can reach it (emails, groups, identity providers, device posture).
The bridge only *verifies* the `Cf-Access-Jwt-Assertion` Access already issued.

> Configure neither and Gate 1 defaults to "anyone in the tenant" (Entra) or
> "whatever your Access policy says" (Cloudflare). Configure it. It is the
> control your security team already audits.

## Gate 2 — mcp-sso's own checks (defense-in-depth)

Enforced **inside** the identity port, after the upstream credential verifies
cryptographically — issuer, audience, tenant, expiry (contracts §6.5). Both
allowlists are optional; an **empty allowlist delegates entirely to Gate 1**.

- **Entra** — `subjectAllowlist` matches the **immutable `oid` claim** by
  default. Matching mutable claims requires the explicit `allowMutableClaims`
  opt-in (`preferred_username` / `email`); Microsoft warns against mutable
  claims for authorization.
- **Cloudflare Access** — `emailAllowlist` matches the verified email from the
  Access JWT.

Why a second gate at all? Gate 1 is configuration you don't control from this
codebase — a broad app assignment, a later policy edit, or a wide Access group
can silently widen access. A short allowlist in the bridge's own config is
reviewable in the same pull request as the deployment, and it **fails closed
independently**.

### Scope ceiling — the IdP-agnostic engine **[shipped — contracts §17.4]**

Gate 2 can be more than yes/no. An identity port may attach an `allowedScopes`
**ceiling** to the resolved identity, and the authorize flow then **guarantees
a subject is never granted a scope outside that ceiling**. The engine is
IdP-agnostic.

- **Requested scopes are narrowed by intersection** with the ceiling at
  `/oauth/authorize`. `defaultScopes` apply when no scope is requested. The
  consent page and the minted token reflect the narrowed set. RFC 6749 permits
  granting fewer scopes than requested, so an un-entitled scope is dropped
  rather than failing the whole request.
- **An empty intersection is `access_denied`** over the redirect channel. The
  redirect URI is already validated by then, so the client sees "you declined"
  semantics, not a dead error page.
- **The ceiling is re-checked at approve.** The consent JWT carries it as the
  `allowed_scopes` claim; at approve, the accumulated `union(requested,
  priorScopes)` is intersected against the ceiling read from the *verified
  token* (`defaultScopes` pass through the same intersection). A prior grant
  **cannot resurrect** a scope a since-removed group granted.
- **Refresh is not re-checked** — there is no identity at refresh. Removing a
  group takes effect at the next full authorize. Shorten
  `refreshTokenTtlSeconds` or revoke the family for faster cutoff.

No shipped identity port sets `allowedScopes` except Entra (below), so behavior
is unchanged from v0.1 unless a port supplies a ceiling.

### Entra group→scope mapping **[shipped S2b — contracts §17.4]**

The ceiling producer for enterprise Entra. Entra group memberships (immutable
group object IDs) map to sets of scopes; their union becomes the `allowedScopes`
ceiling above. **A subject can never be granted a scope outside the union of
their matched groups** (+ `baseScopes`), and overage-truncated group claims
fail closed. Config lives on `EntraConfig.groupAuthorization` (pure core in
`src/identity/entra-groups.ts`, wired in `src/identity/entra.ts`):

```ts
groupAuthorization: {
  mapping: { "11111111-1111-1111-1111-111111111111": ["mcp:read", "mcp:write"] },
  baseScopes: ["mcp:read"], // scopes every authenticated subject gets; default []
}
```

- **Mapping keys are GUIDs only.** Display names are a spoof vector — any user
  can create a duplicate-named group — so non-GUID keys are **boot-rejected**.
  Duplicate case-insensitive keys are also boot-rejected. Matching is
  case-insensitive.
- **Each mapped or base scope must be a single RFC 6749 scope token.** Values
  with whitespace, quote, or control characters are **boot-rejected** — they
  would corrupt the space-joined `allowed_scopes` JWT round-trip.
- **The ceiling is a union.** `baseScopes` plus every matched group's mapped
  scopes, no tier precedence, order-independent.
- **Overage fails closed** (`entra_groups_overage`). It fires when the `groups`
  claim is absent but an overage marker is present (`_claim_names.groups` or
  `hasgroups`). The `_claim_sources` endpoint URL is **never** dereferenced — a
  URL inside a token is data, not instructions. Remedy: set
  `groupMembershipClaims` to `ApplicationGroup` in the app manifest (direct
  membership, solves overage for the mapping use case; requires Entra P1), or
  reduce group sprawl.
- **No usable groups ⇒ distinct fail-closed reasons.** No `groups` claim at all
  with empty `baseScopes` ⇒ `entra_no_groups` (likely a `groupMembershipClaims`
  misconfiguration). A `groups` claim present but every group unmapped with
  empty `baseScopes` ⇒ `entra_no_mapped_groups` (a deployer *mapping* gap — add
  the GUID to `mapping` or grant `baseScopes`). Both deny; the reason names the
  likely knob.
- **Nested-group semantics differ by claim type.** `SecurityGroup` emits
  *transitive* (nested) membership — a user in "Staff → Engineering" matches a
  mapping for "Engineering". `ApplicationGroup` is *direct-only* — nested
  memberships are invisible to the ceiling, so a mapping that "should" match via
  nesting silently won't. Choose `SecurityGroup` if you rely on nesting; either
  way, watch the 200-group cap that triggers overage.
- **Mapping typos fail loudly at boot.** The mapped/base ⊆ `scopeCatalog`
  subset check runs at `createEntraIdentity(config, { scopeCatalog })` — pass
  the catalog when constructing the port.

Exact contract in [contracts.md](contracts.md) §17.4; attacker analysis in
[`docs/threat-model.md`](threat-model.md) row 22. Live-tenant verification
(incl. guest/B2B + overage) is **owner-pending** — see the manual checklist at
the top of `src/identity/entra.ts`.

## What neither gate decides

- **Scopes actually granted** come from client request + user consent, bounded
  by an identity-port `allowedScopes` ceiling when one is supplied
  (contracts §9.3, §11, §17.4).
- **Per-call authorization** is the resource server's `requireScope`: a valid
  token without the needed scope gets a **403 step-up, not access**
  (contracts §8.3).
- **Client identity** (which MCP client is asking) is the DCR + redirect-URI
  policy — a separate axis from user identity (contracts §9.2, §10).

## Which knob for which job

| You want to… | Use |
|---|---|
| Restrict who can sign in at all | Gate 1 — Entra app assignment / Conditional Access, or the Cloudflare Access policy |
| Enforce MFA / device posture / location | Gate 1 (IdP policy) — mcp-sso cannot see these signals |
| Pin an exact permitted-user set in code review | Gate 2 — `subjectAllowlist` (Entra `oid`) / `emailAllowlist` (Cloudflare Access) |
| Give different users different permission levels | Gate 2 — Entra group→scope mapping (contracts §17.4) |
| Limit what a specific MCP client may do | Scope catalog + consent; `requireScope` at the resource |
| Cut off a stolen refresh token | Revocation (RFC 7009) / family replay detection — not an identity gate |

Both gates run **per authorization**, not on every `/mcp` call. Between
authorizations, access rides on the bridge's own short-lived access tokens and
rotating refresh tokens. Removing a user at Gate 1 or Gate 2 takes effect when
the refresh-token family expires or is revoked, or at the next re-authorization
— see the residual-risk notes in [`docs/threat-model.md`](threat-model.md).
