# Authorization model — the two gates

> Who is allowed to use a `mcp-sso`-protected MCP server, and **where** each
> part of that decision is enforced. `docs/contracts.md` defines the exact
> schemas; this document explains the model so a deployer can pick the right
> knob. Sections marked **[v0.2]** are locked design (contracts §17) that is
> not implemented yet; everything else describes shipped behavior.

## The chain, end to end

A request only reaches your MCP tools after passing four independent checks,
enforced at three different places:

```
who can authenticate?          Gate 1 — your IdP (Entra / Cloudflare Access)
who does the bridge accept?    Gate 2 — mcp-sso allowlists (+ group mapping, v0.2)
what does this client get?     consent — the user approves requested scopes
what does this token allow?    RS check — requireScope on each /mcp call
```

`mcp-sso` deliberately does **not** try to replace Gate 1. The upstream IdP is
where enterprise identity controls live (MFA, device posture, session
policies, group management). The bridge's own controls are **defense-in-depth
on top** — a second gate, never the only gate.

## Gate 1 — IdP-side access control (primary)

Enforced entirely **outside** mcp-sso, before the bridge ever sees a subject.
If Gate 1 rejects the user, the identity port never resolves and the authorize
request fails closed (`access_denied`, direct 401 — contracts §9.3).

**Microsoft Entra ID** — two standard controls on the bridge's app
registration:

- **Assignment required.** Enterprise application → Properties →
  *"Assignment required?" = Yes*, then add the permitted users/groups under
  *Users and groups*. Anyone not assigned cannot complete the Entra sign-in
  for this app at all.
- **Conditional Access.** Tenant policies (MFA, compliant device, named
  locations, sign-in risk) apply to the bridge's app like any other app.

**Cloudflare Access** — the Zero Trust **Access policy** on the application in
front of the bridge decides who can reach it (emails, groups, identity
providers, device posture). The bridge then only *verifies* the
`Cf-Access-Jwt-Assertion` that Access already issued.

> If you configure neither, Gate 1 is "anyone in the tenant" (Entra) or
> "whatever your Access policy says". Configure it. It is the control your
> security team already audits.

## Gate 2 — mcp-sso's own checks (defense-in-depth)

Enforced **inside** the identity port, after the upstream credential verifies
cryptographically (issuer, audience, tenant, expiry — contracts §6.5).

Shipped today (both optional; an empty allowlist delegates entirely to Gate 1):

- **Entra:** `subjectAllowlist` — matches the immutable `oid` claim by
  default. Matching mutable claims (`preferred_username`/`email`) requires the
  explicit `allowMutableClaims` opt-in, because Microsoft warns against using
  mutable claims for authorization.
- **Cloudflare Access:** `emailAllowlist` — the verified email from the
  Access JWT.

Why keep a second gate at all? Because Gate 1 is configuration you don't
control from this codebase: a broad app assignment, a later policy edit, or an
overly wide Access group silently widens access. A short allowlist in the
bridge's own config is reviewable in the same pull request as the rest of the
deployment and fails closed independently.

### Scope ceiling — the IdP-agnostic engine **[shipped — contracts §17.4]**

Gate 2 can be more than a yes/no gate: an identity port may attach an
`allowedScopes` **ceiling** to the resolved identity, and the authorize flow
then guarantees a subject is never granted a scope outside that ceiling. The
engine is IdP-agnostic and shipped:

- At `/oauth/authorize`, requested scopes (and `defaultScopes`, when no scope is
  requested) are **narrowed by intersection** with the ceiling. The consent page
  and the minted token reflect the narrowed set — RFC 6749 permits granting
  fewer scopes than requested, so an un-entitled scope is simply dropped rather
  than failing the whole request.
- An **empty intersection is `access_denied`** over the redirect channel (the
  redirect URI is already validated by then, so the client sees "you declined"
  semantics, not a dead error page).
- The ceiling travels the consent JWT (`allowed_scopes` claim), and at **approve
  the accumulated `union(requested, priorScopes)` is re-intersected** against the
  ceiling read from the *verified token* — so a prior grant cannot resurrect a
  scope a since-removed group granted. (`defaultScopes` pass through the same
  intersection.)
- Refresh is **not** re-checked (there is no identity at refresh); removing a
  group takes effect at the next full authorize. Shorten
  `refreshTokenTtlSeconds` or revoke the family for faster cutoff.

Today no shipped identity port sets `allowedScopes`, so behavior is unchanged
from v0.1 unless a port supplies a ceiling.

### Entra group→scope mapping **[v0.2 — contracts §17.4, pending]**

The producer of the ceiling for enterprise Entra deployments: Entra group
memberships (immutable group object IDs) map to sets of scopes, the union of
which becomes the `allowedScopes` ceiling above. A subject can never be granted
a scope outside the union of their matched groups; overage-truncated group
claims fail closed. Exact config shape, combination model (union), and failure
modes (`entra_groups_overage`, `entra_no_groups`) are in contracts §17.4;
attacker analysis in `docs/threat-model.md` (row 22).

## What neither gate decides

- **Scopes actually granted** come from client request + user consent
  (contracts §9.3, §11), bounded by an identity-port `allowedScopes` ceiling
  when one is supplied (contracts §17.4 — the engine is shipped; the Entra
  group→scope producer is pending).
- **Per-call authorization** is the resource server's `requireScope`
  (contracts §8.3) — a valid token without the needed scope gets a 403
  step-up, not access.
- **Client identity** (which MCP client is asking) is the DCR/redirect-URI
  policy (contracts §9.2, §10) — a separate axis from user identity.

## Which knob for which job

| You want to… | Use |
|---|---|
| Restrict which humans can sign in at all | Gate 1: Entra app assignment / Conditional Access, or the Cloudflare Access policy |
| Enforce MFA / device posture / location | Gate 1 (IdP policy) — mcp-sso cannot see these signals |
| Pin an exact set of permitted users in code review | Gate 2: `subjectAllowlist` (Entra `oid`) / `emailAllowlist` (Cloudflare Access) |
| Give different users different permission levels | **[v0.2]** Gate 2 group→scope mapping (contracts §17.4) |
| Limit what a specific MCP client may do | Scope catalog + consent; `requireScope` at the resource |
| Cut off a stolen refresh token | Revocation (RFC 7009) / family replay detection — not an identity gate |

Both gates are per-*authorization*: they run when a user authorizes (or
re-authorizes), not on every `/mcp` call. Between authorizations, access is
carried by the bridge's own short-lived access tokens and rotating refresh
tokens; removing a user at Gate 1 or Gate 2 takes effect the next time a
refresh-token family expires or is revoked, or at the next re-authorization —
see the residual-risk notes in `docs/threat-model.md`.
