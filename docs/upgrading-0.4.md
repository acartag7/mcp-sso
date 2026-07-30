# Upgrading to 0.4.0

## Breaking: everyone re-authorizes once

**Refresh tokens and machine credentials issued before 0.4.0 stop working.**
Interactive clients get `invalid_grant` and must run the authorization flow
again; machine clients get `invalid_client` and must be re-provisioned. Access
tokens already in flight keep working until they expire normally.

Plan the upgrade as a re-authorization event. There is no configuration that
makes it invisible.

## Why

0.4.0 binds every token to exactly one MCP resource, so a token minted for one
endpoint cannot be replayed at another. Records written by 0.3.x carry no
resource — there was only one, so nothing recorded it — and a stored row with no
resource cannot say which one it belonged to.

The library refuses to guess. The alternative would be to assume such records
belong to whatever resource is configured *now*, and that assumption is wrong in
exactly the case that matters: an operator who upgrades and changes the resource
URL in the same deployment. Every consent the user gave to the old endpoint
would transfer to the new one, auto-approving scopes they never granted there.
No attacker is involved — a URL change would be enough.

Rejecting is the only behavior that is correct without trusting a claim the
library cannot verify.

## If you cannot re-authorize your fleet

`legacySingletonResource` opts out. It is an escape hatch, not the recommended
path:

```ts
createBridgeConfig({
  resource: "https://mcp.example/mcp",
  legacySingletonResource: "https://mcp.example/mcp",  // MUST be the same URL
  scopeCatalog: ["mcp:read"],
  defaultScopes: ["mcp:read"],
  // ...
});
```

This asserts that every pre-0.4 record with no resource was issued for that same
resource. Existing refresh tokens then bind to it on first use and keep working.

**Understand its limitation before relying on it.** The library verifies only
that the value equals your *current* `resource`. If you have already changed the
URL, you can satisfy the check with the new value and rebind old grants anyway —
the exact outcome the default prevents. The library cannot detect this, because
a null row does not record where it came from.

Use it only when all of these hold:

- your resource URL is **unchanged** from the 0.3.x deployment;
- the store contains records from **that** deployment only;
- you have not previously served a different resource URL against this store.

If any is uncertain, take the re-authorization instead.

## Multi-resource deployments

`legacySingletonResource` is rejected outright when `resources` is configured.
There is no ambiguity to resolve there: with more than one resource, a null row
could belong to any of them, so it is always rejected.

## Order of operations

1. Drain pre-0.4 token handlers that share the store. They ignore the new
   resource columns and can write unbound records after the cutover.
2. Deploy 0.4.0.
3. Users re-authorize; machine clients are re-provisioned.

Rolling back after resource-bound records exist is unsupported — an old binary
ignores the resource columns and would rotate a bound token while minting its own
configured audience. Roll back from an isolated pre-cutover snapshot only.

## Changing a resource URL later

The resource URL is the token audience, so changing it is changing the resource
identity. Existing refresh lineage bound to the old URL will not rotate under the
new one. Treat a URL change as its own re-authorization event.
