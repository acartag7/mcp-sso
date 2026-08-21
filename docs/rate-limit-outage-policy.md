# Why `POST /oauth/register` returns 503 on limiter outage

`RateLimitPort` limits requests to OAuth operations. Most of those operations continue if the limiter breaks. `POST /oauth/register` with `BridgeConfig.dcr.mode === "stored"` does not because an anonymous request can create durable client state.

## Why stored registration fails closed

If the rate limiter breaks, `POST /oauth/register` returns 503 instead of letting the request through when `BridgeConfig.dcr.mode === "stored"`. `Bridge.handleRegister` returns this response before reading registration fields, writing client state, or emitting a registration success audit.

The same exception does not block `POST /oauth/register` when `BridgeConfig.dcr.mode === "stateless"`. Stateless DCR creates no client record. Exceptions also do not block authorization, approval, token exchange, revocation, upstream redirects, CIMD resolution, or pairing. Those operations keep working when the limiter is unavailable.

The mode decides the result. The `register:` key prefix does not. Treating all `register:` exceptions alike would either reopen durable registration during an outage or block stateless registration without protecting durable state.

This policy covers the current `RateLimitPort` call sites. A future call site that can create anonymous durable state needs its own outage decision. It must not inherit the current fail-open behavior by omission.

## Boot and request checks serve different failures

`Bridge` refuses to start when `BridgeConfig.dcr.mode === "stored"` and no bounded `RateLimitPort` is supplied. The request check handles a limiter that breaks after startup. Without the request check, `POST /oauth/register` could create client records while the limiter was unavailable.

Hono adds an IP requirement because one `register:unknown` bucket would let one caller consume the registration budget for every caller. `createOAuthApp` therefore rejects a `Bridge` whose `BridgeConfig.dcr.mode === "stored"` when `clientIp` is absent. `Bridge.handleRegister` also rejects `POST /oauth/register` in stored mode when the runtime IP is missing, wrongly typed, empty, or the literal `"unknown"`, even if the extractor existed at boot.

## Why `/mcp` uses another policy

`/mcp` is the protected resource, not an OAuth continuity operation. The Fastify protected-resource helper uses a finite `@fastify/rate-limit` budget and returns 503 when its counter store fails. It rejects the request before bearer verification or protected handler work.

`RateLimitPort` exceptions do not block most OAuth operations. That rule does not apply to `/mcp`. The exact call sites and early returns are in [the `RateLimitPort` reference](contracts/06-ports.md#67-ratelimitport).
