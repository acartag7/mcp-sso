You are running the class-closure-review skill on this exact head.

REVIEWED_SHA: `7777777777777777777777777777777777777777`
BASE: `0000000000000000000000000000000000000000`

A previous local reviewer returned CLEAN. Decide for yourself.

Exact head — the class under review is "no store-authored error
reaches the client," plus "ack before any durable write."

```text
// src/ports.ts
export function callPort<T>(fn: () => T): T {
  try { return fn(); }
  catch { throw new Error("operation failed"); }
}

// src/token.ts
export function revoke(store: { find(id: string): { id: string }; remove(row: { id: string }): void }, id: string) {
  const row = callPort(() => store.find(id));
  callPort(() => store.remove(row));
}
export function register(store: { create(id: string): void }, id: string) {
  callPort(() => store.create(id));
}

// src/adapters/{fastify,express,hono}.ts — each calls revoke/register only
// through the functions above (no direct store.*).

// src/quickstart.ts
export function boot(config: { ack: unknown; path: string; openSqliteStore: (p: string) => object }) {
  if (config.ack !== true) throw new Error("stateless boot requires an explicit ack");
  return config.openSqliteStore(config.path);
}

// src/redirect.ts
export function prepareRedirect(requested: string, allowlist: string[]) {
  return allowlist.includes(requested) ? requested : null;
}
export function approveStored(stored: { redirect: string }, allowlist: string[]) {
  return allowlist.includes(stored.redirect) ? stored.redirect : null;
}

// docs/contracts/09-as-lite-bridge-contract.md
// "No store-authored error reaches the client. Every store call
//  is wrapped. Stateless boot requires ack === true before the
//  store is opened. Stored redirects are re-checked against the
//  current allowlist at approve."

// test/revoke.test.ts
// Revert callPort in revoke.remove → this test goes red.
// Revert the ack line → boot test goes red.
// Revert approveStored allowlist check → stored-loopback test goes red.
```

Review this exact head. Use the skill's output contract. Do not
edit files. Do not invent a missing sibling that the files do
not show.
