You are running the class-closure-review skill on this exact head.

REVIEWED_SHA: `2222222222222222222222222222222222222222`
BASE: `0000000000000000000000000000000000000000`

A previous local reviewer returned CLEAN. The implementer says
"no store error reaches the client" because `find` is wrapped.

Exact head:

```text
// src/ports.ts
export function callPort<T>(fn: () => T): T {
  try { return fn(); }
  catch { throw new Error("operation failed"); }
}

// src/token.ts
export function revoke(
  store: {
    find(id: string): { id: string };
    remove(row: { id: string }): void;
    create(id: string): void;
  },
  id: string,
) {
  const row = callPort(() => store.find(id));
  store.remove(row);
}

export function register(
  store: { create(id: string): void },
  id: string,
) {
  store.create(id);
}

// docs/contracts/13-audit-contract.md
// "No store-authored error reaches the client. Every store
//  call is wrapped."
```

Review this exact head. Use the skill's output contract. Do not
edit files.
