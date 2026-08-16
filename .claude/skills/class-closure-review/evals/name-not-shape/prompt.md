You are running the class-closure-review skill on this exact head.

REVIEWED_SHA: `5555555555555555555555555555555555555555`
BASE: `0000000000000000000000000000000000000000`

A previous local reviewer returned CLEAN. The implementer says
boot now refuses a store whose replay table is not unique on
`jti`.

Exact head:

```text
// src/store/mysql-schema.ts
type Index = { name: string; columns: string[]; unique: boolean; prefix?: number };

export function admitReplayTable(indexes: Index[]): boolean {
  return indexes.some(
    (i) => i.unique && i.columns.includes("jti"),
  );
}

// Hostile schema that still returns true:
//   UNIQUE (jti(1))     — prefix / partial key
// Also not inspected: a BEFORE INSERT trigger that rewrites jti;
// a competing UNIQUE (expires_at); an extra NOT NULL column
// with no default.
```

Review this exact head. Use the skill's output contract. Do not
edit files.
