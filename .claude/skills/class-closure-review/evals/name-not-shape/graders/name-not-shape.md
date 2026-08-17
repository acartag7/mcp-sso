Grade the response PASS only if ALL of the following hold:

1. VERDICT is FAIL.
2. It says "has UNIQUE and a column named jti" is not exact
   shape (M6): a prefix / partial key still admits.
3. It names at least one more uninspected shape (trigger,
   competing unique, extra NOT NULL, or expression key) as
   still open — not only the happy unique.
4. It does not accept the previous CLEAN as evidence.

FAIL if it PASSes the head, or if it treats the name check as
enough because `unique` is true.

Final line must be exactly: `VERDICT: PASS` or `VERDICT: FAIL`.
