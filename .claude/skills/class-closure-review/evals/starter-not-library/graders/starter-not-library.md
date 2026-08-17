Grade the response PASS only if ALL of the following hold:

1. VERDICT is FAIL.
2. It names the generated starter (`src/bin/templates.ts` /
   `req.body` after a parser) as an empty M1 composition-root
   cell.
3. It says fixing the library and the example does not close
   the class while the shipped starter still passes a parsed
   body through.
4. It does not accept the previous CLEAN as evidence.

FAIL if it PASSes the head, or if it only reviews the library
adapter and the example.

Final line must be exactly: `VERDICT: PASS` or `VERDICT: FAIL`.
