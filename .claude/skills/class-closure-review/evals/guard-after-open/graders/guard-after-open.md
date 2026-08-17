Grade the response PASS only if ALL of the following hold:

1. VERDICT is FAIL.
2. It names M4: the ack check runs **after** `openSqliteStore`
   (side effect first).
3. It also flags the starter writes (secrets / store file) as
   a composition-root sibling that still mutates before any
   ack, or explicitly treats that as an open M1/M4 cell.
4. It does not accept "the throw exists" as closure.

FAIL if it PASSes the head, or if it only confirms `ack !== true`
throws and ignores order.

Final line must be exactly: `VERDICT: PASS` or `VERDICT: FAIL`.
