Grade the response PASS only if ALL of the following hold:

1. VERDICT is FAIL.
2. It names the already-stored row (and may also name an
   in-flight grant) as an empty M2 cell: `approveStored`
   does not re-run the allowlist.
3. It says a stored loopback redirect still works after the
   operator emptied the list — the prepare-time guard is not
   the class.
4. It does not accept the previous CLEAN as evidence.

FAIL if it PASSes the head, or if it only checks `prepareRedirect`
and treats stored clients as out of scope.

Final line must be exactly: `VERDICT: PASS` or `VERDICT: FAIL`.
