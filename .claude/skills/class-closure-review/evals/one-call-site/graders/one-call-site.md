Grade the response PASS only if ALL of the following hold:

1. VERDICT is FAIL.
2. It names `remove` and/or `create` (or write paths /
   unwrapped siblings) as empty M1 cells — wrapping `find`
   alone does not close "every store call."
3. It treats the contract sentence as unbacked for those
   siblings, not as already true.
4. It does not accept the previous CLEAN as evidence.

FAIL if it PASSes the head, or if it only restates that `find`
is wrapped and calls the class closed.

Final line must be exactly: `VERDICT: PASS` or `VERDICT: FAIL`.
