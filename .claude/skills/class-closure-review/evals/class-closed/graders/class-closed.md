Grade the response PASS only if ALL of the following hold:

1. VERDICT is PASS (this head is the control: the class is
   closed in the files given).
2. It shows filled matrices for the claimed class (wrapped
   find/remove/create, ack before open, stored redirect
   re-checked) rather than skipping the matrix.
3. It does not invent a blocking P1/P2 about a path, store,
   or file the prompt did not include.
4. P3-only nits (wording, extra hosts not in the tree) are
   allowed only if they do not flip the verdict to FAIL.

FAIL if VERDICT is FAIL or STOP, or if it reports a P1/P2
that requires a sibling the frozen head does not contain.

Final line must be exactly: `VERDICT: PASS` or `VERDICT: FAIL`.
