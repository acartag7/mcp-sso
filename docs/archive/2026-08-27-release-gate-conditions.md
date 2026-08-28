# Release gate conditions, 2026-08-27

The release-readiness gate stopped parsing `docs/client-compatibility.md` and started reading JSON receipts under `docs/evidence/`. This is the record of what it enforced before and what happened to each condition, written because deleting a fail-closed surface without enumerating what it enforced is how checks disappear quietly.

The current gate is [`scripts/lib/release-ready.mjs`](../../scripts/lib/release-ready.mjs) and the rule it implements is [§15](../contracts/15-package-and-export-map.md). Every condition in the first table is exercised by `test/release-gate-conditions.test.mjs`, so one of them disappearing turns that test red.

## Kept

| The gate refuses | Where it lives now |
| --- | --- |
| package version is malformed | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| package exports is not an object | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| the release commit does not resolve | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| a recorded runtime commit is malformed | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| a recorded runtime commit does not resolve | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| a recorded runtime commit is not an ancestor of the release commit | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| an export has no live evidence | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| evidence names a matrix row the matrix does not define | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| a matrix row names an export the package does not declare | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| the release matrix repeats a row id | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| a matrix row has no title | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| a matrix row's exports are not strings | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| a matrix row repeats an export | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| a matrix row claims exports without packedArtifact | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| a matrix row has no executable evidence | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| a receipt records a row the campaign does not define | Kept, and widened: the campaign is the rehearsal's rows plus the hand-driven checklist rows, both declared in `scripts/live/rehearsal-support.mjs`. Pinned in `test/release-gate-conditions.test.mjs` |
| a receipt row has a wrongly typed id | New here rather than carried over: the id pattern was applied to `String(row.id)`, so a numeric id passed it and then failed every later comparison, which are all against strings. Pinned in `test/release-gate-conditions.test.mjs` |
| the release matrix is not an object with a rows array | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| a matrix row has no RM.N id | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| a matrix row omits its exports array | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| a hand-driven row is not marked as one | New here: a row only a person can drive carries `driven: true`, so a person's word cannot sit in the receipt looking like a probe result. Pinned in `test/release-gate-conditions.test.mjs` |
| a receipt claims completeness while missing a hand-driven row | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |
| a rehearsal receipt claims completeness while missing rows | `scripts/lib/release-ready.mjs`, pinned in `test/release-gate-conditions.test.mjs` |

Evidence freshness is kept as it was, with one deliberate correction, and is pinned by its own case in the same file: runtime, deployment, package-exports, version and build-script changes age every receipt; the package description and the gate's own script do not; and probe or rehearsal changes age a rehearsal receipt but not an operator's.

The published-version check is gone, and that is the largest single change here. The gate used to read `docs/verification-status.md`, find the `npm package and tag` row, and compare the version written there against `package.json`. Seven review rounds each found another Markdown spelling that put a second, conflicting claim into a document the parser called clean: closing hashes, blockquotes, one-to-three-space indentation, Setext underlines, a lone pipe line, a fence whose closer carried trailing text, and finally a table inside a raw `<div>` block, which renders as text and is not a table at all. Each fix was correct and the next spelling was still there, because the check was a hand-rolled Markdown parser reading a document anyone may edit.

The property it was defending is enforced already, mechanically, and against the real tag rather than a sentence about it. [`.github/workflows/publish.yml`](../../.github/workflows/publish.yml) refuses to publish unless the pushed tag equals `v$PACKAGE_VERSION` read from `package.json`, before any build or publish step runs. A document that names the wrong version cannot cause a wrong publish; it can only be wrong prose, which is what [`docs/verification-status.md`](../verification-status.md) is for and what a reader corrects. The gate now reads no prose at all.

## Dropped

Every one of these is a rule about Markdown rather than about evidence. They existed because a table cell was a field; a receipt has fields.

| The gate refused | Why it no longer needs to |
| --- | --- |
| evidence documents require canonical level-two headings | The gate read evidence out of Markdown, so a heading written in Setext form, indented, or with inline formatting could hide a section from it. It reads JSON now. |
| expected one rendered table, found N (provider and export tables) | There is no provider table and no export table. Coverage comes from the receipt and the release matrix. |
| fenced blocks are not allowed in the table section | A fenced block could hide a table-shaped line from a reader while the parser read it, or the reverse. Nothing parses those sections. |
| HTML comments are not allowed in the table section | Same reason. The one place a hidden row could still matter, the published-release version, is read from that section's rendered table and a commented row is ignored. |
| raw angle-bracket markup is not allowed in the table section | Angle-bracket markup could render differently from the parsed source. No section is parsed for evidence. |
| rendered table has a malformed divider | Applied to the provider and export tables, which are gone. The status table's divider is still required, because that is what makes it a rendered table. |
| table rows contain noncanonical Markdown | Cell-level typography mattered because a cell was a field. A receipt has fields. |
| provider evidence: malformed current-matrix row | There is no current-matrix row to malform. |
| provider evidence: row has missing or malformed Provider/Client/Flow driven cell | Those three cells identified a row. A receipt row has an id. |
| provider evidence: duplicate row for provider / client / flow | Duplicate detection over a three-cell tuple. A receipt rejects a repeated row id. |
| provider evidence: has malformed status / unknown status | The closed vocabulary Verified, Verified with limit, Not run. A receipt row is PASS or it is not evidence. |
| provider evidence: missing or malformed date | The date was part of the receipt-in-prose. A receipt records recordedAt and, more importantly, the commit. |
| provider evidence: missing or malformed limitation | The `Limit:` marker had to follow the runtime receipt in the same cell. A limit is prose for a reader now, and what was actually driven is in the receipt's rows. |
| provider evidence: contradictory Verified evidence | A status that disagreed with its own cell payload. Not expressible in a receipt. |
| provider evidence: malformed runtime evidence receipt | The `Runtime commit ...` grammar inside a table cell. A receipt has a runtimeCommit field. |
| provider evidence: unknown "Recorded by" value | The provenance column existed so a parser could tell a rendered row from an operator's. A receipt names its producer. |
| provider evidence: evidence digest does not match merge commit | The squash-digest scheme let a worktree commit's evidence survive a squash merge. A receipt names the commit on main whose tree ran. |
| export evidence: duplicate row / malformed live evidence / invalid runtime commit | The export table's own shape checks. There is no export table. |
| live evidence ID does not cover export X | The mapping lived in two places, the table and the matrix, and had to agree. It lives in the matrix alone. |
| live evidence row names unknown export | Kept in substance: a matrix row naming an export the package does not declare is refused. |
| missing live evidence row for export X | Kept in substance: an export with no passing packed-artifact row is refused. |
| provider evidence: malformed `Not run` evidence | The `Not run: <reason>.` marker and its empty date cell were a row shape in prose. A receipt records rows that ran; a campaign that did not run one records no row for it, and the gate refuses a receipt that claims rows it did not complete. |
| table-shaped content outside the one rendered table | Applied to the provider and export tables, so that a `|` line in prose could not be read as evidence. Kept exactly where it still matters: the published-release version is read from that section's rendered table, and a row outside it supplies nothing. |
| status version: malformed item label / malformed table row | Typography of the other rows in the status table. Nothing the gate decides depends on them, and the contract no longer claims otherwise. |
| the published-release row is absent or repeated | The version claim is no longer read from prose. `publish.yml` compares the pushed tag against `package.json` before publishing, so agreement is enforced against the tag, not a restatement of it. |
| the published-release row disagrees with itself, with the package, or appears twice in any Markdown spelling | Seven rounds of Markdown shapes, one per review: closing hashes, blockquotes, indentation, Setext underlines, a lone pipe line, an unclosed fence, a raw HTML block. Hand-rolling a Markdown parser over a document anyone may edit has no last edge case. |

## What replaced them

A receipt is refused when its schema is unrecognised, its producer is unknown, its runtime commit is malformed, it is partial, it records no rows, a row did not pass, it repeats a row id, or it carries release-matrix rows without being a rehearsal receipt whose own release-matrix row passed. `docs/evidence/` holds one active receipt per producer and the superseded document moves to `docs/evidence/archive/`.

Current results are in [Client compatibility](../client-compatibility.md) and [Verification status](../verification-status.md). Both are written for readers, and nothing parses either of them.
