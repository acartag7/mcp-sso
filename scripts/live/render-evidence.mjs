// Render a passing rehearsal receipt into docs/client-compatibility.md: the
// provider rows the rehearsal proved, and the public-export rows from the
// release-matrix run it carried, all at the receipt's runtime commit. The
// result is checked with the same parser check:release-ready uses before it
// is written, so a receipt can never produce a document the gate refuses.
//
//   node scripts/live/render-evidence.mjs --receipt <receipt.json> --date <YYYY-MM-DD> [--write]
//
// Without --write the rendered document goes to stdout. A receipt that is not
// evidence (a failed or blocked row, a dirty tree) is refused.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluateReleaseReadiness } from "../lib/release-ready.mjs";
import { ROWS } from "./rehearsal-support.mjs";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));
/** The provider rows a receipt can prove, each gated on the rehearsal rows it
 *  needs. Subjects (provider, client, flow) are what the parser dedupes on. */
export const PROVIDER_ROWS = Object.freeze([
  {
    needs: ["client-entra:member"],
    provider: "Entra ID", client: "Official MCP SDK client, driven by the rehearsal",
    flow: "DCR → authorization → Entra identity through the headless driver as the member test user → consent → token → `/mcp` → refresh",
    status: "Verified", limits: "",
  },
  {
    needs: ["client-entra:nogroups", "client-entra:wronggroup", "client-entra:overage", "client-entra:wrong-tenant", "client-entra:not-allowlisted"],
    provider: "Entra ID", client: "Rehearsal deny fixtures",
    flow: "No-group, no-mapped-group, group-overage, wrong-tenant, and subject-allowlist denials",
    status: "Verified",
    limits: "Each fixture produced its audit reason once (`entra_no_groups`, `entra_no_mapped_groups`, `entra_groups_overage`, `entra_bad_tid`, `entra_subject_not_allowed`) and the client received `access_denied` with the documented description.",
  },
  {
    needs: ["client-cloudflare:member", "access-login", "access-edge-denial", "probe-cloudflare"],
    provider: "Cloudflare Access", client: "Official MCP SDK client, driven by the rehearsal",
    flow: "DCR → Access login through the Entra login method as the member test user → consent → token → `/mcp` → refresh; a non-admitted test user stopped at the Access edge",
    status: "Verified", limits: "",
  },
  {
    needs: ["claude-code:entra", "claude-code:cloudflare"], version: "claude",
    provider: "Cloudflare Access and Entra ID", client: "Claude Code, driven by the rehearsal",
    flow: "CIMD `client_id` → `claude mcp login --no-browser` → provider identity through the headless driver as the member test user → consent → the CLI's loopback callback → token → connection check on `/mcp`",
    status: "Verified", limits: "",
  },
  {
    needs: ["codex-cli:entra", "codex-cli:cloudflare"], version: "codex",
    provider: "Cloudflare Access and Entra ID", client: "Codex CLI, driven by the rehearsal",
    flow: "`codex mcp add` → the client identity Codex chose, CIMD document or dynamic registration → provider identity through the headless driver as the member test user → consent → the CLI's loopback callback → token",
    status: "Verified with limit", limits: "Limit: a tool call runs only when the client-keys file supplies `OPENAI_API_KEY`.",
  },
  {
    needs: ["probe-google"],
    provider: "Google", client: "Provider probe, driven by the rehearsal",
    flow: "Discovery through the shipped resolver, the JWKS, and the authorize redirect",
    status: "Verified with limit", limits: "Limit: the Google sign-in was not driven.",
  },
]);

const PROVIDER_HEADER = "| Provider | Client | Flow driven | Recorded by | Status | Date | Limits |";
const EXPORT_HEADER = "| Export | Live evidence | Runtime commit |";
const DIVIDER = /^\|( --- \|)+$/;


const subjectOf = (cells) => JSON.stringify(cells.slice(0, 3).map((cell) => cell.replace(/`([^`\r\n]+)`/g, "$1").replace(/\s+/gu, " ").trim()));
const cellsOf = (line) => line.split("|").slice(1, -1).map((cell) => cell.trim());
const fence = (value) => value.replace(/\|/g, "");

/** Read a receipt and re-derive, from its rows, everything the caller would
 *  otherwise be trusting it to have summarised: the exact row set of the
 *  rehearsal, once each, all passed, on a clean tree. A truncated or
 *  hand-edited receipt cannot assert its own completeness. */
export function readReceipt(path, expectedRows = ROWS.map((row) => row.id)) {
  const receipt = JSON.parse(readFileSync(path, "utf8"));
  if (receipt?.kind !== "mcp-sso-release-rehearsal" || receipt.schema !== 1) throw new Error("not a rehearsal receipt");
  if (!/^[0-9a-f]{40}$/.test(receipt.runtimeCommit ?? "")) throw new Error("the receipt names no full runtime commit");
  if (receipt.dirty === true) throw new Error("the receipt was produced from a dirty tree");
  if (receipt.crashed !== undefined || receipt.interrupted !== undefined) throw new Error("the rehearsal did not finish");
  const rows = Array.isArray(receipt.rows) ? receipt.rows : [];
  const ids = rows.map((row) => row?.id);
  const missing = expectedRows.filter((id) => !ids.includes(id));
  const unexpected = ids.filter((id) => !expectedRows.includes(id));
  if (missing.length > 0) throw new Error(`the receipt is partial: ${missing.length} row(s) of the rehearsal are absent`);
  if (unexpected.length > 0) throw new Error("the receipt holds a row the rehearsal does not define");
  if (new Set(ids).size !== ids.length) throw new Error("the receipt repeats a row");
  const failed = rows.filter((row) => row?.status !== "PASS");
  if (failed.length > 0) throw new Error(`the receipt is not evidence: ${failed.length} row(s) did not pass`);
  if (receipt.complete !== true) throw new Error("the receipt is partial: a --rows subset is never evidence");
  if (receipt.evidence !== true) throw new Error("the receipt is not evidence: a row failed or was blocked, or the tree was dirty");
  return receipt;
}

function passed(receipt) {
  return new Set(receipt.rows.filter((row) => row.status === "PASS").map((row) => row.id));
}

/** Replace or append one table's rows in the document. */
function replaceTable(lines, header, transform) {
  const start = lines.indexOf(header);
  if (start < 0 || !DIVIDER.test(lines[start + 1] ?? "")) throw new Error(`table not found: ${header}`);
  let end = start + 2;
  while (end < lines.length && lines[end].startsWith("|")) end += 1;
  const rows = transform(lines.slice(start + 2, end));
  return [...lines.slice(0, start + 2), ...rows, ...lines.slice(end)];
}

/** The client version a CLI row observed, from the row's own NOTE line. The
 *  probe prints `NOTE  claude 2.1.247`; `classifyRun` splits that into a kind
 *  and the text after it, so what reaches the receipt is
 *  `{ kind: "NOTE", text: "claude 2.1.247" }` and the kind identifies the line,
 *  never a prefix inside the text. Tier 3 rows must name the client version
 *  when it is visible, and the receipt is where it is visible. */
function observedVersion(receipt, needs, cli) {
  const versions = new Set();
  // Every leg the row covers must name its own version. Joining what was found
  // across legs would let one leg's note stand for a leg that recorded none,
  // and the rendered row claims both.
  for (const id of needs) {
    const row = receipt.rows.find((candidate) => candidate.id === id);
    const found = (row?.lines ?? []).flatMap((line) => {
      if (line?.kind !== "NOTE") return [];
      const match = /^(\w+) (\d+\.\d+\.\d+)$/.exec(line.text ?? "");
      return match !== null && match[1] === cli ? [match[2]] : [];
    });
    if (found.length === 0) return "";
    for (const version of found) versions.add(version);
  }
  return [...versions].sort().join(" and ");
}

export function render({ document, receipt, date, packageJson, releaseMatrix }) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error("date must be YYYY-MM-DD");
  const done = passed(receipt);
  const commit = receipt.runtimeCommit;
  const newRows = PROVIDER_ROWS.filter((row) => row.needs.every((id) => done.has(id))).map((row) => {
    const version = row.version === undefined ? "" : observedVersion(receipt, row.needs, row.version);
    if (row.version !== undefined && version === "") throw new Error(`the receipt does not name the ${row.version} version its rows ran`);
    const limits = `Runtime commit \`${commit}\`.${row.limits ? ` ${fence(row.limits)}` : ""}${version ? ` Client version ${fence(version)}.` : ""}`;
    return `| ${fence(row.provider)} | ${fence(row.client)} | ${fence(row.flow)} | rehearsal | ${row.status} | ${date} | ${limits} |`;
  });
  if (newRows.length === 0) throw new Error("the receipt proves no provider row");
  let lines = document.split("\n");
  lines = replaceTable(lines, PROVIDER_HEADER, (existing) => {
    const subjects = new Set(newRows.map((line) => subjectOf(cellsOf(line))));
    return [...existing.filter((line) => !subjects.has(subjectOf(cellsOf(line)))), ...newRows];
  });
  if (done.has("release-matrix")) {
    const exportRows = Object.keys(packageJson.exports).map((name) => {
      const ids = releaseMatrix.rows.filter((row) => row.packedArtifact === true && Array.isArray(row.exports) && row.exports.includes(name)).map((row) => `\`${row.id}\``);
      if (ids.length === 0) throw new Error(`no packed release-matrix row covers export ${name}`);
      return `| \`${name}\` | ${ids.join(", ")} | \`${commit}\` |`;
    });
    lines = replaceTable(lines, EXPORT_HEADER, () => exportRows);
  }
  return lines.join("\n");
}

const invokedAsMain = () => {
  try {
    return resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
};

if (invokedAsMain()) {
  const argv = process.argv.slice(2);
  const options = { receipt: undefined, date: undefined, write: false, requireHead: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--receipt" && argv[i + 1]) options.receipt = argv[++i];
    else if (argv[i] === "--date" && argv[i + 1]) options.date = argv[++i];
    else if (argv[i] === "--write") options.write = true;
    else if (argv[i] === "--require-head") options.requireHead = true;
    else throw new Error("usage: render-evidence.mjs --receipt <file> --date <YYYY-MM-DD> [--write] [--require-head]");
  }
  if (!options.receipt || !options.date) throw new Error("--receipt and --date are required");
  const receipt = readReceipt(options.receipt);
  if (options.requireHead) {
    const head = execFileSync("git", ["-C", ROOT, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
    if (head !== receipt.runtimeCommit) throw new Error("the receipt's runtime commit is not the checked-out HEAD");
  }
  const compatibilityPath = resolve(ROOT, "docs/client-compatibility.md");
  const rendered = render({
    document: readFileSync(compatibilityPath, "utf8"), receipt, date: options.date,
    packageJson: JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8")),
    releaseMatrix: JSON.parse(readFileSync(resolve(ROOT, "test/release-matrix.json"), "utf8")),
  });
  // The gate's own parser, against the receipt's commit: a rendered document the
  // gate would refuse is never written. Rows the rehearsal did not drive keep
  // their own commits; when those are stale relative to the receipt's commit
  // the gate will still refuse the release until they are re-run or archived,
  // so they are named here rather than hidden.
  const check = evaluateReleaseReadiness({
    packageJson: JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8")),
    releaseMatrix: JSON.parse(readFileSync(resolve(ROOT, "test/release-matrix.json"), "utf8")),
    compatibility: rendered, status: readFileSync(resolve(ROOT, "docs/verification-status.md"), "utf8"),
    gitCwd: ROOT, releaseCommit: receipt.runtimeCommit,
  });
  if (check.errors.length > 0) throw new Error(`rendered evidence would fail check:release-ready:\n- ${check.errors.join("\n- ")}`);
  for (const stale of check.staleEvidence) {
    process.stderr.write(`render-evidence: row commit ${stale.commit.slice(0, 7)} is stale against this receipt (${stale.changedInputs.length} changed inputs); re-run or archive that row before the release\n`);
  }
  if (options.write) {
    writeFileSync(compatibilityPath, rendered);
    process.stdout.write(`docs/client-compatibility.md updated for ${receipt.runtimeCommit}\n`);
  } else {
    process.stdout.write(rendered);
  }
}
