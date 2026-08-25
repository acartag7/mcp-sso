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
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluateReleaseReadiness } from "../lib/release-ready.mjs";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));
const PROVIDER_HEADER = "| Provider | Client | Flow driven | Status | Date | Limits |";
const EXPORT_HEADER = "| Export | Live evidence | Runtime commit |";
const DIVIDER = /^\|( --- \|)+$/;

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
    needs: ["probe-google"],
    provider: "Google", client: "Provider probe, driven by the rehearsal",
    flow: "Discovery through the shipped resolver, the JWKS, and the authorize redirect",
    status: "Verified with limit", limits: "Limit: the Google sign-in was not driven.",
  },
]);

const subjectOf = (cells) => JSON.stringify(cells.slice(0, 3).map((cell) => cell.replace(/`([^`\r\n]+)`/g, "$1").replace(/\s+/gu, " ").trim()));
const cellsOf = (line) => line.split("|").slice(1, -1).map((cell) => cell.trim());
const fence = (value) => value.replace(/\|/g, "");

export function readReceipt(path) {
  const receipt = JSON.parse(readFileSync(path, "utf8"));
  if (receipt?.kind !== "mcp-sso-release-rehearsal" || receipt.schema !== 1) throw new Error("not a rehearsal receipt");
  if (receipt.evidence !== true) throw new Error("the receipt is not evidence: a row failed or was blocked, or the tree was dirty");
  if (!/^[0-9a-f]{40}$/.test(receipt.runtimeCommit ?? "")) throw new Error("the receipt names no full runtime commit");
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

export function render({ document, receipt, date, packageJson, releaseMatrix }) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error("date must be YYYY-MM-DD");
  const done = passed(receipt);
  const commit = receipt.runtimeCommit;
  const newRows = PROVIDER_ROWS.filter((row) => row.needs.every((id) => done.has(id))).map((row) => {
    const limits = `Runtime commit \`${commit}\`.${row.limits ? ` ${fence(row.limits)}` : ""}`;
    return `| ${fence(row.provider)} | ${fence(row.client)} | ${fence(row.flow)} | ${row.status} | ${date} | ${limits} |`;
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
  const options = { receipt: undefined, date: undefined, write: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--receipt" && argv[i + 1]) options.receipt = argv[++i];
    else if (argv[i] === "--date" && argv[i + 1]) options.date = argv[++i];
    else if (argv[i] === "--write") options.write = true;
    else throw new Error("usage: render-evidence.mjs --receipt <file> --date <YYYY-MM-DD> [--write]");
  }
  if (!options.receipt || !options.date) throw new Error("--receipt and --date are required");
  const receipt = readReceipt(options.receipt);
  const compatibilityPath = resolve(ROOT, "docs/client-compatibility.md");
  const rendered = render({
    document: readFileSync(compatibilityPath, "utf8"), receipt, date: options.date,
    packageJson: JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8")),
    releaseMatrix: JSON.parse(readFileSync(resolve(ROOT, "test/release-matrix.json"), "utf8")),
  });
  // The gate's own parser, against the receipt's commit: a rendered document the
  // gate would refuse is never written.
  const check = evaluateReleaseReadiness({
    packageJson: JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8")),
    releaseMatrix: JSON.parse(readFileSync(resolve(ROOT, "test/release-matrix.json"), "utf8")),
    compatibility: rendered, status: readFileSync(resolve(ROOT, "docs/verification-status.md"), "utf8"),
    gitCwd: ROOT, releaseCommit: receipt.runtimeCommit,
  });
  const problems = check.errors.filter((error) => !/^recorded runtime commit .* is not an ancestor/.test(error));
  if (problems.length > 0) throw new Error(`rendered evidence would fail check:release-ready:\n- ${problems.join("\n- ")}`);
  if (options.write) {
    writeFileSync(compatibilityPath, rendered);
    process.stdout.write(`docs/client-compatibility.md updated for ${receipt.runtimeCommit}\n`);
  } else {
    process.stdout.write(rendered);
  }
}
