import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const manifest = JSON.parse(readFileSync(resolve(root, "test/release-matrix.json"), "utf8"));

function fatal(message) { console.error(`release matrix preflight failed: ${message}`); process.exit(1); }
if (process.env.RUN_INTEGRATION !== "true") fatal("RUN_INTEGRATION=true is required");
if (!process.env.MYSQL_URL) fatal("MYSQL_URL is required; MySQL rows never skip");
if (!process.env.REDIS_URL) fatal("REDIS_URL is required; Redis rows never skip");
if (!existsSync(resolve(root, "dist/index.js")) || !existsSync(resolve(root, "dist/bin/init.js"))) fatal("pnpm run build must complete before test:release");
process.env.RUN_RELEASE_MATRIX = "true";

function run(command, args) {
  return new Promise((resolveRun) => {
    execFile(command, args, { cwd: root, env: { ...process.env, NO_COLOR: "1" }, timeout: 180_000, maxBuffer: 20 * 1024 * 1024 },
      (error, stdout, stderr) => resolveRun({ code: error ? 1 : 0, output: `${stdout}${stderr}` }));
  });
}

const integrity = await run(process.execPath, ["scripts/check-release-matrix.mjs"]);
if (integrity.code !== 0) { process.stderr.write(integrity.output); process.exit(integrity.code ?? 1); }

const evidenceByFile = new Map();
for (const row of manifest.rows) {
  for (const evidence of row.evidence) {
    const entry = evidenceByFile.get(evidence.file) ?? new Set();
    entry.add(evidence.name);
    evidenceByFile.set(evidence.file, entry);
  }
}

const runs = await Promise.all([...evidenceByFile].map(async ([file, names]) => {
  const escaped = [...names].map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const pattern = `^(?:${escaped.join("|")})$`;
  const result = await run(process.execPath, ["--test", "--test-reporter=tap", `--test-name-pattern=${pattern}`, file]);
  return { file, names, result };
}));

const failedRuns = runs.filter(({ result }) => result.code !== 0);
if (failedRuns.length > 0) {
  for (const { file, result } of failedRuns) process.stderr.write(`\nrelease evidence failed in ${file}:\n${result.output}`);
  process.exit(1);
}

const results = new Map();
for (const { file, names, result } of runs) {
  for (const name of names) {
    const marker = `# Subtest: ${name}\n`;
    const start = result.output.indexOf(marker);
    // The test's own result line, not merely the next line. A test that declares
    // subtests emits them between its `# Subtest:` marker and its own `ok` line,
    // so reading one line ahead reports a passing parent as `# Subtest: <child>`
    // and fails evidence that is genuinely green. Scan forward for the line that
    // names THIS test, at any indentation, and stop at the first one.
    let outcome = "missing";
    if (start >= 0) {
      const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      // End-anchored, not space-terminated: one evidence name is a strict prefix
      // of another here, and a trailing-space match would let the shorter name
      // resolve against the longer test's result line. TAP allows only a
      // directive comment after the description.
      const own = new RegExp(`^\\s*(not )?ok \\d+ - ${escaped}(?:$|\\s+#)`, "m");
      const rest = result.output.slice(start + marker.length);
      const hit = own.exec(rest);
      outcome = hit === null ? "no result line" : hit[0].trim();
    }
    results.set(`${file}\0${name}`, outcome.startsWith("ok ") && !outcome.includes("# SKIP") ? "pass" : outcome);
  }
}

let failed = false;
for (const row of manifest.rows) {
  const failures = row.evidence.filter((e) => results.get(`${e.file}\0${e.name}`) !== "pass");
  if (failures.length === 0) console.log(`PASS ${row.id} ${row.title} (${row.evidence.length} evidence item${row.evidence.length === 1 ? "" : "s"})`);
  else { failed = true; console.error(`FAIL ${row.id} ${row.title}: ${failures.map((e) => `${e.file} :: ${e.name} [${results.get(`${e.file}\0${e.name}`)}]`).join("; ")}`); }
}
if (failed) process.exit(1);
console.log(`PASS release matrix: ${manifest.rows.length}/${manifest.rows.length} required rows`);
