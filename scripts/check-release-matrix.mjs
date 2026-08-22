import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const manifest = JSON.parse(readFileSync(resolve(root, "test/release-matrix.json"), "utf8"));
const docs = readFileSync(resolve(root, "docs/verification.md"), "utf8");
const pkg = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
const errors = [];
const ids = new Set();

for (const row of manifest.rows) {
  if (ids.has(row.id)) errors.push(`duplicate executable row ${row.id}`);
  ids.add(row.id);
  if (!docs.includes(`### ${row.id} — ${row.title}`)) errors.push(`${row.id} is undocumented or its title drifted`);
  if (!Array.isArray(row.exports) || row.exports.some((name) => typeof name !== "string")) {
    errors.push(`${row.id} requires an exports array of strings`);
  } else {
    if (new Set(row.exports).size !== row.exports.length) errors.push(`${row.id} has duplicate exports`);
    if (row.exports.length > 0 && row.packedArtifact !== true) {
      errors.push(`${row.id} requires packedArtifact true before its exports can count`);
    }
    for (const exportName of row.exports) {
      if (!manifest.requiredExports.includes(exportName)) errors.push(`${row.id} names unknown export ${exportName}`);
    }
  }
  if (!Array.isArray(row.evidence) || row.evidence.length === 0) errors.push(`${row.id} has no executable evidence`);
  for (const evidence of row.evidence ?? []) {
    const path = resolve(root, evidence.file);
    if (!existsSync(path)) { errors.push(`${row.id}: missing ${evidence.file}`); continue; }
    const source = readFileSync(path, "utf8");
    const sourceName = evidence.sourceName ?? evidence.name;
    const literal = JSON.stringify(sourceName);
    const templateLiteral = `\`${sourceName}\``;
    if (!source.includes(literal) && !source.includes(templateLiteral)) {
      errors.push(`${row.id}: test name not found in ${evidence.file}: ${evidence.name}`);
    }
  }
}

const documented = [...docs.matchAll(/^### (RM\.\d+) — /gm)].map((match) => match[1]);
for (const id of documented) if (!ids.has(id)) errors.push(`${id} is documented but not executable`);
for (const file of manifest.requiredExamples) if (!existsSync(resolve(root, file))) errors.push(`shipped example missing: ${file}`);
const actualExports = Object.keys(pkg.exports ?? {}).sort();
const expectedExports = [...manifest.requiredExports].sort();
if (JSON.stringify(actualExports) !== JSON.stringify(expectedExports)) {
  errors.push(`package exports drifted: expected ${expectedExports.join(", ")}; got ${actualExports.join(", ")}`);
}
if (Object.keys(pkg.dependencies ?? {}).join(",") !== "jose") errors.push("published runtime dependencies are no longer jose-only");

if (errors.length > 0) {
  console.error("release matrix integrity failed:");
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}
console.log(`release matrix integrity: ${manifest.rows.length} documented executable rows; examples and exports present`);
