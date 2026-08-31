import { readFile, readdir } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { type Ajv2020 as Ajv2020Class, type ValidateFunction } from "ajv/dist/2020.js";
import type { FormatsPlugin } from "ajv-formats";
import type { ParityFixture } from "./types.ts";
import { FixtureRunnerError } from "./error.ts";

export const PROJECT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
export const FIXTURES_ROOT = resolve(PROJECT_ROOT, "fixtures");
const SCHEMA_PATH = resolve(FIXTURES_ROOT, "schema/fixture.schema.json");
const require = createRequire(import.meta.url);
const Ajv2020 = (require("ajv/dist/2020.js") as { default: typeof Ajv2020Class }).default;
const addFormats = (require("ajv-formats") as { default: FormatsPlugin }).default;
const ajv = createAjv();
let fixtureValidator: ValidateFunction | undefined;
const ROOT_FILES = new Set(["README.md", "FREEZE-LOG.md", "MANIFEST.json", "CATALOGUE.md"]);
const ROOT_DIRECTORIES = new Set(["keys", "schema"]);

export function compileJsonSchema(schema: Record<string, unknown>): ValidateFunction {
  return createAjv().compile(schema);
}

function createAjv(): InstanceType<typeof Ajv2020Class> {
  const instance = new Ajv2020({ allErrors: true, strict: true }); addFormats(instance); return instance;
}

export async function loadCorpus(root = FIXTURES_ROOT): Promise<ParityFixture[]> {
  const validate = await validator();
  const paths = await fixturePaths(root);
  const fixtures: ParityFixture[] = [];
  const ids = new Set<string>();
  for (const path of paths) {
    const fixture = await loadFixture(path, root, validate);
    if (ids.has(fixture.id)) throw new FixtureRunnerError(`duplicate fixture id: ${fixture.id}`);
    ids.add(fixture.id);
    fixtures.push(fixture);
  }
  validateSupersededFixtures(fixtures);
  validateChains(fixtures);
  return fixtures;
}

async function validator(): Promise<ValidateFunction> {
  if (fixtureValidator) return fixtureValidator;
  const schema = JSON.parse(await readFile(SCHEMA_PATH, "utf8")) as Record<string, unknown>;
  fixtureValidator = ajv.compile(schema);
  return fixtureValidator as ValidateFunction;
}

async function fixturePaths(root: string): Promise<string[]> {
  const entries = await readdir(root, { withFileTypes: true });
  const paths: string[] = [];
  for (const entry of entries) {
    if (ROOT_FILES.has(entry.name)) {
      if (!entry.isFile()) throw new FixtureRunnerError(`${entry.name}: corpus root artifact must be a file`);
      continue;
    }
    if (ROOT_DIRECTORIES.has(entry.name)) {
      if (!entry.isDirectory()) throw new FixtureRunnerError(`${entry.name}: corpus root artifact must be a directory`);
      continue;
    }
    if (!/^(0[1-9]|1[0-9])-/.test(entry.name)) {
      throw new FixtureRunnerError(`${entry.name}: unexpected corpus root entry`);
    }
    if (!entry.isDirectory()) throw new FixtureRunnerError(`${entry.name}: numbered corpus section must be a directory`);
    const directory = resolve(root, entry.name);
    for (const file of await readdir(directory, { withFileTypes: true })) {
      if (!file.isFile() || !file.name.endsWith(".json")) {
        throw new FixtureRunnerError(`${entry.name}/${file.name}: unexpected corpus entry`);
      }
      paths.push(resolve(directory, file.name));
    }
  }
  return paths.sort();
}

async function loadFixture(path: string, root: string, validate: ValidateFunction): Promise<ParityFixture> {
  let raw: unknown;
  try { raw = JSON.parse(await readFile(path, "utf8")); }
  catch (error) { throw new FixtureRunnerError(`${path}: invalid JSON`, { cause: error }); }
  if (!validate(raw)) {
    const detail = ajv.errorsText(validate.errors, { separator: "; ", dataVar: "fixture" });
    throw new FixtureRunnerError(`${path}: schema validation failed: ${detail}`);
  }
  const fixture = raw as ParityFixture;
  validateHeaderMaps(fixture);
  const expectedId = relative(root, path).split(sep).join("/").replace(/\.json$/u, "");
  validateFixtureIdentity(fixture, expectedId, path);
  await validateQuote(fixture);
  return fixture;
}

function validateHeaderMaps(fixture: ParityFixture): void {
  for (const [index, exchange] of fixture.given.http.entries()) {
    validateHeaderMap(exchange.response.headers, `${fixture.id} HTTP response ${index + 1}`);
  }
  if (fixture.kind !== "fixture") return;
  validateHeaderMap(fixture.when.request.headers, `${fixture.id} inbound request`);
  validateHeaderMap(fixture.given.protectedResource.success?.headers, `${fixture.id} protected response`);
}

function validateHeaderMap(headers: Record<string, unknown> | undefined, label: string): void {
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (Array.isArray(value) && value.length < 2) {
      throw new FixtureRunnerError(`${label} header ${name} must use a string for one occurrence or an array for multiple occurrences`);
    }
  }
}

export function validateFixtureIdentity(fixture: ParityFixture, expectedId: string, label: string): void {
  if (fixture.id !== expectedId) {
    throw new FixtureRunnerError(`${label}: id ${fixture.id} does not match path ${expectedId}`);
  }
  const [directory, filename] = expectedId.split("/");
  const section = directory?.slice(0, directory.indexOf("-"));
  const clause = filename?.slice(0, filename.indexOf("-"));
  if (section !== fixture.contract.section) {
    throw new FixtureRunnerError(`${label}: id section ${section} does not match contract section ${fixture.contract.section}`);
  }
  if (clause !== fixture.contract.clause) {
    throw new FixtureRunnerError(`${label}: id clause ${clause} does not match contract clause ${fixture.contract.clause}`);
  }
  if (Number(clause.split(".", 1)[0]) !== Number(section)) {
    throw new FixtureRunnerError(`${label}: contract clause ${clause} does not belong to section ${section}`);
  }
}

async function validateQuote(fixture: ParityFixture): Promise<void> {
  const entries = await readdir(resolve(PROJECT_ROOT, "docs/contracts"));
  const prefix = `${fixture.contract.section}-`;
  const names = entries.filter((name) => name.startsWith(prefix) && name.endsWith(".md"));
  if (names.length !== 1) throw new FixtureRunnerError(`${fixture.id}: contract section file is ambiguous`);
  const source = await readFile(resolve(PROJECT_ROOT, "docs/contracts", names[0]!), "utf8");
  const clause = clauseSource(source, fixture.contract.clause);
  if (!clause.includes(fixture.contract.quote)) {
    throw new FixtureRunnerError(`${fixture.id}: contract quote is stale in clause ${fixture.contract.clause}`);
  }
}

export function clauseSource(source: string, clause: string): string {
  const escaped = clause.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const heading = new RegExp(`^(#{1,6})\\s+${escaped}\\.?(?:\\s|$)`, "mu").exec(source);
  if (heading === null || !heading[1]) throw new FixtureRunnerError(`contract clause ${clause} was not found`);
  const level = heading[1].length;
  const rest = source.slice(heading.index + heading[0].length);
  const next = new RegExp(`^#{1,${level}}\\s+`, "mu").exec(rest);
  return rest.slice(0, next?.index ?? rest.length);
}

function validateSupersededFixtures(fixtures: ParityFixture[]): void {
  const byId = new Map(fixtures.map((fixture) => [fixture.id, fixture]));
  for (const fixture of fixtures) {
    if (fixture.status !== "superseded") continue;
    const replacement = fixture.supersededBy ? byId.get(fixture.supersededBy) : undefined;
    if (!replacement) {
      throw new FixtureRunnerError(`${fixture.id}: supersededBy must name a loaded fixture`);
    }
    if (replacement === fixture) {
      throw new FixtureRunnerError(`${fixture.id}: supersededBy must name a different fixture`);
    }
  }
  for (const fixture of fixtures) {
    if (fixture.status !== "superseded") continue;
    const seen = new Set<string>();
    let current = fixture;
    while (current.status === "superseded") {
      if (seen.has(current.id)) {
        throw new FixtureRunnerError(`${fixture.id}: supersededBy chain contains a cycle`);
      }
      seen.add(current.id);
      current = byId.get(current.supersededBy!)!;
    }
  }
}

export function validateChains(fixtures: ParityFixture[]): void {
  const byId = new Map(fixtures.map((fixture) => [fixture.id, fixture]));
  const chains = new Map<string, ParityFixture[]>();
  for (const fixture of fixtures) {
    if (!fixture.chain) continue;
    const members = chains.get(fixture.chain.id) ?? [];
    members.push(fixture); chains.set(fixture.chain.id, members);
  }
  for (const [chainId, members] of chains) {
    const ordered = members.toSorted((a, b) => a.chain!.step - b.chain!.step);
    const captureNames = new Set<string>();
    for (let index = 0; index < ordered.length; index += 1) {
      const fixture = ordered[index]!;
      if (fixture.chain!.step !== index + 1) throw new FixtureRunnerError(`${chainId}: chain steps must be contiguous`);
      const expected = index === 0 ? undefined : ordered[index - 1]!.id;
      if (fixture.chain!.previous !== expected) throw new FixtureRunnerError(`${fixture.id}: wrong chain predecessor`);
      if (fixture.chain!.previous && byId.get(fixture.chain!.previous)?.chain?.id !== chainId) {
        throw new FixtureRunnerError(`${fixture.id}: predecessor belongs to another chain`);
      }
      if (fixture.kind !== "fixture") continue;
      for (const capture of fixture.then.captures ?? []) {
        if (captureNames.has(capture.name)) {
          throw new FixtureRunnerError(`${chainId}: duplicate capture name ${capture.name}`);
        }
        captureNames.add(capture.name);
      }
    }
  }
}
