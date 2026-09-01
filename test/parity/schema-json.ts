import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { parseTree, type Node, type ParseError } from "jsonc-parser";
import { type Ajv2020 as Ajv2020Class, type ValidateFunction } from "ajv/dist/2020.js";
import type { FormatsPlugin } from "ajv-formats";
import type { ParityFixture } from "./types.ts";
import { FixtureRunnerError } from "./error.ts";

const PROJECT_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const SCHEMA_PATH = resolve(PROJECT_ROOT, "fixtures/schema/fixture.schema.json");
const require = createRequire(import.meta.url);
const Ajv2020 = (require("ajv/dist/2020.js") as { default: typeof Ajv2020Class }).default;
const addFormats = (require("ajv-formats") as { default: FormatsPlugin }).default;
const ajv = createAjv();
let fixtureValidator: Promise<ValidateFunction> | undefined;

export function compileJsonSchema(schema: Record<string, unknown>): ValidateFunction {
  return createAjv().compile(schema);
}

function createAjv(): InstanceType<typeof Ajv2020Class> {
  const instance = new Ajv2020({ allErrors: true, strict: true });
  addFormats(instance);
  return instance;
}

function parseStrictJson(source: string): unknown {
  const errors: ParseError[] = [];
  const tree = parseTree(source, errors, {
    disallowComments: true,
    allowTrailingComma: false,
    allowEmptyContent: false,
  });
  if (tree === undefined || errors.length > 0) throw new SyntaxError("invalid JSON");
  assertUniqueObjectMembers(tree);
  return JSON.parse(source) as unknown;
}

function assertUniqueObjectMembers(node: Node): void {
  const children = node.children ?? [];
  if (node.type === "object") {
    const names = new Set<string>();
    for (const property of children) {
      if (property.type !== "property") continue;
      const name = property.children?.[0];
      if (name?.type !== "string" || typeof name.value !== "string") continue;
      if (names.has(name.value)) throw new SyntaxError("duplicate object member");
      names.add(name.value);
    }
  }
  for (const child of children) assertUniqueObjectMembers(child);
}

function fixedSchemaValidator(): Promise<ValidateFunction> {
  fixtureValidator ??= readFile(SCHEMA_PATH, "utf8").then((source) => {
    try {
      const schema = parseStrictJson(source);
      if (schema === null || typeof schema !== "object" || Array.isArray(schema)) {
        throw new SyntaxError("invalid JSON");
      }
      return ajv.compile(schema as Record<string, unknown>);
    } catch (error) {
      throw new FixtureRunnerError(`${SCHEMA_PATH}: invalid JSON`, { cause: error });
    }
  });
  return fixtureValidator;
}

export async function loadFixture(path: string): Promise<ParityFixture> {
  let raw: unknown;
  try {
    raw = parseStrictJson(await readFile(path, "utf8"));
  } catch (error) {
    throw new FixtureRunnerError(`${path}: invalid JSON`, { cause: error });
  }
  const validate = await fixedSchemaValidator();
  if (!validate(raw)) {
    const detail = ajv.errorsText(validate.errors, { separator: "; ", dataVar: "fixture" });
    throw new FixtureRunnerError(`${path}: schema validation failed: ${detail}`);
  }
  const fixture = raw as ParityFixture;
  validateHeaderMaps(fixture);
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
