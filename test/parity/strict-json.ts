import { parseTree, type Node, type ParseError } from "jsonc-parser";

export function parseStrictJson(source: string): unknown {
  const errors: ParseError[] = [];
  const tree = parseTree(source, errors, {
    disallowComments: true,
    allowTrailingComma: false,
    allowEmptyContent: false,
  });
  if (tree === undefined || errors.length > 0) throw new SyntaxError("invalid JSON");
  assertUniqueObjectMembers(tree);
  assertExactNumbers(tree, source);
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

function assertExactNumbers(node: Node, source: string): void {
  if (node.type === "number") {
    const raw = source.slice(node.offset, node.offset + node.length);
    if (typeof node.value !== "number" || !Number.isFinite(node.value)
      || normalizeDecimal(raw) !== normalizeDecimal(node.value.toString())) {
      throw new SyntaxError("lossy JSON number");
    }
  }
  for (const child of node.children ?? []) assertExactNumbers(child, source);
}

function normalizeDecimal(source: string): string {
  const match = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/u.exec(source);
  if (match === null) throw new SyntaxError("invalid JSON number");
  const fraction = match[3] ?? "";
  let digits = `${match[2]}${fraction}`.replace(/^0+/u, "");
  if (digits.length === 0) return "0";
  let exponent = BigInt(match[4] ?? "0") - BigInt(fraction.length);
  const trailingZeroes = /0+$/u.exec(digits)?.[0].length ?? 0;
  if (trailingZeroes > 0) {
    digits = digits.slice(0, -trailingZeroes);
    exponent += BigInt(trailingZeroes);
  }
  return `${match[1]}${digits}e${exponent}`;
}
