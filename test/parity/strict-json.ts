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
