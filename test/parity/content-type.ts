export function contentTypeEssence(value: string): string {
  return value.split(";", 1)[0]!.replace(/^[ \t]+|[ \t]+$/g, "").toLowerCase();
}

export function isApplicationJsonContentType(value: string): boolean {
  return contentTypeEssence(value) === "application/json";
}
