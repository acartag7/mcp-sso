export function isApplicationJsonContentType(value: string): boolean {
  const essence = value.split(";", 1)[0]!.replace(/^[ \t]+|[ \t]+$/g, "").toLowerCase();
  return essence === "application/json";
}
