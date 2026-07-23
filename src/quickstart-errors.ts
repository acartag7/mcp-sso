import { ownDataValue } from "./own-property.ts";

export function isErrorWithCode(error: unknown, codes: readonly string[]): boolean {
  const code = ownDataValue(error, "code");
  return typeof code === "string" && codes.includes(code);
}

export function errorMessage(error: unknown): string {
  try {
    const message = ownDataValue(error, "message");
    if (typeof message === "string") return message;
    if (typeof error === "string") return error;
    if (typeof error === "number" || typeof error === "boolean" || typeof error === "bigint") {
      return String(error);
    }
  } catch { /* fixed fallback below */ }
  return "unknown error";
}
