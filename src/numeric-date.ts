import { finiteClockSnapshot } from "./ports/clock.ts";

export function numericDateIso(value: unknown, label: string): string {
  if (!Number.isSafeInteger(value)) throw new Error(`invalid ${label}`);
  const milliseconds = (value as number) * 1000;
  return new Date(finiteClockSnapshot({ nowMs: () => milliseconds })).toISOString();
}
