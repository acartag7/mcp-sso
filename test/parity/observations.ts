export type Observation =
  | { present: false; value?: never }
  | { present: true; value: unknown };

export function headerObservation(
  headers: Record<string, string | string[]>, name: string,
): Observation {
  const key = name.toLowerCase();
  if (!Object.hasOwn(headers, key)) return { present: false };
  return { present: true, value: headers[key] };
}
