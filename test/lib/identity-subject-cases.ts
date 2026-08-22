export const INVALID_IDENTITY_SUBJECTS = [
  "", " ", " subject", "subject ", "bad\uFFFD", "\uD800", "\uDC00",
  "x".repeat(385), "😀".repeat(385),
] as const;

export const VALID_IDENTITY_SUBJECTS = [
  "x", "x".repeat(384), "😀".repeat(384),
] as const;

export function changingIdentitySubject(): {
  identity: { readonly subject: string };
  reads: () => number;
} {
  let reads = 0;
  const identity = Object.create(null) as { subject: string };
  Object.defineProperty(identity, "subject", {
    enumerable: true,
    get() {
      reads += 1;
      return reads === 1 ? "changing-subject" : " changing-subject";
    },
  });
  return { identity, reads: () => reads };
}
