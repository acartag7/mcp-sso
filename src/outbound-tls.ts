import { isDataDescriptor } from "./own-property.ts";

const TLS_REJECTION_ENV = "NODE_TLS_REJECT_UNAUTHORIZED";
const TLS_DISABLED_ERROR = "default_outbound_tls_verification_disabled";

/** Refuse Node's process-wide certificate-verification bypass before egress.
 * Explicitly injected transports own their own TLS policy. */
export function assertDefaultTlsVerification(): void {
  let current: object | null = process.env;
  const visited = new Set<object>();
  try {
    while (current !== null) {
      if (visited.has(current) || visited.size >= 32) throw new Error(TLS_DISABLED_ERROR);
      visited.add(current);
      const descriptor = Object.getOwnPropertyDescriptor(current, TLS_REJECTION_ENV);
      if (descriptor !== undefined) {
        if (current !== process.env
          || !isDataDescriptor(descriptor) || descriptor.value === "0") {
          throw new Error(TLS_DISABLED_ERROR);
        }
        return;
      }
      current = Object.getPrototypeOf(current) as object | null;
    }
  } catch {
    throw new Error(TLS_DISABLED_ERROR);
  }
}

/** The dependency-free default for deployer-trusted HTTPS egress. */
export const guardedGlobalFetch: typeof fetch = async (input, init) => {
  assertDefaultTlsVerification();
  return globalThis.fetch(input, init);
};
