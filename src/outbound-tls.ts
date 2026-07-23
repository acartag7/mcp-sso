import { isDataDescriptor } from "./own-property.ts";

const TLS_REJECTION_ENV = "NODE_TLS_REJECT_UNAUTHORIZED";
const TLS_DISABLED_ERROR = "default_outbound_tls_verification_disabled";

/** Refuse Node's process-wide certificate-verification bypass before egress.
 * Explicitly injected transports own their own TLS policy. */
export function assertDefaultTlsVerification(): void {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(process.env, TLS_REJECTION_ENV);
  } catch {
    throw new Error(TLS_DISABLED_ERROR);
  }
  if (descriptor !== undefined
    && (!isDataDescriptor(descriptor) || descriptor.value === "0")) {
    throw new Error(TLS_DISABLED_ERROR);
  }
}

/** The dependency-free default for deployer-trusted HTTPS egress. */
export const guardedGlobalFetch: typeof fetch = async (input, init) => {
  assertDefaultTlsVerification();
  return globalThis.fetch(input, init);
};
