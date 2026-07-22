import { CimdError } from "./errors.ts";
import { parseIp } from "./blocklist.ts";

export interface AdmittedUrl {
  readonly raw: string;
  readonly hostname: string;
  readonly port: number;
}

const DENIED_PORTS = new Set([
  22, 25, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 6379,
  9200, 11211, 27017,
]);

export function admitCimdUrl(
  rawClientId: string,
  opts: { allowLoopback?: boolean } = {},
): AdmittedUrl {
  try {
    return admit(rawClientId, opts.allowLoopback === true);
  } catch (error) {
    if (error instanceof CimdError) throw error;
    throw denied();
  }
}

function admit(raw: string, allowLoopback: boolean): AdmittedUrl {
  if (typeof raw !== "string" || raw === "" || Buffer.byteLength(raw, "utf8") > 2048) {
    throw denied();
  }
  if (!raw.startsWith("https://") || raw.includes("\\") || raw.includes("?") || raw.includes("#")) {
    throw denied();
  }
  if (/^[\x09-\x0d\x20]|[\x09-\x0d\x20]$/.test(raw) || /[\x00-\x1f\x7f]/.test(raw)) {
    throw denied();
  }
  if (/%0[ad]/i.test(raw)) throw denied();

  const pathStart = raw.indexOf("/", 8);
  if (pathStart < 0) throw denied();
  const authority = raw.slice(8, pathStart);
  if (authority.includes("@")) throw denied();
  assertNoDotSegments(raw.slice(pathStart));

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw denied();
  }
  if (url.protocol !== "https:" || url.pathname.length <= 1 || url.search || url.hash) throw denied();
  if (url.username || url.password || url.hostname === "") throw denied();

  const rawHost = extractRawHost(authority);
  if (rawHost === null || !/^[\x00-\x7f]+$/.test(rawHost)) throw denied();
  if (rawHost.toLowerCase() !== url.hostname.toLowerCase()) throw denied();
  // A pre-encoded IDNA A-label (xn--…) is pure ASCII and equals url.hostname, so it
  // would slip the checks above — but it is a punycode identity, deferred to §18 (rule 6).
  if (/(^|\.)xn--/i.test(url.hostname)) throw denied();

  const hostname = url.hostname;
  const unbracketed = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  if (hostname.startsWith("[") || parseIp(unbracketed) !== null) throw denied();
  if (hostname.endsWith(".")) throw denied();

  const localhost = hostname === "localhost" || hostname.endsWith(".localhost");
  if (localhost && !allowLoopback) throw denied();

  // Fail closed on an invalid port: `:0` parses to port 0 (WHATWG keeps "0"), which
  // node:https would coerce to the 443 default — a raw-identity(:0)/connect(:443)
  // differential. WHATWG already rejects > 65535 at parse; the bounds are explicit here.
  const port = url.port === "" ? 443 : Number(url.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535 || DENIED_PORTS.has(port)) throw denied();
  return { raw, hostname, port };
}

function assertNoDotSegments(rawPath: string): void {
  for (const segment of rawPath.split("/")) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      throw denied();
    }
    if (decoded === "." || decoded === "..") throw denied();
  }
}

function extractRawHost(authority: string): string | null {
  if (authority === "") return null;
  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    return close < 0 ? null : authority.slice(0, close + 1);
  }
  const colon = authority.lastIndexOf(":");
  return colon < 0 ? authority : authority.slice(0, colon);
}

function denied(): CimdError {
  return new CimdError("url_admission_denied");
}
