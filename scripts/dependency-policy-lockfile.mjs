import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

// Resolved-package keys in a pnpm lockfile, e.g.
//   fast-uri@3.1.2:
//   '@hono/node-server@1.19.17(hono@4.12.34)':
//   express-rate-limit@8.5.2(express@5.2.1): {}
// Anything between the version and the terminal quote/colon — peer groups
// (single, repeated, or nested) and patch hashes — identifies build variants
// of one resolution, not distinct versions, so it is accepted and ignored.
// Unrecognized package-key shapes are NOT ignored: an alias key such as
// 'foo@npm:bar@1.0.0' resolves bar@1.0.0 into the tree under another name, so
// silently skipping it would hide a second resolution of bar and let a
// transitive record for a different bar version pass while an affected build
// still executes. Any key-shaped line the parser cannot classify fails closed.
const SECTION_KEY = /^([A-Za-z][A-Za-z0-9]*):/;
const PACKAGE_KEY = /^ {2}'?((?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*)@(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)[^':]*'?:/;
const KEY_LINE = /^ {2}\S.*:\s*(?:\{\}\s*)?$/;

/**
 * Every package version the committed lockfile resolves, as a Map from package
 * name to the set of its resolved versions (from the `packages:` section; the
 * `snapshots:` section must agree). Fails closed: an unreadable lockfile
 * throws, a package the tree does not resolve is absent, and a snapshots:
 * resolution without a packages: counterpart throws — lockfile format drift
 * fails loudly here instead of silently under-counting versions.
 */
export async function lockfilePackageVersions(root = process.cwd()) {
  const source = await readFile(resolve(root, "pnpm-lock.yaml"), "utf8");
  const packages = new Map();
  const snapshots = new Map();
  let section = "";
  for (const line of source.split(/\r?\n/)) {
    const sectionMatch = SECTION_KEY.exec(line);
    if (sectionMatch) {
      section = sectionMatch[1];
      continue;
    }
    if (section !== "packages" && section !== "snapshots") continue;
    const keyMatch = PACKAGE_KEY.exec(line);
    if (!keyMatch) {
      if (KEY_LINE.test(line)) {
        throw new Error(
          `pnpm-lock.yaml ${section} contains an unsupported package key shape: ${line.trim()};`
          + " transitive advisory bindings fail closed on keys the parser cannot classify",
        );
      }
      continue;
    }
    const target = section === "packages" ? packages : snapshots;
    const resolved = target.get(keyMatch[1]) ?? new Set();
    resolved.add(keyMatch[2]);
    target.set(keyMatch[1], resolved);
  }
  for (const [name, versions] of snapshots) {
    const known = packages.get(name);
    for (const version of versions) {
      if (!known?.has(version)) {
        throw new Error(
          `pnpm-lock.yaml snapshots resolve ${name}@${version} without a packages: entry;`
          + " lockfile format drift must be resolved before trusting transitive advisory bindings",
        );
      }
    }
  }
  return packages;
}
