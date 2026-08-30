import assert from "node:assert/strict";
import { existsSync, realpathSync } from "node:fs";
import { copyFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  authorize, denyAuthorization, fetchBounded, freePort, postForm, run, sdkPing, startGenerated, type GeneratedServer,
} from "./lib/release-packed-flow.ts";

const repo = fileURLToPath(new URL("..", import.meta.url));
const allowedPackageRoots = new Set(["dist", "docs", "fixtures", "README.md", "LICENSE", "package.json"]);
const requiredFixtureFiles = new Set([
  "fixtures/08-resource-server-verifier/8.4-duplicate-authorization-fails-closed.json",
  "fixtures/FREEZE-LOG.md",
  "fixtures/README.md",
  "fixtures/keys/signing-private.pem",
  "fixtures/keys/signing-public.pem",
  "fixtures/schema/fixture.schema.json",
]);
const releaseTest = process.env.RUN_RELEASE_MATRIX === "true" ? test : test.skip;

function exportTargets(value: unknown, label: string): string[] {
  if (typeof value === "string") return [value];
  assert.ok(value && typeof value === "object" && !Array.isArray(value), `${label} is a string or condition map`);
  return Object.entries(value).flatMap(([condition, target]) => exportTargets(target, `${label}.${condition}`));
}

function jsonArray(output: string): unknown[] {
  const start = output.indexOf("["); const end = output.lastIndexOf("]");
  if (start < 0 || end < start) throw new Error(`expected JSON array in output:\n${output}`);
  return JSON.parse(output.slice(start, end + 1)) as unknown[];
}

async function installOffline(cwd: string, label: string): Promise<void> {
  const lock = await run("pnpm", ["install", "--lockfile-only", "--offline", "--ignore-scripts", "--no-frozen-lockfile"], cwd);
  assert.equal(lock.code, 0, `${label} lock resolution failed:\n${lock.output}`);
  await installFrozenOffline(cwd, label);
}

async function installFrozenOffline(cwd: string, label: string): Promise<void> {
  const install = await run("pnpm", ["install", "--offline", "--ignore-scripts", "--frozen-lockfile"], cwd);
  assert.equal(install.code, 0, `${label} install failed:\n${install.output}`);
}

function lockEntry(importer: string, name: string): string {
  const marker = name.startsWith("@") ? `      '${name}':\n` : `      ${name}:\n`;
  const start = importer.indexOf(marker); assert.notEqual(start, -1, `copied lock contains ${name}`);
  const tail = importer.slice(start + marker.length);
  const next = tail.search(/^      (?:'[^']+'|[^\s][^:]*):\n/m);
  return marker + (next < 0 ? tail : tail.slice(0, next));
}

async function writeStandaloneLock(source: string, target: string): Promise<void> {
  const lock = await readFile(source, "utf8"); const packagesAt = lock.indexOf("\npackages:\n");
  const importersAt = lock.indexOf("importers:\n"); assert.notEqual(importersAt, -1); assert.notEqual(packagesAt, -1);
  const importer = lock.slice(lock.indexOf("  .:\n", importersAt), packagesAt);
  const sdk = lockEntry(importer, "@modelcontextprotocol/sdk"); const fastify = lockEntry(importer, "fastify");
  const fastifyRateLimit = lockEntry(importer, "@fastify/rate-limit");
  const mcp = lockEntry(importer, "mcp-sso").replace("specifier: file:./", "specifier: file:../");
  const standalone = `importers:\n\n  .: {}\n\n  generated:\n    dependencies:\n${sdk}${fastifyRateLimit}${fastify}${mcp}`;
  await writeFile(target, lock.slice(0, importersAt) + standalone + lock.slice(packagesAt));
}

releaseTest("RM.1 packed generated server uses the installed npm bin for the complete lifecycle", async () => {
  const base = await mkdtemp(join(tmpdir(), "mcp-sso-release-pack-"));
  const realBase = realpathSync(base);
  const scaffoldRoot = await mkdtemp(join(tmpdir(), "mcp-sso-release-scaffold-"));
  const realScaffoldRoot = realpathSync(scaffoldRoot);
  const generated = join(scaffoldRoot, "generated");
  const stateDir = join(base, "state");
  const repoPkg = JSON.parse(await readFile(join(repo, "package.json"), "utf8")) as {
    version: string; packageManager: string; dependencies: Record<string, string>; devDependencies: Record<string, string>;
    exports: Record<string, unknown>;
  };
  let server: GeneratedServer | undefined;
  try {
    const packed = await run("npm", ["pack", "--ignore-scripts", "--json", "--pack-destination", base], repo);
    assert.equal(packed.code, 0, packed.output);
    const packEntry = jsonArray(packed.output)[0] as { filename: string; files: Array<{ path: string }> };
    const tarball = resolve(base, packEntry.filename);
    assert.ok(existsSync(tarball), "npm pack produced the tarball in the private temporary directory");
    const packedRoots = new Set<string>();
    const packedFiles = new Set(packEntry.files.map((file) => file.path));
    for (const file of packEntry.files) {
      const root = file.path.split("/", 1)[0];
      assert.ok(root && allowedPackageRoots.has(root), `unexpected packed root: ${file.path}`);
      packedRoots.add(root);
    }
    assert.deepEqual([...packedRoots].sort(), [...allowedPackageRoots].sort(), "packed roots exactly match the public artifact contract");
    for (const file of requiredFixtureFiles) assert.ok(packedFiles.has(file), `packed artifact contains ${file}`);
    const josePack = await run("npm", ["pack", "--ignore-scripts", "--json", "--pack-destination", base, join(repo, "node_modules", "jose")], repo);
    assert.equal(josePack.code, 0, `local jose pack failed:\n${josePack.output}`);
    const joseTarball = (jsonArray(josePack.output)[0] as { filename: string }).filename;
    const zodDir = realpathSync(join(repo, "node_modules", ".pnpm", "node_modules", "zod"));
    const zodPack = await run("pnpm", ["--dir", zodDir, "pack", "--pack-destination", base], repo);
    assert.equal(zodPack.code, 0, `local zod pack failed:\n${zodPack.output}`);
    const zodTarball = basename(zodPack.output.trim().split("\n").at(-1) ?? ""); assert.match(zodTarball, /^zod-4\.4\.3\.tgz$/);

    const packageOverrides = { [`mcp-sso@${repoPkg.version}`]: `file:./${basename(tarball)}`,
      jose: `file:./${joseTarball}`, zod: `file:./${zodTarball}` };
    const rootPackage = {
      name: "mcp-sso-release-consumer", private: true, type: "module", packageManager: repoPkg.packageManager,
      dependencies: {
        "mcp-sso": `file:./${basename(tarball)}`,
        jose: `file:./${joseTarball}`,
        zod: `file:./${zodTarball}`,
        "@modelcontextprotocol/sdk": repoPkg.devDependencies["@modelcontextprotocol/sdk"],
        "@fastify/rate-limit": repoPkg.devDependencies["@fastify/rate-limit"],
        fastify: repoPkg.devDependencies.fastify, express: repoPkg.devDependencies.express, hono: repoPkg.devDependencies.hono,
        mysql2: repoPkg.devDependencies.mysql2, ioredis: repoPkg.devDependencies.ioredis,
      },
      devDependencies: { typescript: repoPkg.devDependencies.typescript, "@types/node": repoPkg.devDependencies["@types/node"],
        "@types/express": repoPkg.devDependencies["@types/express"] },
      pnpm: { overrides: packageOverrides },
    };
    await writeFile(join(base, "package.json"), JSON.stringify(rootPackage, null, 2));
    await copyFile(join(repo, "pnpm-lock.yaml"), join(base, "pnpm-lock.yaml"));
    await installOffline(base, "private tarball");

    const installedPackage = realpathSync(join(base, "node_modules", "mcp-sso"));
    assert.ok(installedPackage.startsWith(realBase), `mcp-sso resolved outside the isolated consumer: ${installedPackage}`);
    assert.notEqual(installedPackage, repo, "the consumer did not link the source checkout");
    const installedPkg = JSON.parse(await readFile(join(installedPackage, "package.json"), "utf8")) as {
      dependencies: Record<string, string>; exports: Record<string, unknown>;
    };
    assert.deepEqual(Object.keys(installedPkg.dependencies), ["jose"], "published runtime dependencies remain jose-only");
    assert.deepEqual(installedPkg.exports, repoPkg.exports, "the packed export map matches the reviewed package map");
    for (const [entry, conditions] of Object.entries(installedPkg.exports)) {
      for (const target of exportTargets(conditions, `exports.${entry}`)) {
        assert.match(target, /^\.\//, `packed export ${entry} uses a package-relative target`);
        const resolvedTarget = resolve(installedPackage, target);
        assert.ok(resolvedTarget.startsWith(`${installedPackage}/`) && existsSync(resolvedTarget),
          `packed export ${entry} target exists: ${target}`);
      }
    }

    const installedBin = join(base, "node_modules", ".bin", "mcp-sso");
    assert.ok(installedBin.startsWith(base) && installedBin.includes("node_modules/.bin/mcp-sso") && existsSync(installedBin),
      "the entrypoint is the installed npm bin, never source/dist");
    const scaffold = await run(installedBin, ["init", generated], base);
    assert.equal(scaffold.code, 0, `installed mcp-sso bin failed:\n${scaffold.output}`);
    const generatedPkg = JSON.parse(await readFile(join(generated, "package.json"), "utf8")) as { dependencies: Record<string, string> };
    assert.equal(generatedPkg.dependencies["mcp-sso"], repoPkg.version);
    assert.equal(generatedPkg.dependencies.fastify, repoPkg.devDependencies.fastify);
    assert.equal(generatedPkg.dependencies["@fastify/rate-limit"], repoPkg.devDependencies["@fastify/rate-limit"]);
    assert.equal(generatedPkg.dependencies["@modelcontextprotocol/sdk"], repoPkg.devDependencies["@modelcontextprotocol/sdk"]);
    assert.equal(Object.values(generatedPkg.dependencies).some((version) => /^[~^]/.test(version)), false, "generated versions stay exact");

    await writeFile(join(scaffoldRoot, "package.json"), JSON.stringify({ name: "mcp-sso-release-scaffold-root", private: true,
      packageManager: repoPkg.packageManager, pnpm: { overrides: packageOverrides } }, null, 2));
    await writeFile(join(scaffoldRoot, "pnpm-workspace.yaml"), "packages:\n  - generated\n");
    for (const artifact of [basename(tarball), joseTarball, zodTarball]) {
      await copyFile(join(base, artifact), join(scaffoldRoot, artifact));
    }
    await writeStandaloneLock(join(base, "pnpm-lock.yaml"), join(scaffoldRoot, "pnpm-lock.yaml"));
    await installFrozenOffline(scaffoldRoot, "standalone generated scaffold");
    const installedFromGenerated = realpathSync(join(generated, "node_modules", "mcp-sso"));
    assert.ok(installedFromGenerated.startsWith(realScaffoldRoot)); assert.equal(installedFromGenerated.startsWith(realBase), false);
    assert.notEqual(installedFromGenerated, repo);
    for (const undeclared of ["express", "hono", "mysql2", "ioredis"]) {
      assert.equal(existsSync(join(scaffoldRoot, "node_modules", undeclared)), false,
        `standalone scaffold cannot borrow consumer-only dependency ${undeclared}`);
    }
    const imports = Object.keys(repoPkg.exports).map((entry) => entry === "." ? "mcp-sso" : `mcp-sso/${entry.slice(2)}`);
    const packedImports = Object.keys(installedPkg.exports).map((entry) => entry === "." ? "mcp-sso" : `mcp-sso/${entry.slice(2)}`);
    assert.deepEqual(imports, packedImports, "the import probe covers every export in the packed artifact");
    const importCheck = await run(process.execPath, ["--input-type=module", "-e", `await Promise.all(${JSON.stringify(imports)}.map((id)=>import(id)))`], generated);
    assert.equal(importCheck.code, 0, `published export import failed:\n${importCheck.output}`);
    const typeImports = imports.map((entry, index) => `import * as entry${index} from ${JSON.stringify(entry)};\nvoid entry${index};`).join("\n");
    await writeFile(join(base, "all-exports.ts"), typeImports);
    await writeFile(join(base, "tsconfig.exports.json"), JSON.stringify({ compilerOptions: { module: "nodenext",
      moduleResolution: "nodenext", target: "ES2023", strict: true, noEmit: true, skipLibCheck: true, types: ["node"] },
    include: ["all-exports.ts"] }, null, 2));
    const exportTypecheck = await run(join(base, "node_modules", ".bin", "tsc"), ["-p", join(base, "tsconfig.exports.json")], base);
    assert.equal(exportTypecheck.code, 0, `published export declaration check failed:\n${exportTypecheck.output}`);

    await writeFile(join(generated, "tsconfig.json"), JSON.stringify({ compilerOptions: { module: "nodenext", moduleResolution: "nodenext",
      target: "ES2023", strict: true, noEmit: true, skipLibCheck: true, types: ["node"],
      typeRoots: [join(base, "node_modules", "@types")] }, include: ["server.ts"] }, null, 2));
    const typecheck = await run(join(base, "node_modules", ".bin", "tsc"), ["--noEmit", "-p", join(generated, "tsconfig.json")], generated);
    assert.equal(typecheck.code, 0, `generated server typecheck failed:\n${typecheck.output}`);

    const port = await freePort();
    server = await startGenerated(generated, stateDir, port);
    const prm = await fetchBounded(`${server.origin}/.well-known/oauth-protected-resource`); assert.equal(prm.status, 200);
    const metadata = await fetchBounded(`${server.origin}/.well-known/oauth-authorization-server`); assert.equal(metadata.status, 200);
    assert.equal((await metadata.json() as { client_id_metadata_document_supported: boolean }).client_id_metadata_document_supported, true);
    const registration = await fetchBounded(`${server.origin}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["http://localhost:4321/callback"], application_type: "native" }) });
    assert.equal(registration.status, 201);
    const clientId = (await registration.json() as { client_id: string }).client_id; assert.match(clientId, /^mcpdc_/);
    await server.stop(); server = undefined;
    server = await startGenerated(generated, stateDir, port);
    const firstVerifier = "release-pack-first-0123456789abcdef0123456789012345";
    const denyVerifier = "release-pack-deny-0123456789abcdef01234567890123456";
    const secondVerifier = "release-pack-second-0123456789abcdef012345678901234";
    const first = await authorize(server, clientId, firstVerifier);
    let visiblePong: string | undefined;
    visiblePong = await sdkPing(server.origin, first.accessToken);
    assert.equal(visiblePong, "pong: console-operator", "RM.1 cannot pass without the protected ping/pong call");

    await server.stop(); server = undefined;
    server = await startGenerated(generated, stateDir, port);
    const refreshed = await postForm(server.origin, "/oauth/token", { grant_type: "refresh_token", refresh_token: first.refreshToken, client_id: clientId });
    assert.equal(refreshed.status, 200, "SQLite state survived generated-server restart");
    const successor = (await refreshed.json() as { refresh_token: string }).refresh_token;
    assert.ok(successor); assert.notEqual(successor, first.refreshToken, "refresh rotated to a distinct successor");
    const replay = await postForm(server.origin, "/oauth/token", { grant_type: "refresh_token", refresh_token: first.refreshToken, client_id: clientId });
    assert.equal(replay.status, 400);
    assert.equal((await postForm(server.origin, "/oauth/token", { grant_type: "refresh_token", refresh_token: successor, client_id: clientId })).status, 400,
      "replay revoked the rotated family");

    const deniedConsent = await denyAuthorization(server, clientId, denyVerifier);
    const second = await authorize(server, clientId, secondVerifier);
    assert.equal((await postForm(server.origin, "/oauth/revoke", { token: second.refreshToken })).status, 200);
    assert.equal((await postForm(server.origin, "/oauth/token", { grant_type: "refresh_token", refresh_token: second.refreshToken, client_id: clientId })).status, 400);
    await server.stop(); server = undefined;
    assert.ok(existsSync(join(stateDir, "auth.db")), "generated server used persistent SQLite");
    const audit = await readFile(join(stateDir, "audit.jsonl"), "utf8");
    for (const line of audit.trim().split("\n")) JSON.parse(line);
    const persistedSecrets = JSON.parse(await readFile(join(stateDir, "secrets.json"), "utf8")) as {
      consentSigningSecret: string; signingPrivateJwk: { d: string };
    };
    for (const secret of [first.pairingCode, first.consentToken, first.authCode, first.accessToken, first.refreshToken, successor,
      deniedConsent, second.pairingCode, second.consentToken, second.authCode, second.accessToken, second.refreshToken,
      firstVerifier, denyVerifier, secondVerifier,
      persistedSecrets.consentSigningSecret, persistedSecrets.signingPrivateJwk.d]) {
      assert.equal(audit.includes(secret), false, "JSONL evidence contains no raw credential, consent token, or signing material");
    }
  } finally {
    await server?.stop(); await rm(base, { recursive: true, force: true });
    await rm(scaffoldRoot, { recursive: true, force: true });
  }
});
