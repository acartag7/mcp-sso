// The command scripts/live/ci/infra/scripts/tofu-run.sh executes:
//
//   bundle-output.mjs <stack> output -raw|-json <name>
//
// It answers from $MCP_SSO_BUNDLE_DIR/<stack>.json exactly as `tofu output`
// would, prints the value and nothing else, and fails with a fixed reason on
// anything it does not recognise. run.sh discards this command's stderr and
// reports its own fixed reason, so nothing here needs to be pretty.
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";
import { BundleError, STACK_HANDLE, bundleOutput, readBundleFile } from "./bundle-support.mjs";

export function answer(argv, env) {
  const [stack, verb, format, name, ...rest] = argv;
  if (verb !== "output" || rest.length !== 0) throw new BundleError("only `<stack> output -raw|-json <name>` is supported");
  if (typeof stack !== "string" || !STACK_HANDLE.test(stack)) throw new BundleError("stack handle is invalid");
  const dir = env.MCP_SSO_BUNDLE_DIR;
  if (typeof dir !== "string" || dir.length === 0) throw new BundleError("MCP_SSO_BUNDLE_DIR is not set");
  return bundleOutput(readBundleFile(join(dir, `${stack}.json`)), name, format);
}

const invokedAsMain = () => {
  try {
    return realpathSync(process.argv[1] ?? "") === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
};

if (invokedAsMain()) {
  try {
    process.stdout.write(answer(process.argv.slice(2), process.env));
  } catch (error) {
    const reason = error instanceof BundleError ? error.message : "output lookup failed";
    process.stderr.write(`bundle-output: ${reason}\n`);
    process.exitCode = 1;
  }
}
