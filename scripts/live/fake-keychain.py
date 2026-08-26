"""A private stand-in for macOS `security`, for a CLI run in a disposable HOME.

Claude Code on macOS keeps its MCP OAuth state in the login keychain through
`security`, so a probe run would write into the operator's real keychain item
and read it back unreliably. Installed as `security` on the CLI's PATH, this
keeps that state in an owner-only file inside the private HOME instead, and
implements only the three forms the CLI uses:

    security find-generic-password -a <account> -w -s <service>
    security -i        (stdin: add-generic-password -U -a "<a>" -s "<s>" -X "<hex>")
    security delete-generic-password -a <account> -s <service>

A missing item exits 44, as the real tool does. Anything else exits 1.
"""
import json
import os
import shlex
import sys

HOME = os.environ.get("HOME", "")
if HOME == "":
    sys.exit(1)
STORE = os.path.join(HOME, ".mcp-sso-keychain.json")


def load():
    try:
        with open(STORE, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return {}


def save(items):
    fd = os.open(STORE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(items, handle)


def option(args, flag):
    return args[args.index(flag) + 1] if flag in args and args.index(flag) + 1 < len(args) else None


def key(args):
    account, service = option(args, "-a"), option(args, "-s")
    if account is None or service is None:
        sys.exit(1)
    return f"{account}\0{service}"


def main(argv):
    if argv[:1] == ["-i"]:
        for line in sys.stdin:
            words = shlex.split(line)
            if not words:
                continue
            if words[:1] != ["add-generic-password"]:
                sys.exit(1)
            data = option(words, "-X")
            if data is None:
                sys.exit(1)
            try:
                value = bytes.fromhex(data).decode("utf-8")
            except ValueError:
                sys.exit(1)
            items = load()
            items[key(words)] = value
            save(items)
        return
    if argv[:1] == ["find-generic-password"]:
        value = load().get(key(argv))
        if value is None:
            sys.stderr.write("security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n")
            sys.exit(44)
        if "-w" in argv:
            sys.stdout.write(value + "\n")
        return
    if argv[:1] == ["delete-generic-password"]:
        items = load()
        if items.pop(key(argv), None) is None:
            sys.exit(44)
        save(items)
        return
    sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
