"""Run a command on a wide pseudo-terminal and relay its input and output.

A CLI that refuses a non-terminal stdin, or that wraps what it prints to the
terminal's width, runs here as if on a 400-column terminal, wide enough for
the authorization URLs these CLIs print (a wrapped URL is refused by the
reader, never joined). Stdin is relayed to the command, and
closing it sends the terminal's end-of-transmission character; the command's
exit status becomes this process's exit status, and a termination signal to
this process kills the command's whole process group.

    python3 pty-run.py <command> [args...]
"""
import fcntl
import os
import pty
import select
import signal
import struct
import sys
import termios

ROWS, COLUMNS = 50, 400


def main(argv):
    if not argv:
        sys.exit("pty-run.py: a command is required")
    pid, master = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLUMNS, 0, 0))

    # The command runs in its own session (pty.fork), so ending this relay
    # must end the command and everything it started: on a termination
    # signal, kill the child's process group, then exit as if signalled.
    def stop(signum, _frame):
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except OSError:
            pass
        sys.exit(128 + signum)

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, stop)
    stdin = sys.stdin.fileno()
    stdout = sys.stdout.fileno()
    watched = [master, stdin]
    while True:
        try:
            ready, _, _ = select.select(watched, [], [])
        except InterruptedError:
            continue
        if master in ready:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                chunk = b""
            if not chunk:
                break
            os.write(stdout, chunk)
        if stdin in ready:
            chunk = os.read(stdin, 65536)
            if not chunk:
                # End of the relayed input: the terminal's end-of-transmission
                # character is what a command reading the terminal sees as EOF.
                watched.remove(stdin)
                os.write(master, b"\x04")
            else:
                os.write(master, chunk)
    _, status = os.waitpid(pid, 0)
    if os.WIFSIGNALED(status):
        sys.exit(128 + os.WTERMSIG(status))
    sys.exit(os.WEXITSTATUS(status))


if __name__ == "__main__":
    main(sys.argv[1:])
