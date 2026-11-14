"""Run a login shell with the inherited PTY as its controlling terminal."""
import fcntl
import os
import sys
import termios


def exec_shell(shell: str, argv0: str):
    if not os.path.isabs(shell):
        raise SystemExit(2)
    # The worker created a new session for this child. Claim the inherited
    # PTY so interactive shells, job control and terminal applications work.
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    os.execve(shell, [argv0], os.environ)


def main():
    if len(sys.argv) != 3:
        raise SystemExit(2)
    exec_shell(sys.argv[1], sys.argv[2])


if __name__ == '__main__':
    main()
