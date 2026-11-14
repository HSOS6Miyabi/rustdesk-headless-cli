"""Per-connection unprivileged RustDesk terminal/file/tunnel worker."""
from __future__ import annotations

import errno
import fcntl
import json
import os
import pathlib
import pty
import select
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
from dataclasses import dataclass

from . import protocol as p
from .stream import Stream
from .files import FileManager, FileWorkspace
from . import zstd


@dataclass
class PTYSession:
    ident: int
    master: int
    process: subprocess.Popen


class Worker:
    def __init__(self, stream: Stream, config: dict):
        if os.geteuid() != int(config['uid']):
            raise PermissionError('untrusted worker user identity')
        self.stream = stream
        self.config = config
        self.terminals: dict[int, PTYSession] = {}
        self.lock = threading.RLock()
        self.alive = threading.Event()
        self.alive.set()
        self.files: FileManager | None = None

    def _terminal_response(self, num: int, body: bytes):
        self.stream.send(p.top(p.TERMINAL_RESPONSE, p.field_b(num, body)))

    def _terminal_error(self, ident: int, text: str):
        self._terminal_response(4, p.msg(p.field_u(1, ident), p.field_s(2, text[:300])))

    def _terminal_data(self, ident: int, payload: bytes):
        self._terminal_response(2, p.msg(p.field_u(1, ident), p.field_b(2, payload)))

    def _open_pty(self, args: p.Fields):
        ident, rows, cols = args.u(1), args.u(2), args.u(3)
        if not 1 <= rows <= 4096 or not 1 <= cols <= 4096:
            self._terminal_error(ident, 'Invalid terminal dimensions')
            return
        if ident in self.terminals or len(self.terminals) >= 8:
            self._terminal_error(ident, 'Terminal session limit reached')
            return
        cmd_shell = self.config['shell']
        if not os.path.isabs(cmd_shell) or not os.access(cmd_shell, os.X_OK):
            self._terminal_error(ident, 'Configured shell is not executable')
            return
        master, slave = pty.openpty()
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
            argv0 = '-'+os.path.basename(cmd_shell) if self.config['login_shell'] else os.path.basename(cmd_shell)
            environ = {'HOME': self.config['home'], 'USER': self.config['username'],
                       'LOGNAME': self.config['username'], 'SHELL': cmd_shell,
                       'TERM': 'xterm-256color', 'PATH': '/usr/local/bin:/usr/bin:/bin',
                       'LANG': 'C.UTF-8',
                       'PYTHONPATH': str(pathlib.Path(__file__).resolve().parent.parent)}
            shell_argv = ([sys.executable, '--exec-shell', cmd_shell, argv0] if getattr(sys, 'frozen', False)
                          else [sys.executable, '-m', 'rdheadless.exec_shell', cmd_shell, argv0])
            process = subprocess.Popen(shell_argv,
                                       stdin=slave, stdout=slave,
                                       stderr=slave, close_fds=True, start_new_session=True,
                                       cwd=self.config['home'], env=environ)
        except (OSError, PermissionError) as ex:
            os.close(master)
            self._terminal_error(ident, f'Could not start the shell: {ex.__class__.__name__}')
            return
        finally:
            os.close(slave)
        terminal = PTYSession(ident, master, process)
        self.terminals[ident] = terminal
        self._terminal_response(1, p.msg(p.field_u(1, ident), p.field_u(2, 1),
                                         p.field_u(4, process.pid)))
        thread = threading.Thread(target=self._read_pty, args=(terminal,), daemon=True)
        thread.start()

    def _read_pty(self, terminal: PTYSession):
        try:
            while self.alive.is_set():
                try:
                    data = os.read(terminal.master, 16_384)
                except OSError as ex:
                    if ex.errno in (errno.EIO, errno.EBADF):
                        break
                    raise
                if not data:
                    break
                self._terminal_data(terminal.ident, data)
        except (EOFError, OSError):
            pass
        finally:
            try: status = terminal.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                status = -1
            if self.alive.is_set():
                try:
                    self._terminal_response(3, p.msg(p.field_u(1, terminal.ident), p.field_u(2, status)))
                except (OSError, EOFError):
                    pass
            with self.lock:
                self.terminals.pop(terminal.ident, None)
            try: os.close(terminal.master)
            except OSError: pass

    def _terminal_action(self, raw: bytes):
        fields = p.Fields(raw)
        kind, args = fields.family((1, 2, 3, 4)) or (0, None)
        if args is None:
            return
        ident = args.u(1)
        if kind == 1:
            with self.lock: self._open_pty(args)
        elif kind == 2:
            terminal = self.terminals.get(ident)
            if terminal:
                data = args.b(2)
                if args.u(3):
                    try: data = zstd.decompress(data)
                    except ValueError: return
                if len(data) <= 1024*1024:
                    try: os.write(terminal.master, data)
                    except OSError: pass
        elif kind == 3:
            terminal = self.terminals.get(ident)
            if terminal and 1 <= args.u(2) <= 4096 and 1 <= args.u(3) <= 4096:
                try: fcntl.ioctl(terminal.master, termios.TIOCSWINSZ,
                                 struct.pack('HHHH', args.u(2), args.u(3), 0, 0))
                except OSError: pass
        elif kind == 4:
            terminal = self.terminals.pop(ident, None)
            if terminal:
                try: terminal.process.terminate()
                except OSError: pass
                try: os.close(terminal.master)
                except OSError: pass

    def _tunnel(self):
        host, port = self.config['tunnel']
        if host not in ('localhost', '127.0.0.1', '::1'):
            raise PermissionError('only loopback tunnel destinations are permitted')
        sock = socket.create_connection((host, int(port)), timeout=10)
        with sock:
            self.stream.sock.settimeout(None)
            sock.settimeout(None)
            inputs = [self.stream.sock, sock]
            while self.alive.is_set():
                readable, _, _ = select.select(inputs, [], [], 60)
                for src in readable:
                    data = src.recv(64*1024)
                    if not data:
                        return
                    dst = sock if src is self.stream.sock else self.stream.sock
                    dst.sendall(data)

    def run(self):
        self.stream.sock.settimeout(None)
        try:
            if self.config['feature'] == 'port':
                self._tunnel()
                return
            # The scope remains fixed throughout a connection. A terminal
            # session cannot silently gain file or port-forwarding rights.
            if self.config['feature'] == 'file':
                workspace = FileWorkspace(self.config['workspace'], self.config['home'])
                self.files = FileManager(self.stream, workspace)
                try:
                    self.files.initial(self.config.get('initial_directory', ''),
                                       self.config.get('show_hidden', False))
                    self._run_messages()
                finally:
                    self.files.close()
                    workspace.close()
            else:
                self._run_messages()
        finally:
            self.alive.clear()
            if self.files:
                self.files.close()
            for terminal in list(self.terminals.values()):
                try: terminal.process.terminate()
                except OSError: pass
                try: os.close(terminal.master)
                except OSError: pass
            self.terminals.clear()
            self.stream.close()

    def _run_messages(self):
        while self.alive.is_set():
            try:
                incoming = p.Fields(self.stream.read())
                current = incoming.family((p.TEST_DELAY, p.FILE_ACTION,
                                           p.FILE_RESPONSE, p.TERMINAL_ACTION, p.MISC))
                if current is None:
                    continue
                kind, payload = current
                if kind == p.TEST_DELAY:
                    self.stream.send(p.top(p.TEST_DELAY, incoming.b(p.TEST_DELAY)))
                elif kind in (p.FILE_ACTION, p.FILE_RESPONSE) and self.files:
                    if kind == p.FILE_ACTION:
                        self.files.handle_action(incoming.b(p.FILE_ACTION))
                    else:
                        self.files.handle_response(incoming.b(p.FILE_RESPONSE))
                elif kind == p.TERMINAL_ACTION and self.config['feature'] == 'terminal':
                    self._terminal_action(incoming.b(p.TERMINAL_ACTION))
                elif kind == p.MISC:
                    if payload.has(20):
                        return
            except (EOFError, ConnectionResetError, BrokenPipeError):
                return
            except (OSError, ValueError, PermissionError) as ex:
                # Do not keep using a session after a malformed message; it
                # could desynchronize the terminal/file protocol state.
                return


def run_worker(fd: int):
    settings = json.loads(sys.stdin.buffer.readline())
    sock = socket.socket(fileno=fd)
    stream = Stream(sock)
    stream.set_key(bytes.fromhex(settings['key']))
    stream.send_counter = int(settings['send_counter'])
    stream.recv_counter = int(settings['recv_counter'])
    Worker(stream, settings).run()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: python -m rdheadless.worker <socket_fd>')
    run_worker(int(sys.argv[1]))
