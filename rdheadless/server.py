"""Headless RustDesk peer server, PAM authentication, and user-isolated workers.

Unauthenticated public file sessions see only an in-memory login directory.
Standard RustDesk challenges retain a device-specific salt across connections,
including connections made with a password saved by the desktop client.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hmac
import hashlib
import json
import logging
import os
import pwd
import secrets
import socket
import subprocess
import sys
import threading
import time
import tomllib
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

from . import crypto
from . import protocol as p
from .stream import Stream
from .auth import FailureLimiter, UserAccount, lookup_account, pam_login
from .file_login import FileLoginGateway

LOG = logging.getLogger('rdheadless')


@dataclass(frozen=True)
class Config:
    mode: str
    device_id: str
    identity_file: str
    listen_host: str = '127.0.0.1'
    listen_port: int = 21118
    password_file: str = ''
    pam_service: str = 'login'
    shell: str = ''
    login_shell: bool = True
    file_root: str = ''
    allow_tunnel: bool = False
    tunnel_ports: tuple[int, ...] = ()
    worker_python: str = sys.executable
    file_auth_timeout: float = 180.0
    enable_public_rendezvous: bool = False
    rendezvous_server: str = ''
    relay_server: str = ''
    rendezvous_key: str = ''

    def validate(self):
        if self.mode not in ('private', 'public'):
            raise ValueError('mode must be private or public')
        if not self.device_id or len(self.device_id) > 32 or any(x in self.device_id for x in '\n\x00@/ '):
            raise ValueError('invalid RustDesk device ID')
        if not self.identity_file:
            raise ValueError('identity_file must be configured')
        if not 0 < self.listen_port <= 65535:
            raise ValueError('listen_port must be between 1 and 65535')
        if self.mode == 'public' and os.geteuid() != 0:
            raise PermissionError('public mode requires a root service')
        if self.mode == 'private' and not self.password_file:
            raise ValueError('private mode requires password_file')
        if self.mode == 'private' and os.geteuid() == 0:
            raise PermissionError('private mode refuses root: use an unprivileged service account')
        if self.file_root and not os.path.isabs(self.file_root):
            raise ValueError('file_root must be an absolute path')
        if self.shell and not os.path.isabs(self.shell):
            raise ValueError('shell must be an absolute path')
        if self.allow_tunnel:
            if not self.tunnel_ports or any(port < 1 or port > 65535 for port in self.tunnel_ports):
                raise ValueError('port forwarding requires a nonempty explicit port allowlist')
        if not 10 <= self.file_auth_timeout <= 600:
            raise ValueError('file_auth_timeout must be between 10 and 600 seconds')

    @classmethod
    def from_file(cls, filename: str) -> 'Config':
        with open(filename, 'rb') as f:
            data = tomllib.load(f)
        node = data.get('server', data)
        c = cls(mode=node['mode'], device_id=node['device_id'],
                identity_file=node['identity_file'],
                listen_host=node.get('listen_host', '127.0.0.1'),
                listen_port=int(node.get('listen_port', 21118)),
                password_file=node.get('password_file', ''),
                pam_service=node.get('pam_service', 'login'),
                shell=node.get('shell', ''), login_shell=bool(node.get('login_shell', True)),
                file_root=node.get('file_root', ''),
                allow_tunnel=bool(node.get('allow_tunnel', False)),
                tunnel_ports=tuple(int(p) for p in node.get('tunnel_ports', [])),
                file_auth_timeout=float(node.get('file_auth_timeout', 180)),
                enable_public_rendezvous=bool(node.get('enable_public_rendezvous', False)),
                rendezvous_server=node.get('rendezvous_server', ''),
                relay_server=node.get('relay_server', ''),
                rendezvous_key=node.get('rendezvous_key', ''))
        c.validate()
        return c


def _private_password(path: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        stat = os.fstat(descriptor)
        if (not __import__('stat').S_ISREG(stat.st_mode) or stat.st_mode & 0o077 or
                stat.st_uid != os.geteuid()):
            raise PermissionError('password_file must be a private regular file owned by the service user')
        with os.fdopen(descriptor, 'rb', closefd=False) as f:
            password = f.read(1025).rstrip(b'\r\n')
    finally:
        os.close(descriptor)
    if not 12 <= len(password) <= 1024:
        raise ValueError('private connection password must have 12 to 1024 bytes')
    return password


@dataclass
class AuthResult:
    mode: str
    username: str
    account: UserAccount
    client_id: str
    shell: str
    workspace: str
    feature: str
    tunnel_target: tuple[str, int] | None = None
    pam_session: object | None = None


class HostServer:
    def __init__(self, config: Config, pam: Callable = pam_login):
        config.validate()
        self.cfg = config
        self.identity = crypto.load_identity(config.identity_file, config.device_id)
        self._connection_password = _private_password(config.password_file) if config.password_file else None
        # A saved RustDesk password contains SHA256(password || salt). Keep
        # salt stable for this peer identity, with a fresh challenge each time.
        self._password_salt = hashlib.sha256(b'rdheadless/peer-salt/v1\x00' + self.identity.public).hexdigest()[:32]
        self.pam = pam
        self.limiter = FailureLimiter()
        self.sessions = threading.BoundedSemaphore(64)
        self._listener: socket.socket | None = None
        self._stop = threading.Event()
        self._threads: set[threading.Thread] = set()
        self._thread_lock = threading.Lock()
        self._registration_thread: threading.Thread | None = None

    def start(self):
        if self._listener:
            raise RuntimeError('server already started')
        sock = socket.create_server((self.cfg.listen_host, self.cfg.listen_port), reuse_port=False)
        sock.settimeout(0.5)
        self._listener = sock
        self._stop.clear()
        if self.cfg.enable_public_rendezvous:
            from .rendezvous import register_loop
            self._registration_thread = threading.Thread(target=register_loop, args=(self,), daemon=True)
            self._registration_thread.start()
        return sock.getsockname()

    def serve_forever(self):
        if not self._listener:
            self.start()
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                sock, addr = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                raise
            if not self.sessions.acquire(blocking=False):
                sock.close()
                continue
            thread = threading.Thread(target=self._handle, args=(sock, addr), daemon=True)
            with self._thread_lock:
                self._threads.add(thread)
            thread.start()

    def stop(self):
        self._stop.set()
        if self._listener:
            self._listener.close()
            self._listener = None
        if self._registration_thread:
            self._registration_thread.join(2)
        with self._thread_lock:
            threads = list(self._threads)
        for t in threads:
            t.join(2)

    def _handle(self, sock: socket.socket, addr: tuple):
        try:
            self.handle_socket(sock, addr)
        except (OSError, EOFError, ValueError, PermissionError, TimeoutError) as ex:
            LOG.debug('peer connection ended: %s', ex.__class__.__name__)
        except Exception:
            LOG.exception('unexpected peer session error')
        finally:
            try: sock.close()
            except OSError: pass
            self.sessions.release()
            with self._thread_lock:
                self._threads.discard(threading.current_thread())

    def _handshake(self, stream: Stream):
        local_public, local_private = crypto.box_keypair()
        identity_data = p.msg(p.field_s(1, self.identity.device_id), p.field_b(2, local_public))
        signed = crypto.sign_message(identity_data, self.identity.private)
        stream.send(p.top(p.SIGNED_ID, p.field_b(1, signed)))
        reply = p.Fields(stream.read()).sub(p.PUBLIC_KEY)
        if reply.u(3, 0) != 0:
            raise ValueError('unsupported key-exchange version')
        key = crypto.open_box(reply.b(2), reply.b(1), local_private)
        if len(key) != 32:
            raise ValueError('invalid negotiated encryption key')
        stream.set_key(key)

    def handle_socket(self, sock: socket.socket, addr: tuple | None = None):
        if addr is None:
            addr = sock.getpeername()
        sock.settimeout(12)
        stream = Stream(sock)
        stream.read_limit = 16 * 1024
        # All OS credentials must be protected by a verified RustDesk identity
        # handshake; there is no silent plaintext fallback.
        self._handshake(stream)
        salt, challenge = self._password_salt, secrets.token_hex(16)
        stream.send(p.top(p.HASH, p.msg(p.field_s(1, salt), p.field_s(2, challenge))))
        req = p.Fields(stream.read())
        login = req.sub(p.LOGIN_REQUEST)
        if login.s(1) != self.identity.device_id:
            self._login_error(stream, 'Invalid RustDesk device ID')
            return
        client_id = login.s(4)
        variants = login.family((7, 8, 15, 16))
        if not variants or variants[0] == 15:
            self._login_error(stream, 'Only terminal, file transfer and permitted tunnels are supported')
            return
        feature = {7:'file', 8:'port', 16:'terminal'}[variants[0]]
        address = addr[0]
        auth = None
        try:
            auth = self._authorize(login, feature, client_id, salt, challenge, address, variants[1])
        except (PermissionError, ValueError, LookupError) as ex:
            LOG.info('remote login rejected: feature=%s address=%s', feature, address)
            self._login_error(stream, str(ex))
            return
        try:
            peer_info = p.msg(
                p.field_s(1, auth.username if auth is not None else ''),
                p.field_s(2, socket.gethostname()),
                p.field_s(3, 'Linux'),
                p.field_s(7, '1.4.1'),
                p.field_b(9, p.field_u(2, 1)),
            )
            stream.send(p.top(p.LOGIN_RESPONSE, p.field_b(2, peer_info)))
            if auth is None:
                # A public GUI file session supplies no OSLogin; its PAM
                # authentication runs exclusively inside the virtual folder.
                gate = FileLoginGateway(stream, timeout=self.cfg.file_auth_timeout)
                def authenticate(username: str, password: str) -> AuthResult:
                    return self._pam_authorize(username, password, 'file', client_id, address)
                auth = gate.run(authenticate)
                if auth is None:
                    return
                # The authenticated worker will send the real home listing.
                initial_directory = ''
            else:
                initial_directory = variants[1].s(1, '') if feature == 'file' else ''
            payload = {'key': stream.key.hex(), 'send_counter': stream.send_counter,
                       'recv_counter': stream.recv_counter, 'username': auth.username,
                       'home': auth.account.home, 'uid': auth.account.uid,
                       'gid': auth.account.gid, 'groups': auth.account.groups,
                       'shell': auth.shell, 'workspace': auth.workspace,
                       'login_shell': self.cfg.login_shell, 'feature': auth.feature,
                       'client_id': auth.client_id,
                       'tunnel': auth.tunnel_target,
                       'initial_directory': initial_directory,
                       'show_hidden': bool(variants[1].u(2, 0)) if feature == 'file' else False}
            self._worker(sock, payload, auth.account)
        finally:
            if auth is not None and auth.pam_session is not None:
                auth.pam_session.close()

    def _login_error(self, stream: Stream, text: str):
        try:
            stream.send(p.top(p.LOGIN_RESPONSE, p.field_s(1, text)))
        except OSError:
            pass

    def _pam_authorize(self, username: str, password: str, feature: str,
                       client_id: str, address: str) -> AuthResult:
        if not username or not password:
            raise PermissionError('System authentication failed')
        if not self.limiter.allowed(address):
            raise PermissionError('Too many system login attempts')
        pam_session = None
        try:
            pam_session = self.pam(username, password, self.cfg.pam_service)
            account = lookup_account(username)
        except (PermissionError, LookupError, OSError, ValueError):
            if pam_session is not None:
                pam_session.close()
            self.limiter.report(address, False)
            raise PermissionError('System authentication failed') from None
        self.limiter.report(address, True)
        return AuthResult('public', account.name, account, client_id,
                          self.cfg.shell or account.shell,
                          self.cfg.file_root or account.home, feature,
                          pam_session=pam_session)

    def _authorize(self, login: p.Fields, feature: str, client_id: str,
                   salt: str, challenge: str, address: str, sub: p.Fields) -> AuthResult | None:
        # Public deployments may omit the shared connection password. In that
        # case, no real terminal/file operation proceeds without PAM; tunnels
        # remain protected by the explicit restricted TCP-port allowlist.
        if self._connection_password is not None:
            expected = crypto.password_response(self._connection_password, salt, challenge)
            if not hmac.compare_digest(expected, login.b(2)):
                raise PermissionError('Wrong Password')
        if self.cfg.mode == 'private':
            account = lookup_account(pwd.getpwuid(os.geteuid()).pw_name)
            return AuthResult('private', account.name, account, client_id,
                              self.cfg.shell or account.shell,
                              self.cfg.file_root or account.home, feature,
                              tunnel_target=self._check_tunnel(sub) if feature == 'port' else None)
        if feature == 'terminal':
            if not client_id:
                raise PermissionError('Remote client identity is required')
            creds = login.sub(12)
            return self._pam_authorize(creds.s(1), creds.s(2), feature, client_id, address)
        if feature == 'file':
            # A separate CLI can send OSLogin directly, but the standard GUI
            # file screen has only a connection password field. It enters the
            # virtual authentication directory and renames two placeholder files.
            creds = login.sub(12)
            if creds.s(1) or creds.s(2):
                return self._pam_authorize(creds.s(1), creds.s(2), feature, client_id, address)
            return None
        if feature == 'port':
            target = self._check_tunnel(sub)
            account = lookup_account('nobody')
            return AuthResult('public', account.name, account, client_id,
                              '/bin/false', '/', feature, tunnel_target=target)
        raise PermissionError('Unsupported connection type')

    def _check_tunnel(self, sub: p.Fields) -> tuple[str, int]:
        if not self.cfg.allow_tunnel:
            raise PermissionError('Port forwarding is disabled')
        host, port = sub.s(1) or '127.0.0.1', sub.u(2)
        if host not in ('localhost', '127.0.0.1', '::1'):
            raise PermissionError('Only loopback tunnel destinations are supported')
        if port not in self.cfg.tunnel_ports:
            raise PermissionError('Port forwarding destination is not allowed')
        return (host, port)

    def _worker(self, sock: socket.socket, payload: dict, account: UserAccount):
        # Start a separate process with the authenticated user's UID.  For a
        # public session, filesystem calls and subprocesses cannot inherit the
        # privileged RustDesk daemon's effective UID.
        args = ([sys.executable, '--worker', str(sock.fileno())] if getattr(sys, 'frozen', False)
                else [self.cfg.worker_python, '-m', 'rdheadless.worker', str(sock.fileno())])
        uid, gid, groups = account.uid, account.gid, list(account.groups)
        env = {'PATH': '/usr/local/bin:/usr/bin:/bin'}
        if not getattr(sys, 'frozen', False):
            env['PYTHONPATH'] = str(Path(__file__).resolve().parent.parent)
        command = dict(args=args, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, close_fds=True, pass_fds=(sock.fileno(),),
                       env=env, start_new_session=True)
        if os.geteuid() == 0:
            command.update(user=uid, group=gid, extra_groups=groups)
        elif uid != os.geteuid():
            raise PermissionError('Cannot change user without root')
        child = subprocess.Popen(**command)
        try:
            assert child.stdin is not None
            child.stdin.write(json.dumps(payload).encode() + b'\n')
            child.stdin.close()
            # Do not retain a second writable stream after passing the socket
            # to an unprivileged worker.  PAM stays open until it exits.
            sock.close()
            child.wait()
            if child.returncode:
                LOG.warning('session worker exited with status %d', child.returncode)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()


def serve(config_file: str):
    config = Config.from_file(config_file)
    server = HostServer(config)
    print('RustDesk headless peer ID:', server.identity.device_id, flush=True)
    server.serve_forever()
