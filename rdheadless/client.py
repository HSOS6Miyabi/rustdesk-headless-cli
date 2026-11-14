"""Headless direct RustDesk terminal and file client.

The existing official desktop client remains unchanged.  This CLI can also
connect directly to a headless peer whose Ed25519 identity key is pinned.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from getpass import getpass
import io
import os
import pathlib
import secrets
import signal
import socket
import stat
import sys
import tempfile
import threading
import time

try:
    import termios
    import tty
except ImportError:
    termios = None
    tty = None

from . import crypto, protocol as p, zstd
from .stream import Stream
from .files import (file_block, file_done, file_digest, file_error, TransferFile, FILE_REGULAR,
                    file_dir_response, SEND, RECEIVE, SEND_CONFIRM, BLOCK, DIR, DONE, ERROR, DIGEST)


class RemoteError(Exception):
    pass


@dataclass
class Peer:
    stream: Stream
    peer_id: str
    username: str
    kind: str
    initial_directory: bytes | None = None

    @classmethod
    def connect(cls, address: tuple[str, int], peer_id: str, server_pubkey: bytes,
                mode: str, kind: str, secret: str, username: str = '',
                client_id: str = 'rdheadless-cli', directory: str = '',
                connection_password: str = '',
                connected_socket: socket.socket | None = None) -> 'Peer':
        if len(server_pubkey) != 32 or not client_id:
            raise ValueError('a pinned Ed25519 host public key and a client ID are required')
        if kind not in ('terminal', 'file', 'port'):
            raise ValueError('unsupported connection type')
        sock = connected_socket if connected_socket is not None else socket.create_connection(address, timeout=10)
        stream = Stream(sock)
        try:
            signed_id = p.Fields(stream.read()).sub(p.SIGNED_ID).b(1)
            signed_body = crypto.verify_signed_blob(signed_id, server_pubkey)
            advertised = p.Fields(signed_body)
            if advertised.s(1) != peer_id:
                raise PermissionError('RustDesk peer ID differs from the pinned identity')
            public, private = crypto.box_keypair()
            key = os.urandom(32)
            sealed = crypto.seal_box(key, advertised.b(2), private)
            stream.send(p.top(p.PUBLIC_KEY, p.msg(p.field_b(1, public), p.field_b(2, sealed))))
            stream.set_key(key)
            challenge = p.Fields(stream.read()).sub(p.HASH)
            if mode == 'private':
                digest = crypto.password_response(secret, challenge.s(1), challenge.s(2))
                os_login = b''
            else:
                # The standalone CLI sends PAM credentials directly for both
                # terminal and file sessions. The unmodified GUI's file screen
                # instead uses the virtual directory/rename authentication.
                digest = (crypto.password_response(connection_password, challenge.s(1), challenge.s(2))
                          if connection_password else b'')
                os_login = p.field_b(12, p.msg(p.field_s(1, username),p.field_s(2,secret))) if kind in ('terminal', 'file') else b''
            variant = {'file':7, 'port':8, 'terminal':16}[kind]
            body = p.msg(p.field_s(1, peer_id), p.field_b(2, digest),
                         p.field_s(4, client_id), p.field_s(5, 'rdheadless-cli'),
                         os_login,
                         p.field_b(variant, p.msg(p.field_s(1, directory)) if kind == 'file' else p.msg()))
            stream.send(p.top(p.LOGIN_REQUEST, body))
            result = p.Fields(stream.read()).sub(p.LOGIN_RESPONSE)
            if result.has(1):
                raise RemoteError(result.s(1))
            if not result.has(2):
                raise RemoteError('remote host did not authorize the session')
            username = p.Fields(result.b(2)).s(1)
            sock.settimeout(None)
            initial = None
            if kind == 'file':
                first = p.Fields(stream.read()).sub(p.FILE_RESPONSE)
                if first.has(ERROR):
                    raise RemoteError(first.sub(ERROR).s(2))
                if first.has(DIR):
                    initial = first.b(DIR)
            return cls(stream, peer_id, username, kind, initial)
        except BaseException:
            stream.close()
            raise

    def close(self):
        self.stream.close()

    def recv(self, expected_type: int) -> p.Fields:
        while True:
            message = p.Fields(self.stream.read())
            if message.has(expected_type):
                return message.sub(expected_type)
            if message.has(p.TEST_DELAY):
                self.stream.send(p.top(p.TEST_DELAY, message.b(p.TEST_DELAY)))
            if message.has(p.MISC):
                raise RemoteError('remote session closed')

    def _file_response(self):
        while True:
            fields = self.recv(p.FILE_RESPONSE)
            kind, item = fields.family((DIR, BLOCK, ERROR, DONE, DIGEST)) or (0, None)
            if kind == ERROR:
                raise RemoteError(item.s(2))
            if item is not None:
                return kind, item

    def ls(self, path: str = '') -> list[tuple[str,int,int]]:
        if self.kind != 'file':
            raise ValueError('file session required')
        # A file login includes one initial listing. Explicit ReadDir also
        # works and is independent of any previously buffered listing.
        self.stream.send(p.top(p.FILE_ACTION,p.field_b(1,p.field_s(1,path))))
        while True:
            kind, data = self._file_response()
            if kind == DIR:
                return [(x.s(2),x.u(1),x.u(4)) for x in
                        (p.Fields(raw) for raw in data.bs(3))]

    def get_file(self, remote_path: str, local_path: str):
        if self.kind != 'file':
            raise ValueError('file session required')
        jid = secrets.randbelow((1<<30)-1)+1
        send_req = p.msg(p.field_u(1,jid),p.field_s(2,remote_path))
        self.stream.send(p.top(p.FILE_ACTION,p.field_b(SEND,send_req)))
        files = None
        tempfile_path = None
        descriptor = None
        written = 0
        try:
            while True:
                kind, data = self._file_response()
                if kind == DIR:
                    if files is not None:
                        raise RemoteError('duplicate transfer manifest')
                    files = [p.Fields(raw) for raw in data.bs(3)]
                    if len(files)!=1 or files[0].u(1)!=FILE_REGULAR:
                        raise RemoteError('get_file accepts one regular file')
                    parent = os.path.dirname(os.path.abspath(local_path))
                    if not os.path.isdir(parent):
                        raise RemoteError('local destination directory does not exist')
                    final = pathlib.Path(local_path)
                    if final.is_symlink() or final.exists():
                        raise RemoteError('local destination already exists')
                    tempfile_path = os.path.join(parent,'.rdheadless-'+secrets.token_hex(10))
                    descriptor = os.open(tempfile_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os, "O_NOFOLLOW", 0),0o600)
                elif kind == DIGEST:
                    if files is None or data.u(1)!=jid or p.decode_sint(data.u(2))!=0:
                        raise RemoteError('unexpected file digest')
                    if data.u(4)!=files[0].u(4):
                        raise RemoteError('remote file changed since listing')
                    confirm = p.msg(p.field_u(1,jid),p.field_u(2,0),p.field_u(4,0))
                    self.stream.send(p.top(p.FILE_ACTION,p.field_b(SEND_CONFIRM,confirm)))
                elif kind == BLOCK:
                    if data.u(1)!=jid or descriptor is None:
                        raise RemoteError('unexpected file block')
                    content = data.b(3)
                    if data.u(4):
                        content = zstd.decompress(content)
                    if written+len(content)>files[0].u(4):
                        raise RemoteError('download exceeds declared size')
                    while content:
                        n = os.write(descriptor,content)
                        written += n
                        content=content[n:]
                elif kind == DONE:
                    if descriptor is None:
                        raise RemoteError('download completed without a file')
                    if written!=files[0].u(4):
                        raise RemoteError('incomplete download')
                    os.fsync(descriptor)
                    os.close(descriptor)
                    descriptor = None
                    # Publish via a hard link so another process cannot
                    # replace an unexpected destination between check and rename.
                    try:
                        os.link(tempfile_path, local_path, follow_symlinks=False)
                    except FileExistsError:
                        raise RemoteError('destination exists') from None
                    os.unlink(tempfile_path)
                    tempfile_path = None
                    return
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if tempfile_path and os.path.lexists(tempfile_path):
                os.unlink(tempfile_path)

    def put_file(self, local_path: str, remote_directory: str):
        if self.kind != 'file':
            raise ValueError('file session required')
        stat_info = os.lstat(local_path)
        if not stat.S_ISREG(stat_info.st_mode):
            raise ValueError('upload source must be a regular file')
        if stat_info.st_size > 1<<40:
            raise ValueError('file exceeds upload limit')
        jid=secrets.randbelow((1<<30)-1)+1
        remote_name = os.path.basename(local_path)
        modified = max(0,int(stat_info.st_mtime))
        entry = p.msg(p.field_u(1,FILE_REGULAR),p.field_s(2,remote_name),
                      p.field_u(4,stat_info.st_size),p.field_u(5,modified))
        request = p.msg(p.field_u(1,jid),p.field_s(2,remote_directory),
                        p.field_b(3,entry),p.field_u(5,stat_info.st_size))
        self.stream.send(p.top(p.FILE_ACTION,p.field_b(RECEIVE,request)))
        digest = p.msg(p.field_u(1,jid),p.field_u(2,0),
                       p.field_u(3,modified),p.field_u(4,stat_info.st_size))
        self.stream.send(p.top(p.FILE_RESPONSE,p.field_b(DIGEST,digest)))
        while True:
            envelope=p.Fields(self.stream.read())
            if envelope.has(p.FILE_ACTION):
                action=p.Fields(envelope.b(p.FILE_ACTION))
                if action.has(SEND_CONFIRM):
                    confirm=action.sub(SEND_CONFIRM)
                    if confirm.u(1)!=jid or confirm.has(3) and confirm.u(3) or confirm.u(4,0)!=0:
                        raise RemoteError('remote rejected the upload')
                    break
            if envelope.has(p.FILE_RESPONSE):
                response=p.Fields(envelope.b(p.FILE_RESPONSE))
                if response.has(ERROR):
                    raise RemoteError(response.sub(ERROR).s(2))
        fd = os.open(local_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as file:
            now=os.fstat(file.fileno())
            if not stat.S_ISREG(now.st_mode) or now.st_ino!=stat_info.st_ino or now.st_size!=stat_info.st_size:
                raise RemoteError('upload source changed')
            while True:
                content=file.read(64*1024)
                if not content:
                    break
                self.stream.send(file_block(jid,0,content))
        self.stream.send(file_done(jid,1))
        while True:
            kind,reply=self._file_response()
            if kind==DONE and reply.u(1)==jid and p.decode_sint(reply.u(2))==1:
                return

    def terminal(self):
        if self.kind != 'terminal':
            raise ValueError('terminal session required')
        rows, cols = terminal_size()
        self.stream.send(p.top(p.TERMINAL_ACTION, p.field_b(1,
            p.msg(p.field_u(1,1),p.field_u(2,rows),p.field_u(3,cols)))))
        response = self.recv(p.TERMINAL_RESPONSE)
        opened = response.sub(1)
        if not opened.u(2):
            raise RemoteError(opened.s(3,'Unable to start terminal'))
        previous = None
        if sys.stdin.isatty() and termios is not None:
            previous=termios.tcgetattr(sys.stdin.fileno())
            tty.setraw(sys.stdin.fileno())
        stopping=threading.Event()

        def input_loop():
            while not stopping.is_set():
                try:
                    if os.name == 'nt':
                        import msvcrt
                        key = msvcrt.getwch()
                        if key in ('\x00', '\xe0'):
                            special = msvcrt.getwch()
                            data = {'H': b'\x1b[A', 'P': b'\x1b[B', 'M': b'\x1b[C',
                                    'K': b'\x1b[D', 'G': b'\x1b[H', 'O': b'\x1b[F'}.get(special, b'')
                        else:
                            data = key.encode('utf-8', errors='replace')
                    else:
                        data=os.read(sys.stdin.fileno(),4096)
                    if not data:
                        if os.name != 'nt':
                            break
                        continue
                    self.stream.send(p.top(p.TERMINAL_ACTION, p.field_b(2,
                        p.msg(p.field_u(1,1),p.field_b(2,data)))))
                except OSError:
                    break
        reader=threading.Thread(target=input_loop,daemon=True)
        reader.start()
        try:
            while True:
                tr=self.recv(p.TERMINAL_RESPONSE)
                kind, item = tr.family((1,2,3,4)) or (0,None)
                if kind==2:
                    data=item.b(2)
                    if item.u(3):
                        data=zstd.decompress(data)
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                elif kind==3:
                    return item.u(2)
                elif kind==4:
                    raise RemoteError(item.s(2))
        finally:
            stopping.set()
            if previous is not None:
                termios.tcsetattr(sys.stdin.fileno(),termios.TCSADRAIN,previous)


def terminal_size() -> tuple[int,int]:
    try:
        size=os.get_terminal_size()
        return size.lines,size.columns
    except OSError:
        return 24,80
