"""RustDesk length-prefixed, optionally NaCl-secured stream transport."""
from __future__ import annotations
import socket
import threading
from . import crypto, protocol as p

class Stream:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.key: bytes | None = None
        self.send_counter = 0
        self.recv_counter = 0
        self.lock = threading.RLock()
        self.read_limit = p.MAX_MESSAGE

    def set_key(self, key: bytes):
        if len(key) != 32 or self.key is not None:
            raise ValueError('invalid or repeated stream key')
        self.key = key

    def read_exact(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            chunk = self.sock.recv(n-len(out))
            if not chunk:
                raise EOFError('peer disconnected')
            out.extend(chunk)
        return bytes(out)

    def read(self) -> bytes:
        while True:
            first = self.read_exact(1)
            size = p.frame_length(first, self.read_exact(first[0] & 3))
            if size > self.read_limit + (16 if self.key else 0):
                raise ValueError('message exceeds current connection limit')
            data = self.read_exact(size)
            if self.key and len(data) > 1:
                self.recv_counter += 1
                return crypto.decrypt_secretbox(data, self.key, self.recv_counter)
            if self.key and len(data) <= 1:
                # RustDesk may transmit lightweight heartbeat packets without encryption.
                continue
            if not data:
                continue
            return data

    def send(self, plaintext: bytes):
        with self.lock:
            if self.key:
                self.send_counter += 1
                data = crypto.encrypt_secretbox(plaintext, self.key, self.send_counter)
            else:
                data = plaintext
            self.sock.sendall(p.frame_encode(data))

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()
