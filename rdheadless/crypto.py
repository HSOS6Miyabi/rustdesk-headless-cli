"""RustDesk-compatible Ed25519/X25519/XSalsa20-Poly1305 operations via libsodium.

Only system libsodium is used; operating system credentials are sent after
a RustDesk-compatible encrypted peer session has been established.
"""
from __future__ import annotations
import ctypes as C
from ctypes.util import find_library
import hashlib
import os
from dataclasses import dataclass

try:
    from nacl import bindings as _nacl
except ImportError:
    _nacl = None

_lib = None
if _nacl is None:
    _libname = find_library('sodium')
    if not _libname:
        raise RuntimeError('libsodium or PyNaCl is required')
    _lib = C.CDLL(_libname)
    if _lib.sodium_init() < 0:
        raise RuntimeError('failed to initialize libsodium')

_P = C.c_void_p
_Z = C.c_ulonglong

def _bind(name: str, args: list) -> None:
    if _lib is not None:
        func = getattr(_lib, name)
        func.argtypes = args
        func.restype = C.c_int

_bind('crypto_sign_seed_keypair', [_P, _P, _P])
_bind('crypto_sign_detached', [_P, _P, _P, _Z, _P])
_bind('crypto_sign_verify_detached', [_P, _P, _Z, _P])
_bind('crypto_box_keypair', [_P, _P])
_bind('crypto_box_easy', [_P, _P, _Z, _P, _P, _P])
_bind('crypto_box_open_easy', [_P, _P, _Z, _P, _P, _P])
_bind('crypto_secretbox_easy', [_P, _P, _Z, _P, _P])
_bind('crypto_secretbox_open_easy', [_P, _P, _Z, _P, _P])


def _buf(value: bytes) -> C.Array:
    return C.create_string_buffer(value, max(len(value), 1))


def sign_keypair(seed: bytes) -> tuple[bytes, bytes]:
    if len(seed) != 32:
        raise ValueError('Ed25519 seed must be 32 bytes')
    if _nacl is not None:
        return _nacl.crypto_sign_seed_keypair(seed)
    pk, sk = C.create_string_buffer(32), C.create_string_buffer(64)
    if _lib.crypto_sign_seed_keypair(pk, sk, _buf(seed)) != 0:
        raise ValueError('Ed25519 seed derivation failed')
    return pk.raw, sk.raw


def sign_message(message: bytes, secret_key: bytes) -> bytes:
    if len(secret_key) != 64:
        raise ValueError('invalid Ed25519 signing key')
    if _nacl is not None:
        return _nacl.crypto_sign(message, secret_key)
    sig, siglen = C.create_string_buffer(64), C.c_ulonglong(0)
    if _lib.crypto_sign_detached(sig, C.byref(siglen), _buf(message), len(message), _buf(secret_key)) != 0:
        raise RuntimeError('Ed25519 signing failed')
    return sig.raw + message


def verify_signed_blob(blob: bytes, pub: bytes) -> bytes:
    if len(blob) < 64 or len(pub) != 32:
        raise ValueError('invalid signed blob or key')
    if _nacl is not None:
        return _nacl.crypto_sign_open(blob, pub)
    signature, message = blob[:64], blob[64:]
    if _lib.crypto_sign_verify_detached(_buf(signature), _buf(message), len(message), _buf(pub)) != 0:
        raise ValueError('untrusted signature')
    return message


def box_keypair() -> tuple[bytes, bytes]:
    if _nacl is not None:
        return _nacl.crypto_box_keypair()
    pk, sk = C.create_string_buffer(32), C.create_string_buffer(32)
    if _lib.crypto_box_keypair(pk, sk) != 0:
        raise RuntimeError('X25519 generation failed')
    return pk.raw, sk.raw


def seal_box(message: bytes, public: bytes, private: bytes) -> bytes:
    if len(public) != 32 or len(private) != 32:
        raise ValueError('invalid X25519 keys')
    nonce = bytes(24)
    if _nacl is not None:
        return _nacl.crypto_box(message, nonce, public, private)
    out = C.create_string_buffer(len(message)+16)
    if _lib.crypto_box_easy(out, _buf(message), len(message), _buf(nonce), _buf(public), _buf(private)) != 0:
        raise ValueError('box sealing failed')
    return out.raw


def open_box(ciphertext: bytes, public: bytes, private: bytes) -> bytes:
    if len(public) != 32 or len(private) != 32 or len(ciphertext) < 16:
        raise ValueError('invalid X25519 key or ciphertext')
    if _nacl is not None:
        return _nacl.crypto_box_open(ciphertext, bytes(24), public, private)
    out = C.create_string_buffer(len(ciphertext)-16)
    if _lib.crypto_box_open_easy(out, _buf(ciphertext), len(ciphertext), _buf(bytes(24)), _buf(public), _buf(private)) != 0:
        raise ValueError('box authentication failed')
    return out.raw


def encrypt_secretbox(message: bytes, key: bytes, counter: int) -> bytes:
    if len(key) != 32 or counter < 1:
        raise ValueError('invalid session key or counter')
    nonce = counter.to_bytes(8, 'little') + bytes(16)
    if _nacl is not None:
        return _nacl.crypto_secretbox(message, nonce, key)
    out = C.create_string_buffer(len(message)+16)
    if _lib.crypto_secretbox_easy(out, _buf(message), len(message), _buf(nonce), _buf(key)) != 0:
        raise RuntimeError('session encryption failed')
    return out.raw


def decrypt_secretbox(message: bytes, key: bytes, counter: int) -> bytes:
    if len(key) != 32 or counter < 1 or len(message) < 16:
        raise ValueError('invalid ciphertext')
    nonce = counter.to_bytes(8, 'little') + bytes(16)
    if _nacl is not None:
        return _nacl.crypto_secretbox_open(message, nonce, key)
    out = C.create_string_buffer(len(message)-16)
    if _lib.crypto_secretbox_open_easy(out, _buf(message), len(message), _buf(nonce), _buf(key)) != 0:
        raise ValueError('session authentication failed')
    return out.raw


@dataclass(frozen=True)
class Identity:
    device_id: str
    uuid: bytes
    public: bytes
    private: bytes


def load_identity(path: str, device_id: str) -> Identity:
    """Create a restricted identity on first run; never silently overwrite it."""
    import json
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, mode=0o700, exist_ok=True)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        seed, uuid = os.urandom(32), os.urandom(16)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump({'device_id': device_id, 'seed': seed.hex(), 'uuid': uuid.hex()}, f)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            try:
                os.unlink(path)
            except OSError:
                pass
            raise
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        stat = os.fstat(fd)
        if stat.st_mode & 0o077 or not __import__('stat').S_ISREG(stat.st_mode) or stat.st_uid != os.geteuid():
            raise ValueError('identity file must be owned by the service user and have permissions 0600')
        with os.fdopen(fd, 'r', encoding='utf-8') as f:
            data = json.load(f)
        fd = -1
    finally:
        if fd >= 0:
            os.close(fd)
    if data.get('device_id') != device_id:
        raise ValueError('identity file belongs to a different RustDesk ID')
    seed, uuid = bytes.fromhex(data['seed']), bytes.fromhex(data['uuid'])
    if len(uuid) < 16:
        raise ValueError('invalid identity UUID')
    pk, sk = sign_keypair(seed)
    return Identity(device_id=device_id, uuid=uuid, public=pk, private=sk)


def password_response(password: str | bytes, salt: str, challenge: str) -> bytes:
    if isinstance(password, str):
        password = password.encode('utf-8')
    h1 = hashlib.sha256(password + salt.encode('utf-8')).digest()
    return hashlib.sha256(h1 + challenge.encode('utf-8')).digest()
