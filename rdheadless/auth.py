"""System PAM authentication, account lookup and login attempt throttling."""
from __future__ import annotations

from dataclasses import dataclass
from ctypes import CDLL, Structure, CFUNCTYPE, POINTER, byref, c_int, c_void_p, c_char_p, c_size_t
from .native import load_library
import ctypes
import os
import pwd
import threading
import time
from collections import deque


@dataclass(frozen=True)
class UserAccount:
    name: str
    uid: int
    gid: int
    groups: tuple[int, ...]
    home: str
    shell: str


def lookup_account(username: str) -> UserAccount:
    if not username or '\x00' in username or len(username) > 256:
        raise ValueError('invalid user name')
    item = pwd.getpwnam(username)
    return UserAccount(item.pw_name, item.pw_uid, item.pw_gid,
                       tuple(os.getgrouplist(item.pw_name, item.pw_gid)),
                       item.pw_dir, item.pw_shell or '/bin/sh')


class FailureLimiter:
    """Local per-address throttle for remote OS credential attempts."""
    def __init__(self, attempts=4, interval=90.0, clock=time.monotonic):
        self.attempts, self.interval, self.clock = attempts, interval, clock
        self.lock = threading.Lock()
        self.failures: dict[str, deque[float]] = {}

    def allowed(self, key: str) -> bool:
        with self.lock:
            now = self.clock()
            history = self.failures.get(key, deque())
            while history and history[0] + self.interval <= now:
                history.popleft()
            self.failures[key] = history
            return len(history) < self.attempts

    def report(self, key: str, success: bool):
        with self.lock:
            if success:
                self.failures.pop(key, None)
            else:
                self.failures.setdefault(key, deque()).append(self.clock())


class PAMError(PermissionError):
    pass


class _PamMessage(Structure):
    _fields_ = [('msg_style', c_int), ('msg', c_char_p)]


class _PamResponse(Structure):
    _fields_ = [('resp', c_void_p), ('resp_retcode', c_int)]


_ConvCB = CFUNCTYPE(c_int, c_int, POINTER(POINTER(_PamMessage)),
                     POINTER(POINTER(_PamResponse)), c_void_p)


class _PamConv(Structure):
    _fields_ = [('conv', _ConvCB), ('appdata_ptr', c_void_p)]


class PAMSession:
    def __init__(self, lib, handle, callback, conv, username):
        self._lib, self._handle = lib, handle
        self._callback, self._conv = callback, conv
        self.username = username
        self._closed = False

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._handle:
            self._lib.pam_close_session(self._handle, 0)
            self._lib.pam_setcred(self._handle, 4)  # PAM_DELETE_CRED
            self._lib.pam_end(self._handle, 0)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def pam_login(username: str, password: str, service: str = 'login') -> PAMSession:
    """Authenticate with system PAM; keep its session active until worker exits.

    The server must run as root in public mode.  This function deliberately
    never logs a submitted username/password combination or PAM conversation.
    """
    if os.geteuid() != 0:
        raise PAMError('public-mode PAM login requires root privileges')
    if not username or not password or '\x00' in username or '\x00' in password:
        raise PAMError('missing or invalid system credentials')
    if not service or '/' in service or len(service) > 64:
        raise ValueError('invalid PAM service')
    lib = load_library('pam', 'libpam.so.0', 'libpam.so')
    if lib is None:
        raise RuntimeError('PAM library is not available')
    libc = load_library('c', 'libc.so.6', 'libc.so')
    if libc is None:
        raise RuntimeError('C runtime library is not available')
    libc.calloc.argtypes = [c_size_t, c_size_t]
    libc.calloc.restype = c_void_p
    libc.free.argtypes = [c_void_p]
    libc.strdup.argtypes = [c_char_p]
    libc.strdup.restype = c_void_p
    lib.pam_start.argtypes = [c_char_p, c_char_p, POINTER(_PamConv), POINTER(c_void_p)]
    lib.pam_start.restype = c_int
    for name in ('pam_authenticate', 'pam_acct_mgmt', 'pam_setcred', 'pam_open_session', 'pam_close_session'):
        getattr(lib, name).argtypes = [c_void_p, c_int]
        getattr(lib, name).restype = c_int
    lib.pam_end.argtypes = [c_void_p, c_int]
    lib.pam_end.restype = c_int

    pw = bytearray(password.encode('utf-8'))
    uname = username.encode('utf-8')

    @_ConvCB
    def conversation(n, messages, response, _appdata):
        if n < 1 or n > 16:
            return 19  # PAM_CONV_ERR
        buf = libc.calloc(n, ctypes.sizeof(_PamResponse))
        if not buf:
            return 5  # PAM_BUF_ERR
        answer = ctypes.cast(buf, POINTER(_PamResponse))
        for i in range(n):
            style = messages[i].contents.msg_style
            if style in (1, 2):
                secret = bytes(pw) if style == 1 else uname
                value = libc.strdup(secret)
                if not value:
                    for j in range(i):
                        if answer[j].resp:
                            libc.free(answer[j].resp)
                    libc.free(buf)
                    return 5
                answer[i].resp = value
            elif style not in (3, 4):
                for j in range(i):
                    if answer[j].resp:
                        libc.free(answer[j].resp)
                libc.free(buf)
                return 19
        response[0] = ctypes.cast(buf, POINTER(_PamResponse))
        return 0

    conv = _PamConv(conversation, None)
    handle = c_void_p()
    if lib.pam_start(service.encode(), uname, byref(conv), byref(handle)) != 0:
        pw[:] = b'\x00' * len(pw)
        raise PAMError('PAM initialization failed')
    try:
        if lib.pam_authenticate(handle, 0) != 0:
            raise PAMError('PAM authentication failed')
        if lib.pam_acct_mgmt(handle, 0) != 0:
            raise PAMError('PAM account policy denied login')
        if lib.pam_setcred(handle, 2) != 0:  # PAM_ESTABLISH_CRED
            raise PAMError('PAM credential initialization failed')
        if lib.pam_open_session(handle, 0) != 0:
            raise PAMError('PAM session initialization failed')
    except BaseException:
        lib.pam_end(handle, 1)
        pw[:] = b'\x00' * len(pw)
        raise
    # The callback remains installed for PAM session cleanup; clear its
    # captured password immediately after the authentication exchange.
    pw[:] = b'\x00' * len(pw)
    return PAMSession(lib, handle, conversation, conv, username)
