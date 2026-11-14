"""Isolated RustDesk FileAction-based PAM login for unchanged desktop clients.

No actual filesystem object is created while authentication is pending. The
remote file manager can rename USERNAME and PASSWORD and open LOGIN to submit.
Successful authentication returns control to the host, which starts a worker
under the selected account. Credentials never appear in response filenames.
"""
from __future__ import annotations

import os
import time
from typing import Callable, TypeVar

from . import protocol as p
from .files import FILE_DIR, FILE_REGULAR, file_dir_response, file_done, file_error, TransferFile


AUTH_ROOT = '/__rd_login__'
AUTH_SUBMIT = AUTH_ROOT + '/LOGIN'
AUTH_USERNAME = AUTH_ROOT + '/USERNAME'
AUTH_PASSWORD = AUTH_ROOT + '/PASSWORD'
AUTH_MAX_LENGTH = 200

_T = TypeVar('_T')


def _accepted_filename(value: str) -> bool:
    """Require a filename supported by common GUI clients, with tight limits."""
    if not 1 <= len(value.encode('utf-8')) <= AUTH_MAX_LENGTH:
        return False
    if value in ('.', '..') or value[-1] in (' ', '.'):
        return False
    return not any(ord(char) < 32 or ord(char) == 127 or char in '/\\:*?"<>|' for char in value)


class FileLoginGateway:
    """Keep every unauthenticated FileAction inside a virtual directory."""

    def __init__(self, stream, timeout: float = 180.0, clock: Callable[[], float] = time.monotonic):
        if not 10 <= timeout <= 600:
            raise ValueError('invalid file authentication timeout')
        self.stream = stream
        self.clock = clock
        self.timeout = timeout
        self.username = ''
        self.password = ''
        self.attempts = 0

    def clear(self):
        self.username = ''
        self.password = ''

    def listing(self):
        files = [TransferFile('USERNAME', FILE_REGULAR, 0, 0),
                 TransferFile('PASSWORD', FILE_REGULAR, 0, 0),
                 TransferFile('LOGIN', FILE_DIR, 0, 0)]
        self.stream.send(file_dir_response(0, AUTH_ROOT, files))

    def error(self, job: int, text: str):
        self.stream.send(file_error(job, 0, text))

    def run(self, authorize: Callable[[str, str], _T]) -> _T | None:
        """After login success, caller must switch to a user-privileged worker."""
        deadline = self.clock() + self.timeout
        self.listing()
        try:
            while self.clock() < deadline:
                # Limit time spent in the root process, even with a stalled peer.
                self.stream.sock.settimeout(max(0.1, deadline - self.clock()))
                frame = p.Fields(self.stream.read(), max_size=16 * 1024)
                if frame.has(p.TEST_DELAY):
                    self.stream.send(p.top(p.TEST_DELAY, frame.b(p.TEST_DELAY)))
                    continue
                envelope = frame.family((p.FILE_ACTION, p.FILE_RESPONSE, p.TERMINAL_ACTION, p.MISC))
                if envelope is None:
                    self.error(0, 'Authentication required')
                    continue
                family, content = envelope
                if family != p.FILE_ACTION:
                    # This connection cannot transition to a terminal or use
                    # file-response block uploads before authentication.
                    self.error(0, 'Authentication required')
                    continue
                variant = content.family(range(1, 12))
                if variant is None:
                    self.error(0, 'Authentication required')
                    continue
                kind, action = variant
                if kind == 10:  # FileRename(id, path, new_name)
                    job = action.u(1)
                    source = action.s(2)
                    name = action.s(3)
                    if source not in (AUTH_USERNAME, AUTH_PASSWORD) or not _accepted_filename(name):
                        self.error(job, 'Invalid authentication entry')
                        continue
                    if source == AUTH_USERNAME:
                        self.username = name
                    else:
                        self.password = name
                    self.stream.send(file_done(job, 0))
                    continue
                if kind == 1:  # ReadDir(path, include_hidden)
                    directory = action.s(1)
                    if directory in (AUTH_ROOT, AUTH_ROOT + '/'):
                        self.listing()
                        continue
                    if directory == AUTH_SUBMIT:
                        if not self.username or not self.password:
                            self.error(0, 'Rename USERNAME and PASSWORD before opening LOGIN')
                            continue
                        self.attempts += 1
                        username, password = self.username, self.password
                        self.clear()
                        try:
                            # PAM is called in the privileged host process; the
                            # resulting worker runs with the authenticated UID.
                            outcome = authorize(username, password)
                        except (PermissionError, OSError, LookupError):
                            self.error(0, 'System authentication failed')
                            if self.attempts >= 4:
                                return None
                            continue
                        return outcome
                    self.error(0, 'Authentication required')
                    continue
                # Disallow all reads, writes, directory modifications, transfer
                # requests and port forwarding until the account is verified.
                self.error(action.u(1), 'Authentication required')
        finally:
            self.clear()
        return None
