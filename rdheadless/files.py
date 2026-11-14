"""User-privileged RustDesk file transfer implementation.

All filesystem operations run in the user worker process.  Paths are
resolved with directory file descriptors and O_NOFOLLOW, with a configured
workspace root, so symlink swaps cannot redirect operations outside it.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
import errno
import os
import pathlib
import secrets
import stat
import time
from typing import Callable

from . import protocol as p
from . import zstd


# FileAction oneof
READ_DIR, SEND, RECEIVE, CREATE, REMOVE_DIR, REMOVE_FILE, ALL_FILES, CANCEL, SEND_CONFIRM, RENAME, READ_EMPTY_DIRS = range(1, 12)
# FileResponse oneof
DIR, BLOCK, ERROR, DONE, DIGEST, EMPTY_DIRS = range(1, 7)
FILE_DIR = 0
FILE_DIR_LINK = 2
FILE_REGULAR = 4
FILE_LINK = 5


def entry(name: str, info: os.stat_result) -> bytes:
    if stat.S_ISDIR(info.st_mode):
        kind = FILE_DIR
    elif stat.S_ISLNK(info.st_mode):
        kind = FILE_DIR_LINK
    else:
        kind = FILE_REGULAR
    return p.msg(p.field_u(1, kind), p.field_s(2, name),
                 p.field_u(3, int(name.rsplit('/', 1)[-1].startswith('.'))),
                 p.field_u(4, max(0, info.st_size)),
                 p.field_u(5, max(0, int(info.st_mtime))))


@dataclass
class TransferFile:
    name: str
    kind: int
    size: int
    modified: int


def parse_entry(raw: bytes) -> TransferFile:
    fields = p.Fields(raw)
    return TransferFile(fields.s(2), fields.u(1), fields.u(4), fields.u(5))


class FileWorkspace:
    """A rooted, symlink-resistant directory descriptor interface."""
    def __init__(self, root: str, home: str):
        if not os.path.isabs(root):
            raise ValueError('workspace must be absolute')
        self.root = os.path.realpath(root)
        self.home = home
        self.default = home if os.path.commonpath((self.root, os.path.abspath(home))) == self.root else self.root
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)

    def close(self):
        os.close(self.fd)

    def relative(self, user_path: str) -> str:
        if '\x00' in user_path or len(user_path) > 4096:
            raise ValueError('invalid remote path')
        absolute = user_path if user_path else self.default
        if os.path.isabs(absolute):
            normalized = os.path.normpath(absolute)
            if os.path.commonpath((self.root, normalized)) != self.root:
                raise PermissionError('remote path is outside the permitted workspace')
            relative = os.path.relpath(normalized, self.root)
        else:
            relative = os.path.normpath(absolute)
        parts = pathlib.PurePath(relative).parts
        if any(x in ('..', '', '/') for x in parts) or relative.startswith('/'):
            raise PermissionError('remote path escapes workspace')
        if len(parts) > 64:
            raise ValueError('remote path exceeds directory depth limit')
        return relative

    @contextlib.contextmanager
    def parent(self, remote_path: str):
        rel = self.relative(remote_path)
        parts = pathlib.PurePath(rel).parts
        if not parts or rel == '.':
            raise PermissionError('cannot modify the workspace root')
        fd = os.dup(self.fd)
        try:
            for name in parts[:-1]:
                new = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=fd)
                os.close(fd)
                fd = new
            yield fd, parts[-1]
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def directory(self, remote_path: str):
        rel = self.relative(remote_path)
        fd = os.dup(self.fd)
        try:
            for name in pathlib.PurePath(rel).parts:
                if name == '.':
                    continue
                new = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=fd)
                os.close(fd)
                fd = new
            yield fd
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def open_read(self, remote_path: str):
        with self.parent(remote_path) as (fd, name):
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=fd)
            try:
                st = os.fstat(descriptor)
                if not stat.S_ISREG(st.st_mode):
                    raise PermissionError('read target must be a regular file')
                yield descriptor, st
            finally:
                os.close(descriptor)

    def list(self, remote_path: str, include_hidden: bool = False) -> list[tuple[str, os.stat_result]]:
        with self.directory(remote_path) as fd:
            records = []
            for name in sorted(os.listdir(fd)):
                if name.startswith('.') and not include_hidden:
                    continue
                if len(records) >= 10_000:
                    raise ValueError('directory has too many entries')
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                records.append((name, info))
            return records

    def mkdir(self, remote_path: str, recursive: bool = True):
        rel = self.relative(remote_path)
        fd = os.dup(self.fd)
        try:
            for i, component in enumerate(pathlib.PurePath(rel).parts):
                if component == '.':
                    continue
                try:
                    os.mkdir(component, 0o750, dir_fd=fd)
                except FileExistsError:
                    if not recursive:
                        raise
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
        finally:
            os.close(fd)

    def remove(self, remote_path: str, directory: bool = False):
        with self.parent(remote_path) as (fd, name):
            if directory:
                os.rmdir(name, dir_fd=fd)
            else:
                os.unlink(name, dir_fd=fd)

    def rename(self, remote_path: str, new_name: str):
        if (not new_name or new_name in ('.', '..') or '/' in new_name or '\\' in new_name or
                '\x00' in new_name):
            raise ValueError('new_name must be a single filename')
        with self.parent(remote_path) as (fd, name):
            os.rename(name, new_name, src_dir_fd=fd, dst_dir_fd=fd)

    def scan_tree(self, remote_path: str, include_hidden: bool = False) -> list[TransferFile]:
        rel = self.relative(remote_path)
        items: list[TransferFile] = []
        try:
            with self.open_read(remote_path) as (_, st):
                return [TransferFile('', FILE_REGULAR, st.st_size, int(st.st_mtime))]
        except IsADirectoryError:
            pass
        except PermissionError:
            # A path may denote a directory, in which case open_read rejects it.
            with self.directory(remote_path):
                pass
        def walk(prefix: str, rel_dir: str, depth: int):
            if depth > 32:
                raise ValueError('transfer directory depth exceeds limit')
            for name, st in self.list(rel_dir, include_hidden):
                if stat.S_ISLNK(st.st_mode):
                    continue
                if not stat.S_ISREG(st.st_mode) and not stat.S_ISDIR(st.st_mode):
                    continue
                if len(items) >= 10_000:
                    raise ValueError('transfer has too many entries')
                current = f'{prefix}/{name}' if prefix else name
                kind = FILE_DIR if stat.S_ISDIR(st.st_mode) else FILE_REGULAR
                items.append(TransferFile(current, kind, st.st_size if kind == FILE_REGULAR else 0,
                                          int(st.st_mtime)))
                if kind == FILE_DIR:
                    walk(current, os.path.join(rel_dir, name), depth+1)
        walk('', remote_path, 0)
        return items

    @contextlib.contextmanager
    def staged_file(self, remote_path: str):
        with self.parent(remote_path) as (fd, basename):
            stage_name = f'.rdheadless-tmp-{secrets.token_hex(12)}'
            output = os.open(stage_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=fd)
            committed = False
            try:
                def commit(modified: int):
                    nonlocal committed
                    os.fsync(output)
                    os.fchmod(output, 0o600)
                    if modified:
                        os.utime(output, (modified, modified))
                    os.replace(stage_name, basename, src_dir_fd=fd, dst_dir_fd=fd)
                    os.fsync(fd)
                    committed = True
                yield output, commit
            finally:
                os.close(output)
                if not committed:
                    try: os.unlink(stage_name, dir_fd=fd)
                    except FileNotFoundError: pass


def file_dir_response(job_id: int, path: str, files: list[TransferFile]) -> bytes:
    body = p.msg(p.field_u(1, job_id), p.field_s(2, path),
                 *(p.field_b(3, p.msg(p.field_u(1, x.kind), p.field_s(2, x.name),
                                      p.field_u(4, max(0, x.size)), p.field_u(5, max(0, x.modified))))
                   for x in files))
    return p.top(p.FILE_RESPONSE, p.field_b(DIR, body))


def file_error(job_id: int, file_num: int, detail: str) -> bytes:
    # FileTransferError: id=1 error=2 file_num=3 (sint32)
    return p.top(p.FILE_RESPONSE, p.field_b(ERROR,
        p.msg(p.field_u(1, job_id), p.field_s(2, detail[:512]),
              p.field_u(3, p.encode_sint(file_num)))))


def file_done(job_id: int, file_num: int) -> bytes:
    return p.top(p.FILE_RESPONSE, p.field_b(DONE,
        p.msg(p.field_u(1, job_id), p.field_u(2, p.encode_sint(file_num)))))


def file_digest(job_id: int, file_num: int, info: TransferFile) -> bytes:
    return p.top(p.FILE_RESPONSE, p.field_b(DIGEST,
        p.msg(p.field_u(1, job_id), p.field_u(2, p.encode_sint(file_num)),
              p.field_u(3, max(0,info.modified)), p.field_u(4, max(0,info.size)))))


def file_block(job_id: int, file_num: int, data: bytes) -> bytes:
    return p.top(p.FILE_RESPONSE, p.field_b(BLOCK,
        p.msg(p.field_u(1, job_id), p.field_u(2, p.encode_sint(file_num)), p.field_b(3, data))))


@dataclass
class Download:
    job_id: int
    source: str
    files: list[TransferFile]
    index: int = 0


@dataclass
class Upload:
    job_id: int
    destination: str
    files: list[TransferFile]
    current: int = -1
    stage: object | None = None
    descriptor: int | None = None
    commit: Callable | None = None
    bytes_written: int = 0


class FileManager:
    def __init__(self, stream, workspace: FileWorkspace):
        self.stream, self.workspace = stream, workspace
        self.downloads: dict[int, Download] = {}
        self.uploads: dict[int, Upload] = {}

    def close(self):
        for upload in self.uploads.values():
            if upload.stage:
                upload.stage.__exit__(None, None, None)
        self.downloads.clear()
        self.uploads.clear()

    def initial(self, remote_path: str, hidden: bool):
        self._read_dir(remote_path, hidden)

    def _read_dir(self, remote_path: str, hidden: bool):
        files = [TransferFile(name, FILE_DIR if stat.S_ISDIR(info.st_mode) else
                FILE_LINK if stat.S_ISLNK(info.st_mode) else FILE_REGULAR,
                info.st_size, int(info.st_mtime)) for name, info in
                self.workspace.list(remote_path, hidden)]
        self.stream.send(file_dir_response(0, remote_path or self.workspace.default, files))

    def _send_error(self, job_id, file_num, ex):
        self.stream.send(file_error(job_id, file_num, str(ex)))

    def handle_action(self, raw: bytes):
        f = p.Fields(raw)
        kind, args = f.family((READ_DIR, SEND, RECEIVE, CREATE, REMOVE_DIR,
                               REMOVE_FILE, ALL_FILES, CANCEL, SEND_CONFIRM, RENAME)) or (0, None)
        if args is None:
            raise ValueError('unsupported file action')
        job_id = args.u(1, 0) if kind != READ_DIR else 0
        try:
            if kind == READ_DIR:
                self._read_dir(args.s(1), bool(args.u(2)))
            elif kind == ALL_FILES:
                self.stream.send(file_dir_response(job_id, args.s(2),
                    self.workspace.scan_tree(args.s(2), bool(args.u(3)))))
            elif kind == SEND:
                self._start_download(args)
            elif kind == SEND_CONFIRM:
                self._send_file(args)
            elif kind == RECEIVE:
                self._start_upload(args)
            elif kind == CANCEL:
                self.downloads.pop(job_id, None)
                item = self.uploads.pop(job_id, None)
                if item and item.stage:
                    item.stage.__exit__(None, None, None)
            elif kind == CREATE:
                self.workspace.mkdir(args.s(2))
                self.stream.send(file_done(job_id, 0))
            elif kind == REMOVE_DIR:
                if args.u(3):
                    raise PermissionError('recursive removal is disabled')
                self.workspace.remove(args.s(2), directory=True)
                self.stream.send(file_done(job_id, 0))
            elif kind == REMOVE_FILE:
                self.workspace.remove(args.s(2))
                self.stream.send(file_done(job_id, 0))
            elif kind == RENAME:
                self.workspace.rename(args.s(2), args.s(3))
                self.stream.send(file_done(job_id, 0))
        except (PermissionError, OSError, ValueError, RuntimeError) as ex:
            self._send_error(job_id, 0, ex)

    def _start_download(self, req: p.Fields):
        jid, remote_path = req.u(1), req.s(2)
        if jid in self.downloads or len(self.downloads) >= 8:
            raise PermissionError('duplicate download ID or session limit reached')
        files = self.workspace.scan_tree(remote_path, bool(req.u(3)))
        if len(files) > 10_000:
            raise ValueError('too many transfer entries')
        job = Download(jid, remote_path, files)
        self.downloads[jid] = job
        self.stream.send(file_dir_response(jid, remote_path, files))
        self._advance_download(job)

    def _advance_download(self, job: Download):
        while job.index < len(job.files) and job.files[job.index].kind == FILE_DIR:
            self.stream.send(file_done(job.job_id, job.index))
            job.index += 1
        if job.index >= len(job.files):
            self.stream.send(file_done(job.job_id, len(job.files)))
            self.downloads.pop(job.job_id, None)
            return
        self.stream.send(file_digest(job.job_id, job.index, job.files[job.index]))

    def _send_file(self, req: p.Fields):
        job = self.downloads.get(req.u(1))
        if not job or job.index != p.decode_sint(req.u(2)) or job.index >= len(job.files):
            raise ValueError('unexpected file confirmation')
        if not req.has(3) and not req.has(4):
            raise ValueError('missing download confirmation')
        index = job.index
        if req.has(4):
            if req.u(4) != 0:
                raise PermissionError('remote transfer resume is disabled')
            name = job.files[index].name
            target = os.path.join(job.source, name) if name else job.source
            with self.workspace.open_read(target) as (fd, st):
                expected = job.files[index]
                if st.st_size != expected.size or int(st.st_mtime) != expected.modified:
                    raise PermissionError('download source changed while transferring')
                while True:
                    block = os.read(fd, 64*1024)
                    if not block:
                        break
                    self.stream.send(file_block(job.job_id, index, block))
        self.stream.send(file_done(job.job_id, index))
        job.index += 1
        self._advance_download(job)

    def _start_upload(self, req: p.Fields):
        jid, destination = req.u(1), req.s(2)
        if jid in self.uploads or len(self.uploads) >= 8:
            raise PermissionError('duplicate upload ID or session limit reached')
        entries = [parse_entry(raw) for raw in req.bs(3)]
        if not entries or len(entries) > 10_000:
            raise ValueError('invalid upload manifest')
        total = 0
        for x in entries:
            self.workspace.relative(os.path.join(destination, x.name))
            if not x.name or x.name.startswith('/') or '..' in pathlib.PurePath(x.name).parts:
                raise ValueError('unsafe upload filename')
            if x.kind not in (FILE_DIR, FILE_REGULAR) or x.size > 1<<40:
                raise ValueError('unsupported file type or size')
            total += x.size
            if total > 1<<40:
                raise ValueError('upload exceeds maximum total size')
        with self.workspace.directory(destination):
            pass
        for entry in entries:
            if entry.kind == FILE_DIR:
                self.workspace.mkdir(os.path.join(destination, entry.name))
        self.uploads[jid] = Upload(jid, destination, entries)

    def handle_response(self, raw: bytes):
        result = p.Fields(raw).family((BLOCK, DONE, DIGEST))
        if result is None:
            return
        kind, response = result
        if kind == DIGEST:
            self._upload_digest(response)
        elif kind == BLOCK:
            self._upload_block(response)
        else:
            self._upload_done(response)

    def _upload_digest(self, response: p.Fields):
        jid, idx = response.u(1), p.decode_sint(response.u(2))
        job = self.uploads.get(jid)
        if job is None:
            return
        try:
            if idx != job.current + 1 or idx >= len(job.files):
                raise ValueError('upload file sequence invalid')
            if job.stage:
                self._complete_upload(job)
            ent = job.files[idx]
            if ent.kind != FILE_REGULAR or ent.size != response.u(4) or ent.modified != response.u(3):
                raise PermissionError('upload manifest differs from source metadata')
            location = os.path.join(job.destination, ent.name)
            job.stage = self.workspace.staged_file(location)
            job.descriptor, job.commit = job.stage.__enter__()
            job.bytes_written = 0
            job.current = idx
            # SendConfirm is an official FileAction, not a new client message.
            confirm = p.msg(p.field_u(1, jid), p.field_u(2, p.encode_sint(idx)), p.field_u(4, 0))
            self.stream.send(p.top(p.FILE_ACTION, p.field_b(SEND_CONFIRM, confirm)))
        except (OSError, ValueError, PermissionError) as ex:
            self._upload_error(job, idx, ex)

    def _upload_block(self, response: p.Fields):
        jid, idx = response.u(1), p.decode_sint(response.u(2))
        job = self.uploads.get(jid)
        if job is None:
            return
        try:
            if job.current != idx or job.descriptor is None:
                raise ValueError('unexpected upload block')
            data = response.b(3)
            if response.u(4):
                data = zstd.decompress(data, 1024*1024)
            if len(data) > 1024*1024 or job.bytes_written + len(data) > job.files[idx].size:
                raise ValueError('upload exceeds declared file size')
            while data:
                consumed = os.write(job.descriptor, data)
                if consumed < 1:
                    raise OSError('short file write')
                job.bytes_written += consumed
                data = data[consumed:]
        except (OSError, ValueError, PermissionError) as ex:
            self._upload_error(job, idx, ex)

    def _upload_done(self, response: p.Fields):
        jid, count = response.u(1), p.decode_sint(response.u(2))
        job = self.uploads.get(jid)
        if job is None:
            return
        try:
            if count != len(job.files) or job.current < 0:
                raise ValueError('upload completion did not match manifest')
            self._complete_upload(job)
            self.uploads.pop(jid, None)
            self.stream.send(file_done(jid, count))
        except (OSError, ValueError, PermissionError) as ex:
            self._upload_error(job, count, ex)

    def _complete_upload(self, job: Upload):
        assert job.commit is not None
        if job.bytes_written != job.files[job.current].size:
            raise ValueError('upload is shorter than declared file size')
        job.commit(job.files[job.current].modified)
        job.stage.__exit__(None, None, None)
        job.stage, job.descriptor, job.commit = None, None, None

    def _upload_error(self, job: Upload, idx: int, ex: Exception):
        if job.stage:
            job.stage.__exit__(type(ex), ex, None)
        self.uploads.pop(job.job_id, None)
        self._send_error(job.job_id, idx, ex)
