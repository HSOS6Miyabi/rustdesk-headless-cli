"""Root-owned private sessions and musl-compatible dependency loading."""
import importlib
import os
import pwd
import socket
import time
from unittest import mock

import pytest

from rdheadless import crypto, protocol as p, zstd
from rdheadless.server import Config, HostServer
from rdheadless.client import Peer
from rdheadless.stream import Stream
from test_host_e2e import client, login, run_server


def _cfg(tmp_path, *, shell='/bin/sh'):
    password_file = tmp_path / 'secret'
    password_file.write_text('root-private-long-password\n')
    password_file.chmod(0o600)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    return Config(mode='private', device_id='HostCliTest',
                  identity_file=str(tmp_path/'identity.json'),
                  password_file=str(password_file), shell=shell, login_shell=False,
                  file_root=str(tmp_path), listen_port=port)


@pytest.mark.skipif(os.geteuid() != 0, reason='private-mode root integration test')
def test_root_private_can_read_files_without_pam(tmp_path):
    def no_pam(*_args):
        raise AssertionError('Private mode must never invoke PAM')

    item = tmp_path / 'root-file.txt'
    item.write_text('ROOT_PRIVATE_READ_OK')
    item.chmod(0o600)
    cfg = _cfg(tmp_path)
    server = HostServer(cfg, pam=no_pam)
    addr, thread = run_server(server)
    try:
        peer = Peer.connect(addr, cfg.device_id, server.identity.public, 'private', 'file',
                            'root-private-long-password')
        with peer.stream.sock:
            listing = peer.ls(str(tmp_path))
            assert 'root-file.txt' in {name for name, *_ in listing}
            target = tmp_path / 'downloaded.txt'
            peer.get_file(str(item), str(target))
            assert target.read_text() == 'ROOT_PRIVATE_READ_OK'
    finally:
        server.stop()
        thread.join(timeout=3)


@pytest.mark.skipif(os.geteuid() != 0, reason='private-mode root integration test')
def test_root_private_terminal_uses_root_without_pam(tmp_path):
    def no_pam(*_args):
        raise AssertionError('Private mode must never invoke PAM')

    cfg = _cfg(tmp_path)
    server = HostServer(cfg, pam=no_pam)
    addr, thread = run_server(server)
    try:
        with socket.create_connection(addr, timeout=4) as raw:
            stream, salt, challenge = client(raw, server.identity)
            assert login(stream, salt, challenge, 'root-private-long-password', 16).has(2)
            stream.send(p.top(p.TERMINAL_ACTION, p.field_b(1, p.msg(
                p.field_u(1, 10), p.field_u(2, 24), p.field_u(3, 80)))))
            deadline = time.monotonic() + 9
            while time.monotonic() < deadline:
                family = p.Fields(stream.read()).sub(p.TERMINAL_RESPONSE).family((1, 2, 3, 4))
                if family and family[0] == 1:
                    assert family[1].u(2) == 1
                    break
            else:
                pytest.fail('No terminal opened response')
            stream.send(p.top(p.TERMINAL_ACTION, p.field_b(2, p.msg(
                p.field_u(1, 10), p.field_b(2, b'printf ROOT_UID=; id -u; exit\n')))))
            data = b''
            while time.monotonic() < deadline:
                family = p.Fields(stream.read()).sub(p.TERMINAL_RESPONSE).family((1, 2, 3, 4))
                if family and family[0] == 2:
                    data += family[1].b(2)
                    if b'ROOT_UID=0' in data.replace(b'\r', b''):
                        break
            assert b'ROOT_UID=0' in data.replace(b'\r', b'')
    finally:
        server.stop()
        thread.join(timeout=3)


def test_private_configuration_accepts_root_account(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    cfg.validate()


def test_private_connection_still_requires_password(tmp_path):
    cfg = _cfg(tmp_path)
    server = HostServer(cfg)
    addr, thread = run_server(server)
    try:
        with pytest.raises(Exception, match='Wrong Password'):
            Peer.connect(addr, cfg.device_id, server.identity.public, 'private', 'file',
                         'incorrect-password')
    finally:
        server.stop()
        thread.join(timeout=3)


def test_musl_loads_soname_without_ldconfig():
    with mock.patch('rdheadless.native.find_library', return_value=None):
        fresh_crypto = importlib.reload(crypto)
        fresh_zstd = importlib.reload(zstd)
        assert fresh_crypto._lib is not None or fresh_crypto._nacl is not None
        assert fresh_zstd.lib is not None or fresh_zstd._zstandard is not None
        pk, sk = fresh_crypto.sign_keypair(os.urandom(32))
        assert fresh_crypto.verify_signed_blob(fresh_crypto.sign_message(b'ow', sk), pk) == b'ow'
    importlib.reload(crypto)
    importlib.reload(zstd)
