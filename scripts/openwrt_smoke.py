"""Exercise actual OpenWrt Python, musl libraries, root worker and BusyBox ash."""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time

from rdheadless import crypto, zstd, protocol as p
from rdheadless.client import Peer
from rdheadless.stream import Stream


def _socket_client(sock, identity):
    stream = Stream(sock)
    identity_blob = p.Fields(stream.read()).sub(p.SIGNED_ID).b(1)
    idpk = p.Fields(crypto.verify_signed_blob(identity_blob, identity.public))
    pk, sk = crypto.box_keypair()
    key = os.urandom(32)
    stream.send(p.top(p.PUBLIC_KEY, p.msg(p.field_b(1, pk), p.field_b(2, crypto.seal_box(key, idpk.b(2), sk)))))
    stream.set_key(key)
    h = p.Fields(stream.read()).sub(p.HASH)
    return stream, h.s(1), h.s(2)


def main():
    assert os.geteuid() == 0, 'OpenWrt smoke test must run as root'
    assert crypto._nacl is None, 'OpenWrt must be tested using system libsodium'
    assert zstd._zstandard is None, 'OpenWrt must be tested using system libzstd'
    assert crypto._lib is not None and zstd.lib is not None
    with tempfile.TemporaryDirectory(prefix='ow-') as directory:
        base = Path(directory)
        (base / 'secret.txt').write_text('OpenWrt file download verified')
        (base / 'secret.txt').chmod(0o600)
        (base / 'password').write_text('root-openwrt-unique-secret\n')
        (base / 'password').chmod(0o600)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        cfg = base / 'config.toml'
        cfg.write_text(f'''[server]
mode="private"
device_id="RDOpenWrtSmoke"
identity_file="{base}/identity.json"
password_file="{base}/password"
listen_host="127.0.0.1"
listen_port={port}
shell="/bin/ash"
login_shell=true
file_root="{base}"
''')
        cmd = '/usr/bin/rdheadless'
        info = subprocess.run([cmd, 'identity', '--config', str(cfg)], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, check=True, timeout=20)
        assert 'Public key (base64):' in info.stdout
        identity = crypto.load_identity(str(base/'identity.json'), 'RDOpenWrtSmoke')
        host = subprocess.Popen([cmd, 'host', '--config', str(cfg)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 25
            while True:
                if host.poll() is not None:
                    raise RuntimeError(f'OpenWrt host failed with {host.returncode}')
                try:
                    peer = Peer.connect(('127.0.0.1', port), 'RDOpenWrtSmoke', identity.public,
                                        'private', 'file', 'root-openwrt-unique-secret')
                    break
                except (OSError, EOFError, ConnectionError):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.2)
            with peer.stream.sock:
                names = {name for name, *_ in peer.ls(directory)}
                assert 'secret.txt' in names
                result = base / 'download.txt'
                peer.get_file(str(base/'secret.txt'), str(result))
                assert result.read_text() == 'OpenWrt file download verified'
            with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
                raw.settimeout(15)
                stream, salt, challenge = _socket_client(raw, identity)
                login = p.msg(p.field_s(1, 'RDOpenWrtSmoke'),
                              p.field_b(2, crypto.password_response('root-openwrt-unique-secret', salt, challenge)),
                              p.field_s(4, 'openwrt-smoke'), p.field_b(16, p.msg()))
                stream.send(p.top(p.LOGIN_REQUEST, login))
                assert p.Fields(stream.read()).sub(p.LOGIN_RESPONSE).has(2)
                stream.send(p.top(p.TERMINAL_ACTION, p.field_b(1, p.msg(
                    p.field_u(1, 1), p.field_u(2, 24), p.field_u(3, 80)))))
                limit = time.monotonic() + 10
                while time.monotonic() < limit:
                    reply = p.Fields(stream.read()).sub(p.TERMINAL_RESPONSE).family((1, 2, 3, 4))
                    if reply and reply[0] == 1:
                        assert reply[1].u(2) == 1
                        break
                else:
                    raise RuntimeError('OpenWrt BusyBox terminal did not start')
                stream.send(p.top(p.TERMINAL_ACTION, p.field_b(2, p.msg(
                    p.field_u(1, 1), p.field_b(2, b'printf OW_UID=; id -u; exit\n')))))
                output = b''
                while time.monotonic() < limit:
                    reply = p.Fields(stream.read()).sub(p.TERMINAL_RESPONSE).family((1, 2, 3, 4))
                    if reply and reply[0] == 2:
                        output += reply[1].b(2)
                        if b'OW_UID=0' in output.replace(b'\r', b''):
                            break
                assert b'OW_UID=0' in output.replace(b'\r', b''), output[:300]
            print('OpenWrt musl libsodium/libzstd, root file transfer and BusyBox ash terminal: passed')
        finally:
            host.terminate()
            try:
                host.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                host.kill()
                host.communicate(timeout=5)


if __name__ == '__main__':
    main()
