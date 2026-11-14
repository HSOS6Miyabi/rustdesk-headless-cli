import os
import pwd
import socket
import threading
import time
from pathlib import Path

import pytest
from rdheadless import protocol as p
from rdheadless import crypto
from rdheadless.server import Config, HostServer
from rdheadless.stream import Stream


def fixture_config(tmp_path, mode='private'):
    password = tmp_path / 'passwd'
    password.write_text('private-password-strong')
    password.chmod(0o600)
    return Config(mode=mode, device_id='HostCliTest',
                  identity_file=str(tmp_path/'identity.json'),
                  password_file=str(password), shell='/bin/sh', login_shell=False,
                  file_root=str(tmp_path), listen_port=21118)


def client(sock, identity):
    sock.settimeout(8)
    stream = Stream(sock)
    msg = p.Fields(stream.read()).sub(p.SIGNED_ID)
    identity_body = crypto.verify_signed_blob(msg.b(1), identity.public)
    idpk = p.Fields(identity_body)
    assert idpk.s(1) == identity.device_id
    peer_pub, private = crypto.box_keypair()
    key = os.urandom(32)
    sealed = crypto.seal_box(key, idpk.b(2), private)
    stream.send(p.top(p.PUBLIC_KEY, p.msg(p.field_b(1, peer_pub), p.field_b(2, sealed))))
    stream.set_key(key)
    digest = p.Fields(stream.read()).sub(p.HASH)
    return stream, digest.s(1), digest.s(2)


def login(stream, salt, challenge, password, conn_kind, my_id='test-client'):
    request = p.msg(p.field_s(1, 'HostCliTest'),
                    p.field_b(2, crypto.password_response(password, salt, challenge)),
                    p.field_s(4, my_id), p.field_s(5, 'tester'),
                    p.field_b(conn_kind, p.msg()))
    stream.send(p.top(p.LOGIN_REQUEST, request))
    return p.Fields(stream.read()).sub(p.LOGIN_RESPONSE)


def run_server(server):
    addr = server.start()
    background = threading.Thread(target=server.serve_forever, daemon=True)
    background.start()
    return addr, background


def test_private_remote_terminal_without_gui(tmp_path):
    cfg = fixture_config(tmp_path)
    server = HostServer(cfg)
    addr, bg = run_server(server)
    try:
        with socket.create_connection(addr, timeout=2) as raw:
            stream, salt, challenge = client(raw, server.identity)
            response = login(stream, salt, challenge, 'private-password-strong', 16)
            assert p.Fields(response.b(2)).s(3) == 'Linux'
            stream.send(p.top(p.TERMINAL_ACTION, p.field_b(1, p.msg(
                p.field_u(1, 7), p.field_u(2, 40), p.field_u(3, 120)))))
            replies = []
            deadline = time.monotonic()+6
            while time.monotonic()<deadline:
                reply = p.Fields(stream.read())
                tr = reply.sub(p.TERMINAL_RESPONSE)
                variant = tr.family((1,2,3,4))
                if variant and variant[0] == 1:
                    assert variant[1].u(2)==1
                    break
            else: pytest.fail('terminal open response missing')
            stream.send(p.top(p.TERMINAL_ACTION, p.field_b(2, p.msg(
                p.field_u(1, 7), p.field_b(2, b"printf 'RDC_TERM_E2E\\n'; exit\n")))))
            output = b''
            while time.monotonic()<deadline:
                result = p.Fields(stream.read()).sub(p.TERMINAL_RESPONSE)
                current = result.family((1,2,3,4))
                if current and current[0] == 2:
                    output+=current[1].b(2)
                    if b'RDC_TERM_E2E' in output:
                        break
            assert b'RDC_TERM_E2E' in output
    finally:
        server.stop()
        bg.join(timeout=3)


def test_private_file_session_and_challenge(tmp_path):
    (tmp_path/'hello.txt').write_bytes(b'file-data-from-user')
    server = HostServer(fixture_config(tmp_path))
    addr,bg = run_server(server)
    try:
        with socket.create_connection(addr, timeout=2) as raw:
            stream,salt,challenge = client(raw,server.identity)
            response = login(stream,salt,challenge,'private-password-strong',7)
            assert response.has(2)
            listing = p.Fields(stream.read()).sub(p.FILE_RESPONSE).sub(1)
            entries=[p.Fields(raw).s(2) for raw in listing.bs(3)]
            assert 'hello.txt' in entries
            # Download a single file without changing the official FileAction layout.
            stream.send(p.top(p.FILE_ACTION,p.field_b(2,p.msg(
                p.field_u(1,9),p.field_s(2,str(tmp_path/'hello.txt'))))))
            got_manifest=p.Fields(stream.read()).sub(p.FILE_RESPONSE).sub(1)
            assert got_manifest.u(1) == 9
            digest=p.Fields(stream.read()).sub(p.FILE_RESPONSE).sub(5)
            assert digest.u(4)==len(b'file-data-from-user')
            stream.send(p.top(p.FILE_ACTION,p.field_b(9,p.msg(
                p.field_u(1,9),p.field_u(2,0),p.field_u(4,0)))))
            result=p.Fields(stream.read()).sub(p.FILE_RESPONSE).sub(2)
            assert result.b(3)==b'file-data-from-user'
    finally:
        server.stop()
        bg.join(timeout=3)


def test_wrong_private_password_is_rejected(tmp_path):
    server = HostServer(fixture_config(tmp_path))
    addr,bg = run_server(server)
    try:
        with socket.create_connection(addr,timeout=2) as raw:
            stream,salt,challenge=client(raw,server.identity)
            response=login(stream,salt,challenge,'wrong-password-here',16)
            assert response.s(1)=='Wrong Password'
    finally:
        server.stop()
        bg.join(timeout=3)


def test_saved_password_digest_survives_server_restart(tmp_path):
    import hashlib
    cfg = fixture_config(tmp_path)
    first = HostServer(cfg)
    addr, thread = run_server(first)
    try:
        with socket.create_connection(addr, timeout=2) as raw:
            stream, salt, challenge = client(raw, first.identity)
            response = login(stream, salt, challenge, 'private-password-strong', 7)
            assert response.has(2)
            assert p.Fields(stream.read()).sub(p.FILE_RESPONSE).has(1)
            saved_first_stage = hashlib.sha256(b'private-password-strong'+salt.encode()).digest()
    finally:
        first.stop()
        thread.join(timeout=3)

    restarted = HostServer(cfg)
    addr, thread = run_server(restarted)
    try:
        with socket.create_connection(addr, timeout=2) as raw:
            stream, salt2, challenge2 = client(raw, restarted.identity)
            assert salt2 == salt
            assert challenge2 != challenge
            saved_response = hashlib.sha256(saved_first_stage + challenge2.encode()).digest()
            payload = p.msg(p.field_s(1, cfg.device_id), p.field_b(2, saved_response),
                            p.field_s(4, 'same-client'), p.field_b(7, p.msg()))
            stream.send(p.top(p.LOGIN_REQUEST, payload))
            assert p.Fields(stream.read()).sub(p.LOGIN_RESPONSE).has(2)
            assert p.Fields(stream.read()).sub(p.FILE_RESPONSE).has(1)
    finally:
        restarted.stop()
        thread.join(timeout=3)
