"""RustDesk GUI wire-format tests for public mode file login and PAM isolation."""
from dataclasses import replace
import hashlib
import os
import pwd
import socket
import tempfile
import threading

import pytest
from rdheadless import crypto
from rdheadless import protocol as p
from rdheadless.file_login import AUTH_ROOT, AUTH_SUBMIT, AUTH_USERNAME, AUTH_PASSWORD
from rdheadless.server import Config, HostServer
from rdheadless.client import Peer
from test_host_e2e import client, login, run_server


class FakePAMSession:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


@pytest.fixture
def public_server():
    assert os.geteuid() == 0
    user = pwd.getpwnam('oai')
    with tempfile.TemporaryDirectory(prefix='rdheadless-public-') as temp:
        workspace = os.path.join(temp, 'workspace')
        os.chmod(temp, 0o755)
        os.mkdir(workspace, 0o700)
        os.chown(workspace, user.pw_uid, user.pw_gid)
        known = os.path.join(workspace, 'known.txt')
        with open(known, 'w') as out:
            out.write('private-user-content')
        os.chown(known, user.pw_uid, user.pw_gid)
        logins = []
        def fake_pam(username, password, service):
            logins.append((username, password, service))
            if username != user.pw_name or password != 'correct-account-password':
                raise PermissionError('invalid credentials')
            return FakePAMSession()
        cfg = Config('public', 'HostCliTest', os.path.join(temp, 'identity.json'),
                     file_root=workspace, shell='/bin/sh', login_shell=False)
        srv = HostServer(cfg, pam=fake_pam)
        yield srv, workspace, logins, user


def login_public(stream, kind=7, os_username=None, password='', client_id='client-a',
                 salt='', challenge='', target=None):
    payload = p.msg(p.field_s(1, 'HostCliTest'),
                    p.field_s(4, client_id), p.field_s(5, 'OfficialRustDesk'),
                    p.field_b(kind, target if target is not None else p.msg()))
    if os_username is not None:
        payload += p.field_b(12, p.msg(p.field_s(1, os_username), p.field_s(2, password)))
    elif password:
        payload += p.field_b(2, crypto.password_response(password, salt, challenge))
    stream.send(p.top(p.LOGIN_REQUEST, payload))
    return p.Fields(stream.read()).sub(p.LOGIN_RESPONSE)


def open_gui_file(addr, srv, password=''):
    sock = socket.create_connection(addr, timeout=3)
    stream, salt, challenge = client(sock, srv.identity)
    result = login_public(stream, password=password, salt=salt, challenge=challenge)
    if not result.has(2):
        sock.close()
        raise AssertionError('file login rejected: '+result.s(1))
    initial = p.Fields(stream.read()).sub(p.FILE_RESPONSE).sub(1)
    assert initial.s(2) == AUTH_ROOT
    names = [p.Fields(blob).s(2) for blob in initial.bs(3)]
    assert names == ['USERNAME', 'PASSWORD', 'LOGIN']
    return sock, stream, salt, challenge


def rename(stream, source, new_name, job=1):
    action = p.msg(p.field_u(1, job), p.field_s(2, source), p.field_s(3, new_name))
    stream.send(p.top(p.FILE_ACTION, p.field_b(10, action)))
    return p.Fields(stream.read()).sub(p.FILE_RESPONSE)


def read_dir(stream, remote_path):
    stream.send(p.top(p.FILE_ACTION, p.field_b(1, p.field_s(1, remote_path))))
    return p.Fields(stream.read()).sub(p.FILE_RESPONSE)


def submit(stream, username='oai', password='correct-account-password'):
    assert rename(stream, AUTH_USERNAME, username).has(4)
    assert rename(stream, AUTH_PASSWORD, password, job=2).has(4)
    return read_dir(stream, AUTH_SUBMIT)


def test_public_gui_file_auth_isolated_then_switches_to_pam_user(public_server):
    server, workspace, logins, account = public_server
    addr, thread = run_server(server)
    try:
        raw, stream, *_ = open_gui_file(addr, server)
        with raw:
            for path in (workspace, '/etc', '/', '/home/oai'):
                assert read_dir(stream, path).has(3), path
            # A file download and terminal action cannot bypass authentication.
            stream.send(p.top(p.FILE_ACTION, p.field_b(2, p.msg(
                p.field_u(1, 9), p.field_s(2, os.path.join(workspace, 'known.txt'))))))
            assert p.Fields(stream.read()).sub(p.FILE_RESPONSE).has(3)
            stream.send(p.top(p.TERMINAL_ACTION, p.field_b(1, p.msg(
                p.field_u(1, 3), p.field_u(2, 24), p.field_u(3, 80)))))
            assert p.Fields(stream.read()).sub(p.FILE_RESPONSE).has(3)
            assert logins == []
            assert read_dir(stream, AUTH_ROOT).has(1)
            listing = submit(stream)
            assert listing.has(1), p.Fields(listing.b(3)).s(2) if listing.has(3) else ''
            files = [p.Fields(blob).s(2) for blob in listing.sub(1).bs(3)]
            assert 'known.txt' in files
            assert logins == [('oai','correct-account-password','login')]
            assert read_dir(stream, workspace).has(1)
            assert read_dir(stream, '/etc').has(3)
            # The privileged daemon must delegate writes to the account worker.
            new_dir = os.path.join(workspace, 'created-by-authenticated-user')
            request = p.msg(p.field_u(1, 42), p.field_s(2, new_dir))
            stream.send(p.top(p.FILE_ACTION, p.field_b(4, request)))
            assert p.Fields(stream.read()).sub(p.FILE_RESPONSE).has(4)
            assert os.stat(new_dir).st_uid == account.pw_uid
    finally:
        server.stop()
        thread.join(timeout=3)


def test_public_gui_file_login_failure_retry_and_password_not_reflected(public_server):
    server, workspace, logins, account = public_server
    addr, thread = run_server(server)
    try:
        raw, stream, *_ = open_gui_file(addr, server)
        with raw:
            assert read_dir(stream, AUTH_SUBMIT).has(3)
            assert rename(stream, AUTH_USERNAME, account.pw_name).has(4)
            reply = rename(stream, AUTH_PASSWORD, 'incorrect-password')
            assert reply.has(4)
            assert b'incorrect-password' not in reply.data.get(4, [b''])[0]
            listing = read_dir(stream, AUTH_ROOT).sub(1)
            names = [p.Fields(blob).s(2) for blob in listing.bs(3)]
            assert 'incorrect-password' not in names
            rejected = read_dir(stream, AUTH_SUBMIT)
            assert rejected.has(3)
            assert rejected.sub(3).s(2) == 'System authentication failed'
            assert read_dir(stream, workspace).has(3)
            assert submit(stream).has(1)
            assert len(logins) == 2
    finally:
        server.stop()
        thread.join(timeout=3)


def test_public_gui_file_requires_two_fields_and_denies_unsafe_names(public_server):
    server, workspace, logins, account = public_server
    addr, thread = run_server(server)
    try:
        raw, stream, *_ = open_gui_file(addr, server)
        with raw:
            for invalid in ('', 'x/y', '..', 'a:b', 'wrong\\path', 'a\x00b', 'A' * 201):
                assert rename(stream, AUTH_PASSWORD, invalid).has(3)
            assert rename(stream, workspace+'/known.txt', 'faked').has(3)
            assert rename(stream, AUTH_USERNAME, 'oai').has(4)
            assert read_dir(stream, AUTH_SUBMIT).has(3)
            assert not logins
            assert read_dir(stream, AUTH_ROOT+'/other').has(3)
    finally:
        server.stop()
        thread.join(timeout=3)


def test_public_gui_file_failed_login_rate_limited(public_server):
    server, workspace, logins, account = public_server
    addr, thread = run_server(server)
    try:
        raw, stream, *_ = open_gui_file(addr, server)
        with raw:
            for i in range(4):
                assert rename(stream, AUTH_USERNAME, 'oai', 10+i).has(4)
                assert rename(stream, AUTH_PASSWORD, 'bad-password', 20+i).has(4)
                assert read_dir(stream, AUTH_SUBMIT).has(3)
            # Connection is closed after the fourth failed submission.
            with pytest.raises((EOFError, OSError)):
                read_dir(stream, AUTH_ROOT)
            assert len(logins)==4
    finally:
        server.stop()
        thread.join(timeout=3)


def test_public_gui_saved_password_reconnect_keeps_same_salt(public_server):
    server, workspace, logins, account = public_server
    with tempfile.NamedTemporaryFile(dir=os.path.dirname(server.cfg.identity_file), delete=False) as pw:
        pw.write(b'optional-connection-password-long\n')
    os.chmod(pw.name, 0o600)
    server.cfg = replace(server.cfg, password_file=pw.name)
    server._connection_password = b'optional-connection-password-long'
    addr, thread = run_server(server)
    try:
        with socket.create_connection(addr, timeout=3) as raw:
            st, salt, challenge = client(raw, server.identity)
            first_hash = hashlib.sha256(b'optional-connection-password-long'+salt.encode()).digest()
            reply = login_public(st, password='optional-connection-password-long',salt=salt,challenge=challenge)
            assert reply.has(2)
            assert p.Fields(st.read()).sub(p.FILE_RESPONSE).has(1)
        with socket.create_connection(addr, timeout=3) as raw:
            st, salt2, challenge2 = client(raw, server.identity)
            assert salt == salt2
            assert challenge != challenge2
            saved_response = hashlib.sha256(first_hash + challenge2.encode()).digest()
            payload = p.msg(p.field_s(1, 'HostCliTest'), p.field_b(2, saved_response),
                            p.field_s(4,'client-a'), p.field_b(7,p.msg()))
            st.send(p.top(p.LOGIN_REQUEST,payload))
            assert p.Fields(st.read()).sub(p.LOGIN_RESPONSE).has(2)
            assert p.Fields(st.read()).sub(p.FILE_RESPONSE).sub(1).s(2) == AUTH_ROOT
            assert read_dir(st, workspace).has(3)
    finally:
        server.stop()
        thread.join(timeout=3)


def test_public_direct_file_login_uses_pam_without_virtual_directory(public_server):
    server, workspace, logins, account = public_server
    addr, thread = run_server(server)
    try:
        peer = Peer.connect(addr, server.identity.device_id, server.identity.public,
                            'public','file','correct-account-password',account.pw_name)
        try:
            assert any(name=='known.txt' for name,kind,size in peer.ls(workspace))
            assert logins == [('oai','correct-account-password','login')]
        finally:
            peer.close()
    finally:
        server.stop()
        thread.join(timeout=3)


def test_public_terminal_pam_login_and_user_shell(public_server):
    server, workspace, logins, account = public_server
    addr, thread = run_server(server)
    try:
        with socket.create_connection(addr, timeout=3) as raw:
            st, salt, challenge = client(raw, server.identity)
            assert login_public(st, kind=16, os_username='oai',password='wrong-password').has(1)
        with socket.create_connection(addr, timeout=3) as raw:
            st, salt, challenge = client(raw, server.identity)
            assert login_public(st,kind=16,os_username='oai',password='correct-account-password').has(2)
            st.send(p.top(p.TERMINAL_ACTION,p.field_b(1,p.msg(
                p.field_u(1,5),p.field_u(2,24),p.field_u(3,80)))))
            seen = []
            while True:
                answer = p.Fields(st.read()).sub(p.TERMINAL_RESPONSE)
                kind, item = answer.family((1,2,3,4))
                if kind==1:
                    assert item.u(2)
                    break
                if kind==2: seen.append(item.b(2))
            st.send(p.top(p.TERMINAL_ACTION,p.field_b(2,p.msg(
                p.field_u(1,5),p.field_b(2,b'echo SESSION_UID_$(id -u); exit\n')))))
            output=b''
            for _ in range(25):
                response = p.Fields(st.read()).sub(p.TERMINAL_RESPONSE)
                kind, item = response.family((1,2,3,4))
                if kind==2:
                    output += item.b(2)
                if ('SESSION_UID_'+str(account.pw_uid)).encode() in output:
                    break
                if kind==3:
                    break
            assert ('SESSION_UID_'+str(account.pw_uid)).encode() in output
            assert len(logins)==2
    finally:
        server.stop()
        thread.join(timeout=3)


def test_port_forward_requires_explicit_allowlist(public_server):
    server, workspace, logins, account = public_server
    server.cfg=replace(server.cfg,allow_tunnel=True,tunnel_ports=(54321,))
    addr, thread = run_server(server)
    try:
        with socket.create_connection(addr,timeout=3) as raw:
            st, *_ = client(raw, server.identity)
            target=p.msg(p.field_s(1,'192.0.2.1'),p.field_u(2,54321))
            assert login_public(st,kind=8,target=target).has(1)
        with socket.create_connection(addr,timeout=3) as raw:
            st, *_ = client(raw, server.identity)
            target=p.msg(p.field_s(1,'127.0.0.1'),p.field_u(2,22))
            assert login_public(st,kind=8,target=target).has(1)
    finally:
        server.stop()
        thread.join(timeout=3)


def test_public_second_file_connection_same_client_still_requires_pam(public_server):
    server, workspace, logins, account = public_server
    addr, thread = run_server(server)
    try:
        raw, stream, *_ = open_gui_file(addr, server)
        with raw:
            assert submit(stream).has(1)
        assert len(logins)==1
        raw2, second, *_ = open_gui_file(addr, server)
        with raw2:
            assert read_dir(second, workspace).has(3)
            assert len(logins)==1
            assert read_dir(second, AUTH_ROOT).has(1)
            assert submit(second).has(1)
            assert len(logins)==2
    finally:
        server.stop()
        thread.join(timeout=3)


def test_public_shared_connection_password_also_works_with_cli(public_server):
    server, workspace, logins, account = public_server
    with tempfile.NamedTemporaryFile(dir=os.path.dirname(server.cfg.identity_file), delete=False) as pw:
        pw.write(b'correct-public-shared-password\n')
    os.chmod(pw.name, 0o600)
    server.cfg = replace(server.cfg, password_file=pw.name)
    server._connection_password = b'correct-public-shared-password'
    addr, thread = run_server(server)
    try:
        from rdheadless.client import RemoteError
        with pytest.raises(RemoteError, match='Wrong Password'):
            Peer.connect(addr,server.identity.device_id,server.identity.public,'public','file',
                         'correct-account-password','oai')
        peer=Peer.connect(addr,server.identity.device_id,server.identity.public,'public','file',
                          'correct-account-password','oai',
                          connection_password='correct-public-shared-password')
        try:
            assert any(name=='known.txt' for name,kind,size in peer.ls(workspace))
        finally:
            peer.close()
    finally:
        server.stop()
        thread.join(timeout=3)
