import socket
import pytest
from rdheadless import protocol as p
from rdheadless.files import FileWorkspace
from rdheadless.server import HostServer
from test_host_e2e import fixture_config, client, login, run_server


def test_workspace_canonical_path_check(tmp_path):
    allowed = tmp_path / 'allowed'
    allowed.mkdir()
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'secret').write_text('classified')
    (allowed / 'link').symlink_to(outside, target_is_directory=True)
    workspace = FileWorkspace(str(allowed), str(allowed))
    try:
        with pytest.raises(PermissionError):
            workspace.relative(str(outside / 'secret'))
        with pytest.raises(PermissionError):
            workspace.relative('../../etc/passwd')
        with pytest.raises(OSError):
            workspace.list('link')
        with pytest.raises(OSError):
            with workspace.open_read('link/secret'):
                pass
        workspace.mkdir('sub/a')
        assert (allowed / 'sub' / 'a').is_dir()
        workspace.rename('sub/a', 'b')
        assert (allowed / 'sub' / 'b').is_dir()
        workspace.remove('sub/b', directory=True)
        assert not (allowed / 'sub' / 'b').exists()
    finally:
        workspace.close()


def test_file_upload_full_protocol_private_session(tmp_path):
    server = HostServer(fixture_config(tmp_path))
    addr, background = run_server(server)
    try:
        with socket.create_connection(addr, timeout=2) as raw:
            stream, salt, challenge = client(raw, server.identity)
            assert login(stream, salt, challenge, 'private-password-strong', 7).has(2)
            assert p.Fields(stream.read()).has(p.FILE_RESPONSE)
            payload = b'HELLO_FROM_OFFICIAL_PROTOCOL'
            manifest = p.msg(p.field_u(1, 4), p.field_s(2, 'upload.txt'),
                             p.field_u(4, len(payload)), p.field_u(5, 1000000000))
            receive = p.msg(p.field_u(1, 55), p.field_s(2, str(tmp_path)),
                            p.field_b(3, manifest), p.field_u(5, len(payload)))
            stream.send(p.top(p.FILE_ACTION, p.field_b(3, receive)))
            digest = p.msg(p.field_u(1, 55), p.field_u(2, 0),
                           p.field_u(3, 1000000000), p.field_u(4, len(payload)))
            stream.send(p.top(p.FILE_RESPONSE, p.field_b(5, digest)))
            confirm = p.Fields(stream.read()).sub(p.FILE_ACTION).sub(9)
            assert confirm.u(1) == 55 and confirm.u(4) == 0
            block = p.msg(p.field_u(1, 55), p.field_u(2, 0), p.field_b(3, payload))
            stream.send(p.top(p.FILE_RESPONSE, p.field_b(2, block)))
            stream.send(p.top(p.FILE_RESPONSE, p.field_b(4,
                p.msg(p.field_u(1, 55), p.field_u(2, 2)))))
            finished = p.Fields(stream.read()).sub(p.FILE_RESPONSE).sub(4)
            assert finished.u(1) == 55
            assert (tmp_path / 'upload.txt').read_bytes() == payload
    finally:
        server.stop()
        background.join(2)


def test_private_file_protocol_rejects_unsafe_paths(tmp_path):
    server = HostServer(fixture_config(tmp_path))
    addr, background = run_server(server)
    try:
        with socket.create_connection(addr, timeout=2) as raw:
            stream, salt, challenge = client(raw, server.identity)
            assert login(stream, salt, challenge, 'private-password-strong', 7).has(2)
            p.Fields(stream.read())
            stream.send(p.top(p.FILE_ACTION, p.field_b(1, p.field_s(1, '/etc'))))
            response = p.Fields(stream.read()).sub(p.FILE_RESPONSE).sub(3)
            assert 'workspace' in response.s(2)
    finally:
        server.stop()
        background.join(2)
