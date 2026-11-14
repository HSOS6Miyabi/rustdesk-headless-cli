from rdheadless.client import Peer
from rdheadless.server import HostServer
from test_host_e2e import fixture_config,run_server


def test_cli_file_upload_download_and_directory_listing(tmp_path):
    (tmp_path/'remote.txt').write_bytes(b'client-data-e2e')
    source=tmp_path/'local_upload.txt'
    source.write_bytes(b'uploaded-through-client-API')
    server=HostServer(fixture_config(tmp_path))
    addr,bg=run_server(server)
    try:
        client=Peer.connect(addr,'HostCliTest',server.identity.public,
                            'private','file','private-password-strong',client_id='cli-test')
        try:
            listing=client.ls(str(tmp_path))
            assert 'remote.txt' in [x[0] for x in listing]
            output=tmp_path/'output.dat'
            client.get_file(str(tmp_path/'remote.txt'),str(output))
            assert output.read_bytes()==b'client-data-e2e'
            client.put_file(str(source),str(tmp_path))
            assert source.read_bytes()==b'uploaded-through-client-API'
        finally:
            client.close()
    finally:
        server.stop()
        bg.join(2)


def test_cli_refuses_untrusted_remote_identity(tmp_path):
    server=HostServer(fixture_config(tmp_path))
    addr,bg=run_server(server)
    try:
        import pytest
        with pytest.raises(ValueError):
            Peer.connect(addr,'HostCliTest',b'wrong-key','private','file','private-password-strong')
        with pytest.raises(PermissionError):
            Peer.connect(addr,'WrongPeerID',server.identity.public,'private','file','private-password-strong')
    finally:
        server.stop()
        bg.join(2)
