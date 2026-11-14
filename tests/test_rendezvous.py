import socket
import threading
import time

from rdheadless import crypto, protocol as p
from rdheadless.rendezvous import Registration, server_address
from rdheadless.stream import Stream
from rdheadless.server import Config


def test_ipv4_ipv6_address_parsing():
    assert server_address('localhost',21116)==('localhost',21116)
    assert server_address('example.test:21117',21116)==('example.test',21117)
    assert server_address('[::1]:21117',21116)==('::1',21117)


def test_rendezvous_register_and_relay_coordination(tmp_path):
    tcp_hbbs=socket.socket()
    tcp_hbbs.bind(('127.0.0.1',0))
    tcp_hbbs.listen(1)
    tcp_hbbs.settimeout(6)
    port=tcp_hbbs.getsockname()[1]
    udp_hbbs=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    udp_hbbs.bind(('127.0.0.1',port))
    udp_hbbs.settimeout(6)
    hbbr=socket.socket()
    hbbr.bind(('127.0.0.1',0))
    hbbr.listen(1)
    hbbr.settimeout(6)
    relay_port=hbbr.getsockname()[1]

    class Stub:
        def __init__(self):
            self.cfg=Config('private','TestPeer123',str(tmp_path/'identity.json'),
                            password_file='unused',
                            rendezvous_server=f'127.0.0.1:{port}',
                            relay_server=f'127.0.0.1:{relay_port}')
            self.identity=crypto.load_identity(self.cfg.identity_file,self.cfg.device_id)
            self._stop=threading.Event()
            self.visited=[]
        def handle_socket(self, sock):
            self.visited.append(True)

    host=Stub()
    registration=Registration(host)
    bg=threading.Thread(target=registration.run,daemon=True)
    bg.start()
    try:
        raw,source=udp_hbbs.recvfrom(8192)
        reg=p.Fields(raw).sub(p.REGISTER_PK)
        assert reg.s(1)=='TestPeer123'
        assert reg.b(2)==host.identity.uuid
        assert reg.b(3)==host.identity.public
        udp_hbbs.sendto(p.top(p.REGISTER_PK_RESPONSE,p.field_u(1,0)),source)
        # Use the exact official relay handshake fields, including the UUID.
        punch=p.msg(p.field_b(1,b'peer-address'),p.field_s(2,f'127.0.0.1:{relay_port}'),
                    p.field_u(5,1))
        udp_hbbs.sendto(p.top(p.PUNCH_HOLE,punch),source)
        conn,_=tcp_hbbs.accept()
        with conn:
            result=p.Fields(Stream(conn).read()).sub(p.RELAY_RESPONSE)
            relay_uuid=result.s(2)
            assert relay_uuid
            assert result.s(3)==f'127.0.0.1:{relay_port}'
            assert result.s(4)=='TestPeer123'
        peer,_=hbbr.accept()
        with peer:
            request=p.Fields(Stream(peer).read()).sub(p.REQUEST_RELAY)
            assert request.s(2)==relay_uuid
        deadline=time.monotonic()+2
        while time.monotonic()<deadline and not host.visited:
            time.sleep(0.03)
        assert host.visited
    finally:
        host._stop.set()
        bg.join(2)
        udp_hbbs.close()
        tcp_hbbs.close()
        hbbr.close()
