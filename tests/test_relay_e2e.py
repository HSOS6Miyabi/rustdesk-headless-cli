"""Local hbbs/hbbr socket simulator exercising the standard relay protocol."""
from __future__ import annotations

import select
import socket
import threading
import time

from rdheadless import protocol as p
from rdheadless.client import Peer
from rdheadless.rendezvous import connect_via_relay
from rdheadless.server import Config, HostServer
from rdheadless.stream import Stream


def encode_addr(address: tuple[str, int]) -> bytes:
    ipv4 = int.from_bytes(socket.inet_aton(address[0]), 'little')
    stamp = int(time.time_ns() // 1000) & 0xffffffff
    number = ((ipv4 + stamp) << 49) | (stamp << 17) | (address[1] + (stamp & 65535))
    return number.to_bytes(16, 'little').rstrip(b'\0')


class RelaySimulator:
    def __init__(self):
        self.hbbs = socket.socket()
        self.hbbs.bind(('127.0.0.1', 0))
        self.hbbs.listen(8)
        self.hbbs.settimeout(0.25)
        self.hbbs_port = self.hbbs.getsockname()[1]
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(('127.0.0.1', self.hbbs_port))
        self.udp.settimeout(0.25)
        self.hbbr = socket.socket()
        self.hbbr.bind(('127.0.0.1', 0))
        self.hbbr.listen(8)
        self.hbbr.settimeout(0.25)
        self.hbbr_port = self.hbbr.getsockname()[1]
        self.registered = threading.Event()
        self.done = threading.Event()
        self.error = None
        self._stop = threading.Event()
        self.threads = []

    def start(self):
        for target in (self._hbbs_loop, self._hbbr_loop):
            t = threading.Thread(target=self._run, args=(target,), daemon=True)
            self.threads.append(t)
            t.start()

    def _run(self, target):
        try:
            target()
        except BaseException as ex:
            self.error = ex
            self.done.set()

    def _hbbs_loop(self):
        source = None
        while not self._stop.is_set():
            try:
                data, source = self.udp.recvfrom(4096)
            except socket.timeout:
                continue
            msg = p.Fields(data)
            if msg.has(p.REGISTER_PK):
                register = msg.sub(p.REGISTER_PK)
                assert register.s(1) == 'RelayedPeer123'
                assert len(register.b(2)) >= 16
                assert len(register.b(3)) == 32
                self.udp.sendto(p.top(p.REGISTER_PK_RESPONSE, p.field_u(1, 0)), source)
                self.registered.set()
                break
        assert self.registered.is_set()
        controller = None
        while not self._stop.is_set():
            try:
                controller, controller_addr = self.hbbs.accept()
                break
            except socket.timeout:
                continue
        assert controller is not None
        with controller:
            req = p.Fields(Stream(controller).read()).sub(p.REQUEST_RELAY)
            assert req.s(1) == 'RelayedPeer123'
            assert req.u(5) == 1
            assert req.u(7) == p.FILE_TRANSFER_CONN
            uid = req.s(2)
            assert len(uid) == 36
            encoded = encode_addr(controller_addr)
            to_host = p.msg(p.field_s(1, 'RelayedPeer123'), p.field_s(2, uid),
                            p.field_b(3, encoded),
                            p.field_s(4, f'127.0.0.1:{self.hbbr_port}'), p.field_u(5, 1))
            self.udp.sendto(p.top(p.REQUEST_RELAY, to_host), source)
            response_conn = None
            while not self._stop.is_set():
                try:
                    response_conn, _ = self.hbbs.accept()
                    break
                except socket.timeout:
                    continue
            assert response_conn is not None
            with response_conn:
                ack = p.Fields(Stream(response_conn).read()).sub(p.RELAY_RESPONSE)
                assert ack.b(1) == encoded
                assert ack.s(2) == ''  # Official response to RequestRelay.
            Stream(controller).send(p.top(p.RELAY_RESPONSE, p.field_s(7, '1.4.1')))
            self.done.wait(10)

    def _hbbr_loop(self):
        pair = []
        try:
            while len(pair) < 2 and not self._stop.is_set():
                try:
                    sock, _ = self.hbbr.accept()
                except socket.timeout:
                    continue
                req = p.Fields(Stream(sock).read()).sub(p.REQUEST_RELAY)
                assert req.s(2) and req.s(6) == ''
                pair.append((sock, req.s(2)))
            if len(pair) != 2:
                return
            assert pair[0][1] == pair[1][1], 'relay pairing UUID mismatch'
            sockets = [conn for conn, _ in pair]
            for sock in sockets:
                sock.setblocking(False)
            while not self._stop.is_set():
                reads, _, _ = select.select(sockets, [], [], .25)
                for src in reads:
                    try:
                        data = src.recv(65536)
                    except BlockingIOError:
                        continue
                    if not data:
                        return
                    dst = sockets[1] if src is sockets[0] else sockets[0]
                    dst.sendall(data)
        finally:
            self.done.set()
            for conn, _ in pair:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self._stop.set()
        for sock in (self.udp, self.hbbs, self.hbbr):
            sock.close()
        for thread in self.threads:
            thread.join(2)
        if self.error is not None:
            raise self.error


def test_relay_simulation_to_real_host_worker(tmp_path):
    simulation = RelaySimulator()
    simulation.start()
    (tmp_path / 'hello.txt').write_bytes(b'over-a-vanilla-rustdesk-relay')
    password_file = tmp_path / 'password'
    password_file.write_text('A-secure-test-password\n')
    password_file.chmod(0o600)
    temp_listener = socket.socket()
    temp_listener.bind(('127.0.0.1', 0))
    listen_port = temp_listener.getsockname()[1]
    temp_listener.close()
    host = HostServer(Config(
        mode='private', device_id='RelayedPeer123',
        identity_file=str(tmp_path / 'identity.json'),
        password_file=str(password_file),
        file_root=str(tmp_path), listen_host='127.0.0.1', listen_port=listen_port,
        enable_public_rendezvous=True,
        rendezvous_server=f'127.0.0.1:{simulation.hbbs_port}',
        relay_server=f'127.0.0.1:{simulation.hbbr_port}',
    ))
    host.start()
    handler = threading.Thread(target=host.serve_forever, daemon=True)
    handler.start()
    try:
        assert simulation.registered.wait(3), 'device not registered with mock hbbs'
        remote = connect_via_relay(
            f'127.0.0.1:{simulation.hbbs_port}',
            f'127.0.0.1:{simulation.hbbr_port}',
            host.identity.device_id, p.FILE_TRANSFER_CONN,
        )
        peer = Peer.connect(('127.0.0.1', 0), host.identity.device_id,
                            host.identity.public, 'private', 'file',
                            'A-secure-test-password', connected_socket=remote)
        try:
            assert ('hello.txt', 4, len(b'over-a-vanilla-rustdesk-relay')) in peer.ls(str(tmp_path))
            target = tmp_path / 'received.txt'
            peer.get_file(str(tmp_path / 'hello.txt'), str(target))
            assert target.read_bytes() == b'over-a-vanilla-rustdesk-relay'
        finally:
            peer.close()
        assert simulation.done.wait(3)
    finally:
        host.stop()
        handler.join(3)
        simulation.close()
