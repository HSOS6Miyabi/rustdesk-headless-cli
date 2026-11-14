"""RustDesk hbbs registration and hbbr relay coordination (TCP/UDP).

This module uses the unchanged RustDesk rendezvous Protobuf fields. TCP
relaying is available; UDP/KCP and WebRTC ICE paths have separate upstream
implementations and are not represented as implemented here.
"""
from __future__ import annotations

import ipaddress
import logging
import secrets
import socket
import threading
import time
import uuid

from . import protocol as p
from .stream import Stream

LOG = logging.getLogger('rdheadless.rendezvous')


def server_address(value: str, default_port: int) -> tuple[str, int]:
    value = value.strip()
    if not value:
        raise ValueError('server address must be configured')
    if value.startswith('['):
        close = value.find(']')
        if close < 0:
            raise ValueError('invalid IPv6 server address')
        host = value[1:close]
        port = int(value[close+2:]) if len(value) > close+1 and value[close+1] == ':' else default_port
    elif value.count(':') == 1:
        host, port_string = value.rsplit(':', 1)
        port = int(port_string)
    else:
        host, port = value, default_port
    if not host or not 0 < port <= 65535:
        raise ValueError('invalid server address or port')
    return host, port


def decode_relay_host(value: str, default_port: int) -> tuple[str, int]:
    host, port = server_address(value, default_port)
    if host in ('localhost', '127.0.0.1', '::1'):
        return host, port
    # Domain names can be configured by the operator; the caller still
    # authenticates its selection against a trusted rendezvous source.
    if any(c in host for c in '\r\n\x00\t/@'):
        raise ValueError('invalid relay hostname')
    return host, port


class Registration:
    def __init__(self, host_server):
        self.host = host_server
        cfg = host_server.cfg
        self.rendezvous = server_address(cfg.rendezvous_server, 21116)
        if cfg.relay_server:
            self.relay = server_address(cfg.relay_server, 21117)
        else:
            self.relay = server_address(cfg.rendezvous_server, 21117)
        self._permitted_relays: dict[tuple[str, int], float] = {}
        self.sem = threading.BoundedSemaphore(16)
        self.accepted_pk = False
        self.timer = 20.0
        self.sock = None

    def _register_pk(self):
        ident = self.host.identity
        body = p.msg(p.field_s(1, ident.device_id),
                     p.field_b(2, ident.uuid), p.field_b(3, ident.public))
        self.sock.send(p.top(p.REGISTER_PK, body))

    def _register_peer(self):
        self.sock.send(p.top(p.REGISTER_PEER, p.field_s(1, self.host.identity.device_id)))

    def _allowed_relay(self, proposed: str) -> tuple[str,int]:
        # hbbs can advertise a relay. It is accepted only from the configured
        # rendezvous server and re-validated on any later relay request.
        if self.host.cfg.relay_server:
            configured = self.relay
            if proposed and server_address(proposed, 21117) != configured:
                raise PermissionError('relay does not match the configured host')
            return configured
        if proposed and decode_relay_host(proposed, 21117) != self.relay:
            raise PermissionError('relay must be explicitly configured')
        return self.relay

    def _handle(self, message: bytes):
        parsed = p.Fields(message)
        kind, fields = parsed.family((p.REGISTER_PEER_RESPONSE, p.REGISTER_PK_RESPONSE,
                                      p.PUNCH_HOLE, p.REQUEST_RELAY)) or (0, None)
        if fields is None:
            return
        if kind == p.REGISTER_PEER_RESPONSE:
            if fields.u(2):
                self._register_pk()
        elif kind == p.REGISTER_PK_RESPONSE:
            result = fields.u(1)
            self.accepted_pk = result == 0
            if not self.accepted_pk:
                LOG.warning('rendezvous refused registration with status %d', result)
            if fields.u(2) > 0:
                self.timer = max(5.0, min(float(fields.u(2)), 120.0))
        elif kind == p.PUNCH_HOLE:
            relay = self._allowed_relay(fields.s(2))
            source = fields.b(1)
            if not source or len(source) > 18:
                return
            if self.sem.acquire(False):
                thread = threading.Thread(target=self._relay_connection,
                    args=(source, relay, True, True, None), daemon=True)
                thread.start()
        elif kind == p.REQUEST_RELAY:
            if not fields.u(5):
                return  # Public/OS credentials may not cross plaintext sessions.
            relay = self._allowed_relay(fields.s(4))
            relay_uuid = fields.s(2)
            try:
                uuid.UUID(relay_uuid)
            except (ValueError, AttributeError):
                return
            if not fields.b(3) or len(fields.b(3)) > 18:
                return
            if self.sem.acquire(False):
                thread = threading.Thread(target=self._relay_connection,
                    args=(fields.b(3), relay, False, True, relay_uuid), daemon=True)
                thread.start()

    def _relay_connection(self, source, relay, initiated, secure, token):
        try:
            relay_uuid = token if token is not None else str(uuid.uuid4())
            # Tell hbbs which relay pairing the controlled peer will open.
            message = p.msg(p.field_b(1, source), p.field_s(7, '1.4.1'))
            if initiated:
                message += p.field_s(2, relay_uuid)
                message += p.field_s(3, f'{relay[0]}:{relay[1]}')
                message += p.field_s(4, self.host.identity.device_id)
            with socket.create_connection(self.rendezvous, timeout=8) as control:
                Stream(control).send(p.top(p.RELAY_RESPONSE, message))
            # hbbr pairs the host and controller by the UUID provided by hbbs.
            with socket.create_connection(relay, timeout=8) as peer:
                channel = Stream(peer)
                channel.send(p.top(p.REQUEST_RELAY, p.msg(p.field_s(2, relay_uuid),
                    p.field_s(6, self.host.cfg.rendezvous_key))))
                self.host.handle_socket(peer)
        except (EOFError, OSError, PermissionError, ValueError) as ex:
            LOG.debug('relay session ended: %s', type(ex).__name__)
        finally:
            self.sem.release()

    def run(self):
        # Only packets from the configured hbbs address are processed.
        host, port = self.rendezvous
        candidates = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        family, _, _, _, remote = candidates[0]
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        with self.sock:
            self.sock.connect(remote)
            self.sock.settimeout(1)
            self._register_pk()
            last = time.monotonic()
            while not self.host._stop.is_set():
                try:
                    message = self.sock.recv(8192)
                    if message:
                        self._handle(message)
                except socket.timeout:
                    pass
                except (OSError, ValueError, PermissionError) as ex:
                    LOG.warning('rendezvous datagram rejected: %s', type(ex).__name__)
                if time.monotonic() - last >= self.timer:
                    try:
                        if self.accepted_pk:
                            self._register_peer()
                        else:
                            self._register_pk()
                    except OSError:
                        break
                    last = time.monotonic()


def register_loop(host_server):
    while not host_server._stop.is_set():
        try:
            Registration(host_server).run()
        except (OSError, ValueError) as ex:
            LOG.warning('rendezvous connection retrying after %s', type(ex).__name__)
            host_server._stop.wait(5)


def connect_via_relay(rendezvous_server: str, relay_server: str,
                      peer_id: str, conn_type: int, licence_key: str = '',
                      timeout: float = 12) -> socket.socket:
    """Open an official hbbs/hbbr relay session; peer identity is verified separately.

    RequestRelay is deliberately sent without account credentials. The outer
    hbbs channel may be unencrypted, but the eventual peer channel MUST pass
    the pinned Ed25519 identity check before sending login information.
    """
    if not peer_id or not 1 <= len(peer_id) <= 64:
        raise ValueError('invalid peer ID')
    hbbs = server_address(rendezvous_server, 21116)
    hbbr = server_address(relay_server, 21117)
    relay_label = f'[{hbbr[0]}]:{hbbr[1]}' if ':' in hbbr[0] else f'{hbbr[0]}:{hbbr[1]}'
    attempt_id = str(uuid.uuid4())
    request = p.msg(p.field_s(1, peer_id), p.field_s(2, attempt_id),
                    p.field_s(4, relay_label), p.field_u(5, 1),
                    p.field_u(7, conn_type))
    with socket.create_connection(hbbs, timeout=timeout) as coordination:
        coordination.settimeout(timeout)
        channel = Stream(coordination)
        channel.send(p.top(p.REQUEST_RELAY, request))
        for _ in range(5):
            frame = p.Fields(channel.read())
            if not frame.has(p.RELAY_RESPONSE):
                # Some hbbs versions advertise key exchange support first.
                if frame.has(p.KEY_EXCHANGE):
                    continue
                raise ConnectionError('unexpected hbbs relay response')
            reply = frame.sub(p.RELAY_RESPONSE)
            reason = reply.s(6)
            if reason:
                raise PermissionError('rendezvous server refused relay: ' + reason)
            break
        else:
            raise TimeoutError('hbbs did not confirm a relay session')
    try:
        peer = socket.create_connection(hbbr, timeout=timeout)
        peer.settimeout(timeout)
        channel = Stream(peer)
        channel.send(p.top(p.REQUEST_RELAY, p.msg(p.field_s(1, peer_id),
            p.field_s(2, attempt_id), p.field_s(6, licence_key),
            p.field_u(7, conn_type))))
        return peer
    except BaseException:
        if 'peer' in locals():
            peer.close()
        raise
