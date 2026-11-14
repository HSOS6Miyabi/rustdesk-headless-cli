"""Protocol and CLI modules can be imported without platform-specific host APIs."""
from rdheadless import protocol as p
from rdheadless.client import Peer
from rdheadless.cli import main


def test_protocol_roundtrip_for_terminal_and_file():
    request = p.top(p.LOGIN_REQUEST, p.msg(p.field_s(1, 'Target123'),
                  p.field_b(16, p.msg())))
    assert p.Fields(request).sub(p.LOGIN_REQUEST).s(1) == 'Target123'
    assert callable(Peer.connect)
    assert callable(main)
