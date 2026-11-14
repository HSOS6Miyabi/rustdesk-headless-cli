"""Small, bounded Protobuf wire implementation for RustDesk message families.

Message field numbers follow rustdesk/rustdesk and rustdesk/hbb_common. Unknown
fields are ignored by readers and rejected when malformed. Compatible wire
encoding, with no generated GUI/media types in the headless executable.
"""
from __future__ import annotations
from typing import Iterable

MAX_MESSAGE = 8 * 1024 * 1024

# RustDesk Message oneof
SIGNED_ID = 3
PUBLIC_KEY = 4
TEST_DELAY = 5
LOGIN_REQUEST = 7
LOGIN_RESPONSE = 8
HASH = 9
FILE_ACTION = 17
FILE_RESPONSE = 18
MISC = 19
TERMINAL_ACTION = 31
TERMINAL_RESPONSE = 32

# RustDesk RendezvousMessage oneof
REGISTER_PEER = 6
REGISTER_PEER_RESPONSE = 7
PUNCH_HOLE_REQUEST = 8
PUNCH_HOLE = 9
PUNCH_HOLE_SENT = 10
PUNCH_HOLE_RESPONSE = 11
FETCH_LOCAL_ADDR = 12
LOCAL_ADDR = 13
REGISTER_PK = 15
REGISTER_PK_RESPONSE = 16
REQUEST_RELAY = 18
RELAY_RESPONSE = 19
KEY_EXCHANGE = 25

# Connection types from rendezvous.proto
DEFAULT_CONN = 0
FILE_TRANSFER_CONN = 1
PORT_FORWARD_CONN = 2
TERMINAL_CONN = 5


def varint(n: int) -> bytes:
    if n < 0:
        n &= (1 << 64) - 1
    out = bytearray()
    while n > 127:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def field_u(num: int, value: int) -> bytes:
    return varint(num << 3) + varint(value)


def field_b(num: int, value: bytes) -> bytes:
    return varint((num << 3) | 2) + varint(len(value)) + value


def field_s(num: int, value: str) -> bytes:
    return field_b(num, value.encode('utf-8'))


def msg(*fields: bytes) -> bytes:
    return b''.join(fields)


def _decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    for i in range(10):
        if pos >= len(data):
            raise ValueError('truncated Protobuf varint')
        c = data[pos]
        pos += 1
        if i == 9 and c > 1:
            raise ValueError('invalid 64-bit Protobuf varint')
        value |= (c & 0x7f) << (i * 7)
        if not c & 0x80:
            return value, pos
    raise ValueError('Protobuf varint too long')


class Fields:
    """Decodes one message. Repeated fields retain their on-wire order."""
    def __init__(self, data: bytes, max_size: int = MAX_MESSAGE):
        if len(data) > max_size:
            raise ValueError('Protobuf message exceeds limit')
        self.data: dict[int, list[int | bytes]] = {}
        pos = 0
        nfields = 0
        while pos < len(data):
            nfields += 1
            if nfields > 100_000:
                raise ValueError('too many Protobuf fields')
            tag, pos = _decode_varint(data, pos)
            number, wire = tag >> 3, tag & 7
            if number < 1 or number > 536870911:
                raise ValueError('invalid Protobuf field number')
            if wire == 0:
                value, pos = _decode_varint(data, pos)
            elif wire == 1:
                if pos + 8 > len(data):
                    raise ValueError('truncated fixed64 field')
                value = data[pos:pos+8]
                pos += 8
            elif wire == 2:
                length, pos = _decode_varint(data, pos)
                if length > len(data)-pos:
                    raise ValueError('truncated length-delimited field')
                value = data[pos:pos+length]
                pos += length
            elif wire == 5:
                if pos + 4 > len(data):
                    raise ValueError('truncated fixed32 field')
                value = data[pos:pos+4]
                pos += 4
            else:
                raise ValueError('invalid/unsupported Protobuf wire type')
            self.data.setdefault(number, []).append(value)

    def has(self, n: int) -> bool:
        return n in self.data

    def u(self, n: int, default: int = 0) -> int:
        v = self.data.get(n, [default])[-1]
        if not isinstance(v, int):
            raise ValueError(f'field {n} is not an integer')
        return v

    def b(self, n: int, default: bytes = b'') -> bytes:
        v = self.data.get(n, [default])[-1]
        if not isinstance(v, bytes):
            raise ValueError(f'field {n} is not bytes')
        return v

    def s(self, n: int, default: str = '') -> str:
        return self.b(n, default.encode()).decode('utf-8')

    def sub(self, n: int) -> 'Fields':
        return Fields(self.b(n))

    def bs(self, n: int) -> list[bytes]:
        values = self.data.get(n, [])
        if not all(isinstance(x, bytes) for x in values):
            raise ValueError('repeated field type mismatch')
        return values  # type: ignore

    def family(self, known: Iterable[int]) -> tuple[int, 'Fields'] | None:
        hits = [(k, self.sub(k)) for k in known if self.has(k)]
        if len(hits) > 1:
            raise ValueError('multiple message variants in oneof')
        return hits[0] if hits else None


def top(kind: int, payload: bytes) -> bytes:
    return field_b(kind, payload)


def frame_encode(payload: bytes) -> bytes:
    if len(payload) > MAX_MESSAGE:
        raise ValueError('frame exceeds maximum message size')
    for nbytes, limit in ((1, 1 << 6), (2, 1 << 14), (3, 1 << 22), (4, 1 << 30)):
        if len(payload) < limit:
            header = (len(payload) << 2) | (nbytes - 1)
            return header.to_bytes(nbytes, 'little') + payload
    raise ValueError('frame is too large')


def frame_length(first: bytes, rest: bytes) -> int:
    count = (first[0] & 3) + 1
    if len(first) != 1 or len(rest) != count - 1:
        raise ValueError('invalid frame header')
    full = int.from_bytes(first + rest, 'little')
    if (full & 3) != count - 1:
        raise ValueError('invalid frame encoding')
    value = full >> 2
    if value > MAX_MESSAGE + 16:
        raise ValueError('incoming frame exceeds size limit')
    return value


def encode_sint(n: int) -> int:
    return (n << 1) ^ (n >> 63)


def decode_sint(n: int) -> int:
    return (n >> 1) ^ -(n & 1)
