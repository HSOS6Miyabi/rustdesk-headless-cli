"""Bounded Zstandard decompression through system libzstd."""
import ctypes as C
from ctypes.util import find_library

try:
    import zstandard as _zstandard
except ImportError:
    _zstandard = None

name = find_library('zstd') if _zstandard is None else None
if name:
    lib = C.CDLL(name)
    lib.ZSTD_getFrameContentSize.argtypes = [C.c_void_p, C.c_size_t]
    lib.ZSTD_getFrameContentSize.restype = C.c_ulonglong
    lib.ZSTD_decompress.argtypes = [C.c_void_p, C.c_size_t, C.c_void_p, C.c_size_t]
    lib.ZSTD_decompress.restype = C.c_size_t
    lib.ZSTD_isError.argtypes = [C.c_size_t]
    lib.ZSTD_isError.restype = C.c_uint
else:
    lib = None


def decompress(data: bytes, max_size: int = 1024*1024) -> bytes:
    if _zstandard is not None:
        if not data or len(data) > max_size + 4096:
            raise ValueError('invalid compressed block size')
        return _zstandard.ZstdDecompressor(max_window_size=max_size).decompress(data, max_output_size=max_size)
    if lib is None:
        raise RuntimeError('libzstd or zstandard is required for compressed RustDesk messages')
    if not data or len(data) > max_size + 4096:
        raise ValueError('invalid compressed block size')
    src = C.create_string_buffer(data)
    size = lib.ZSTD_getFrameContentSize(src, len(data))
    if size in ((1 << 64) - 1, (1 << 64) - 2) or size > max_size:
        raise ValueError('invalid or oversized Zstandard frame')
    out = C.create_string_buffer(max(size, 1))
    written = lib.ZSTD_decompress(out, size, src, len(data))
    if lib.ZSTD_isError(written) or written != size:
        raise ValueError('invalid Zstandard frame')
    return out.raw[:written]
