"""Load system shared libraries without relying on ldconfig (musl/OpenWrt)."""
from __future__ import annotations

from ctypes import CDLL
from ctypes.util import find_library


# OpenWrt and other musl distributions do not necessarily ship ldconfig,
# gcc or objdump; ctypes.util.find_library() may return None there.
def load_library(name: str, *sonames: str) -> CDLL | None:
    candidate = find_library(name)
    paths = [candidate] if candidate else []
    paths.extend(sonames)
    for path in dict.fromkeys(paths):
        try:
            return CDLL(path)
        except OSError:
            continue
    return None
