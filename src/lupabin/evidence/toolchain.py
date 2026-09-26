"""Toolchain markers: bytes that compilers, linkers and packagers leave in a PE file.

The catalog `lupabin-toolchains-v1` is closed: each marker has one exact form, parsed
here and shared by the worker (which finds them) and the host (which re-checks them
against the sample). A marker says which tool left those bytes, never who used it or
what the program does, and any of them can be copied or forged (docs/metodo.md).
"""

import struct
from collections.abc import Sequence
from typing import Literal

from lupabin.evidence.primitives import Location

CATALOG = "lupabin-toolchains-v1"
Marker = Literal[
    "rich_header",
    "gcc_ident",
    "mingw_w64_runtime",
    "go_buildinfo",
    "clr_header",
    "pyinstaller_cookie",
]
MARKERS: tuple[Marker, ...] = (
    "rich_header",
    "gcc_ident",
    "mingw_w64_runtime",
    "go_buildinfo",
    "clr_header",
    "pyinstaller_cookie",
)
GCC_IDENTS = 8  # distinct GCC .ident texts published, the first occurrence of each
QUOTA = 1 + GCC_IDENTS + 4  # every other marker is published once

# Microsoft's linker: "DanS" and three zero dwords, (@comp.id, count) pairs, "Rich" and
# the key; everything before "Rich" is XORed with the key, which is a checksum of the
# DOS header and stub before the structure (without e_lfanew) and of every pair.
DANS = int.from_bytes(b"DanS", "little")
RICH = b"Rich"
RICH_MAX = 4096
# GCC's .ident directive (gcc/toplev.cc): "GCC: " + package version + version.
GCC = b"GCC: ("
GCC_MAX = 200
# mingw-w64-crt/crt/pseudo-reloc.c, __report_error.
MINGW_W64 = b"Mingw-w64 runtime failure:"
# Go's build information header (src/debug/buildinfo/buildinfo.go): 16-byte aligned,
# 32 bytes; with flag 2 the version follows inline as a varint-prefixed string.
GO = b"\xff Go buildinf:"
GO_INLINE = 0x2
GO_FLAGS = 0x1 | GO_INLINE  # flagsEndian and flagsVersionInl
GO_ALIGN = 16
GO_HEADER = 32
GO_VERSION_MAX = 64
# ECMA-335 II.25.3.3: the CLI header starts with its size, 72, and the runtime version.
CLR_SIZE = 72
CLR_DIRECTORY = 14
# PyInstaller's CArchive cookie (PyInstaller/archive/writers.py, '!8sIIii64s'): magic,
# archive length, TOC offset, TOC length, Python version, Python library name.
PYINSTALLER = b"MEI\x0c\x0b\x0a\x0b\x0e"
PYINSTALLER_COOKIE = struct.Struct("!8sIIii64s")


def _printable(raw: bytes) -> str | None:
    if not raw or any(not 0x20 <= byte <= 0x7E for byte in raw):
        return None
    return raw.decode("ascii")


def _rol(value: int, count: int) -> int:
    count &= 31
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def rich_entries(raw: bytes) -> tuple[int, tuple[tuple[int, int], ...]]:
    """The key and the (@comp.id, count) pairs of a Rich header, or ValueError."""
    if len(raw) < 24 or len(raw) % 8 or len(raw) > RICH_MAX or raw[-8:-4] != RICH:
        raise ValueError("not a Rich header")
    key = struct.unpack_from("<I", raw, len(raw) - 4)[0]
    head = struct.unpack_from("<4I", raw, 0)
    if head[0] ^ key != DANS or any(value ^ key for value in head[1:]):
        raise ValueError("a Rich header starts with DanS and three zero dwords")
    pairs = tuple(
        (
            struct.unpack_from("<I", raw, at)[0] ^ key,
            struct.unpack_from("<I", raw, at + 4)[0] ^ key,
        )
        for at in range(16, len(raw) - 8, 8)
    )
    return key, pairs


def rich_checksum(prefix: bytes, pairs: Sequence[tuple[int, int]]) -> int:
    """The key Microsoft's linker derives from the bytes before the structure."""
    checksum = len(prefix)
    for index, byte in enumerate(prefix):
        if not 0x3C <= index < 0x40:  # e_lfanew is left out
            checksum = (checksum + _rol(byte, index)) & 0xFFFFFFFF
    for compid, count in pairs:
        checksum = (checksum + _rol(compid, count)) & 0xFFFFFFFF
    return checksum


def find_rich(data: bytes) -> tuple[int, bytes] | None:
    """The offset and bytes of the Rich header between the DOS header and the PE header,
    if its checksum holds."""
    if len(data) < 0x40:
        return None
    end = min(struct.unpack_from("<I", data, 0x3C)[0], len(data))
    at = data.rfind(RICH, 0x40, end)
    if at < 0 or at + 8 > end:
        return None
    key = struct.unpack_from("<I", data, at + 4)[0]
    start = at - 16
    while start >= 0x40 and at + 8 - start <= RICH_MAX:
        if struct.unpack_from("<I", data, start)[0] ^ key == DANS:
            raw = data[start : at + 8]
            try:
                _, pairs = rich_entries(raw)
            except ValueError:
                return None
            return (start, raw) if rich_checksum(data[:start], pairs) == key else None
        start -= 8
    return None


def go_version(raw: bytes) -> str | None:
    """The version an inline Go build information header declares, or ValueError."""
    if len(raw) < 16 or raw[:14] != GO:
        raise ValueError("not a Go build information header")
    if raw[15] & ~GO_FLAGS:
        raise ValueError("a Go header only sets the endianness and inline flags")
    if not raw[15] & GO_INLINE:
        if len(raw) != 16:
            raise ValueError("an older Go header is published without inline strings")
        return None
    length, shift, at = 0, 0, GO_HEADER
    while True:
        if at >= len(raw) or shift > 7:
            raise ValueError("truncated Go version length")
        byte = raw[at]
        length |= (byte & 0x7F) << shift
        at += 1
        if byte < 0x80:
            break
        shift += 7
    if not 1 <= length <= GO_VERSION_MAX or at + length != len(raw):
        raise ValueError("a Go header is published up to the end of its version")
    text = _printable(raw[at:])
    if text is None:
        raise ValueError("the Go version must be printable ASCII")
    return text


def read_go(data: bytes, offset: int) -> bytes | None:
    """The Go header at `offset`, up to its inline version when it has one."""
    if data[offset : offset + 14] != GO or offset + 16 > len(data):
        return None
    if data[offset + 15] & ~GO_FLAGS:
        return None
    if not data[offset + 15] & GO_INLINE:
        return data[offset : offset + 16]
    at = offset + GO_HEADER
    length, shift = 0, 0
    while at < len(data) and shift <= 7:
        byte = data[at]
        length |= (byte & 0x7F) << shift
        at += 1
        if byte < 0x80:
            raw = data[offset : at + length]
            try:
                go_version(raw)
            except ValueError:
                return None
            return raw
        shift += 7
    return None


def pyinstaller_fields(raw: bytes) -> tuple[int, int, int, str]:
    """Archive length, TOC offset, TOC length and Python library of a cookie."""
    if len(raw) != PYINSTALLER_COOKIE.size:
        raise ValueError("a PyInstaller cookie has 88 bytes")
    magic, archive, toc, toc_length, _, library = PYINSTALLER_COOKIE.unpack(raw)
    if magic != PYINSTALLER:
        raise ValueError("not a PyInstaller cookie")
    name, _, rest = library.partition(b"\0")
    text = _printable(name)
    if text is None or any(rest):
        raise ValueError("the Python library name must be printable and NUL-padded")
    if archive < len(raw) or toc + toc_length > archive:
        raise ValueError("the cookie's table of contents lies outside its archive")
    return archive, toc, toc_length, text


def marker_text(marker: Marker, raw: bytes) -> str | None:
    """The text a marker's bytes carry (None if it carries none); ValueError if the
    bytes are not that marker's exact form."""
    if marker == "rich_header":
        rich_entries(raw)
        return None
    if marker == "gcc_ident":
        if not raw.startswith(GCC) or not raw.endswith(b"\0") or len(raw) > GCC_MAX + 1:
            raise ValueError("a GCC ident is 'GCC: (' and printable text up to its NUL")
        text = _printable(raw[:-1])
        if text is None:
            raise ValueError("a GCC ident is printable ASCII")
        return text
    if marker == "mingw_w64_runtime":
        if raw != MINGW_W64:
            raise ValueError("not the MinGW-w64 runtime message")
        return None
    if marker == "go_buildinfo":
        return go_version(raw)
    if marker == "clr_header":
        if len(raw) != 8:
            raise ValueError("a CLR header marker is its first 8 bytes")
        size, major, minor = struct.unpack("<IHH", raw)
        if size != CLR_SIZE:
            raise ValueError("a CLR header declares its size, 72")
        return f"{major}.{minor}"
    return pyinstaller_fields(raw)[3]


def clr_directory(data: bytes) -> tuple[int, int] | None:
    """The CLR Runtime Header data directory entry (RVA, size), if the file has one."""
    if len(data) < 0x40:
        return None
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    optional = nt + 24
    if optional + 2 > len(data):
        return None
    magic = struct.unpack_from("<H", data, optional)[0]
    fixed = {267: 96, 523: 112}.get(magic)
    if fixed is None or optional + fixed > len(data):
        return None
    count = struct.unpack_from("<I", data, optional + fixed - 4)[0]
    entry = optional + fixed + 8 * CLR_DIRECTORY
    if count <= CLR_DIRECTORY or entry + 8 > len(data):
        return None
    rva, size = struct.unpack_from("<II", data, entry)
    return (rva, size) if rva else None


def location_ok(marker: Marker, where: Location) -> bool:
    """Which markers claim a place in the image (the Go header and the CLR header)."""
    mapped = marker in ("go_buildinfo", "clr_header")
    return (where.rva is not None) == mapped and (where.section is None or mapped)
