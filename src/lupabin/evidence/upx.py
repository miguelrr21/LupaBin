"""Executables packed with UPX 5 (win32/pe and win64/pe), read without running anything
(docs/metodo.md, «UPX»).

UPX moves the program into one compressed block and adds a small loader that rebuilds
it in memory when the program starts. LupaBin decompresses that block statically and
publishes what the block itself declares: the original sections, the original entry
point and the functions the loader resolves. The worker and the host run the same
functions here, so the host can repeat the whole derivation from the sample's bytes.

The layout was established by experiment on copies of benign programs packed with
upx 5.2.1, never from UPX's source code:

- a 32-byte header that starts with `UPX!`: version, format, method, level, the Adler-32
  of the unpacked and of the packed bytes, both sizes, the original file size, the
  filter, its parameter, a count and a check byte;
- the packed block, right after the header or at the start of a section's bytes; only a
  position where the declared Adler-32 holds is accepted;
- NRV2B, NRV2D and NRV2E streams: bits read from the most significant end of 32-bit
  little-endian words, fetched from the same stream as the literal bytes; LZMA streams
  with two leading bytes (`lp<<4 | lc`, then `(lc+lp)<<3 | pb`, in that order reversed);
- the unpacked bytes: the image from its first section on, then the list of imports,
  then the relocations, then a copy of the original PE header and section table,
  followed by the offsets of the imports and of the relocations and, last, the offset
  of that header copy.

Anything outside these forms is not guessed at: the header is not published, or the
block is published without what its tail would add.
"""

import hashlib
import lzma
import struct
import zlib
from dataclasses import dataclass
from typing import Literal

Format = Literal["win32/pe", "win64/pe"]
Method = Literal["nrv2b", "nrv2d", "nrv2e", "lzma"]

MAGIC = b"UPX!"
HEADER_SIZE = 32
VERSIONS = frozenset({13})  # the header version of UPX 5, the only one measured
FORMATS: dict[int, Format] = {9: "win32/pe", 36: "win64/pe"}
METHODS: dict[int, Method] = {2: "nrv2b", 5: "nrv2d", 8: "nrv2e", 14: "lzma"}
MACHINES: dict[Format, int] = {"win32/pe": 0x14C, "win64/pe": 0x8664}
MAX_UNPACKED = 32 * 1024 * 1024  # bytes: about 13 s of NRV decoding in the worker
MAX_SECTIONS = 96
MAX_IMPORTS = 10000
MAX_NAME = 4096  # bytes of a DLL or function name (decorated C++ names can be long)
MAX_HEADERS = 8  # well-formed headers tried, so that copies of `UPX!` cannot cost much
_END = 0xFFFFFFFF


@dataclass(frozen=True)
class Header:
    offset: int
    raw: bytes
    version: int
    format: Format
    method: Method
    level: int
    unpacked_adler32: int
    packed_adler32: int
    unpacked_size: int
    packed_size: int
    original_size: int


@dataclass(frozen=True)
class Section:
    name: bytes  # the 8 bytes of the table, padding included
    rva: int
    virtual_size: int


@dataclass(frozen=True)
class Import:
    dll_rva: int  # where the packed file keeps the DLL's name
    function: bytes | None
    ordinal: int | None
    iat_rva: int  # the slot in the original image
    stream_offset: int  # the entry in the unpacked bytes
    stream_length: int


@dataclass(frozen=True)
class Tail:
    machine: int
    entry_rva: int
    image_base: int
    sections: tuple[Section, ...]
    imports: tuple[Import, ...]


@dataclass(frozen=True)
class Unpacked:
    header: Header
    packed_offset: int
    unpacked_sha256: str
    tail: Tail | None
    stream: bytes


def section_text(raw: bytes) -> str | None:
    """A section name as text: the 8 bytes without their trailing NULs, if ASCII."""
    try:
        return raw.rstrip(b"\0").decode("ascii")
    except UnicodeDecodeError:
        return None


def decode_header(raw: bytes, at: int = 0) -> Header | None:
    """The header in `raw` (found at `at`), or None unless every field has a measured
    value."""
    if len(raw) != HEADER_SIZE or raw[:4] != MAGIC:
        return None
    version, kind, method, level = raw[4:8]
    if version not in VERSIONS or kind not in FORMATS or method not in METHODS:
        return None
    unpacked_adler, packed_adler, unpacked, packed, original = struct.unpack_from("<5I", raw, 8)
    if not 0 < unpacked <= MAX_UNPACKED or packed == 0:
        return None
    return Header(
        at,
        raw,
        version,
        FORMATS[kind],
        METHODS[method],
        level,
        unpacked_adler,
        packed_adler,
        unpacked,
        packed,
        original,
    )


def packed_offset(data: bytes, header: Header, section_starts: list[int]) -> int | None:
    """Where the packed block starts: the only candidate (right after the header, or the
    first byte of a section's data after it) whose bytes have the declared Adler-32."""
    candidates = sorted(
        {header.offset + HEADER_SIZE} | {s for s in section_starts if s >= header.offset}
    )
    found = [
        at
        for at in candidates
        if at + header.packed_size <= len(data)
        and zlib.adler32(data[at : at + header.packed_size]) == header.packed_adler32
    ]
    return found[0] if len(found) == 1 else None


def nrv(block: bytes, method: Method, size: int) -> bytes:
    """Decode an NRV2B/2D/2E stream of exactly `size` bytes, or raise ValueError."""
    out = bytearray()
    at = word = left = 0
    last = 1
    limit = len(block)
    two_b, two_d = method == "nrv2b", method == "nrv2d"

    def bit() -> int:
        nonlocal at, word, left
        if not left:
            if at + 4 > limit:
                raise ValueError("the packed stream ends early")
            word = int.from_bytes(block[at : at + 4], "little")
            at += 4
            left = 32
        left -= 1
        return (word >> left) & 1

    def number(value: int) -> int:
        while True:
            value = value * 2 + bit()
            if bit():
                return value
            if value > _END:
                raise ValueError("a length out of range")

    while True:
        while bit():  # literals
            if at >= limit or len(out) >= size:
                raise ValueError("a literal outside the stream or the output")
            out.append(block[at])
            at += 1
        offset = 1
        while True:
            offset = offset * 2 + bit()
            if bit():
                break
            if not two_b:
                offset = (offset - 1) * 2 + bit()
            if offset > _END:
                raise ValueError("an offset out of range")
        if offset == 2:
            offset = last
            low = 0 if two_b else bit()
        else:
            if at >= limit:
                raise ValueError("the packed stream ends early")
            offset = (offset - 3) * 256 + block[at]
            at += 1
            if offset == _END:
                break
            if two_b:
                offset, low = offset + 1, 0
            else:
                offset, low = (offset >> 1) + 1, (offset ^ _END) & 1
            last = offset
        if two_b:
            length = bit() * 2 + bit()
            if length == 0:
                length = number(1) + 2
            length += 1 + (offset > 0xD00)
        elif two_d:
            length = low * 2 + bit()
            if length == 0:
                length = number(1) + 2
            length += 1 + (offset > 0x500)
        else:
            if low:
                length = 1 + bit()
            elif bit():
                length = 3 + bit()
            else:
                length = number(1) + 3
            length += 1 + (offset > 0x500)
        if offset > len(out) or len(out) + length > size:
            raise ValueError("a match outside the output")
        start = len(out) - offset
        if offset >= length:
            out += out[start : start + length]
        else:
            out += (out[start:] * (length // offset + 1))[:length]
    if len(out) != size or at != limit:
        raise ValueError("the stream does not end where its sizes say")
    return bytes(out)


def unlzma(block: bytes, size: int) -> bytes:
    """Decode UPX's LZMA stream: two bytes of properties, then raw LZMA1."""
    if len(block) < 3:
        raise ValueError("the packed stream ends early")
    lc, lp, pb = block[1] & 0x0F, block[1] >> 4, block[0] & 0x07
    if block[0] >> 3 != lc + lp or lc + lp > 4 or pb > 4:
        raise ValueError("unknown LZMA properties")
    decoder = lzma.LZMADecompressor(
        lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": size}],
    )
    try:
        out = decoder.decompress(block[2:], max_length=size)
    except lzma.LZMAError as error:
        raise ValueError("invalid LZMA stream") from error
    if len(out) != size:
        raise ValueError("the stream does not hold the declared size")
    return out


def _name(data: bytes, at: int) -> bytes:
    end = data.find(b"\0", at, at + MAX_NAME + 1)
    if end <= at:
        raise ValueError("a name without its end")
    return data[at:end]


def read_tail(stream: bytes, header: Header, base: int) -> Tail:
    """What the end of the unpacked bytes declares, or ValueError if it does not have
    exactly the measured form. `base` is the RVA where the unpacked image starts."""
    if len(stream) < 4:
        raise ValueError("no header copy")
    copy = struct.unpack_from("<I", stream, len(stream) - 4)[0]
    if copy + 24 > len(stream) or stream[copy : copy + 4] != b"PE\0\0":
        raise ValueError("no header copy")
    machine, count = struct.unpack_from("<HH", stream, copy + 4)
    optional = struct.unpack_from("<H", stream, copy + 20)[0]
    if machine != MACHINES[header.format] or not 0 < count <= MAX_SECTIONS:
        raise ValueError("the header copy disagrees with the UPX header")
    magic = 0x10B if header.format == "win32/pe" else 0x20B
    body = copy + 24
    if optional < (96 if magic == 0x10B else 112) or body + optional > len(stream):
        raise ValueError("a short optional header")
    if struct.unpack_from("<H", stream, body)[0] != magic:
        raise ValueError("the header copy disagrees with the UPX header")
    entry = struct.unpack_from("<I", stream, body + 16)[0]
    image_base = (
        struct.unpack_from("<I", stream, body + 28)[0]
        if magic == 0x10B
        else struct.unpack_from("<Q", stream, body + 24)[0]
    )
    table = body + optional
    after = table + 40 * count
    offsets = stream[after : len(stream) - 4]
    if len(offsets) < 8:
        raise ValueError("a short section table")
    sections = []
    for index in range(count):
        at = table + 40 * index
        virtual_size, rva = struct.unpack_from("<II", stream, at + 8)
        sections.append(Section(stream[at : at + 8], rva, virtual_size))
    if sections[0].rva != base:
        raise ValueError("the image does not start at the first original section")
    imports_at, zero = struct.unpack_from("<II", offsets)
    rest = offsets[8:]
    # Two measured forms: the offset of the relocations and up to 3 zero bytes, or, in
    # programs without relocations, only up to 3 zero bytes. The import list must end
    # exactly where the relocations start, or where the header copy starts.
    if len(rest) >= 4 and rest[:4] != bytes(4):
        end = struct.unpack_from("<I", rest)[0]
        rest = rest[4:]
    else:
        end = copy
    if zero or len(rest) > 3 or any(rest) or not imports_at <= end <= copy:
        raise ValueError("the offsets after the header copy have an unmeasured form")
    imports = _imports(stream, imports_at, end, base, header.format)
    return Tail(machine, entry, image_base, tuple(sections), imports)


def _imports(stream: bytes, at: int, end: int, base: int, kind: Format) -> tuple[Import, ...]:
    """Each DLL: u32 where its name lies (from the packed file's import directory),
    u32 its IAT relative to the image, then entries `01 name 00` or `FF ordinal(u16)`,
    and 00; a u32 zero ends the list, exactly where the relocations start."""
    width = 4 if kind == "win32/pe" else 8
    found: list[Import] = []
    while True:
        if at + 4 > end:
            raise ValueError("the import list runs past its end")
        name = struct.unpack_from("<I", stream, at)[0]
        at += 4
        if name == 0:
            break
        if at + 4 > end:
            raise ValueError("the import list runs past its end")
        iat = struct.unpack_from("<I", stream, at)[0]
        at += 4
        slot = 0
        while True:
            if at >= end:
                raise ValueError("the import list runs past its end")
            tag, entry = stream[at], at
            at += 1
            if tag == 0:
                break
            if tag == 1:
                function = _name(stream, at)
                at += len(function) + 1
                ordinal = None
            elif tag == 0xFF:
                if at + 2 > end:
                    raise ValueError("the import list runs past its end")
                function, ordinal = None, struct.unpack_from("<H", stream, at)[0]
                at += 2
            else:
                raise ValueError("an unknown import entry")
            if at > end or len(found) == MAX_IMPORTS:
                raise ValueError("the import list runs past its end or its quota")
            found.append(
                Import(name, function, ordinal, base + iat + slot * width, entry, at - entry)
            )
            slot += 1
    if at != end:
        raise ValueError("the import list does not end where the relocations start")
    return tuple(found)


@dataclass(frozen=True)
class Span:
    """A section of the packed file, as the PE extractor reads it."""

    rva: int
    virtual_size: int
    raw_offset: int
    raw_size: int


@dataclass(frozen=True)
class Derived:
    unpacked: Unpacked
    dlls: tuple[bytes, ...] | None  # the DLL name of each import, when the tail is read


def import_directory(data: bytes) -> int | None:
    """The RVA of the packed file's import directory, read from its optional header."""
    if len(data) < 0x40:
        return None
    optional = struct.unpack_from("<I", data, 0x3C)[0] + 24
    if optional + 2 > len(data):
        return None
    fixed = {0x10B: 96, 0x20B: 112}.get(struct.unpack_from("<H", data, optional)[0])
    if fixed is None or optional + fixed + 16 > len(data):
        return None
    count = struct.unpack_from("<I", data, optional + fixed - 4)[0]
    rva = struct.unpack_from("<I", data, optional + fixed + 8)[0]
    return rva if count > 1 and rva else None


def read_at(data: bytes, sections: list[Span], rva: int) -> bytes | None:
    """The NUL-terminated name at `rva` of the packed file, through its section table."""
    for section in sections:
        size = min(section.virtual_size or section.raw_size, section.raw_size)
        if section.rva <= rva < section.rva + size:
            at = section.raw_offset + rva - section.rva
            end = min(section.raw_offset + size, len(data))
            stop = data.find(b"\0", at, min(end, at + MAX_NAME + 1))
            return data[at:stop] if stop > at else None
    return None


def derive(data: bytes, sections: list[Span]) -> Derived | None:
    """Everything LupaBin publishes about a UPX block, from the sample and its section
    table, or None if no header verifies. The DLL names are only kept when every one of
    them reads; otherwise the tail is dropped as a whole."""
    if not sections:
        return None
    starts = [s.raw_offset for s in sections if s.raw_size]
    unpacked = unpack(data, starts, sections[0].rva)
    if unpacked is None or unpacked.tail is None:
        return None if unpacked is None else Derived(unpacked, None)
    directory = import_directory(data)
    names = []
    for item in unpacked.tail.imports:
        name = None if directory is None else read_at(data, sections, directory + item.dll_rva)
        if name is None:
            return Derived(
                Unpacked(
                    unpacked.header,
                    unpacked.packed_offset,
                    unpacked.unpacked_sha256,
                    None,
                    unpacked.stream,
                ),
                None,
            )
        names.append(name)
    return Derived(unpacked, tuple(names))


def unpack(data: bytes, section_starts: list[int], base: int) -> Unpacked | None:
    """The UPX block of `data`, decompressed and checked, or None. Only the first header
    that verifies is used. `section_starts` are the file offsets where sections' data
    start; `base` is the RVA of the packed file's first section."""
    at, tried = data.find(MAGIC), 0
    while at >= 0 and tried < MAX_HEADERS:
        header = decode_header(data[at : at + HEADER_SIZE], at)
        tried += header is not None
        start = None if header is None else packed_offset(data, header, section_starts)
        if header is not None and start is not None:
            block = data[start : start + header.packed_size]
            try:
                stream = (
                    unlzma(block, header.unpacked_size)
                    if header.method == "lzma"
                    else nrv(block, header.method, header.unpacked_size)
                )
            except ValueError:
                stream = None
            if stream is not None and zlib.adler32(stream) == header.unpacked_adler32:
                try:
                    tail = read_tail(stream, header, base)
                except (ValueError, struct.error):
                    tail = None
                digest = hashlib.sha256(stream).hexdigest()
                return Unpacked(header, start, digest, tail, stream)
        at = data.find(MAGIC, at + 1)
    return None
