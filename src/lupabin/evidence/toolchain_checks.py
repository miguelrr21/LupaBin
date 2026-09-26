"""Checks of toolchain markers: the report alone proves where each one may lie, the
sample the bytes (and what needs more of the sample: the Rich checksum and the CLR
directory)."""

import struct
from collections import Counter
from collections.abc import Sequence

from lupabin.evidence import toolchain
from lupabin.evidence.code import _holder, _named
from lupabin.evidence.facts import Evidence, SectionData, ToolchainEvidence


def _inside_section(offset: int, size: int, sections: Sequence[SectionData]) -> bool:
    return any(
        s.raw_status == "present"
        and s.raw_offset <= offset
        and offset + size <= s.raw_offset + s.raw_size
        for s in sections
    )


def validate_markers(markers: Sequence[ToolchainEvidence], sections: Sequence[SectionData]) -> None:
    """Raise unless each marker lies where its tool puts it and is published once
    (a GCC ident once per distinct text, up to the catalog's quota)."""
    counts = Counter(fact.data.marker for fact in markers)
    if any(count > 1 for marker, count in counts.items() if marker != "gcc_ident"):
        raise ValueError("a toolchain marker is published once")
    if counts["gcc_ident"] > toolchain.GCC_IDENTS:
        raise ValueError("too many GCC idents")
    texts = [fact.data.text for fact in markers if fact.data.marker == "gcc_ident"]
    if len(texts) != len(set(texts)):
        raise ValueError("a GCC ident is published once per distinct text")
    for fact in markers:
        where = fact.location
        offset, size = where.offset or 0, where.length or 0
        marker = fact.data.marker
        if marker in ("gcc_ident", "mingw_w64_runtime"):
            if not _inside_section(offset, size, sections):
                raise ValueError("a compiler string lies in a section's bytes")
        elif marker in ("go_buildinfo", "clr_header"):
            if where.rva is None:
                raise ValueError("a Go or CLR header locates itself in the image")
            section = _holder(where.rva, offset, size, sections)
            _named(where, section)
            if marker == "go_buildinfo" and where.rva % toolchain.GO_ALIGN:
                raise ValueError("Go aligns its build information header to 16 bytes")
        elif marker == "pyinstaller_cookie":
            archive = toolchain.pyinstaller_fields(bytes.fromhex(fact.data.raw_hex))[0]
            start = offset + size - archive
            end = max(
                (s.raw_offset + s.raw_size for s in sections if s.raw_status == "present"),
                default=0,
            )
            if start < end:
                raise ValueError("a PyInstaller archive is appended after the sections")
        elif marker == "rich_header" and offset < 0x40:
            raise ValueError("a Rich header follows the DOS header")


def verify_markers(evidence: Sequence[Evidence], data: bytes) -> None:
    """Raise unless every marker's bytes are the sample's bytes at their offset, the Rich
    checksum holds over the bytes before it and the CLR directory points to the header."""
    for fact in evidence:
        if not isinstance(fact, ToolchainEvidence):
            continue
        raw = bytes.fromhex(fact.data.raw_hex)
        offset = fact.location.offset
        if offset is None or data[offset : offset + len(raw)] != raw:
            raise ValueError("toolchain marker bytes differ from the sample")
        if fact.data.marker == "rich_header":
            key, pairs = toolchain.rich_entries(raw)
            if toolchain.rich_checksum(data[:offset], pairs) != key:
                raise ValueError("the Rich header checksum does not hold")
            if offset + len(raw) > struct.unpack_from("<I", data, 0x3C)[0]:
                raise ValueError("a Rich header lies before the PE header")
        if fact.data.marker == "clr_header":
            directory = toolchain.clr_directory(data)
            if directory is None or directory[0] != fact.location.rva:
                raise ValueError("the CLR directory does not point to this header")
            if directory[1] < toolchain.CLR_SIZE:
                raise ValueError("the CLR directory is smaller than the header")
