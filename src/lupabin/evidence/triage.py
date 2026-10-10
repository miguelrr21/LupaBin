"""Triage facts of a PE: the PDB reference, the certificate table, the overlay and the
version strings, as the bounded readers pe_triage and pe_resources find them.

The worker publishes them and the host reads the sample again with the same readers, so
these budgets and exact forms are shared. No budget was reached in the 398 benign
binaries they were compared on (docs/metodo.md): they bound the work, they are not
thresholds of what a normal file has.
"""

import struct
from dataclasses import dataclass
from uuid import UUID

from lupabin.evidence import pe_resources, pe_triage

_MIB = 1024 * 1024
BUDGETS = pe_triage.Budgets(
    max_input_bytes=20 * _MIB,
    max_sections=96,
    max_certificates=16,
    max_debug_entries=64,
    max_path_bytes=1024,
    max_hash_bytes=20 * _MIB,
)
RESOURCE_LIMITS = pe_resources.Limits(
    regions=128,
    directories=4096,
    entries=65536,
    depth=4,
    name_bytes=4096,
    total_read_bytes=16 * _MIB,
    version_bytes=65536,
    version_blocks=4096,
    version_depth=8,
    translations=256,
)
PDBS = 4
CERTIFICATES = BUDGETS.max_certificates
OVERLAYS = 2  # before and after the certificate table
VERSION_STRINGS = 64
VERSION_KEY_CHARACTERS = 128
VERSION_BLOCK_BYTES = 4096
RSDS_SIZE = 24


def rsds_fields(raw: bytes) -> tuple[str, int, bytes]:
    """Identifier, age and path of an RSDS record that ends at its path's terminator."""
    if len(raw) <= RSDS_SIZE or raw[:4] != b"RSDS" or raw.find(b"\0", RSDS_SIZE) != len(raw) - 1:
        raise ValueError("not an RSDS record that ends at its path's terminator")
    age = struct.unpack_from("<I", raw, 20)[0]
    return str(UUID(bytes_le=raw[4:20])), age, raw[RSDS_SIZE:-1]


def certificate_header(raw: bytes) -> tuple[int, int, int]:
    """dwLength, wRevision and wCertificateType of a WIN_CERTIFICATE header."""
    if len(raw) != 8:
        raise ValueError("a certificate header has eight bytes")
    length, revision, kind = struct.unpack("<IHH", raw)
    return length, revision, kind


def string_block(raw: bytes) -> tuple[str, str]:
    """Key and value of a String block of a version resource. A block starts on a 32-bit
    boundary of its resource, so its value is aligned from the block's own start."""
    if len(raw) < 8:
        raise ValueError("truncated version block")
    length, value_length, value_type = struct.unpack_from("<HHH", raw)
    if length != len(raw) or value_type != 1:
        raise ValueError("not a whole text block")
    end = 6
    while raw[end : end + 2] != b"\0\0":
        end += 2
        if end + 2 > len(raw):
            raise ValueError("unterminated version key")
    start = (end + 2 + 3) & ~3
    if start + value_length * 2 > len(raw):
        raise ValueError("version value outside its block")
    key = raw[6:end].decode("utf-16-le")
    text = raw[start : start + value_length * 2].decode("utf-16-le")
    if not key or not text.endswith("\0") or "\0" in text[:-1]:
        raise ValueError("empty key or value without a single terminator")
    return key, text[:-1]


def read_resources(data: bytes, result: pe_triage.Triage) -> pe_resources.ResourceResult | None:
    """The resource tree, through the raw bytes of the headers and of each section."""
    layout = result.layout
    if layout is None:
        return None
    regions = (pe_resources.RawRegion(0, 0, layout.size_of_headers),) + tuple(
        pe_resources.RawRegion(section.rva, section.raw_offset, section.raw_size)
        for section in layout.sections
        if section.raw_size
    )
    return pe_resources.read(
        data, layout.resources.address, layout.resources.size, regions, limits=RESOURCE_LIMITS
    )


@dataclass(frozen=True)
class VersionText:
    offset: int
    raw: bytes
    language: int
    codepage: int
    key: str
    value: str


@dataclass(frozen=True)
class VersionTexts:
    found: tuple[VersionText, ...]
    resources: int  # version resources read
    unread: bool  # some string, or part of the tree, has a form that is not read
    limited: bool  # some string is longer than what is published


def version_texts(
    data: bytes, parsed: pe_resources.ResourceResult, characters: int
) -> VersionTexts:
    """Every version string whose block has the exact form string_block reads."""
    found = []
    kinds = [omission.kind for omission in parsed.omissions] + [
        omission.kind for version in parsed.versions for omission in version.omissions
    ]
    unread = any(kind != "limit" for kind in kinds)
    limited = "limit" in kinds
    for version in parsed.versions:
        for item in version.strings:
            block = version.blocks[item.block_index]
            where = block.location
            key, value = block.key.text, item.value.text
            if key is None or value is None:
                unread = True
                continue
            if (
                where.size > VERSION_BLOCK_BYTES
                or len(key) > VERSION_KEY_CHARACTERS
                or len(value) > characters
            ):
                limited = True
                continue
            raw = data[where.file_offset : where.file_offset + where.size]
            try:
                exact = string_block(raw) == (key, value)
            except ValueError:
                exact = False
            if not exact:
                unread = True
                continue
            found.append(
                VersionText(where.file_offset, raw, item.language, item.codepage, key, value)
            )
    return VersionTexts(tuple(found), len(parsed.versions), unread, limited)
