import hashlib
import struct
from dataclasses import dataclass, fields
from typing import Literal
from uuid import UUID

RESOURCE_DIRECTORY = 2
SECURITY_DIRECTORY = 4
DEBUG_DIRECTORY = 6
CODEVIEW_TYPE = 2
DIRECTORY_COUNT = 16
SECTION_SIZE = 40
DEBUG_SIZE = 28
CERTIFICATE_HEADER_SIZE = 8
CERTIFICATE_ALIGNMENT = 8
RSDS_SIZE = 24
UINT32_END = 1 << 32

Status = Literal["complete", "absent", "incomplete", "unavailable"]
IssueKind = Literal["malformed", "limit", "ignored", "dependency"]


@dataclass(frozen=True)
class Budgets:
    max_input_bytes: int
    max_sections: int
    max_certificates: int
    max_debug_entries: int
    max_path_bytes: int
    max_hash_bytes: int

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{field.name} must be a nonnegative integer")


@dataclass(frozen=True)
class Issue:
    kind: IssueKind
    code: str
    offset: int | None = None


@dataclass(frozen=True)
class Inventory[T]:
    status: Status
    items: tuple[T, ...] = ()
    issues: tuple[Issue, ...] = ()


@dataclass(frozen=True)
class Span:
    offset: int
    length: int
    sha256: str


@dataclass(frozen=True)
class Directory:
    address: int
    size: int
    entry_offset: int | None


@dataclass(frozen=True)
class Section:
    header_offset: int
    name_raw: bytes
    rva: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int


@dataclass(frozen=True)
class Layout:
    bits: Literal[32, 64]
    size_of_headers: int
    size_of_image: int
    tail_offset: int
    sections: tuple[Section, ...]
    security: Directory
    debug: Directory
    resources: Directory


@dataclass(frozen=True)
class Certificate:
    index: int
    offset: int
    length: int
    revision: int
    certificate_type: int
    payload: Span
    padding_length: int


@dataclass(frozen=True)
class DebugEntry:
    index: int
    offset: int
    characteristics: int
    timestamp: int
    major_version: int
    minor_version: int
    debug_type: int
    size_of_data: int
    address_of_raw_data: int
    pointer_to_raw_data: int


@dataclass(frozen=True)
class CodeView:
    debug: DebugEntry
    guid_raw: bytes
    guid: str
    age: int
    path_offset: int
    path_raw: bytes
    record_length: int

    @property
    def path_ascii(self) -> str | None:
        try:
            return self.path_raw.decode("ascii")
        except UnicodeDecodeError:
            return None


@dataclass(frozen=True)
class Triage:
    layout: Layout | None
    layout_issues: tuple[Issue, ...]
    certificates: Inventory[Certificate]
    codeview: Inventory[CodeView]
    overlay: Inventory[Span]


class _Failure(ValueError):
    def __init__(self, kind: IssueKind, code: str, offset: int | None = None) -> None:
        super().__init__(code)
        self.issue = Issue(kind, code, offset)


def _inside(offset: int, length: int, end: int) -> bool:
    return 0 <= offset <= end and 0 <= length <= end - offset


def _overlap(a: int, length_a: int, b: int, length_b: int) -> bool:
    return length_a > 0 and length_b > 0 and max(a, b) < min(a + length_a, b + length_b)


def _disjoint(ranges: list[tuple[int, int]]) -> bool:
    ordered = sorted((start, start + size) for start, size in ranges if size)
    return all(left[1] <= right[0] for left, right in zip(ordered, ordered[1:], strict=False))


def _layout(data: bytes, budgets: Budgets) -> Layout:
    if len(data) > budgets.max_input_bytes:
        raise _Failure("limit", "input_bytes")
    if len(data) < 64 or data[:2] != b"MZ":
        raise _Failure("malformed", "dos_header", 0)
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    if nt < 64 or not _inside(nt, 24, len(data)) or data[nt : nt + 4] != b"PE\0\0":
        raise _Failure("malformed", "pe_header", 0x3C)
    section_count = struct.unpack_from("<H", data, nt + 6)[0]
    optional_size = struct.unpack_from("<H", data, nt + 20)[0]
    optional = nt + 24
    if optional_size < 2 or not _inside(optional, optional_size, len(data)):
        raise _Failure("malformed", "optional_header", nt + 20)
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in (0x10B, 0x20B):
        raise _Failure("ignored", "optional_magic", optional)
    fixed = 96 if magic == 0x10B else 112
    if optional_size < fixed:
        raise _Failure("malformed", "optional_header", optional)
    directory_count = struct.unpack_from("<I", data, optional + fixed - 4)[0]
    if directory_count > DIRECTORY_COUNT:
        raise _Failure("ignored", "directory_count", optional + fixed - 4)
    if fixed + directory_count * 8 > optional_size:
        raise _Failure("malformed", "directory_table", optional + fixed - 4)
    image_size, header_size = struct.unpack_from("<II", data, optional + 56)
    section_start = optional + optional_size
    if not section_start + section_count * SECTION_SIZE <= header_size <= len(data):
        raise _Failure("malformed", "headers_or_section_table", optional + 60)
    if header_size > image_size:
        raise _Failure("malformed", "headers_outside_image", optional + 56)
    if not section_count:
        raise _Failure("ignored", "no_sections", nt + 6)
    if section_count > budgets.max_sections:
        raise _Failure("limit", "sections", nt + 6)
    sections = []
    for index in range(section_count):
        at = section_start + index * SECTION_SIZE
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, at + 8)
        characteristics = struct.unpack_from("<I", data, at + 36)[0]
        if raw_size and (raw_offset < header_size or not _inside(raw_offset, raw_size, len(data))):
            raise _Failure("malformed", "section_raw_range", at)
        mapped_size = max(virtual_size, raw_size)
        if mapped_size and (rva < header_size or not _inside(rva, mapped_size, image_size)):
            raise _Failure("malformed", "section_virtual_range", at)
        sections.append(
            Section(at, data[at : at + 8], rva, virtual_size, raw_offset, raw_size, characteristics)
        )
    if not _disjoint([(s.raw_offset, s.raw_size) for s in sections]):
        raise _Failure("malformed", "section_raw_overlap", section_start)
    if not _disjoint([(s.rva, max(s.virtual_size, s.raw_size)) for s in sections]):
        raise _Failure("malformed", "section_virtual_overlap", section_start)

    def directory(index: int) -> Directory:
        if index >= directory_count:
            return Directory(0, 0, None)
        at = optional + fixed + index * 8
        address, size = struct.unpack_from("<II", data, at)
        return Directory(address, size, at)

    return Layout(
        32 if magic == 0x10B else 64,
        header_size,
        image_size,
        max([header_size] + [s.raw_offset + s.raw_size for s in sections if s.raw_size]),
        tuple(sections),
        directory(SECURITY_DIRECTORY),
        directory(DEBUG_DIRECTORY),
        directory(RESOURCE_DIRECTORY),
    )


def _locate(layout: Layout, rva: int, length: int) -> int | None:
    if length <= 0 or not _inside(rva, length, UINT32_END):
        return None
    regions = [(0, 0, layout.size_of_headers)] + [
        (s.rva, s.raw_offset, s.raw_size) for s in layout.sections if s.raw_size
    ]
    matches = [
        offset + rva - start
        for start, offset, size in regions
        if start <= rva and rva + length <= start + size
    ]
    return matches[0] if len(matches) == 1 else None


@dataclass
class _Hashes:
    remaining: int

    def span(self, data: bytes, offset: int, length: int) -> Span:
        if length > self.remaining:
            raise _Failure("limit", "hash_bytes", offset)
        self.remaining -= length
        return Span(
            offset, length, hashlib.sha256(memoryview(data)[offset : offset + length]).hexdigest()
        )


def _certificates(
    data: bytes, layout: Layout, budgets: Budgets, hashes: _Hashes
) -> Inventory[Certificate]:
    directory = layout.security
    start, size = directory.address, directory.size
    if start == size == 0:
        return Inventory("absent")
    items: list[Certificate] = []
    try:
        if (
            not start
            or not size
            or start % CERTIFICATE_ALIGNMENT
            or not _inside(start, size, len(data))
        ):
            raise _Failure("malformed", "security_range", directory.entry_offset)
        if start < layout.size_of_headers or any(
            _overlap(start, size, section.raw_offset, section.raw_size)
            for section in layout.sections
        ):
            raise _Failure("malformed", "security_overlaps_image", directory.entry_offset)
        at, end = start, start + size
        while at < end:
            if len(items) >= budgets.max_certificates:
                raise _Failure("limit", "certificates", at)
            if not _inside(at, CERTIFICATE_HEADER_SIZE, end):
                raise _Failure("malformed", "certificate_header", at)
            length, revision, certificate_type = struct.unpack_from("<IHH", data, at)
            if length < CERTIFICATE_HEADER_SIZE or not _inside(at, length, end):
                raise _Failure("malformed", "certificate_length", at)
            padded_length = (length + CERTIFICATE_ALIGNMENT - 1) & ~(CERTIFICATE_ALIGNMENT - 1)
            if not _inside(at, padded_length, end):
                raise _Failure("malformed", "certificate_padding_missing", at)
            if any(data[at + length : at + padded_length]):
                raise _Failure("malformed", "certificate_padding_nonzero", at + length)
            payload = hashes.span(
                data, at + CERTIFICATE_HEADER_SIZE, length - CERTIFICATE_HEADER_SIZE
            )
            items.append(
                Certificate(
                    len(items),
                    at,
                    length,
                    revision,
                    certificate_type,
                    payload,
                    padded_length - length,
                )
            )
            at += padded_length
    except _Failure as error:
        return Inventory("incomplete", tuple(items), (error.issue,))
    return Inventory("complete", tuple(items))


def _codeview_record(
    data: bytes, layout: Layout, entry: DebugEntry, max_path_bytes: int
) -> CodeView:
    if entry.characteristics:
        raise _Failure("ignored", "debug_characteristics_unsupported", entry.offset)
    pointer, size, rva = entry.pointer_to_raw_data, entry.size_of_data, entry.address_of_raw_data
    if not pointer or not size or not _inside(pointer, size, len(data)):
        raise _Failure("malformed", "debug_payload_range", entry.offset)
    if rva:
        if _locate(layout, rva, size) != pointer:
            raise _Failure("malformed", "debug_pointer_rva_mismatch", entry.offset)
    elif _overlap(pointer, size, 0, layout.size_of_headers) or any(
        _overlap(pointer, size, s.raw_offset, s.raw_size) for s in layout.sections
    ):
        raise _Failure("malformed", "debug_zero_rva_in_image", entry.offset)
    if _overlap(pointer, size, layout.security.address, layout.security.size):
        raise _Failure("malformed", "debug_overlaps_security", entry.offset)
    if size < 4:
        raise _Failure("malformed", "codeview_signature_truncated", pointer)
    if data[pointer : pointer + 4] != b"RSDS":
        raise _Failure("ignored", "codeview_signature_unsupported", pointer)
    if size < RSDS_SIZE + 1:
        raise _Failure("malformed", "rsds_truncated", pointer)
    path_at, end = pointer + RSDS_SIZE, pointer + size
    stop = data.find(b"\0", path_at, min(end, path_at + max_path_bytes + 1))
    if stop < 0:
        if end - path_at > max_path_bytes:
            raise _Failure("limit", "path_bytes", path_at)
        raise _Failure("malformed", "path_not_terminated", path_at)
    guid_raw = data[pointer + 4 : pointer + 20]
    age = struct.unpack_from("<I", data, pointer + 20)[0]
    return CodeView(
        entry,
        guid_raw,
        str(UUID(bytes_le=guid_raw)),
        age,
        path_at,
        data[path_at:stop],
        stop + 1 - pointer,
    )


def _codeview(data: bytes, layout: Layout, budgets: Budgets) -> Inventory[CodeView]:
    directory = layout.debug
    if directory.address == directory.size == 0:
        return Inventory("absent")
    if not directory.address or not directory.size or directory.size % DEBUG_SIZE:
        return Inventory(
            "incomplete",
            issues=(Issue("malformed", "debug_directory_size", directory.entry_offset),),
        )
    offset = _locate(layout, directory.address, directory.size)
    if offset is None:
        return Inventory(
            "incomplete",
            issues=(Issue("malformed", "debug_directory_range", directory.entry_offset),),
        )
    count = directory.size // DEBUG_SIZE
    items = []
    issues = []
    for index in range(min(count, budgets.max_debug_entries)):
        at = offset + index * DEBUG_SIZE
        flags, stamp, major, minor, kind, size, rva, pointer = struct.unpack_from(
            "<IIHHIIII", data, at
        )
        entry = DebugEntry(index, at, flags, stamp, major, minor, kind, size, rva, pointer)
        if kind != CODEVIEW_TYPE:
            issues.append(Issue("ignored", "debug_type_unsupported", at))
            continue
        try:
            items.append(_codeview_record(data, layout, entry, budgets.max_path_bytes))
        except _Failure as error:
            issues.append(error.issue)
    if count > budgets.max_debug_entries:
        issues.append(
            Issue("limit", "debug_entries", offset + budgets.max_debug_entries * DEBUG_SIZE)
        )
    # Entries of other debug types are listed but are not CodeView records left unread.
    unread = any(issue.code != "debug_type_unsupported" for issue in issues)
    return Inventory("incomplete" if unread else "complete", tuple(items), tuple(issues))


def _overlay(
    data: bytes, layout: Layout, certificates: Inventory[Certificate], hashes: _Hashes
) -> Inventory[Span]:
    if certificates.status not in ("absent", "complete"):
        return Inventory("unavailable", issues=(Issue("dependency", "security_not_verified"),))
    start = layout.tail_offset
    ranges = [(start, len(data) - start)]
    security = layout.security
    if certificates.status == "complete" and security.address + security.size > start:
        ranges = [
            (start, max(0, security.address - start)),
            (security.address + security.size, len(data) - security.address - security.size),
        ]
    try:
        total = sum(length for _, length in ranges)
        if total > hashes.remaining:
            raise _Failure("limit", "hash_bytes", start)
        spans = tuple(hashes.span(data, offset, length) for offset, length in ranges if length)
    except _Failure as error:
        return Inventory("incomplete", issues=(error.issue,))
    return Inventory("complete", spans)


def read(data: bytes, *, budgets: Budgets) -> Triage:
    if not isinstance(data, bytes):
        raise TypeError("data must be immutable bytes")
    try:
        layout = _layout(data, budgets)
    except _Failure as error:
        dependency = (Issue("dependency", "layout_not_verified"),)
        return Triage(
            None,
            (error.issue,),
            Inventory("unavailable", issues=dependency),
            Inventory("unavailable", issues=dependency),
            Inventory("unavailable", issues=dependency),
        )
    hashes = _Hashes(budgets.max_hash_bytes)
    certificates = _certificates(data, layout, budgets, hashes)
    return Triage(
        layout,
        (),
        certificates,
        _codeview(data, layout, budgets),
        _overlay(data, layout, certificates, hashes),
    )
