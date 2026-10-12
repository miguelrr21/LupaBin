import struct
from bisect import bisect_left
from dataclasses import dataclass, fields
from typing import Literal

RT_VERSION = 16
VS_FFI_SIGNATURE = 0xFEEF04BD
State = Literal["absent", "complete", "partial"]
IssueKind = Literal["malformed", "limit", "unsupported"]


@dataclass(frozen=True, slots=True)
class RawRegion:
    rva: int
    file_offset: int
    raw_size: int


@dataclass(frozen=True, slots=True)
class Location:
    rva: int
    file_offset: int
    size: int


@dataclass(frozen=True, slots=True)
class Limits:
    regions: int
    directories: int
    entries: int
    depth: int
    name_bytes: int
    total_read_bytes: int
    version_bytes: int
    version_blocks: int
    version_depth: int
    translations: int

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value < 0:
                raise ValueError("resource limit must be a nonnegative integer")


@dataclass(frozen=True, slots=True)
class Omission:
    kind: IssueKind
    code: str
    relative_offset: int
    base: Literal["resource_directory", "version_payload"]
    location: Location | None = None


@dataclass(frozen=True, slots=True)
class UnicodeValue:
    location: Location
    raw: bytes
    text: str | None


@dataclass(frozen=True, slots=True)
class Identifier:
    raw: int
    number: int | None
    name: UnicodeValue | None


@dataclass(frozen=True, slots=True)
class Directory:
    location: Location
    path: tuple[Identifier, ...]
    characteristics: int
    timestamp: int
    major_version: int
    minor_version: int
    named_entries: int
    id_entries: int


@dataclass(frozen=True, slots=True)
class Entry:
    location: Location
    path: tuple[Identifier, ...]
    target_offset: int
    is_directory: bool


@dataclass(frozen=True, slots=True)
class Resource:
    entry_index: int
    location: Location
    path: tuple[Identifier, ...]
    data_rva: int
    data_size: int
    codepage: int
    reserved: int
    data_location: Location | None

    @property
    def resource_type(self) -> Identifier | None:
        return self.path[0] if self.path else None

    @property
    def resource_name(self) -> Identifier | None:
        return self.path[1] if len(self.path) == 3 else None

    @property
    def resource_language(self) -> Identifier | None:
        return self.path[2] if len(self.path) == 3 else None


@dataclass(frozen=True, slots=True)
class VersionBlock:
    parent_index: int | None
    location: Location
    value_length: int
    value_type: int
    key: UnicodeValue
    value_location: Location
    value: bytes


@dataclass(frozen=True, slots=True)
class FixedFileInfo:
    location: Location
    signature: int
    structure_version: int
    file_version_ms: int
    file_version_ls: int
    product_version_ms: int
    product_version_ls: int
    file_flags_mask: int
    file_flags: int
    file_os: int
    file_type: int
    file_subtype: int
    file_date_ms: int
    file_date_ls: int


@dataclass(frozen=True, slots=True)
class VersionString:
    block_index: int
    table_index: int
    language: int
    codepage: int
    value: UnicodeValue


@dataclass(frozen=True, slots=True)
class Translation:
    block_index: int
    location: Location
    language: int
    codepage: int


@dataclass(frozen=True, slots=True)
class VersionInfo:
    resource_index: int
    state: State
    blocks: tuple[VersionBlock, ...]
    fixed: FixedFileInfo | None
    strings: tuple[VersionString, ...]
    translations: tuple[Translation, ...]
    omissions: tuple[Omission, ...]


@dataclass(frozen=True, slots=True)
class ResourceResult:
    state: State
    directories: tuple[Directory, ...]
    entries: tuple[Entry, ...]
    resources: tuple[Resource, ...]
    versions: tuple[VersionInfo, ...]
    omissions: tuple[Omission, ...]


class _Failure(Exception):
    def __init__(self, code: str, kind: IssueKind = "malformed") -> None:
        self.code = code
        self.kind = kind
        super().__init__(code)


class _Budget:
    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.read_bytes = 0
        self.version_blocks = 0
        self.translations = 0

    def consume(self, size: int) -> None:
        if size > self.limits.total_read_bytes - self.read_bytes:
            raise _Failure("read_bytes_limit", "limit")
        self.read_bytes += size


class _Reader:
    def __init__(self, data: bytes, regions: tuple[RawRegion, ...], budget: _Budget) -> None:
        self.data = data
        self.regions = regions
        self.budget = budget

    def locate(self, rva: int, size: int) -> Location:
        if rva < 0 or size < 0 or rva + size > 0x100000000:
            raise _Failure("rva_overflow")
        candidates = [
            region
            for region in self.regions
            if region.raw_size > 0
            and (
                region.rva <= rva <= region.rva + region.raw_size
                if size == 0
                else rva < region.rva + region.raw_size and region.rva < rva + size
            )
        ]
        if len(candidates) != 1:
            raise _Failure("ambiguous_rva" if candidates else "unmapped_rva")
        region = candidates[0]
        if rva < region.rva or rva + size > region.rva + region.raw_size:
            raise _Failure("noncontiguous_rva")
        offset = region.file_offset + rva - region.rva
        if offset + size > len(self.data):
            raise _Failure("truncated_raw_data")
        for other in self.regions:
            if other is region or other.raw_size == 0:
                continue
            if (
                size
                and offset < other.file_offset + other.raw_size
                and other.file_offset < offset + size
            ):
                raise _Failure("overlapping_raw_regions")
        return Location(rva, offset, size)

    def take(self, location: Location) -> bytes:
        self.budget.consume(location.size)
        return self.data[location.file_offset : location.file_offset + location.size]


class _Claims:
    def __init__(self) -> None:
        self.spans: list[tuple[int, int]] = []

    def add(self, offset: int, size: int) -> None:
        if not size:
            return
        end = offset + size
        index = bisect_left(self.spans, (offset, -1))
        if index < len(self.spans) and self.spans[index][0] == offset:
            raise _Failure("offset_alias", "unsupported")
        if (index and self.spans[index - 1][1] > offset) or (
            index < len(self.spans) and self.spans[index][0] < end
        ):
            raise _Failure("overlapping_ranges")
        self.spans.insert(index, (offset, end))


def _decode(raw: bytes) -> str | None:
    try:
        return raw.decode("utf-16-le", errors="strict")
    except UnicodeDecodeError:
        return None


def _align(offset: int) -> int:
    return (offset + 3) & ~3


class _Versions:
    def __init__(self, raw: bytes, origin: Location, budget: _Budget) -> None:
        self.raw = raw
        self.origin = origin
        self.budget = budget
        self.blocks: list[VersionBlock] = []
        self.omissions: list[Omission] = []
        self.fixed: FixedFileInfo | None = None
        self.strings: list[VersionString] = []
        self.translations: list[Translation] = []
        self.roles: dict[int, str] = {}
        self.tables: dict[int, tuple[int, int]] = {}

    def location(self, offset: int, size: int) -> Location:
        return Location(self.origin.rva + offset, self.origin.file_offset + offset, size)

    def issue(self, code: str, offset: int, kind: IssueKind = "malformed") -> None:
        location = self.location(offset, 0) if 0 <= offset <= len(self.raw) else None
        self.omissions.append(Omission(kind, code, offset, "version_payload", location))

    def padding(self, start: int, end: int) -> None:
        if any(self.raw[start:end]):
            self.issue("nonzero_version_padding", start)

    def block(self, start: int, end: int, parent: int | None) -> tuple[int, int]:
        if end - start < 6:
            raise _Failure("truncated_version_header")
        length, value_length, value_type = struct.unpack_from("<HHH", self.raw, start)
        stop = start + length
        if length < 8 or stop > end:
            raise _Failure("invalid_version_length")
        if value_type not in (0, 1):
            raise _Failure("invalid_version_type")
        key_start = start + 6
        cursor = key_start
        while cursor + 2 <= stop:
            if cursor - key_start > self.budget.limits.name_bytes:
                raise _Failure("version_key_limit", "limit")
            if self.raw[cursor : cursor + 2] == b"\0\0":
                break
            cursor += 2
        else:
            raise _Failure("unterminated_version_key")
        key_raw = self.raw[key_start:cursor]
        key = UnicodeValue(self.location(key_start, len(key_raw)), key_raw, _decode(key_raw))
        if key.text is None:
            self.issue("invalid_version_key_utf16", key_start)
        key_end = cursor + 2
        value_start = _align(key_end)
        value_size = value_length * (2 if value_type == 1 else 1)
        if value_size == 0 and key_end == stop:
            value_start = stop
        if value_start > stop or value_size > stop - value_start:
            raise _Failure("version_value_out_of_bounds")
        self.padding(key_end, value_start)
        value_end = value_start + value_size
        index = len(self.blocks)
        self.blocks.append(
            VersionBlock(
                parent,
                self.location(start, length),
                value_length,
                value_type,
                key,
                self.location(value_start, value_size),
                self.raw[value_start:value_end],
            )
        )
        children = min(_align(value_end), stop)
        self.padding(value_end, children)
        return index, children

    def interpret(self, index: int) -> bool:
        block = self.blocks[index]
        parent = block.parent_index
        key = block.key.text
        offset = block.location.file_offset - self.origin.file_offset
        role = self.roles.get(parent, "") if parent is not None else ""
        if parent is None:
            if key != "VS_VERSION_INFO" or block.value_type != 0:
                self.issue("invalid_version_root", offset)
                return False
            self.roles[index] = "root"
            if block.value:
                if len(block.value) != 52:
                    self.issue("fixed_file_info_size", offset)
                else:
                    values = struct.unpack("<13I", block.value)
                    if values[0] != VS_FFI_SIGNATURE:
                        self.issue("fixed_file_info_signature", offset)
                    else:
                        self.fixed = FixedFileInfo(block.value_location, *values)
            return True
        if role == "root" and key in ("StringFileInfo", "VarFileInfo"):
            if block.value_length or block.value_type != 1:
                self.issue("invalid_version_container", offset)
                return False
            self.roles[index] = "strings" if key == "StringFileInfo" else "vars"
            return True
        if role == "strings":
            if (
                block.value_length
                or block.value_type != 1
                or key is None
                or len(key) != 8
                or any(char not in "0123456789abcdefABCDEF" for char in key)
            ):
                self.issue("invalid_string_table", offset)
                return False
            self.roles[index] = "table"
            self.tables[index] = int(key[:4], 16), int(key[4:], 16)
            return True
        if role == "table" and parent is not None:
            if block.value_type != 1:
                self.issue("invalid_version_string_type", offset)
                return False
            text = _decode(block.value)
            if text is None:
                self.issue("invalid_version_value_utf16", offset)
            elif not text.endswith("\0") or "\0" in text[:-1]:
                self.issue("invalid_version_string_terminator", offset)
                text = None
            else:
                text = text[:-1]
            language, codepage = self.tables[parent]
            self.strings.append(
                VersionString(
                    index,
                    parent,
                    language,
                    codepage,
                    UnicodeValue(block.value_location, block.value, text),
                )
            )
            return False
        if role == "vars" and key == "Translation":
            if block.value_type != 0 or not block.value or len(block.value) % 4:
                self.issue("invalid_translation_value", offset)
                return False
            for pos in range(0, len(block.value), 4):
                if self.budget.translations >= self.budget.limits.translations:
                    self.issue("translations_limit", offset, "limit")
                    break
                self.budget.translations += 1
                language, codepage = struct.unpack_from("<HH", block.value, pos)
                self.translations.append(
                    Translation(
                        index,
                        Location(
                            block.value_location.rva + pos,
                            block.value_location.file_offset + pos,
                            4,
                        ),
                        language,
                        codepage,
                    )
                )
            return False
        self.issue("unknown_version_block", offset, "unsupported")
        return False

    def read(self, resource_index: int) -> VersionInfo:
        tasks: list[tuple[int, int, int | None, int]] = [(0, len(self.raw), None, 0)]
        while tasks:
            start, end, parent, depth = tasks.pop()
            if depth > self.budget.limits.version_depth:
                self.issue("version_depth_limit", start, "limit")
                continue
            if self.budget.version_blocks >= self.budget.limits.version_blocks:
                self.issue("version_blocks_limit", start, "limit")
                break
            self.budget.version_blocks += 1
            if end - start < 2:
                self.issue("truncated_version_header", start)
                continue
            length = struct.unpack_from("<H", self.raw, start)[0]
            stop = start + length
            if length < 8 or stop > end:
                self.issue("invalid_version_length", start)
                continue
            if parent is not None and stop < end:
                next_start = _align(stop)
                self.padding(stop, min(next_start, end))
                if next_start < end:
                    tasks.append((next_start, end, parent, depth))
            elif parent is None and any(self.raw[stop:end]):
                self.issue("trailing_version_bytes", stop)
            try:
                index, children = self.block(start, stop, parent)
            except _Failure as error:
                self.issue(error.code, start, error.kind)
                continue
            descend = self.interpret(index)
            if children < stop:
                if descend:
                    tasks.append((children, stop, index, depth + 1))
                else:
                    self.issue("unread_version_children", children, "unsupported")
        return VersionInfo(
            resource_index,
            "partial" if self.omissions else "complete",
            tuple(self.blocks),
            self.fixed,
            tuple(self.strings),
            tuple(self.translations),
            tuple(self.omissions),
        )


class _Resources:
    def __init__(self, reader: _Reader, rva: int, size: int) -> None:
        self.reader = reader
        self.rva = rva
        self.size = size
        self.limits = reader.budget.limits
        self.claims = _Claims()
        self.directories: list[Directory] = []
        self.entries: list[Entry] = []
        self.resources: list[Resource] = []
        self.versions: list[VersionInfo] = []
        self.omissions: list[Omission] = []
        self.seen: set[int] = set()

    def issue(self, error: _Failure, offset: int, location: Location | None = None) -> None:
        self.omissions.append(
            Omission(error.kind, error.code, offset, "resource_directory", location)
        )

    def metadata(self, offset: int, size: int, alignment: int = 4) -> tuple[Location, bytes]:
        if offset % alignment:
            raise _Failure("misaligned_metadata")
        if offset < 0 or offset > self.size or size > self.size - offset:
            raise _Failure("metadata_out_of_bounds")
        location = self.reader.locate(self.rva + offset, size)
        self.claims.add(location.file_offset, size)
        return location, self.reader.take(location)

    def identifier(self, raw: int) -> Identifier:
        if not raw & 0x80000000:
            return Identifier(raw, raw, None)
        offset = raw & 0x7FFFFFFF
        try:
            _, prefix = self.metadata(offset, 2, 2)
            size = struct.unpack("<H", prefix)[0] * 2
            if size > self.limits.name_bytes:
                raise _Failure("resource_name_limit", "limit")
            location, value = self.metadata(offset + 2, size, 2)
            text = _decode(value)
            if text is None:
                self.issue(_Failure("invalid_resource_name_utf16"), offset, location)
            return Identifier(raw, None, UnicodeValue(location, value, text))
        except _Failure as error:
            self.issue(error, offset)
            return Identifier(raw, None, None)

    def leaf(self, entry_index: int, offset: int, path: tuple[Identifier, ...]) -> None:
        location, raw = self.metadata(offset, 16)
        data_rva, size, codepage, reserved = struct.unpack("<4I", raw)
        data_location = None
        try:
            data_location = self.reader.locate(data_rva, size)
        except _Failure as error:
            self.issue(error, offset, location)
        if len(path) != 3:
            self.issue(_Failure("noncanonical_resource_levels", "unsupported"), offset, location)
        if reserved:
            self.issue(_Failure("nonzero_resource_reserved"), offset, location)
        self.resources.append(
            Resource(entry_index, location, path, data_rva, size, codepage, reserved, data_location)
        )

    def payloads(self) -> None:
        for index, resource in enumerate(self.resources):
            location = resource.data_location
            relative = resource.location.rva - self.rva
            if location is None:
                continue
            try:
                self.claims.add(location.file_offset, location.size)
            except _Failure as error:
                self.issue(error, relative, location)
                continue
            if len(resource.path) != 3 or resource.path[0].number != RT_VERSION:
                continue
            omissions: tuple[Omission, ...] = ()
            try:
                if location.size > self.limits.version_bytes:
                    raise _Failure("version_bytes_limit", "limit")
                raw = self.reader.take(location)
                version = _Versions(raw, location, self.reader.budget).read(index)
            except _Failure as error:
                omissions = (Omission(error.kind, error.code, 0, "version_payload", location),)
                version = VersionInfo(index, "partial", (), None, (), (), omissions)
            self.versions.append(version)

    def read(self) -> ResourceResult:
        try:
            self.reader.locate(self.rva, self.size)
        except _Failure as error:
            self.issue(error, 0)
        tasks: list[tuple[int, tuple[Identifier, ...], tuple[int, ...]]] = [(0, (), ())]
        processed_entries = 0
        while tasks:
            offset, path, ancestors = tasks.pop()
            try:
                if offset in ancestors:
                    raise _Failure("resource_cycle")
                if offset in self.seen:
                    raise _Failure("directory_alias", "unsupported")
                if len(path) > self.limits.depth:
                    raise _Failure("resource_depth_limit", "limit")
                if len(self.seen) >= self.limits.directories:
                    raise _Failure("directories_limit", "limit")
                self.seen.add(offset)
                location, raw = self.metadata(offset, 16)
            except _Failure as error:
                self.issue(error, offset)
                continue
            flags, timestamp, major, minor, named, ids = struct.unpack("<IIHHHH", raw)
            self.directories.append(
                Directory(location, path, flags, timestamp, major, minor, named, ids)
            )
            children: list[tuple[int, tuple[Identifier, ...], tuple[int, ...]]] = []
            for row in range(named + ids):
                entry_offset = offset + 16 + row * 8
                if processed_entries >= self.limits.entries:
                    self.issue(_Failure("entries_limit", "limit"), entry_offset)
                    break
                processed_entries += 1
                try:
                    entry_location, entry_raw = self.metadata(entry_offset, 8)
                except _Failure as error:
                    self.issue(error, entry_offset)
                    break
                name, target = struct.unpack("<II", entry_raw)
                if bool(name & 0x80000000) != (row < named):
                    self.issue(_Failure("resource_name_partition"), entry_offset, entry_location)
                identifier = self.identifier(name)
                entry_path = (*path, identifier)
                target_offset = target & 0x7FFFFFFF
                is_directory = bool(target & 0x80000000)
                entry_index = len(self.entries)
                self.entries.append(Entry(entry_location, entry_path, target_offset, is_directory))
                if is_directory:
                    children.append((target_offset, entry_path, (*ancestors, offset)))
                else:
                    try:
                        self.leaf(entry_index, target_offset, entry_path)
                    except _Failure as error:
                        self.issue(error, target_offset)
            tasks.extend(reversed(children))
        self.payloads()
        partial = bool(self.omissions) or any(v.state == "partial" for v in self.versions)
        return ResourceResult(
            "partial" if partial else "complete",
            tuple(self.directories),
            tuple(self.entries),
            tuple(self.resources),
            tuple(self.versions),
            tuple(self.omissions),
        )


def read(
    data: bytes,
    directory_rva: int,
    directory_size: int,
    regions: tuple[RawRegion, ...],
    *,
    limits: Limits,
) -> ResourceResult:
    if directory_rva == 0 and directory_size == 0:
        return ResourceResult("absent", (), (), (), (), ())
    error: _Failure | None = None
    if directory_rva <= 0 or directory_size <= 0 or directory_rva + directory_size > 0x100000000:
        error = _Failure("invalid_resource_directory")
    elif len(regions) > limits.regions:
        error = _Failure("regions_limit", "limit")
    elif any(
        region.rva < 0
        or region.file_offset < 0
        or region.raw_size < 0
        or region.rva + region.raw_size > 0x100000000
        for region in regions
    ):
        error = _Failure("invalid_raw_region")
    if error is not None:
        return ResourceResult(
            "partial", (), (), (), (), (Omission(error.kind, error.code, 0, "resource_directory"),)
        )
    return _Resources(_Reader(data, regions, _Budget(limits)), directory_rva, directory_size).read()
