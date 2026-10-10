import argparse
import hashlib
import json
import platform
import re
import struct
import sys
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

import pefile

from lupabin.evidence import pe_resources as resources
from lupabin.evidence import pe_triage as triage

PEFILE_VERSION = "2024.8.26"
GROUPS = (
    "layout",
    "sections",
    "directories",
    "debug",
    "codeview",
    "resources",
    "version_strings",
    "certificate_structure",
    "certificate_oracle",
    "overlay",
)
SOURCES = (
    "https://learn.microsoft.com/en-us/windows/win32/debug/pe-format",
    "https://github.com/erocarrera/pefile/blob/v2024.8.26/pefile.py",
    "https://github.com/microsoft/microsoft-pdb/blob/master/PDB/dbi/locator.h",
)
SCOPE = {
    "sections": "original table order restored using pefile section header file offsets",
    "debug": "all eight raw fields and file offsets; RSDS declarations separately",
    "resources": "ordered leaf paths, IDs/counted name bytes, RVA/size/codepage/reserved",
    "version_strings": (
        "ordered strings, table language/codepage/offset and resource index; "
        "dictionary loss unavailable"
    ),
    "certificate_structure": (
        "independent boundary walk from pefile Security offset/size; raw payload SHA256, no ASN.1"
    ),
    "certificate_oracle": "unavailable with Security: pefile has no WIN_CERTIFICATE parser",
    "overlay": (
        "not native pefile overlay: max(SizeOfHeaders, all raw section ends), "
        "subtract structurally checked Security"
    ),
    "reference_limits": (
        "input bounded; native pefile parsing uses its own fingerprinted limits; "
        "configured row/depth/name/version limits additionally bound reference projection"
    ),
    "excluded": (
        "version fixed fields/translations/block grammar, resource internal directories, "
        "ASN.1, cryptographic validity, trust, execution"
    ),
}
DEBUG_FIELDS = (
    "Characteristics",
    "TimeDateStamp",
    "MajorVersion",
    "MinorVersion",
    "Type",
    "SizeOfData",
    "AddressOfRawData",
    "PointerToRawData",
)
DEBUG_KEYS = (
    "characteristics",
    "timestamp",
    "major_version",
    "minor_version",
    "debug_type",
    "size_of_data",
    "address_of_raw_data",
    "pointer_to_raw_data",
)
MISSING = object()


@dataclass(frozen=True)
class Config:
    triage: triage.Budgets
    resources: resources.Limits
    max_details: int
    max_detail_bytes: int

    def __post_init__(self) -> None:
        for value in (self.max_details, self.max_detail_bytes):
            if type(value) is not int or value < 0:
                raise ValueError("detail limits must be nonnegative integers")


@dataclass(frozen=True)
class Observation:
    value: Any
    status: Literal["complete", "incomplete", "unavailable", "failed"] = "complete"
    reasons: tuple[str, ...] = ()


Snapshot = dict[str, Observation]


class NotComparable(ValueError):
    pass


def bounded(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise NotComparable("byte_range_outside_file")
    return data[offset : offset + size]


def original_directory(data: bytes, layout: triage.Layout, index: int) -> tuple[int, int]:
    header = bounded(data, 0, layout.size_of_headers)
    nt = int.from_bytes(bounded(header, 0x3C, 4), "little")
    if bounded(header, nt, 4) != b"PE\0\0":
        raise NotComparable("pe_signature_changed")
    optional = nt + 24
    size = int.from_bytes(bounded(header, nt + 20, 2), "little")
    raw = bounded(header, optional, size)
    magic = int.from_bytes(bounded(raw, 0, 2), "little")
    if magic != (0x10B if layout.bits == 32 else 0x20B):
        raise NotComparable("optional_magic_changed")
    fixed = 96 if layout.bits == 32 else 112
    count = int.from_bytes(bounded(raw, fixed - 4, 4), "little")
    if count > 16 or fixed + count * 8 > len(raw):
        raise NotComparable("directory_table_boundary")
    return struct.unpack("<II", bounded(raw, fixed + index * 8, 8)) if index < count else (0, 0)


def read_resources(
    data: bytes, result: triage.Triage, limits: resources.Limits
) -> resources.ResourceResult | None:
    if result.layout is None or result.layout_issues:
        return None
    layout = result.layout
    rva, size = original_directory(data, layout, 2)
    regions = (resources.RawRegion(0, 0, layout.size_of_headers),) + tuple(
        resources.RawRegion(s.rva, s.raw_offset, s.raw_size) for s in layout.sections if s.raw_size
    )
    for region in regions:
        bounded(data, region.file_offset, region.raw_size)
    return resources.read(data, rva, size, regions, limits=limits)


def resource_path(path: tuple[resources.Identifier, ...]) -> list[dict[str, Any]]:
    return [
        dict(raw=p.raw, id=p.number, name_raw=None if p.name is None else p.name.raw) for p in path
    ]


def reader_snapshot(data: bytes, config: Config) -> Snapshot:
    result = triage.read(data, budgets=config.triage)
    if result.layout is None or result.layout_issues:
        return {
            key: Observation(None, "unavailable", tuple(i.code for i in result.layout_issues))
            for key in GROUPS
        }
    layout = result.layout
    snapshot = {
        "layout": Observation(
            dict(bits=layout.bits, headers=layout.size_of_headers, image=layout.size_of_image)
        ),
        "sections": Observation([asdict(s) for s in layout.sections]),
        "directories": Observation(
            {str(i): original_directory(data, layout, i) for i in (2, 4, 6)}
        ),
    }
    for key, inventory in (
        ("codeview", result.codeview),
        ("certificate_structure", result.certificates),
        ("overlay", result.overlay),
    ):
        snapshot[key] = Observation(
            [asdict(item) for item in inventory.items],
            "complete" if inventory.status in ("complete", "absent") else "incomplete",
            tuple(i.code for i in inventory.issues),
        )
    snapshot["certificate_oracle"] = Observation([])
    try:
        rva, size = original_directory(data, layout, 6)
        debug = []
        if rva or size:
            regions = [(0, 0, layout.size_of_headers)] + [
                (s.rva, s.raw_offset, s.raw_size) for s in layout.sections if s.raw_size
            ]
            matches = [
                offset + rva - base
                for base, offset, length in regions
                if base <= rva and rva + size <= base + length
            ]
            if (
                not rva
                or not size
                or size % 28
                or len(matches) != 1
                or size // 28 > config.triage.max_debug_entries
            ):
                raise NotComparable("debug_directory_boundary_or_limit")
            for index in range(size // 28):
                at = matches[0] + index * 28
                values = struct.unpack("<IIHHIIII", bounded(data, at, 28))
                debug.append(
                    dict(index=index, offset=at, **dict(zip(DEBUG_KEYS, values, strict=True)))
                )
        snapshot["debug"] = Observation(debug)
    except NotComparable as error:
        snapshot["debug"] = Observation(None, "incomplete", (str(error),))
    parsed = read_resources(data, result, config.resources)
    if parsed is None:
        snapshot["resources"] = snapshot["version_strings"] = Observation(
            None, "unavailable", ("layout_not_verified",)
        )
        return snapshot
    snapshot["resources"] = Observation(
        [
            dict(
                path=resource_path(r.path),
                offset=r.location.file_offset,
                rva=r.data_rva,
                size=r.data_size,
                codepage=r.codepage,
                reserved=r.reserved,
            )
            for r in parsed.resources
        ],
        "incomplete" if parsed.omissions else "complete",
        tuple(f"{o.base}:{o.relative_offset}:{o.code}" for o in parsed.omissions),
    )
    strings = []
    for version in parsed.versions:
        for value in version.strings:
            block = version.blocks[value.block_index]
            strings.append(
                dict(
                    resource_index=version.resource_index,
                    table_offset=version.blocks[value.table_index].location.file_offset,
                    language=value.language,
                    codepage=value.codepage,
                    key_offset=block.key.location.file_offset,
                    value_offset=value.value.location.file_offset,
                    key_utf8=None if block.key.text is None else block.key.text.encode("utf-8"),
                    value_utf8=None
                    if value.value.text is None
                    else value.value.text.encode("utf-8"),
                )
            )
    snapshot["version_strings"] = Observation(
        strings,
        "complete"
        if parsed.state in ("absent", "complete")
        and all(v.state == "complete" for v in parsed.versions)
        else "incomplete",
        tuple(
            f"resource[{v.resource_index}]:{o.base}:{o.relative_offset}:{o.code}"
            for v in parsed.versions
            for o in v.omissions
        ),
    )
    return snapshot


def reference_directory(pe: Any, index: int) -> tuple[int, int]:
    count = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
    if index >= count:
        return 0, 0
    if index >= len(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
        raise NotComparable("pefile_directory_missing")
    item = pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
    return item.VirtualAddress, item.Size


def reference_sections(pe: Any, data: bytes, config: Config) -> list[dict[str, Any]]:
    sections = sorted(pe.sections, key=lambda s: s.get_file_offset())
    if (
        len(sections) != pe.FILE_HEADER.NumberOfSections
        or len(sections) > config.triage.max_sections
    ):
        raise NotComparable("pefile_sections_missing_or_limit")
    rows = [
        dict(
            header_offset=s.get_file_offset(),
            name_raw=s.Name,
            rva=s.VirtualAddress,
            virtual_size=s.Misc_VirtualSize,
            raw_offset=s.PointerToRawData,
            raw_size=s.SizeOfRawData,
            characteristics=s.Characteristics,
        )
        for s in sections
    ]
    headers = pe.OPTIONAL_HEADER.SizeOfHeaders
    bounded(data, 0, headers)
    for s in rows:
        if s["header_offset"] + 40 > headers or (s["raw_size"] and s["raw_offset"] < headers):
            raise NotComparable("pefile_section_header_overlap")
        if s["raw_size"]:
            bounded(data, s["raw_offset"], s["raw_size"])
    for offset, size in (("raw_offset", "raw_size"), ("rva", "virtual_size")):
        ranges = sorted(
            (
                s[offset],
                s[offset] + (s[size] if size == "raw_size" else max(s[size], s["raw_size"])),
            )
            for s in rows
            if s[size] or (size == "virtual_size" and s["raw_size"])
        )
        if any(a[1] > b[0] for a, b in zip(ranges, ranges[1:], strict=False)):
            raise NotComparable("pefile_section_overlap")
    return rows


def reference_debug(pe: Any, config: Config) -> tuple[list[Any], list[Any]]:
    rva, size = reference_directory(pe, 6)
    if rva == size == 0:
        return [], []
    if not rva or not size or size % 28 or size // 28 > config.triage.max_debug_entries:
        raise NotComparable("pefile_debug_boundary_or_limit")
    entries = pe.parse_debug_directory(rva, size)
    if entries is None or len(entries) != size // 28:
        raise NotComparable("pefile_debug_missing_entries")
    rows, pdbs = [], []
    for index, value in enumerate(entries):
        row = dict(
            index=index,
            offset=value.struct.get_file_offset(),
            **{
                key: getattr(value.struct, name)
                for key, name in zip(DEBUG_KEYS, DEBUG_FIELDS, strict=True)
            },
        )
        rows.append(row)
        if value.struct.Type != 2:
            continue
        cv = value.entry
        if cv is None or getattr(cv, "CvSignature", None) != b"RSDS":
            raise NotComparable("pefile_codeview_not_rsds")
        path = cv.PdbFileName
        stop = path.find(b"\0")
        if stop < 0 or stop > config.triage.max_path_bytes:
            raise NotComparable("pefile_pdb_path_unterminated_or_limit")
        guid = UUID(
            fields=(
                cv.Signature_Data1,
                cv.Signature_Data2,
                cv.Signature_Data3,
                cv.Signature_Data4,
                cv.Signature_Data5,
                int.from_bytes(cv.Signature_Data6, "big"),
            )
        )
        pdbs.append(
            dict(
                debug=row,
                guid_raw=guid.bytes_le,
                guid=str(guid),
                age=cv.Age,
                path_offset=value.struct.PointerToRawData + 24,
                path_raw=path[:stop],
                record_length=24 + stop + 1,
            )
        )
    return rows, pdbs


def reference_resources(pe: Any, config: Config) -> tuple[list[Any], list[Any]]:
    rva, size = reference_directory(pe, 2)
    if rva == size == 0:
        return [], []
    if not rva or not size:
        raise NotComparable("pefile_resource_directory_half_empty")
    root = pe.parse_resources_directory(rva, size)
    if root is None:
        raise NotComparable("pefile_resources_missing")
    tasks = [(root, [], 0)]
    rows, leaves = [], []
    entries = directories = 0
    while tasks:
        directory, path, depth = tasks.pop()
        directories += 1
        declared = directory.struct.NumberOfNamedEntries + directory.struct.NumberOfIdEntries
        if len(directory.entries) != declared:
            raise NotComparable("pefile_resource_entries_omitted")
        if depth > config.resources.depth or directories > config.resources.directories:
            raise NotComparable("reference_resource_directory_limit")
        children = []
        for entry in directory.entries:
            entries += 1
            if entries > config.resources.entries:
                raise NotComparable("reference_resource_entry_limit")
            name = None
            if entry.name is not None:
                length = entry.name.get_pascal_16_length() * 2
                if length > config.resources.name_bytes:
                    raise NotComparable("reference_resource_name_limit")
                name = pe.get_data(entry.name.get_rva() + 2, length)
                if len(name) != length:
                    raise NotComparable("pefile_resource_name_truncated")
            child_path = path + [dict(raw=entry.struct.Name, id=entry.id, name_raw=name)]
            if hasattr(entry, "directory"):
                children.append((entry.directory, child_path, depth + 1))
            else:
                leaf = entry.data.struct
                rows.append(
                    dict(
                        path=child_path,
                        offset=leaf.get_file_offset(),
                        rva=leaf.OffsetToData,
                        size=leaf.Size,
                        codepage=leaf.CodePage,
                        reserved=leaf.Reserved,
                    )
                )
                leaves.append(leaf)
        tasks.extend(reversed(children))
    return rows, leaves


def reference_strings(pe: Any, rows: list[Any], leaves: list[Any], config: Config) -> list[Any]:
    result = []
    for index, (row, leaf) in enumerate(zip(rows, leaves, strict=True)):
        if len(row["path"]) != 3 or row["path"][0]["id"] != 16:
            continue
        if leaf.Size > config.resources.version_bytes:
            raise NotComparable("reference_version_bytes_limit")
        start = len(pe.__structures__)
        before = len(getattr(pe, "FileInfo", []))
        pe.parse_version_information(leaf)
        groups = getattr(pe, "FileInfo", [])[before:]
        if len(groups) != 1:
            raise NotComparable("pefile_version_missing")
        headers = [s for s in pe.__structures__[start:] if s.name == "String"]
        for group in groups[0]:
            for table in getattr(group, "StringTable", []):
                at = table.get_file_offset()
                count = sum(at <= h.get_file_offset() < at + table.Length for h in headers)
                if count != len(table.entries):
                    raise NotComparable("pefile_version_dictionary_loss")
                language = table.LangID.decode("ascii")
                if len(language) != 8:
                    raise NotComparable("pefile_version_language")
                for key, value in table.entries.items():
                    if b"\\u" in key or b"\\u" in value:
                        raise NotComparable("pefile_version_escaped_unicode")
                    key_at, value_at = table.entries_offsets[key]
                    result.append(
                        dict(
                            resource_index=index,
                            table_offset=at,
                            language=int(language[:4], 16),
                            codepage=int(language[4:], 16),
                            key_offset=key_at,
                            value_offset=value_at,
                            key_utf8=key,
                            value_utf8=value,
                        )
                    )
                    if len(result) > config.resources.version_blocks:
                        raise NotComparable("reference_version_strings_limit")
    return result


def structural_tail(
    data: bytes, pe: Any, sections: list[Any], config: Config
) -> tuple[list[Any], list[Any]]:
    start, size = reference_directory(pe, 4)
    headers = pe.OPTIONAL_HEADER.SizeOfHeaders
    tail = max([headers] + [s["raw_offset"] + s["raw_size"] for s in sections if s["raw_size"]])
    certificates = []
    hashed = 0
    if start or size:
        if not start or not size or start % 8 or start < headers:
            raise NotComparable("security_boundary")
        bounded(data, start, size)
        if any(
            s["raw_size"]
            and start < s["raw_offset"] + s["raw_size"]
            and s["raw_offset"] < start + size
            for s in sections
        ):
            raise NotComparable("security_image_overlap")
        cursor = start
        while cursor < start + size:
            if len(certificates) >= config.triage.max_certificates or start + size - cursor < 8:
                raise NotComparable("certificate_count_or_header_limit")
            raw = bounded(data, cursor, 8)
            length, revision, kind = (
                int.from_bytes(raw[a:b], "little") for a, b in ((0, 4), (4, 6), (6, 8))
            )
            advance = ((length + 7) // 8) * 8
            if (
                length < 8
                or cursor + advance > start + size
                or any(bounded(data, cursor + length, advance - length))
            ):
                raise NotComparable("certificate_length_or_padding")
            hashed += length - 8
            if hashed > config.triage.max_hash_bytes:
                raise NotComparable("reference_hash_limit")
            payload = dict(
                offset=cursor + 8,
                length=length - 8,
                sha256=hashlib.sha256(memoryview(data)[cursor + 8 : cursor + length]).hexdigest(),
            )
            certificates.append(
                dict(
                    index=len(certificates),
                    offset=cursor,
                    length=length,
                    revision=revision,
                    certificate_type=kind,
                    payload=payload,
                    padding_length=advance - length,
                )
            )
            cursor += advance
    ranges = [(tail, len(data))]
    if size and start + size > tail:
        ranges = [(tail, max(tail, start)), (start + size, len(data))]
    if hashed + sum(b - a for a, b in ranges) > config.triage.max_hash_bytes:
        raise NotComparable("reference_hash_limit")
    overlay = [
        dict(offset=a, length=b - a, sha256=hashlib.sha256(memoryview(data)[a:b]).hexdigest())
        for a, b in ranges
        if b > a
    ]
    return certificates, overlay


def reference_snapshot(data: bytes, config: Config) -> Snapshot:
    if pefile.__version__ != PEFILE_VERSION:
        raise RuntimeError("pefile_version_not_pinned")
    snapshot: Snapshot = {}
    pe = pefile.PE(data=data, fast_load=True)
    try:

        def collect(keys: tuple[str, ...], operation: Callable[[], tuple[Any, ...]]) -> None:
            before = len(pe.get_warnings())
            try:
                values = operation()
                for key, value in zip(keys, values, strict=True):
                    snapshot[key] = Observation(value)
                if len(pe.get_warnings()) > before:
                    for key in keys:
                        snapshot[key] = Observation(
                            snapshot[key].value, "unavailable", tuple(pe.get_warnings()[before:])
                        )
            except (NotComparable, AttributeError, ValueError, IndexError, TypeError) as error:
                for key in keys:
                    snapshot[key] = Observation(
                        None, "unavailable", (f"{type(error).__name__}:{error}",)
                    )

        collect(
            ("layout",),
            lambda: (
                dict(
                    bits={0x10B: 32, 0x20B: 64}[pe.OPTIONAL_HEADER.Magic],
                    headers=pe.OPTIONAL_HEADER.SizeOfHeaders,
                    image=pe.OPTIONAL_HEADER.SizeOfImage,
                ),
            ),
        )
        collect(("sections",), lambda: (reference_sections(pe, data, config),))
        collect(
            ("directories",), lambda: ({str(i): reference_directory(pe, i) for i in (2, 4, 6)},)
        )
        collect(("debug", "codeview"), lambda: reference_debug(pe, config))
        collect(("resources", "_leaves"), lambda: reference_resources(pe, config))
        if snapshot["resources"].status == "complete":
            collect(
                ("version_strings",),
                lambda: (
                    reference_strings(
                        pe, snapshot["resources"].value, snapshot["_leaves"].value, config
                    ),
                ),
            )
        if snapshot["sections"].status == "complete":
            collect(
                ("certificate_structure", "overlay"),
                lambda: structural_tail(data, pe, snapshot["sections"].value, config),
            )
        security = reference_directory(pe, 4)
        snapshot["certificate_oracle"] = (
            Observation([])
            if security == (0, 0)
            else Observation(None, "unavailable", ("pefile_has_no_certificate_parser",))
        )
        if pe.get_warnings():
            snapshot["layout"] = Observation(
                snapshot["layout"].value,
                "unavailable",
                tuple(pe.get_warnings()),
            )
        return {
            key: snapshot.get(
                key, Observation(None, "unavailable", ("reference_dependency_incomplete",))
            )
            for key in GROUPS
        }
    finally:
        pe.close()


def flatten(value: Any, path: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(value, dict):
        yield path + ".keys", tuple(sorted(value))
        for key, item in sorted(value.items()):
            yield from flatten(item, path + "." + key)
    elif isinstance(value, tuple | list):
        yield path + ".length", len(value)
        for index, item in enumerate(value):
            yield from flatten(item, f"{path}[{index}]")
    else:
        yield path, value


def detail(value: Any, limit: int) -> Any:
    if value is MISSING:
        return {"missing": True}
    if isinstance(value, bytes):
        return dict(
            hex=value[:limit].hex(), size=len(value), sha256=hashlib.sha256(value).hexdigest()
        )
    if isinstance(value, str | tuple):
        text = value if isinstance(value, str) else repr(value)
        raw = text.encode("utf-8")
        return dict(
            text=raw[:limit].decode("utf-8", "replace"),
            bytes=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(),
        )
    return value


def compare(reader: Snapshot, reference: Snapshot, config: Config) -> dict[str, Any]:
    groups = {}
    code = 0
    for key in GROUPS:
        mine = reader.get(key, Observation(None, "unavailable", ("reader_group_missing",)))
        theirs = reference.get(key, Observation(None, "unavailable", ("reference_group_missing",)))
        if mine.status == "complete" and mine.value is None:
            mine = Observation(None, "unavailable", ("reader_value_missing",))
        if theirs.status == "complete" and theirs.value is None:
            theirs = Observation(None, "unavailable", ("reference_value_missing",))
        left = {} if mine.value is None else dict(flatten(mine.value))
        right = {} if theirs.value is None else dict(flatten(theirs.value))
        row: dict[str, Any] = dict(
            reader_status=mine.status,
            reference_status=theirs.status,
            reader_rows=len(mine.value) if isinstance(mine.value, list) else None,
            reference_rows=len(theirs.value) if isinstance(theirs.value, list) else None,
            reader_fields=len(left),
            reference_fields=len(right),
            compared=0,
            differences=0,
            reasons_total=len(mine.reasons) + len(theirs.reasons),
            reasons=[
                detail(s, config.max_detail_bytes)
                for s in (mine.reasons + theirs.reasons)[: config.max_details]
            ],
            fields={},
            details=[],
        )
        if mine.status != "complete" or theirs.status != "complete":
            row["status"] = "failed" if "failed" in (mine.status, theirs.status) else "unavailable"
            code = 1 if row["status"] == "failed" else (2 if code == 0 else code)
        else:
            for path in sorted(left.keys() | right.keys()):
                a, b = left.get(path, MISSING), right.get(path, MISSING)
                column = re.sub(r"\[\d+\]", "[]", path)
                counts = row["fields"].setdefault(column, dict(compared=0, differences=0))
                counts["compared"] += 1
                row["compared"] += 1
                if a != b:
                    row["differences"] += 1
                    counts["differences"] += 1
                    if len(row["details"]) < config.max_details:
                        row["details"].append(
                            dict(
                                field=path,
                                reader=detail(a, config.max_detail_bytes),
                                reference=detail(b, config.max_detail_bytes),
                            )
                        )
            row["status"] = "different" if row["differences"] else "match"
            if row["differences"]:
                code = 1
        row["details_omitted"] = row["differences"] - len(row["details"])
        row["reasons_omitted"] = row["reasons_total"] - len(row["reasons"])
        groups[key] = row
    return dict(
        exit_code=code,
        groups=groups,
        compared=sum(r["compared"] for r in groups.values()),
        differences=sum(r["differences"] for r in groups.values()),
    )


def evaluate(
    data: bytes,
    config: Config,
    *,
    reader: Callable[[bytes, Config], Snapshot] = reader_snapshot,
    reference: Callable[[bytes, Config], Snapshot] = reference_snapshot,
) -> dict[str, Any]:
    if len(data) > config.triage.max_input_bytes:
        return dict(
            exit_code=2,
            reason="input_bytes_limit",
            sha256=None,
            sha256_reason="input_not_read_completely",
            compared=0,
            differences=0,
        )
    snapshots = []
    for operation in (reader, reference):
        try:
            snapshots.append(operation(data, config))
        except Exception as error:
            snapshots.append(
                {key: Observation(None, "failed", (type(error).__name__,)) for key in GROUPS}
            )
    result = compare(*snapshots, config)
    return dict(result, sha256=hashlib.sha256(data).hexdigest())


def provenance(config: Config, selected: list[Path]) -> dict[str, Any]:
    files = [str(p.resolve()) for p in selected]
    sources = {
        "triage": triage.__file__,
        "resources": resources.__file__,
        "reference": pefile.__file__,
        "evaluator": __file__,
    }
    return dict(
        type="config",
        configuration=asdict(config),
        budgets_measured=False,
        files=files,
        selection_sha256=hashlib.sha256(json.dumps(files, ensure_ascii=True).encode()).hexdigest(),
        fingerprints={
            key: dict(path=str(path), sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest())
            for key, path in sources.items()
        },
        dependencies=dict(
            pefile=pefile.__version__,
            python=platform.python_version(),
            implementation=platform.python_implementation(),
        ),
        sources=SOURCES,
        scope=SCOPE,
    )


def run(selected: list[Path], output: Path, config: Config) -> int:
    if not selected or output.resolve() in [p.resolve() for p in selected]:
        raise ValueError("explicit inputs and a distinct new output are required")
    counts: Counter[int] = Counter()
    compared = differences = 0
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(provenance(config, selected), ensure_ascii=True) + "\n")
        for index, path in enumerate(selected):
            try:
                if not path.is_file():
                    raise OSError("not_a_regular_file")
                size = path.stat().st_size
                if size > config.triage.max_input_bytes:
                    result = dict(
                        exit_code=2,
                        sha256=None,
                        sha256_reason="input_not_read",
                        reason="input_bytes_limit",
                        compared=0,
                        differences=0,
                    )
                else:
                    with path.open("rb") as source:
                        data = source.read(config.triage.max_input_bytes + 1)
                    result = evaluate(data, config)
            except OSError as error:
                size = None
                result = dict(
                    exit_code=1, sha256=None, reason=type(error).__name__, compared=0, differences=0
                )
            counts[result["exit_code"]] += 1
            compared += result["compared"]
            differences += result["differences"]
            stream.write(
                json.dumps(
                    dict(type="file", index=index, path=str(path.resolve()), size=size, **result),
                    ensure_ascii=True,
                )
                + "\n"
            )
            stream.flush()
        code = 1 if counts[1] else (2 if counts[2] or not compared else 0)
        stream.write(
            json.dumps(
                dict(
                    type="summary",
                    exit_code=code,
                    files=len(selected),
                    statuses=dict(counts),
                    compared=compared,
                    differences=differences,
                )
            )
            + "\n"
        )
    return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare explicitly selected benign files; no execution or crawling."
    )
    parser.add_argument("--files", nargs="+", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    for prefix, model in (("triage", triage.Budgets), ("resource", resources.Limits)):
        for field in fields(model):
            parser.add_argument(
                f"--{prefix}-{field.name.replace('_', '-')}", type=int, required=True
            )
    parser.add_argument("--max-details", type=int, required=True)
    parser.add_argument("--max-detail-bytes", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        config = Config(
            triage.Budgets(
                **{f.name: getattr(args, "triage_" + f.name) for f in fields(triage.Budgets)}
            ),
            resources.Limits(
                **{f.name: getattr(args, "resource_" + f.name) for f in fields(resources.Limits)}
            ),
            args.max_details,
            args.max_detail_bytes,
        )
        if pefile.__version__ != PEFILE_VERSION:
            raise ValueError("pefile_version_not_pinned")
        return run(args.files, args.output, config)
    except (OSError, ValueError) as error:
        print(f"triage_eval: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
