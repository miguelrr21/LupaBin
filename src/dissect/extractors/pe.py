import struct
from dataclasses import dataclass
from typing import Literal

import pefile

from dissect.evidence.models import (
    Coverage,
    ErrorCode,
    ExtractorError,
    ImportData,
    Limits,
    Location,
    Name,
    Run,
)
from dissect.extractors.base import Extraction, Finding


class InvalidPE(ValueError):
    pass


class InvalidTable(ValueError):
    pass


class ImportLimit(ValueError):
    pass


@dataclass(frozen=True)
class Region:
    rva: int
    offset: int
    size: int
    name: bytes = b""


@dataclass(frozen=True)
class Layout:
    data: bytes
    bits: int
    imagebase: int
    regions: tuple[Region, ...]
    directories: tuple[tuple[int, int], ...]
    warning: bool

    def locate(self, rva: int, size: int) -> tuple[int, Region]:
        matches = [
            region
            for region in self.regions
            if region.rva <= rva and rva + size <= region.rva + region.size
        ]
        if len(matches) != 1 or rva < 0:
            raise InvalidTable
        region = matches[0]
        offset = region.offset + rva - region.rva
        if offset + size > len(self.data):
            raise InvalidTable
        return offset, region

    def string(self, rva: int) -> bytes:
        offset, region = self.locate(rva, 1)
        end = self.data.find(b"\0", offset, min(offset + 4097, region.offset + region.size))
        if end <= offset:
            raise InvalidTable
        return self.data[offset:end]


def layout_of(data: bytes) -> Layout:
    if len(data) < 64 or data[:2] != b"MZ":
        raise InvalidPE
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    if nt < 64 or nt + 26 > len(data) or data[nt : nt + 4] != b"PE\0\0":
        raise InvalidPE
    sections = struct.unpack_from("<H", data, nt + 6)[0]
    optional_size = struct.unpack_from("<H", data, nt + 20)[0]
    optional = nt + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in (0x10B, 0x20B) or not 1 <= sections <= 96:
        raise InvalidPE
    fixed = 96 if magic == 0x10B else 112
    if optional_size < fixed or optional + optional_size + sections * 40 > len(data):
        raise InvalidPE
    count = struct.unpack_from("<I", data, optional + fixed - 4)[0]
    if count > 16 or fixed + count * 8 > optional_size:
        raise InvalidPE
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError:
        raise InvalidPE from None
    try:
        headers = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
        if not optional + optional_size + sections * 40 <= headers <= len(data):
            raise InvalidPE
        if len(pe.sections) != sections:
            raise InvalidPE
        regions = [Region(0, 0, headers)]
        for section in pe.sections:
            offset, size = int(section.PointerToRawData), int(section.SizeOfRawData)
            rva = int(section.VirtualAddress)
            if size:
                if offset < headers or offset + size > len(data):
                    raise InvalidPE
                if rva < headers or rva + size > int(pe.OPTIONAL_HEADER.SizeOfImage):
                    raise InvalidPE
                for other in regions:
                    if max(other.rva, rva) < min(other.rva + other.size, rva + size):
                        raise InvalidPE
                    if max(other.offset, offset) < min(other.offset + other.size, offset + size):
                        raise InvalidPE
                regions.append(Region(rva, offset, size, bytes(section.Name).rstrip(b"\0")))
        directories = tuple(
            struct.unpack_from("<II", data, optional + fixed + index * 8) for index in range(count)
        )
        return Layout(
            data,
            32 if magic == 0x10B else 64,
            int(pe.OPTIONAL_HEADER.ImageBase),
            tuple(regions),
            directories,
            bool(pe.get_warnings()),
        )
    finally:
        pe.close()


def read_table(
    layout: Layout, table: Literal["normal", "delay"], findings: list[Finding], limits: Limits
) -> None:
    index = 1 if table == "normal" else 13
    if index >= len(layout.directories):
        return
    rva, size = layout.directories[index]
    if rva == size == 0:
        return
    descriptor_size = 20 if table == "normal" else 32
    if not rva or size < descriptor_size:
        raise InvalidTable
    offset, _ = layout.locate(rva, size)
    width = layout.bits // 8
    for number in range(min(size // descriptor_size, 4096)):
        descriptor = offset + number * descriptor_size
        values = struct.unpack_from("<5I" if table == "normal" else "<8I", layout.data, descriptor)
        if not any(values):
            return
        if table == "normal":
            lookup, timestamp, _, name_rva, iat = values
            if not lookup and timestamp:
                raise InvalidTable
            thunk_rva = lookup or iat
            virtual = False
        else:
            attrs, name_rva, _, iat, thunk_rva, _, _, _ = values
            if attrs not in (0, 1):
                raise InvalidTable
            virtual = attrs == 0
            if virtual:
                name_rva -= layout.imagebase
                thunk_rva -= layout.imagebase
                iat -= layout.imagebase
        if not thunk_rva or not iat or not name_rva:
            raise InvalidTable
        layout.locate(iat, width)
        dll = Name.from_bytes(layout.string(name_rva))
        for entry in range(limits.imports + 1):
            address = thunk_rva + entry * width
            pointer, region = layout.locate(address, width)
            value = int.from_bytes(layout.data[pointer : pointer + width], "little")
            if value == 0:
                break
            if len(findings) >= limits.imports:
                raise ImportLimit
            ordinal = None
            function = None
            flag = 1 << (layout.bits - 1)
            if value & flag:
                if value & ~(flag | 0xFFFF):
                    raise InvalidTable
                ordinal = value & 0xFFFF
            else:
                value -= layout.imagebase if virtual else 0
                layout.locate(value, 2)
                function = Name.from_bytes(layout.string(value + 2))
            findings.append(
                Finding(
                    "pe",
                    ImportData(dll=dll, function=function, ordinal=ordinal, table=table),
                    Location(
                        offset=pointer,
                        rva=address,
                        length=width,
                        section=Name.from_bytes(region.name) if region.name else None,
                    ),
                )
            )
        else:
            raise ImportLimit
    raise InvalidTable


class PEExtractor:
    source = "pe"
    version = str(pefile.__version__)

    def extract(self, data: bytes, limits: Limits) -> Extraction:
        try:
            layout = layout_of(data)
        except InvalidPE:
            code: ErrorCode = "invalid_pe" if data.startswith(b"MZ") else "unsupported_format"
            return Extraction(
                "unknown",
                (),
                Run(source=self.source, version=self.version, status="failed"),
                (ExtractorError(source=self.source, code=code),),
            )
        findings: list[Finding] = []
        codes: list[ErrorCode] = ["parser_warning"] if layout.warning else []
        coverage: dict[str, Coverage] = {}
        for table in ("normal", "delay"):
            try:
                read_table(layout, table, findings, limits)
                coverage[table] = "complete"
            except (InvalidTable, ImportLimit) as exc:
                codes.append(
                    "import_limit" if isinstance(exc, ImportLimit) else "invalid_import_table"
                )
                coverage[table] = "partial"
        status: Literal["completed", "partial", "failed"] = (
            "completed" if not codes else "partial" if findings else "failed"
        )
        return Extraction(
            "PE32" if layout.bits == 32 else "PE32+",
            tuple(findings),
            Run(
                source=self.source,
                version=self.version,
                status=status,
                normal=coverage["normal"],
                delay=coverage["delay"],
            ),
            tuple(ExtractorError(source=self.source, code=code) for code in dict.fromkeys(codes)),
        )
