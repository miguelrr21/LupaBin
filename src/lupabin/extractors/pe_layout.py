import struct
from dataclasses import dataclass
from typing import Literal

import pefile

from lupabin.evidence.facts import HeaderData, SectionData
from lupabin.evidence.primitives import Limits, Location, Name


class InvalidPE(ValueError):
    pass


class InvalidTable(ValueError):
    pass


@dataclass(frozen=True)
class Section:
    data: SectionData
    location: Location

    @property
    def key(self) -> str:
        return f"pe:section:{self.data.index}"


@dataclass(frozen=True)
class Layout:
    data: bytes
    header: HeaderData
    header_location: Location
    sections: tuple[Section, ...]
    directories: tuple[tuple[int, int], ...]
    safe: bool
    section_complete: bool
    warning: bool

    @property
    def bits(self) -> int:
        return 32 if self.header.optional_magic == 267 else 64

    def locate(self, rva: int, size: int) -> tuple[int, int]:
        if not self.safe or rva < 0 or size < 1:
            raise InvalidTable
        regions = [(0, 0, self.header.size_of_headers)] + [
            (s.data.rva, s.data.raw_offset, s.data.raw_size)
            for s in self.sections
            if s.data.raw_status == "present"
        ]
        matches = [
            (offset + rva - base, offset + length)
            for base, offset, length in regions
            if base <= rva and rva + size <= base + length
        ]
        if len(matches) != 1:
            raise InvalidTable
        return matches[0]

    def location(self, rva: int, size: int) -> Location:
        offset, _ = self.locate(rva, size)
        name = None
        for item in self.sections:
            section = item.data
            if section.rva <= rva and rva + size <= section.rva + section.raw_size:
                raw = bytes.fromhex(section.name_raw_hex).rstrip(b"\0")
                name = Name.from_bytes(raw) if raw else None
                break
        return Location(offset=offset, rva=rva, length=size, section=name)

    def string(self, rva: int, end_rva: int | None = None) -> bytes:
        offset, end = self.locate(rva, 1)
        if end_rva is not None:
            end = min(end, offset + end_rva - rva)
        stop = self.data.find(b"\0", offset, min(end, offset + 4097))
        if stop <= offset:
            raise InvalidTable
        return self.data[offset:stop]


def overlap(a: int, size_a: int, b: int, size_b: int) -> bool:
    return size_a > 0 and size_b > 0 and max(a, b) < min(a + size_a, b + size_b)


def parse_layout(data: bytes, limits: Limits) -> Layout:
    if len(data) < 64 or data[:2] != b"MZ":
        raise InvalidPE
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    if nt < 64 or nt + 26 > len(data) or data[nt : nt + 4] != b"PE\0\0":
        raise InvalidPE
    machine, count, stamp, _, _, optional_size, flags = struct.unpack_from("<HHIIIHH", data, nt + 4)
    optional = nt + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    fixed = 96 if magic == 267 else 112
    if magic not in (267, 523) or count < 1 or optional_size < fixed:
        raise InvalidPE
    if optional + optional_size > len(data):
        raise InvalidPE
    directory_count = struct.unpack_from("<I", data, optional + fixed - 4)[0]
    if directory_count > 16 or fixed + 8 * directory_count > optional_size:
        raise InvalidPE
    imagebase = struct.unpack_from(
        "<I" if magic == 267 else "<Q", data, optional + (28 if magic == 267 else 24)
    )[0]
    entry = struct.unpack_from("<I", data, optional + 16)[0]
    alignment, file_alignment = struct.unpack_from("<II", data, optional + 32)
    image_size, header_size = struct.unpack_from("<II", data, optional + 56)
    if not optional + optional_size <= header_size <= len(data):
        raise InvalidPE
    header = HeaderData(
        machine=machine,
        number_of_sections=count,
        timestamp_raw=stamp,
        characteristics=flags,
        optional_magic=magic,
        image_base=imagebase,
        entry_point_rva=entry,
        section_alignment=alignment,
        file_alignment=file_alignment,
        size_of_image=image_size,
        size_of_headers=header_size,
    )
    section_start = optional + optional_size
    available = min(count, limits.sections, (len(data) - section_start) // 40)
    permission_bits: tuple[tuple[int, Literal["read", "write", "execute"]], ...] = (
        (0x40000000, "read"),
        (0x80000000, "write"),
        (0x20000000, "execute"),
    )
    sections = []
    for index in range(available):
        offset = section_start + index * 40
        raw_name = data[offset : offset + 8]
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        try:
            name = raw_name.rstrip(b"\0").decode("utf-8")
        except UnicodeDecodeError:
            name = None
        section = SectionData(
            index=index,
            name_raw_hex=raw_name.hex(),
            name_text=name,
            rva=rva,
            virtual_size=virtual_size,
            raw_offset=raw_offset,
            raw_size=raw_size,
            characteristics=characteristics,
            raw_status="empty"
            if raw_size == 0
            else ("present" if raw_offset + raw_size <= len(data) else "out_of_bounds"),
            permissions=tuple(label for flag, label in permission_bits if characteristics & flag),
        )
        sections.append(Section(section, Location(offset=offset, length=40)))
    safe = available == count and section_start + count * 40 <= header_size
    for index, item in enumerate(sections):
        s = item.data
        if s.raw_size and (
            s.raw_status != "present"
            or s.raw_offset < header_size
            or s.rva < header_size
            or s.rva + max(s.virtual_size, s.raw_size) > image_size
        ):
            safe = False
        for previous in sections[:index]:
            p = previous.data
            if overlap(s.raw_offset, s.raw_size, p.raw_offset, p.raw_size) or overlap(
                s.rva, max(s.virtual_size, s.raw_size), p.rva, max(p.virtual_size, p.raw_size)
            ):
                safe = False
    warning = False
    if count <= limits.sections:
        try:
            pe = pefile.PE(data=data, fast_load=True)
            try:
                warning = bool(pe.get_warnings())
            finally:
                pe.close()
        except pefile.PEFormatError:
            warning = True
    directories = tuple(
        struct.unpack_from("<II", data, optional + fixed + i * 8) for i in range(directory_count)
    )
    return Layout(
        data,
        header,
        Location(offset=nt, length=24 + optional_size),
        tuple(sections),
        directories,
        safe,
        available == count,
        warning,
    )
