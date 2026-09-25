"""Executable regions and the known entry points the code walk starts from."""

import bisect
import struct
from array import array
from collections.abc import Iterable

from lupabin.extractors.code_disasm import Region
from lupabin.extractors.pe_layout import InvalidTable, Layout

_TLS = 9
_EXCEPTION = 3
_BASERELOC = 5
_HIGHLOW, _DIR64 = 3, 10  # base relocation types (winnt.h)
# Twice the most measured on 2026-09-25 in 6,444 benign binaries (532,810, edgehtml.dll
# x86); an image declaring more gets no relocated fields.
_MAX_RELOCATIONS = 1 << 20
_LOAD_CONFIG = 10
# IMAGE_LOAD_CONFIG_DIRECTORY offsets (winnt.h): SEHandlerTable/Count (x86 only) and
# GuardCFFunctionTable/Count/GuardFlags, for 32 and 64 bits.
_SEH = {32: (0x40, 0x44)}
_GUARD = {32: (0x50, 0x54, 0x58), 64: (0x80, 0x88, 0x90)}
_GUARD_TABLE_PRESENT = 0x400
_GUARD_STRIDE_SHIFT = 28
# Where the walk may start, all written by the compiler or linker, none guessed.
SOURCES = frozenset({"tls", "pdata", "guard", "seh"})
_TLS_CALLBACKS = 64
_RUNTIME_FUNCTION = 12


def regions(layout: Layout) -> list[Region]:
    """Sections marked executable, with their bytes on disk (the report's mapping) and
    the relocated fields that lie in them."""
    found = relocations(layout)
    width = 4 if layout.bits == 32 else 8
    result = []
    for s in layout.sections:
        if "execute" not in s.data.permissions or s.data.raw_status != "present":
            continue
        start, size = s.data.rva, s.data.raw_size
        fields = None
        if found is not None:
            fields = bytearray(size)
            begin = bisect.bisect_left(found, start - width + 1)
            end = bisect.bisect_left(found, start + size)
            for at in found[begin:end]:
                first, last = max(at - start + 1, 0), min(at - start + width, size)
                if first < last:
                    fields[first:last] = b"" * (last - first)
        data = bytearray(layout.data[s.data.raw_offset : s.data.raw_offset + size])
        result.append(Region(start, data, fields))
    return result


def relocations(layout: Layout) -> array[int] | None:
    """Sorted RVAs of the image's pointer-sized base relocations (HIGHLOW in x86,
    DIR64 in x64), or None when it has none or the table cannot be read whole."""
    rva, size = _directory(layout, _BASERELOC)
    if not rva or size < 8:
        return None
    try:
        offset, _ = layout.locate(rva, size)
    except InvalidTable:
        return None
    kind = _HIGHLOW if layout.bits == 32 else _DIR64
    found = array("I")
    position, stop = offset, offset + size
    while position + 8 <= stop:
        page, block = struct.unpack_from("<II", layout.data, position)
        if block < 8 or block % 2 or position + block > stop:
            return None
        for (item,) in struct.iter_unpack("<H", layout.data[position + 8 : position + block]):
            if item >> 12 == kind:
                found.append(page + (item & 0xFFF))
                if len(found) > _MAX_RELOCATIONS:
                    return None
        position += block
    if not found:
        return None
    if any(a > b for a, b in zip(found, found[1:], strict=False)):
        found = array("I", sorted(found))  # linkers write them in order; rarely needed
    return found


def entries(
    layout: Layout, exports: Iterable[int], limit: int, sources: frozenset[str] = SOURCES
) -> tuple[list[int], bool]:
    """Entry point, exported code and the tables the toolchain writes: TLS callbacks,
    x64 `.pdata` function starts, Control Flow Guard call targets and x86 SafeSEH
    handlers.

    Returns at most `limit` distinct entries and whether any were left out. Unreadable
    tables add no entries; they never invent any.
    """
    found = [layout.header.entry_point_rva] if layout.header.entry_point_rva else []
    found += exports
    if "tls" in sources:
        found += _tls_callbacks(layout)
    if "pdata" in sources and layout.bits == 64:
        found += _function_starts(layout, limit + 1)
    if "guard" in sources:
        found += guard_targets(layout, limit + 1)
    if "seh" in sources:
        found += _safe_handlers(layout, limit + 1)
    unique = list(dict.fromkeys(found))
    return unique[:limit], len(unique) > limit


def _directory(layout: Layout, index: int) -> tuple[int, int]:
    return layout.directories[index] if index < len(layout.directories) else (0, 0)


def _tls_callbacks(layout: Layout) -> list[int]:
    rva, size = _directory(layout, _TLS)
    width = layout.bits // 8
    base = layout.header.image_base
    if not rva or size < 4 * width:
        return []
    try:
        offset, _ = layout.locate(rva, 4 * width)
        pointer = int.from_bytes(layout.data[offset + 3 * width : offset + 4 * width], "little")
        if pointer <= base:
            return []
        found = []
        for index in range(_TLS_CALLBACKS):
            slot, _ = layout.locate(pointer - base + index * width, width)
            value = int.from_bytes(layout.data[slot : slot + width], "little")
            if value == 0:
                break
            if value > base:
                found.append(value - base)
        return found
    except InvalidTable:
        return []


def _function_starts(layout: Layout, max_functions: int) -> list[int]:
    rva, size = _directory(layout, _EXCEPTION)
    count = min(size // _RUNTIME_FUNCTION, max_functions)
    if not rva or not count:
        return []
    try:
        offset, _ = layout.locate(rva, count * _RUNTIME_FUNCTION)
    except InvalidTable:
        return []
    return [
        struct.unpack_from("<I", layout.data, offset + index * _RUNTIME_FUNCTION)[0]
        for index in range(count)
    ]


class FunctionRanges:
    """The x64 `.pdata` entries, to find the one entry that
    holds an address. Learn documents the table as sorted and without overlaps; if two
    entries overlap the table is malformed and no address has an entry (never guessed)."""

    def __init__(self, layout: Layout, max_functions: int):
        self.entries: list[tuple[int, int, int, int]] = []  # begin, end, unwind, entry RVA
        self.overlap = False
        rva, size = _directory(layout, _EXCEPTION)
        count = min(size // _RUNTIME_FUNCTION, max_functions)
        if layout.bits != 64 or not rva or not count:
            return
        try:
            offset, _ = layout.locate(rva, count * _RUNTIME_FUNCTION)
        except InvalidTable:
            return
        for index in range(count):
            begin, end, unwind = struct.unpack_from(
                "<III", layout.data, offset + index * _RUNTIME_FUNCTION
            )
            if begin < end:
                self.entries.append((begin, end, unwind, rva + index * _RUNTIME_FUNCTION))
        self.entries.sort()
        if any(a[1] > b[0] for a, b in zip(self.entries, self.entries[1:], strict=False)):
            self.overlap, self.entries = True, []
        self.begins = [entry[0] for entry in self.entries]

    def holding(self, address: int) -> tuple[int, int, int, int] | None:
        index = bisect.bisect_right(self.begins, address) - 1 if self.entries else -1
        if index < 0 or not self.entries[index][0] <= address < self.entries[index][1]:
            return None
        return self.entries[index]


def _load_config(layout: Layout) -> tuple[int, int] | None:
    """(offset, declared size) of the load configuration directory, if readable."""
    rva, size = _directory(layout, _LOAD_CONFIG)
    if not rva or size < 4:
        return None
    try:
        offset, end = layout.locate(rva, 4)
    except InvalidTable:
        return None
    declared = struct.unpack_from("<I", layout.data, offset)[0]
    return offset, min(declared, end - offset)


def _field(layout: Layout, config: tuple[int, int], at: int, width: int) -> int | None:
    offset, size = config
    if at + width > size:
        return None  # older linkers write a shorter structure
    return int.from_bytes(layout.data[offset + at : offset + at + width], "little")


def _rva_table(layout: Layout, va: int, count: int, stride: int, limit: int) -> list[int]:
    base = layout.header.image_base
    count = min(count, limit)
    if va <= base or not count:
        return []
    try:
        offset, _ = layout.locate(va - base, count * stride)
    except InvalidTable:
        return []
    return [
        struct.unpack_from("<I", layout.data, offset + index * stride)[0] for index in range(count)
    ]


def guard_targets(layout: Layout, limit: int) -> list[int]:
    """Control Flow Guard's table of valid indirect-call targets: function starts."""
    config = _load_config(layout)
    if config is None:
        return []
    width = layout.bits // 8
    table_at, count_at, flags_at = _GUARD[layout.bits]
    table = _field(layout, config, table_at, width)
    count = _field(layout, config, count_at, width)
    flags = _field(layout, config, flags_at, 4)
    if table is None or count is None or flags is None or not flags & _GUARD_TABLE_PRESENT:
        return []
    stride = 4 + (flags >> _GUARD_STRIDE_SHIFT)  # an RVA plus per-entry metadata bytes
    return _rva_table(layout, table, count, stride, limit)


def _safe_handlers(layout: Layout, limit: int) -> list[int]:
    """x86 SafeSEH: the exception handlers the image registers, which are functions."""
    if layout.bits != 32:
        return []
    config = _load_config(layout)
    if config is None:
        return []
    table = _field(layout, config, _SEH[32][0], 4)
    count = _field(layout, config, _SEH[32][1], 4)
    if table is None or count is None:
        return []
    return _rva_table(layout, table, count, 4, limit)
