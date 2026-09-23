"""Executable regions and the known entry points the code walk starts from."""

import struct
from collections.abc import Iterable

from dissect.extractors.code_disasm import Region
from dissect.extractors.pe_layout import InvalidTable, Layout

_TLS = 9
_EXCEPTION = 3
_TLS_CALLBACKS = 64
_RUNTIME_FUNCTION = 12


def regions(layout: Layout) -> list[Region]:
    """Sections marked executable, with their bytes on disk (the report's mapping)."""
    return [
        Region(
            s.data.rva,
            bytearray(layout.data[s.data.raw_offset : s.data.raw_offset + s.data.raw_size]),
        )
        for s in layout.sections
        if "execute" in s.data.permissions and s.data.raw_status == "present"
    ]


def entries(layout: Layout, exports: Iterable[int], max_functions: int) -> list[int]:
    """Entry point, exported code, TLS callbacks and, in x64, `.pdata` function starts.

    Unreadable TLS or exception tables add no entries; they never invent any.
    """
    found = [layout.header.entry_point_rva] if layout.header.entry_point_rva else []
    found += exports
    found += _tls_callbacks(layout)
    if layout.bits == 64:
        found += _function_starts(layout, max_functions)
    return list(dict.fromkeys(found))


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
