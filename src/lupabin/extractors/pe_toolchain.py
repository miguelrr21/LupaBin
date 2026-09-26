"""Toolchain markers of the catalog lupabin-toolchains-v1 (evidence/toolchain.py).

Each marker is looked for only where its tool puts it, and only its exact form is
published: a candidate that fails any check is left out, not guessed at.
"""

from collections.abc import Iterator

from lupabin.evidence import toolchain
from lupabin.evidence.collector import Collector, Progress
from lupabin.evidence.facts import SectionData, ToolchainData
from lupabin.evidence.primitives import Location
from lupabin.extractors.pe_layout import InvalidTable, Layout


def _section_at(offset: int, size: int, sections: list[SectionData]) -> SectionData | None:
    for section in sections:
        if section.raw_offset <= offset and offset + size <= section.raw_offset + section.raw_size:
            return section
    return None


def _occurrences(data: bytes, needle: bytes, start: int = 0) -> Iterator[int]:
    at = data.find(needle, start)
    while at >= 0:
        yield at
        at = data.find(needle, at + 1)


def read_toolchain(layout: Layout, collector: Collector, progress: Progress) -> None:
    if not layout.safe:
        progress.issue("toolchain", "unsafe_mapping", blocked=True)
        return
    data = layout.data
    sections = [s.data for s in layout.sections if s.data.raw_status == "present"]
    progress.examined["toolchain"] = len(toolchain.MARKERS)

    def emit(key: str, marker: toolchain.Marker, raw: bytes, location: Location) -> bool:
        payload = ToolchainData(
            marker=marker, raw_hex=raw.hex(), text=toolchain.marker_text(marker, raw)
        )
        return collector.add(f"pe:toolchain:{key}", progress, "toolchain", payload, location)

    def mapped(offset: int, size: int) -> Location | None:
        section = _section_at(offset, size, sections)
        if section is None:
            return None
        try:
            return layout.location(section.rva + offset - section.raw_offset, size)
        except InvalidTable:
            return None

    rich = toolchain.find_rich(data)
    if rich is not None:
        offset, raw = rich
        if not emit("rich", "rich_header", raw, Location(offset=offset, length=len(raw))):
            return

    idents: list[str] = []
    for at in _occurrences(data, toolchain.GCC):
        end = data.find(b"\0", at, at + toolchain.GCC_MAX + 1)
        if end < 0 or _section_at(at, end + 1 - at, sections) is None:
            continue
        raw = data[at : end + 1]
        try:
            text = toolchain.marker_text("gcc_ident", raw)
        except ValueError:
            continue
        if text in idents:
            continue
        if len(idents) == toolchain.GCC_IDENTS:
            progress.issue("toolchain", "toolchain_limit", limit=True)
            break
        idents.append(text or "")
        if not emit(f"gcc:{at}", "gcc_ident", raw, Location(offset=at, length=len(raw))):
            return

    size = len(toolchain.MINGW_W64)
    for at in _occurrences(data, toolchain.MINGW_W64):
        if _section_at(at, size, sections) is not None:
            if not emit(
                "mingw", "mingw_w64_runtime", toolchain.MINGW_W64, Location(offset=at, length=size)
            ):
                return
            break

    for at in _occurrences(data, toolchain.GO):
        header = toolchain.read_go(data, at)
        where = None if header is None else mapped(at, len(header))
        if header is None or where is None or (where.rva or 0) % toolchain.GO_ALIGN:
            continue
        if not emit("go", "go_buildinfo", header, where):
            return
        break

    directory = (
        layout.directories[toolchain.CLR_DIRECTORY]
        if len(layout.directories) > toolchain.CLR_DIRECTORY
        else (0, 0)
    )
    if directory[0] and directory[1] >= toolchain.CLR_SIZE:
        try:
            offset, _ = layout.locate(directory[0], 8)
            where = layout.location(directory[0], 8)
            raw = data[offset : offset + 8]
            toolchain.marker_text("clr_header", raw)
        except (InvalidTable, ValueError):
            where = None
        if where is not None and not emit("clr", "clr_header", raw, where):
            return

    end = max((s.raw_offset + s.raw_size for s in sections), default=0)
    cookie = toolchain.PYINSTALLER_COOKIE.size
    for at in reversed(list(_occurrences(data, toolchain.PYINSTALLER, end))):
        raw = data[at : at + cookie]
        try:
            archive = toolchain.pyinstaller_fields(raw)[0]
        except ValueError:
            continue
        if at + cookie - archive < end:
            continue
        if not emit("pyinstaller", "pyinstaller_cookie", raw, Location(offset=at, length=cookie)):
            return
        break
    progress.complete("toolchain")
