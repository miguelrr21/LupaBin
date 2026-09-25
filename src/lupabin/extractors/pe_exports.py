import struct
from typing import Literal

from lupabin.evidence.collector import Collector, Progress
from lupabin.evidence.facts import ExportData
from lupabin.evidence.primitives import Location, Name
from lupabin.extractors.pe_layout import InvalidTable, Layout


def read_exports(layout: Layout, collector: Collector, progress: Progress) -> None:
    if not layout.directories or layout.directories[0] == (0, 0):
        progress.complete("exports")
        return
    rva, size = layout.directories[0]
    if not rva or size < 40 or rva + size > 0x100000000:
        raise InvalidTable
    offset, _ = layout.locate(rva, 40)
    _, _, _, _, _, base, entries, names_count, eat, names_rva, ordinals = struct.unpack_from(
        "<IIHHIIIIIII", layout.data, offset
    )
    names: dict[int, list[Name]] = {}
    names_status: Literal["complete", "incomplete"] = "complete"
    name_bytes = 0
    for index in range(min(names_count, collector.limits.export_names)):
        try:
            pointer, _ = layout.locate(names_rva + index * 4, 4)
            ordinal_pointer, _ = layout.locate(ordinals + index * 2, 2)
            name_rva = struct.unpack_from("<I", layout.data, pointer)[0]
            eat_index = struct.unpack_from("<H", layout.data, ordinal_pointer)[0]
            if eat_index >= entries:
                raise InvalidTable
            name = Name.from_bytes(layout.string(name_rva))
            name_bytes += len(name.model_dump_json().encode("utf-8"))
            if name_bytes > collector.limits.evidence_bytes // 2:
                names_status = "incomplete"
                progress.issue("exports", "evidence_budget", limit=True)
                break
            names.setdefault(eat_index, []).append(name)
        except InvalidTable:
            names_status = "incomplete"
            progress.issue("exports", "invalid_export_table")
            break
    if names_count > collector.limits.export_names:
        names_status = "incomplete"
        progress.issue("exports", "export_name_limit", limit=True)
    if entries > collector.limits.exports:
        progress.issue("exports", "export_limit", limit=True)
    for index in range(min(entries, collector.limits.exports)):
        pointer, _ = layout.locate(eat + index * 4, 4)
        value = struct.unpack_from("<I", layout.data, pointer)[0]
        progress.examined["exports"] += 1
        if value == 0:
            if index in names:
                progress.issue("exports", "invalid_export_table")
            continue
        if base + index > 0xFFFFFFFF:
            raise InvalidTable
        forwarder = None
        target_kind: Literal["declared_rva", "forwarder", "unreadable_forwarder"] = "declared_rva"
        if rva <= value < rva + size:
            try:
                forwarder = Name.from_bytes(layout.string(value, rva + size))
                target_kind = "forwarder"
            except InvalidTable:
                target_kind = "unreadable_forwarder"
                progress.issue("exports", "invalid_export_table")
        if not collector.add(
            f"pe:export:{index}",
            progress,
            "exports",
            ExportData(
                eat_index=index,
                ordinal=base + index,
                names=tuple(names.get(index, ())),
                names_status=names_status,
                target_rva=value,
                forwarder=forwarder,
                target_kind=target_kind,
            ),
            Location(offset=pointer, length=4, rva=eat + index * 4),
        ):
            return
    progress.complete("exports")
