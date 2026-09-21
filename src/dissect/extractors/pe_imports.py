import struct
from typing import Literal

from dissect.evidence.collector import Collector, Progress
from dissect.evidence.facts import ImportData
from dissect.evidence.primitives import Component, Name
from dissect.extractors.pe_layout import InvalidTable, Layout


def read_imports(
    layout: Layout, table: Literal["normal", "delay"], collector: Collector, progress: Progress
) -> None:
    component: Component = "imports_normal" if table == "normal" else "imports_delay"
    index = 1 if table == "normal" else 13
    if index >= len(layout.directories) or layout.directories[index] == (0, 0):
        progress.complete(component)
        return
    rva, size = layout.directories[index]
    descriptor_size = 20 if table == "normal" else 32
    if not rva or size < descriptor_size:
        raise InvalidTable
    offset, _ = layout.locate(rva, size)
    width = layout.bits // 8
    count = min(size // descriptor_size, collector.limits.import_descriptors)
    for number in range(count):
        values = struct.unpack_from(
            "<5I" if table == "normal" else "<8I", layout.data, offset + number * descriptor_size
        )
        if not any(values):
            progress.complete(component)
            return
        if table == "normal":
            lookup, stamp, _, name_rva, iat = values
            if not lookup and stamp:
                raise InvalidTable
            thunk_rva, virtual = lookup or iat, False
        else:
            attrs, name_rva, _, iat, thunk_rva, _, _, _ = values
            if attrs not in (0, 1):
                raise InvalidTable
            virtual = attrs == 0
            if virtual:
                name_rva -= layout.header.image_base
                thunk_rva -= layout.header.image_base
                iat -= layout.header.image_base
        if min(thunk_rva, iat, name_rva) <= 0:
            raise InvalidTable
        dll = Name.from_bytes(layout.string(name_rva))
        for entry in range(collector.limits.imports + 1):
            layout.locate(iat + entry * width, width)
            address = thunk_rva + entry * width
            pointer, _ = layout.locate(address, width)
            value = int.from_bytes(layout.data[pointer : pointer + width], "little")
            if value == 0:
                break
            progress.examined[component] += 1
            if collector.counts["import"] >= collector.limits.imports:
                progress.issue(component, "import_limit", limit=True)
                return
            ordinal = None
            function = None
            flag = 1 << (layout.bits - 1)
            if value & flag:
                if value & ~(flag | 65535):
                    raise InvalidTable
                ordinal = value & 65535
            else:
                value -= layout.header.image_base if virtual else 0
                layout.locate(value, 2)
                function = Name.from_bytes(layout.string(value + 2))
            if not collector.add(
                f"pe:import:{table}:{number}:{entry}",
                progress,
                component,
                ImportData(dll=dll, function=function, ordinal=ordinal, table=table),
                layout.location(address, width),
            ):
                return
        else:
            progress.issue(component, "import_limit", limit=True)
            return
    if size // descriptor_size > count:
        progress.issue(component, "descriptor_limit", limit=True)
        return
    raise InvalidTable
