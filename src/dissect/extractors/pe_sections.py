import math
from collections import Counter

from dissect.evidence.collector import Collector, Progress
from dissect.evidence.facts import EntropyData
from dissect.evidence.primitives import Location
from dissect.extractors.pe_layout import Layout


def entropy(data: bytes) -> float:
    if not data:
        raise ValueError("entropy requires nonempty bytes")
    counts = Counter(data)
    size = len(data)
    value = -math.fsum(
        (counts[byte] / size) * math.log2(counts[byte] / size) for byte in sorted(counts)
    )
    return max(0.0, round(value, 6))


def read_sections(layout: Layout, collector: Collector, progress: Progress) -> None:
    used = 0
    for section in layout.sections:
        data = section.data
        progress.examined["sections"] += 1
        collector.add(section.key, progress, "sections", data, section.location)
        if data.raw_status == "empty":
            continue
        if data.raw_status != "present":
            progress.issue("entropy", "invalid_section_table")
            continue
        if used + data.raw_size > collector.limits.entropy_bytes:
            progress.issue("entropy", "entropy_limit", limit=True)
            continue
        if section.key not in collector.ids:
            progress.issue("entropy", "dependency_omitted", limit=True)
            continue
        used += data.raw_size
        progress.examined["entropy"] = used
        value = entropy(layout.data[data.raw_offset : data.raw_offset + data.raw_size])
        collector.add(
            f"pe:entropy:{data.index}",
            progress,
            "entropy",
            EntropyData(byte_count=data.raw_size, bits_per_byte=value),
            Location(offset=data.raw_offset, length=data.raw_size),
            (section.key,),
        )
    if not layout.section_complete:
        limited = layout.header.number_of_sections > collector.limits.sections
        for part in ("sections", "entropy"):
            progress.issue(
                part, "section_limit" if limited else "invalid_section_table", limit=limited
            )
    progress.complete("sections")
    progress.complete("entropy")
