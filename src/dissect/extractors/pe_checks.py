from dissect.evidence.collector import Collector, Progress
from dissect.evidence.facts import AnomalyCode, AnomalyData
from dissect.evidence.primitives import Location
from dissect.extractors.pe_layout import Layout, overlap


def read_checks(layout: Layout, collector: Collector, progress: Progress) -> None:
    def emit(
        code: AnomalyCode, indices: tuple[int, ...], location: Location, refs: tuple[str, ...]
    ) -> bool:
        progress.examined["anomalies"] += 1
        return collector.add(
            f"pe:anomaly:{code}:{indices}",
            progress,
            "anomalies",
            AnomalyData(code=code, section_indices=indices),
            location,
            refs,
        )

    for index, section in enumerate(layout.sections):
        s = section.data
        if s.raw_status == "out_of_bounds":
            if not emit("section_raw_out_of_bounds", (s.index,), section.location, (section.key,)):
                return
        if s.rva + max(s.virtual_size, s.raw_size) > layout.header.size_of_image:
            if not emit(
                "section_exceeds_image", (s.index,), section.location, (section.key, "pe:header")
            ):
                return
        for previous in layout.sections[:index]:
            p = previous.data
            checks: tuple[tuple[AnomalyCode, bool], ...] = (
                (
                    "section_raw_overlap",
                    overlap(s.raw_offset, s.raw_size, p.raw_offset, p.raw_size),
                ),
                (
                    "section_virtual_overlap",
                    overlap(
                        s.rva,
                        max(s.virtual_size, s.raw_size),
                        p.rva,
                        max(p.virtual_size, p.raw_size),
                    ),
                ),
            )
            for code, present in checks:
                if present and not emit(
                    code, (p.index, s.index), section.location, (previous.key, section.key)
                ):
                    return
    header = layout.header
    if header.entry_point_rva and header.entry_point_rva >= header.size_of_image:
        if not emit("entry_point_outside_image", (), layout.header_location, ("pe:header",)):
            return
    if not layout.section_complete:
        progress.issue("anomalies", "invalid_section_table")
    progress.complete("anomalies")
