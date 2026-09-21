import pefile

from dissect.evidence.collector import Collector, Progress
from dissect.evidence.primitives import Component, Source
from dissect.extractors.base import Extraction
from dissect.extractors.pe_checks import read_checks
from dissect.extractors.pe_exports import read_exports
from dissect.extractors.pe_imports import read_imports
from dissect.extractors.pe_layout import InvalidPE, InvalidTable, parse_layout
from dissect.extractors.pe_sections import read_sections


class PEExtractor:
    source: Source = "pe"
    version = str(pefile.__version__)

    def extract(self, data: bytes, collector: Collector, progress: Progress) -> Extraction:
        try:
            layout = parse_layout(data, collector.limits)
        except InvalidPE:
            progress.block_remaining(
                "invalid_pe" if data.startswith(b"MZ") else "unsupported_format"
            )
            return Extraction("unknown", progress)
        progress.examined["headers"] = 1
        collector.add("pe:header", progress, "headers", layout.header, layout.header_location)
        if layout.warning:
            progress.issue("headers", "parser_warning", limit=True)
        progress.complete("headers")
        read_sections(layout, collector, progress)
        for table in ("normal", "delay"):
            component: Component = "imports_normal" if table == "normal" else "imports_delay"
            if not layout.safe:
                progress.issue(component, "unsafe_mapping", blocked=True)
                continue
            try:
                read_imports(layout, table, collector, progress)
            except InvalidTable:
                progress.issue(component, "invalid_import_table")
        if layout.safe:
            try:
                read_exports(layout, collector, progress)
            except InvalidTable:
                progress.issue("exports", "invalid_export_table")
        else:
            progress.issue("exports", "unsafe_mapping", blocked=True)
        read_checks(layout, collector, progress)
        return Extraction("PE32" if layout.bits == 32 else "PE32+", progress)
