import bisect
from collections.abc import Callable

from dissect.evidence.collector import Collector, Progress
from dissect.evidence.facts import ApiCallData, ExportEvidence, ImportEvidence, Instruction
from dissect.evidence.primitives import Component, Source
from dissect.extractors.base import Extraction
from dissect.extractors.code_calls import Call, CallFinder
from dissect.extractors.code_disasm import Region, walk
from dissect.extractors.code_entries import entries, regions
from dissect.extractors.pe_layout import InvalidPE, Layout, parse_layout

_ARCHITECTURES = {(32, 0x14C), (64, 0x8664)}


class CodeExtractor:
    """Which imported functions the code calls, and from where (design sections 3.1-3.3)."""

    source: Source = "code"
    version = "dissect-code-v1"

    def extract(self, data: bytes, collector: Collector, progress: Progress) -> Extraction:
        try:
            layout = parse_layout(data, collector.limits)
        except InvalidPE:
            progress.block_remaining(
                "invalid_pe" if data.startswith(b"MZ") else "unsupported_format"
            )
            return Extraction("unknown", progress)
        if (layout.bits, layout.header.machine) not in _ARCHITECTURES:
            progress.block_remaining("unsupported_architecture")
            return Extraction("unknown", progress)
        if not layout.safe:
            progress.block_remaining("unsafe_mapping")
            return Extraction("unknown", progress)
        limits = collector.limits.code
        code = regions(layout)
        exported = [
            fact.data.target_rva
            for fact in collector.facts
            if isinstance(fact, ExportEvidence) and fact.data.target_kind == "declared_rva"
        ]
        starts, truncated = entries(layout, exported, limits.entries)
        keys = {public: key for key, public in collector.ids.items()}
        slots = {
            fact.data.iat_rva: keys[fact.id]
            for fact in collector.facts
            if isinstance(fact, ImportEvidence)
        }
        finder = CallFinder(
            _reader(code), layout.bits, layout.header.image_base, slots, limits.calls
        )
        result = walk(
            code, starts, layout.bits, limits.instructions, finder.visit, limits.call_sites
        )
        progress.examined["disassembly"] = result.instructions
        progress.examined["api_calls"] = result.calls
        if truncated:
            progress.issue("disassembly", "code_entry_limit", limit=True)
            progress.issue("api_calls", "code_entry_limit", limit=True)
        if result.limit:
            progress.issue("disassembly", "code_instruction_limit", limit=True)
            progress.issue("api_calls", "code_instruction_limit", limit=True)
        if result.call_limit:
            progress.issue("disassembly", "call_site_limit", limit=True)
            progress.issue("api_calls", "call_site_limit", limit=True)
        progress.complete("disassembly")
        tables: tuple[Component, ...] = ("imports_normal", "imports_delay")
        if any(collector.coverage.get(("pe", table)) != "complete" for table in tables):
            # calls through imports that were not published cannot be cited
            progress.issue("api_calls", "dependency_omitted", limit=True)
        if finder.dropped:
            progress.issue("api_calls", "api_call_limit", limit=True)
        for call in finder.calls():
            if not collector.add(
                f"code:call:{call.rva}",
                progress,
                "api_calls",
                _data(call, layout),
                layout.location(call.rva, call.size),
                refs=(slots[call.slot],),
            ):
                return Extraction("unknown", progress)  # the collector recorded why
        progress.complete("api_calls")
        return Extraction("unknown", progress)


def _reader(code: list[Region]) -> Callable[[int, int], bytes | None]:
    ordered = sorted(code, key=lambda region: region.rva)
    starts = [region.rva for region in ordered]
    ends = [region.end for region in ordered]

    def read(rva: int, size: int) -> bytes | None:
        index = bisect.bisect_right(starts, rva) - 1
        if index < 0 or rva + size > ends[index]:
            return None
        start = rva - starts[index]
        return bytes(ordered[index].data[start : start + size])

    return read


def _data(call: Call, layout: Layout) -> ApiCallData:
    offset, _ = layout.locate(call.rva, call.size)
    helper = None
    if call.helper is not None:
        rva, size = call.helper
        start, _ = layout.locate(rva, size)
        helper = Instruction(offset=start, rva=rva, raw_hex=layout.data[start : start + size].hex())
    return ApiCallData(
        via=call.via,
        raw_hex=layout.data[offset : offset + call.size].hex(),
        helper=helper,
    )
