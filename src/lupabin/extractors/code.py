import bisect
from collections.abc import Callable

from lupabin.evidence import argument_forms
from lupabin.evidence.api_catalog import Encoding, Function, Parameter, hkey_name, lookup
from lupabin.evidence.collector import Collector, Progress
from lupabin.evidence.facts import (
    ApiCallData,
    ArgumentString,
    CallArgumentData,
    CodeFunctionData,
    ExportEvidence,
    ImportEvidence,
    Instruction,
)
from lupabin.evidence.models import ErrorCode
from lupabin.evidence.primitives import Component, Source
from lupabin.extractors.base import Extraction
from lupabin.extractors.code_args import ArgumentFinder, Budget, Found
from lupabin.extractors.code_calls import Call, CallFinder
from lupabin.extractors.code_disasm import Region, Targets, walk
from lupabin.extractors.code_entries import FunctionRanges, entries, regions
from lupabin.extractors.pe_layout import InvalidPE, InvalidTable, Layout, parse_layout

_ARCHITECTURES = {(32, 0x14C), (64, 0x8664)}


class CodeExtractor:
    """Which imported functions the code calls, from where, and with which constant
    arguments for the functions of the catalog (design sections 3.1-3.4)."""

    source: Source = "code"
    version = "lupabin-code-v1"

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
        seconds = min(limits.seconds, collector.limits.timeout_seconds / 2)
        deadline = collector.started + seconds
        result = walk(
            code,
            starts,
            layout.bits,
            limits.instructions,
            finder.visit,
            limits.call_sites,
            deadline,
        )
        progress.examined["disassembly"] = result.instructions
        progress.examined["api_calls"] = result.calls
        if truncated:
            progress.issue("disassembly", "code_entry_limit", limit=True)
            progress.issue("api_calls", "code_entry_limit", limit=True)
        if result.limit:
            progress.issue("disassembly", "code_instruction_limit", limit=True)
            progress.issue("api_calls", "code_instruction_limit", limit=True)
        if result.time_limit:
            progress.issue("disassembly", "code_time_limit", limit=True)
            progress.issue("api_calls", "code_time_limit", limit=True)
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
        catalog = {
            fact.data.iat_rva: entry
            for fact in collector.facts
            if isinstance(fact, ImportEvidence)
            and fact.data.function is not None
            and (
                entry := lookup(
                    bytes.fromhex(fact.data.dll.raw_hex),
                    bytes.fromhex(fact.data.function.raw_hex),
                )
            )
            is not None
        }
        if not _functions(layout, finder.calls(), catalog, limits.entries, collector, progress):
            return Extraction("unknown", progress)
        progress.complete("api_calls")
        _arguments(
            layout, code, result.targets, catalog, finder.calls(), collector, progress, deadline
        )
        return Extraction("unknown", progress)


def _functions(
    layout: Layout,
    calls: list[Call],
    catalog: dict[int, Function],
    max_functions: int,
    collector: Collector,
    progress: Progress,
) -> bool:
    """Publish the x64 `.pdata` entry that holds each published call to a catalog
    function, once (design section 11 of Phase 5). False if the collector refused one."""
    ranges = FunctionRanges(layout, max_functions)
    for call in calls:
        if call.slot not in catalog or f"code:call:{call.rva}" not in collector.ids:
            continue
        entry = ranges.holding(call.rva)
        if entry is None or f"code:function:{entry[0]}" in collector.ids:
            continue
        begin, end, unwind, rva = entry
        raw = layout.data[layout.locate(rva, 12)[0] :][:12]
        if not collector.add(
            f"code:function:{begin}",
            progress,
            "api_calls",
            CodeFunctionData(begin=begin, end=end, unwind=unwind, raw_hex=raw.hex()),
            layout.location(rva, 12),
        ):
            return False
    return True


def _arguments(
    layout: Layout,
    code: list[Region],
    targets: Targets,
    catalog: dict[int, Function],
    calls: list[Call],
    collector: Collector,
    progress: Progress,
    deadline: float,
) -> None:
    """Publishes the constant arguments of every published call to a catalog function."""
    if progress.states["api_calls"] != "complete":
        # the arguments of calls that were not walked or published cannot be cited
        progress.issue("call_arguments", "dependency_omitted", limit=True)
    budget = Budget(collector.limits.code.argument_instructions, deadline)
    finder = ArgumentFinder(code, targets, layout.bits, budget)
    for call in calls:
        entry = catalog.get(call.slot)
        if entry is None:
            continue
        found = finder.constants(call.start, call.rva)
        if found is None:
            reason: ErrorCode = (
                "argument_instruction_limit" if budget.exhausted else "code_time_limit"
            )
            progress.issue("call_arguments", reason, limit=True)
            return
        progress.examined["call_arguments"] += 1
        for parameter in entry.parameters:
            known = found.get(parameter.position)
            if known is None:
                continue  # no canonical constant sets it in the stretch
            rva, size = known.setter
            try:
                data = _argument(
                    parameter, entry, known, layout, collector.limits.string_characters
                )
                location = layout.location(rva, size)
            except InvalidTable:
                continue  # the setter's bytes do not map to one place in the file
            if data is None:
                continue  # not of the parameter's type
            if not collector.add(
                f"code:argument:{call.rva}:{parameter.position}",
                progress,
                "call_arguments",
                data,
                location,
                refs=(f"code:call:{call.rva}",),
            ):
                return  # the collector recorded why
    progress.complete("call_arguments")


def _argument(
    parameter: Parameter, entry: Function, found: Found, layout: Layout, characters: int
) -> CallArgumentData | None:
    """The argument as its parameter's type reads it, or None if it is not of that type."""
    setting = found.setting
    rva, size = found.setter
    offset, _ = layout.locate(rva, size)
    if parameter.bits is None and found.width != 8:
        return None  # a pointer needs the whole stack slot
    source = None
    if found.source is not None:
        start, length = found.source
        at, _ = layout.locate(start, length)
        source = Instruction(offset=at, rva=start, raw_hex=layout.data[at : at + length].hex())
    value = setting.value
    constant: str | None = None
    string: ArgumentString | None = None
    if parameter.type == "hkey":
        constant = hkey_name(setting.value, layout.bits)
        if constant is None:
            return None
    elif parameter.type == "integer":
        if setting.kind != "immediate" or parameter.bits is None:
            return None
        value = setting.value % (1 << parameter.bits)
    else:
        target = argument_forms.address_of(setting, layout.bits, layout.header.image_base)
        string = None if target is None else _string(layout, target, entry.encoding, characters)
        if string is None:
            return None
    return CallArgumentData(
        method="stack-slot-v1" if found.method == "stack-slot-v1" else "block-constant-v1",
        source=source,
        position=parameter.position,
        name=parameter.name,
        type=parameter.type,
        value=value,
        raw_hex=layout.data[offset : offset + size].hex(),
        constant=constant,
        string=string,
    )


def _string(layout: Layout, rva: int, encoding: Encoding, characters: int) -> ArgumentString | None:
    """The printable NUL-terminated string at `rva`, when the one section that holds it
    on disk is not writable: a writable one may no longer hold it when the call runs."""
    unit = 1 if encoding == "ascii" else 2
    holders = [
        item.data
        for item in layout.sections
        if item.data.raw_status == "present"
        and item.data.rva <= rva < item.data.rva + item.data.raw_size
    ]
    if len(holders) != 1 or "write" in holders[0].permissions:
        return None
    section = holders[0]
    offset = section.raw_offset + rva - section.rva
    end = min(section.raw_offset + section.raw_size, offset + (characters + 1) * unit)
    raw = layout.data[offset:end]
    stop = next(
        (i for i in range(0, len(raw) - unit + 1, unit) if raw[i : i + unit] == bytes(unit)),
        None,
    )
    if stop is None:
        return None  # no terminator within the section or the character limit
    try:
        text = raw[:stop].decode(encoding)
    except UnicodeDecodeError:
        return None
    if not text or len(text) > characters:
        return None
    if any(not 32 <= ord(char) <= 126 for char in text):
        return None
    return ArgumentString(offset=offset, rva=rva, raw_hex=raw[: stop + unit].hex(), text=text)


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
