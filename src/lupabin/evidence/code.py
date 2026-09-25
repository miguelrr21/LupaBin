"""Checks of code evidence: the report alone proves the arithmetic, the sample the bytes.

A call is re-derived from the bytes it cites with the same canonical forms the worker
used (call_forms.py), and an argument's value from the bytes of the instruction that
sets it (argument_forms.py): no disassembler runs outside the isolated worker. What
neither check can prove is that the worker walked to that instruction, or that no
instruction between the setter and the call changes the value; those are rules of
the walk, tested with negative cases, and the reason arguments are `inferred`.
"""

from collections.abc import Sequence

from lupabin.evidence import api_catalog, argument_forms, call_forms
from lupabin.evidence.facts import (
    ApiCallEvidence,
    ArgumentString,
    CallArgumentEvidence,
    CodeFunctionEvidence,
    Evidence,
    HeaderData,
    ImportEvidence,
    SectionData,
)
from lupabin.evidence.primitives import Location, Name


def _holder(rva: int, offset: int, size: int, sections: Sequence[SectionData]) -> SectionData:
    """The one section whose bytes on disk hold [rva, rva + size) at `offset`."""
    holders = [
        s
        for s in sections
        if s.raw_status == "present" and s.rva <= rva and rva + size <= s.rva + s.raw_size
    ]
    if len(holders) != 1:
        raise ValueError("code evidence must lie in exactly one section")
    if offset != holders[0].raw_offset + rva - holders[0].rva:
        raise ValueError("code evidence offset disagrees with its section mapping")
    return holders[0]


def _mapped(rva: int, offset: int, size: int, sections: Sequence[SectionData]) -> SectionData:
    """The one executable section whose bytes on disk hold [rva, rva + size) at `offset`."""
    section = _holder(rva, offset, size, sections)
    if "execute" not in section.permissions:
        raise ValueError("code evidence must lie in exactly one executable section")
    return section


def _named(where: Location, section: SectionData) -> None:
    raw_name = bytes.fromhex(section.name_raw_hex).rstrip(b"\0")
    if where.section != (Name.from_bytes(raw_name) if raw_name else None):
        raise ValueError("code evidence section name disagrees with its mapping")


def validate_call(
    fact: ApiCallEvidence,
    cited: Evidence | None,
    sections: Sequence[SectionData],
    header: HeaderData | None,
) -> None:
    """Raise unless the cited import's slot follows from the call's own bytes."""
    if not isinstance(cited, ImportEvidence):
        raise ValueError("a call must cite an import")
    if header is None:
        raise ValueError("a call needs the PE header for its image base")
    where, data = fact.location, fact.data
    if where.offset is None or where.rva is None or where.length is None:
        raise ValueError("a call must locate its instruction in the file and the image")
    _named(where, _mapped(where.rva, where.offset, where.length, sections))
    bits = 32 if header.optional_magic == 267 else 64
    base = header.image_base
    raw = bytes.fromhex(data.raw_hex)
    helper = data.helper
    if helper is not None:
        _mapped(helper.rva, helper.offset, len(helper.raw_hex) // 2, sections)
        helper_raw = bytes.fromhex(helper.raw_hex)
    slot: int | None = None
    if data.via == "direct":
        slot = call_forms.memory_slot(raw, where.rva, bits, base, call_forms.CALL)
    elif data.via == "thunk" and helper is not None:
        if call_forms.relative_target(raw, where.rva) == helper.rva:
            slot = call_forms.memory_slot(helper_raw, helper.rva, bits, base, call_forms.JMP)
    elif data.via == "register" and helper is not None:
        load = call_forms.register_load(helper_raw, helper.rva, bits, base)
        if load is not None and call_forms.register_call(raw, bits) == load[0]:
            slot = load[1]
    if slot is None or slot != cited.data.iat_rva:
        raise ValueError("call bytes do not reach the slot of the cited import")


def validate_argument(
    fact: CallArgumentEvidence,
    call: Evidence | None,
    callee: Evidence | None,
    sections: Sequence[SectionData],
    header: HeaderData | None,
    characters: int,
) -> None:
    """Raise unless the argument's value and type follow from the bytes it cites."""
    if not isinstance(call, ApiCallEvidence):
        raise ValueError("an argument must cite a call")
    if not isinstance(callee, ImportEvidence) or callee.data.function is None:
        raise ValueError("an argument's call must reach an import by name")
    entry = api_catalog.lookup(
        bytes.fromhex(callee.data.dll.raw_hex), bytes.fromhex(callee.data.function.raw_hex)
    )
    data = fact.data
    parameter = (
        None
        if entry is None
        else next((p for p in entry.parameters if p.position == data.position), None)
    )
    if entry is None or parameter is None:
        raise ValueError("an argument must be a parameter the catalog interprets")
    if (parameter.name, parameter.type) != (data.name, data.type):
        raise ValueError("argument name or type disagrees with the catalog")
    if header is None:
        raise ValueError("an argument needs the PE header")
    where, at = fact.location, call.location
    if where.offset is None or where.rva is None or where.length is None:
        raise ValueError("an argument must locate the instruction that sets it")
    if at.offset is None or at.rva is None or at.length is None:
        raise ValueError("a call must locate its instruction in the file and the image")
    section = _mapped(where.rva, where.offset, where.length, sections)
    _named(where, section)
    if (
        where.rva + where.length > at.rva
        or _holder(at.rva, at.offset, at.length, sections) != section
    ):
        raise ValueError("an argument must be set before its call, in the same section")
    bits = 32 if header.optional_magic == 267 else 64
    raw = bytes.fromhex(data.raw_hex)
    setting: argument_forms.Setting | None
    if data.method == "stack-slot-v1":
        setting = _stack_setting(fact, raw, section, sections, bits, parameter)
    elif bits == 64:
        setting = argument_forms.x64_setting(raw, where.rva)
        if setting is not None and setting.target != data.position:
            setting = None
    else:
        setting = argument_forms.x86_push(raw)
    if setting is None:
        raise ValueError("argument bytes are not a canonical setting of that parameter")
    if data.type == "hkey":
        key = api_catalog.hkey_name(setting.value, bits)
        if key is None or data.value != setting.value or data.constant != key:
            raise ValueError("a key argument must be the predefined key its bytes set")
    elif data.type == "integer":
        if setting.kind != "immediate" or parameter.bits is None:
            raise ValueError("an integer argument must be an immediate")
        if data.value != setting.value % (1 << parameter.bits):
            raise ValueError("integer argument disagrees with its bytes")
    else:
        string = data.string
        target = argument_forms.address_of(setting, bits, header.image_base)
        if string is None or data.value != setting.value or target != string.rva:
            raise ValueError("a string argument must point to its string")
        _validate_string(string, entry.encoding, sections, characters)


def _stack_setting(
    fact: CallArgumentEvidence,
    raw: bytes,
    section: SectionData,
    sections: Sequence[SectionData],
    bits: int,
    parameter: api_catalog.Parameter,
) -> argument_forms.Setting | None:
    """The value an x64 stack store puts in its slot (design section 11), or None."""
    data, where = fact.data, fact.location
    store = argument_forms.x64_stack_store(raw) if bits == 64 else None
    if store is None or store.position != data.position or where.rva is None:
        return None
    if parameter.bits is None and store.width != 8:
        return None  # a pointer needs the whole slot
    if store.value is not None:
        if data.source is not None:
            return None
        return argument_forms.Setting(store.position, "immediate", store.value)
    source = data.source
    if source is None:
        return None
    size = len(source.raw_hex) // 2
    if _mapped(source.rva, source.offset, size, sections) != section:
        raise ValueError("a register an argument copies must be set in the same section")
    if source.rva + size > where.rva:
        raise ValueError("a register must be set before the store that copies it")
    found = argument_forms.x64_register(bytes.fromhex(source.raw_hex), source.rva)
    if found is None or found[0] != store.register:
        return None
    kind, value = found[1].kind, found[1].value
    if store.width == 4:
        if kind == "address":
            return None  # the low half of an address is not the address
        value &= 0xFFFFFFFF
    return argument_forms.Setting(store.position, kind, value)


def _validate_string(
    string: ArgumentString,
    encoding: api_catalog.Encoding,
    sections: Sequence[SectionData],
    characters: int,
) -> None:
    raw = bytes.fromhex(string.raw_hex)
    holder = _holder(string.rva, string.offset, len(raw), sections)
    if "write" in holder.permissions:
        # the program could change a writable string before the call
        raise ValueError("an argument string must lie in a section that is not writable")
    terminator = b"\0" if encoding == "ascii" else b"\0\0"
    if string.text.encode(encoding) + terminator != raw:
        raise ValueError("argument string differs from its bytes")
    if len(string.text) > characters:
        raise ValueError("argument string exceeds character limit")


def validate_function(
    fact: CodeFunctionEvidence,
    calls: Sequence[ApiCallEvidence],
    sections: Sequence[SectionData],
    header: HeaderData | None,
) -> None:
    """Raise unless a published function range is an x64 entry that holds a published
    call. The report cannot prove that the entry lies in the exception directory (it
    does not carry the data directories); the host compares its bytes with the sample."""
    if header is None or header.optional_magic != 523:
        raise ValueError("function ranges come from x64 .pdata")
    where = fact.location
    if where.offset is None or where.rva is None or where.length is None:
        raise ValueError("a function range must locate its entry")
    _named(where, _holder(where.rva, where.offset, where.length, sections))
    begin, end = fact.data.begin, fact.data.end
    if not any(begin <= (call.location.rva or 0) < end for call in calls):
        raise ValueError("a function range is published only for a call it holds")


def verify_calls(evidence: Sequence[Evidence], data: bytes) -> None:
    """Raise unless the bytes every call, argument and function range cite are the
    sample's bytes at their offsets."""
    for fact in evidence:
        if isinstance(fact, CodeFunctionEvidence):
            spans = [(fact.location.offset, fact.data.raw_hex)]
        elif isinstance(fact, ApiCallEvidence):
            spans = [(fact.location.offset, fact.data.raw_hex)]
            if fact.data.helper is not None:
                spans.append((fact.data.helper.offset, fact.data.helper.raw_hex))
        elif isinstance(fact, CallArgumentEvidence):
            spans = [(fact.location.offset, fact.data.raw_hex)]
            if fact.data.source is not None:
                spans.append((fact.data.source.offset, fact.data.source.raw_hex))
            if fact.data.string is not None:
                spans.append((fact.data.string.offset, fact.data.string.raw_hex))
        else:
            continue
        for offset, raw_hex in spans:
            raw = bytes.fromhex(raw_hex)
            if offset is None or data[offset : offset + len(raw)] != raw:
                raise ValueError("code evidence bytes differ from the sample")
