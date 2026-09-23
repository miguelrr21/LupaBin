"""Checks of code evidence: the report alone proves the arithmetic, the sample the bytes.

A call is re-derived from the bytes it cites with the same canonical forms the worker
used (call_forms.py): no disassembler runs outside the isolated worker. What neither
check can prove is that the worker walked to that instruction; that is a rule of the
walk, tested with negative cases.
"""

from collections.abc import Sequence

from dissect.evidence import call_forms
from dissect.evidence.facts import (
    ApiCallEvidence,
    Evidence,
    HeaderData,
    ImportEvidence,
    SectionData,
)
from dissect.evidence.primitives import Name


def _mapped(rva: int, offset: int, size: int, sections: Sequence[SectionData]) -> SectionData:
    """The one executable section whose bytes on disk hold [rva, rva + size) at `offset`."""
    holders = [
        s
        for s in sections
        if s.raw_status == "present" and s.rva <= rva and rva + size <= s.rva + s.raw_size
    ]
    if len(holders) != 1 or "execute" not in holders[0].permissions:
        raise ValueError("code evidence must lie in exactly one executable section")
    if offset != holders[0].raw_offset + rva - holders[0].rva:
        raise ValueError("code evidence offset disagrees with its section mapping")
    return holders[0]


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
    section = _mapped(where.rva, where.offset, where.length, sections)
    raw_name = bytes.fromhex(section.name_raw_hex).rstrip(b"\0")
    if where.section != (Name.from_bytes(raw_name) if raw_name else None):
        raise ValueError("call section name disagrees with its mapping")
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


def verify_calls(evidence: Sequence[Evidence], data: bytes) -> None:
    """Raise unless every call's instruction bytes are the sample's bytes at their offsets."""
    for fact in evidence:
        if not isinstance(fact, ApiCallEvidence):
            continue
        spans = [(fact.location.offset, fact.data.raw_hex)]
        if fact.data.helper is not None:
            spans.append((fact.data.helper.offset, fact.data.helper.raw_hex))
        for offset, raw_hex in spans:
            raw = bytes.fromhex(raw_hex)
            if offset is None or data[offset : offset + len(raw)] != raw:
                raise ValueError("call bytes differ from the sample")
