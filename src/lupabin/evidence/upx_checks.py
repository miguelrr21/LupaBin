"""UPX facts from a derivation (evidence/upx.py), built the same way in the worker and
in the host: the host derives everything again from the sample's bytes and its section
table, and rejects a report whose UPX facts differ in anything."""

from collections.abc import Sequence

from lupabin.evidence import upx
from lupabin.evidence.facts import (
    Evidence,
    SectionData,
    SectionEvidence,
    UpxImageData,
    UpxImageEvidence,
    UpxImportData,
    UpxImportEvidence,
    UpxSection,
)
from lupabin.evidence.primitives import Name


def image_data(derived: upx.Derived) -> UpxImageData:
    unpacked = derived.unpacked
    header, tail = unpacked.header, unpacked.tail
    described = tail is not None and derived.dlls is not None
    return UpxImageData(
        header_hex=header.raw.hex(),
        version=header.version,
        format=header.format,
        method=header.method,
        level=header.level,
        packed_offset=unpacked.packed_offset,
        packed_size=header.packed_size,
        packed_adler32=header.packed_adler32,
        unpacked_size=header.unpacked_size,
        unpacked_adler32=header.unpacked_adler32,
        unpacked_sha256=unpacked.unpacked_sha256,
        original_size=header.original_size,
        original_entry_rva=tail.entry_rva if described and tail else None,
        original_image_base=tail.image_base if described and tail else None,
        original_sections=(
            tuple(
                UpxSection(
                    name_raw_hex=s.name.hex(),
                    name_text=upx.section_text(s.name),
                    rva=s.rva,
                    virtual_size=s.virtual_size,
                )
                for s in tail.sections
            )
            if described and tail
            else None
        ),
        imports=len(tail.imports) if described and tail else None,
    )


def import_data(derived: upx.Derived) -> list[UpxImportData]:
    tail, dlls = derived.unpacked.tail, derived.dlls
    if tail is None or dlls is None:
        return []
    return [
        UpxImportData(
            dll=Name.from_bytes(dll),
            dll_rva=item.dll_rva,
            function=None if item.function is None else Name.from_bytes(item.function),
            ordinal=item.ordinal,
            iat_rva=item.iat_rva,
            stream_offset=item.stream_offset,
            stream_length=item.stream_length,
        )
        for dll, item in zip(dlls, tail.imports, strict=True)
    ]


def spans(sections: Sequence[SectionData]) -> list[upx.Span]:
    return [
        upx.Span(s.rva, s.virtual_size, s.raw_offset, s.raw_size)
        for s in sorted(sections, key=lambda section: section.index)
        if s.raw_status != "out_of_bounds"
    ]


def verify_upx(evidence: Sequence[Evidence], data: bytes) -> None:
    """Raise unless the report's UPX facts are exactly what the sample's bytes give: the
    same block and, in order, a prefix of its import list (a prefix when the quota or the
    evidence budget cut it)."""
    images = [fact for fact in evidence if isinstance(fact, UpxImageEvidence)]
    imports = [fact.data for fact in evidence if isinstance(fact, UpxImportEvidence)]
    if not images:
        if imports:
            raise ValueError("UPX imports without their block")
        return
    sections = [fact.data for fact in evidence if isinstance(fact, SectionEvidence)]
    derived = upx.derive(data, spans(sections))
    if derived is None:
        raise ValueError("the sample has no UPX block that verifies")
    image = images[0]
    if image.data != image_data(derived) or image.location.offset != derived.unpacked.header.offset:
        raise ValueError("the UPX block differs from what the sample gives")
    expected = import_data(derived)
    if imports != expected[: len(imports)]:
        raise ValueError("the UPX import list differs from what the sample gives")
