"""Checks of triage facts: the report alone proves that they do not overlap each other
or the sections; the sample, read again with the same bounded readers, proves each one."""

from collections.abc import Sequence

from lupabin.evidence import pe_triage, triage
from lupabin.evidence.facts import (
    CertificateEvidence,
    Evidence,
    HeaderData,
    OverlayEvidence,
    PdbEvidence,
    SectionData,
    VersionStringEvidence,
)

TriageFact = PdbEvidence | CertificateEvidence | OverlayEvidence | VersionStringEvidence


def _span(fact: TriageFact) -> tuple[int, int]:
    start = fact.location.offset or 0
    return start, start + (fact.location.length or 0)


def validate_triage(
    evidence: Sequence[Evidence], sections: Sequence[SectionData], header: HeaderData | None
) -> None:
    """Raise unless the certificate entries follow each other, the overlay lies after
    every section and outside the certificates, and nothing is published twice."""
    pdbs = [fact for fact in evidence if isinstance(fact, PdbEvidence)]
    certificates = [fact for fact in evidence if isinstance(fact, CertificateEvidence)]
    overlays = [fact for fact in evidence if isinstance(fact, OverlayEvidence)]
    strings = [fact for fact in evidence if isinstance(fact, VersionStringEvidence)]
    if not (pdbs or certificates or overlays or strings):
        return
    if len({fact.data.debug_index for fact in pdbs}) != len(pdbs):
        raise ValueError("a debug entry is published once")
    if len({fact.location.offset for fact in strings}) != len(strings):
        raise ValueError("a version string is published once")
    tail = max(
        [header.size_of_headers if header is not None else 0]
        + [s.raw_offset + s.raw_size for s in sections if s.raw_status == "present"]
    )
    if [fact.data.index for fact in certificates] != list(range(len(certificates))):
        raise ValueError("certificate entries are published in table order")
    end = tail
    padded = []
    for entry in certificates:
        start, stop = _span(entry)
        if start < end:
            raise ValueError("a certificate entry follows the sections and the previous entry")
        end = stop + entry.data.padding
        padded.append((start, end))
    end = tail
    for span in overlays:
        start, stop = _span(span)
        if start < end:
            raise ValueError("the overlay follows every section and its previous part")
        if any(start < last and first < stop for first, last in padded):
            raise ValueError("the overlay excludes the certificate table")
        end = stop


def verify_triage(evidence: Sequence[Evidence], data: bytes, characters: int) -> None:
    """Raise unless reading the sample again finds every published triage fact."""
    pdbs = [fact for fact in evidence if isinstance(fact, PdbEvidence)]
    certificates = [fact for fact in evidence if isinstance(fact, CertificateEvidence)]
    overlays = [fact for fact in evidence if isinstance(fact, OverlayEvidence)]
    strings = [fact for fact in evidence if isinstance(fact, VersionStringEvidence)]
    if not (pdbs or certificates or overlays or strings):
        return
    result = pe_triage.read(data, budgets=triage.BUDGETS)
    if result.layout is None:
        raise ValueError("triage facts need a layout the reader accepts")
    records = {
        item.debug.index: (
            item.debug.pointer_to_raw_data,
            data[
                item.debug.pointer_to_raw_data : item.debug.pointer_to_raw_data + item.record_length
            ],
        )
        for item in result.codeview.items
    }
    for pdb in pdbs:
        expected = (pdb.location.offset, bytes.fromhex(pdb.data.raw_hex))
        if records.get(pdb.data.debug_index) != expected:
            raise ValueError("no debug entry points to this PDB record")
    if certificates and result.certificates.status != "complete":
        raise ValueError("the certificate table cannot be walked to its end")
    entries = {
        item.index: (
            item.offset,
            data[item.offset : item.offset + 8].hex(),
            item.payload.sha256,
            item.padding_length,
        )
        for item in result.certificates.items
    }
    for entry in certificates:
        published = (
            entry.location.offset,
            entry.data.header_hex,
            entry.data.content_sha256,
            entry.data.padding,
        )
        if entries.get(entry.data.index) != published:
            raise ValueError("certificate entry differs from the sample's table")
    spans = {(item.offset, item.length, item.sha256) for item in result.overlay.items}
    for span in overlays:
        if (span.location.offset, span.location.length, span.data.sha256) not in spans:
            raise ValueError("overlay differs from the bytes after the sections")
    if strings:
        parsed = triage.read_resources(data, result)
        texts = (
            {}
            if parsed is None
            else {
                text.offset: (text.raw, text.language, text.codepage)
                for text in triage.version_texts(data, parsed, characters).found
            }
        )
        for string in strings:
            published_text = (
                bytes.fromhex(string.data.raw_hex),
                string.data.language,
                string.data.codepage,
            )
            if texts.get(string.location.offset or 0) != published_text:
                raise ValueError("version string differs from the sample's version resource")
