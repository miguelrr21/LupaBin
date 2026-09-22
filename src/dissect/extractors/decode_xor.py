from collections.abc import Callable
from typing import Literal

from dissect.evidence.facts import DecodedStringData, DecodedStringEvidence, StringEvidence
from dissect.evidence.primitives import Provenance, Transform
from dissect.extractors.strings import ascii_runs, utf16_runs

Encoding = Literal["ascii", "utf-16-le"]


def full_coverage_encoding(data: bytes) -> Encoding | None:
    length = len(data)
    if any(start == 0 and end == length for start, _, end in ascii_runs(data)):
        return "ascii"
    # alignment=1 can never start at offset 0, so only alignment 0 can cover the
    # whole buffer; checking it alone is sufficient for full coverage.
    if any(start == 0 and end == length for start, _, end in utf16_runs(data, 0)):
        return "utf-16-le"
    return None


def single_byte_xor_candidates(data: bytes) -> list[tuple[bytes, Encoding]]:
    results: list[tuple[bytes, Encoding]] = []
    for key in range(1, 256):
        decoded = bytes(byte ^ key for byte in data)
        encoding = full_coverage_encoding(decoded)
        if encoding is not None:
            results.append((bytes([key]), encoding))
    return results


def _evidence(
    source: StringEvidence,
    evidence_id: str,
    key: bytes,
    encoding: Encoding,
    decoded: bytes,
) -> DecodedStringEvidence:
    text = decoded.decode(encoding)
    return DecodedStringEvidence(
        id=evidence_id,
        location=source.location,
        provenance=Provenance(evidence_ids=(source.id,)),
        transform=Transform(name="xor-repeating-v1", key_hex=key.hex()),
        data=DecodedStringData(
            encoding=encoding,
            text=text,
            raw_hex=decoded.hex(),
            characters=len(text),
            complete=True,
            total_characters=len(text),
        ),
    )


def candidates(source: StringEvidence, next_id: Callable[[], str]) -> list[DecodedStringEvidence]:
    if not source.data.complete:
        return []
    raw = bytes.fromhex(source.data.raw_hex)
    results = []
    for key, encoding in single_byte_xor_candidates(raw):
        decoded = bytes(byte ^ key[0] for byte in raw)
        results.append(_evidence(source, next_id(), key, encoding, decoded))
    return results
