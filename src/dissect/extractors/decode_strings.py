import base64
import binascii
import re
from collections.abc import Callable

from dissect.evidence.facts import DecodedStringData, DecodedStringEvidence, StringEvidence
from dissect.evidence.primitives import Provenance, Transform

_BASE64_RE = re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
_HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2})+$")


def _printable(data: bytes) -> bool:
    return len(data) >= 4 and all(0x20 <= byte <= 0x7E for byte in data)


def base64_candidate(text: str) -> bytes | None:
    if len(text) < 8 or len(text) % 4 != 0 or not _BASE64_RE.match(text):
        return None
    try:
        decoded = base64.b64decode(text, validate=True)
    except binascii.Error:
        return None
    if base64.b64encode(decoded).decode("ascii") != text:
        return None
    return decoded if _printable(decoded) else None


def hex_candidate(text: str) -> bytes | None:
    if len(text) < 8 or len(text) % 2 != 0 or not _HEX_RE.match(text):
        return None
    decoded = bytes.fromhex(text)
    return decoded if _printable(decoded) else None


def _evidence(
    source: StringEvidence, evidence_id: str, transform: Transform, decoded: bytes
) -> DecodedStringEvidence:
    text = decoded.decode("ascii")
    return DecodedStringEvidence(
        id=evidence_id,
        location=source.location,
        provenance=Provenance(evidence_ids=(source.id,)),
        transform=transform,
        data=DecodedStringData(
            encoding="ascii",
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
    text = source.data.text
    results = []
    if (decoded := base64_candidate(text)) is not None:
        results.append(_evidence(source, next_id(), Transform(name="base64-strict-v1"), decoded))
    if (decoded := hex_candidate(text)) is not None:
        results.append(_evidence(source, next_id(), Transform(name="hex-strict-v1"), decoded))
    return results
