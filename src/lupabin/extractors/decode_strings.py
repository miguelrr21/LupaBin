import base64
import binascii
import re
from collections.abc import Callable

from lupabin.evidence.facts import DecodedStringData, DecodedStringEvidence, StringEvidence
from lupabin.evidence.primitives import Provenance, Transform, TransformName

# Method parameters of base64-strict-v1 / hex-strict-v1. Changing them changes the
# algorithm, not a tunable limit: every value below was set from measurements on
# benign binaries (docs/metodo.md, «Decodificación»). Identifiers (fileType, SystemEventW) are valid
# unpadded Base64 and never carry "=", so unpadded text needs more length; decimal
# numbers (2147483647) are valid hex, so digit-only text is not treated as hex.
BASE64_MIN_CHARS = 12
BASE64_UNPADDED_MIN_CHARS = 16
HEX_MIN_CHARS = 8
MIN_DECODED_BYTES = 4
MIN_DISTINCT_CHARS = 4

_BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2})+")


def _readable(data: bytes) -> bool:
    return (
        len(data) >= MIN_DECODED_BYTES
        and all(0x20 <= byte <= 0x7E for byte in data)
        and len(set(data)) >= MIN_DISTINCT_CHARS
    )


def base64_candidate(text: str) -> bytes | None:
    minimum = BASE64_MIN_CHARS if text.endswith("=") else BASE64_UNPADDED_MIN_CHARS
    if len(text) < minimum or len(text) % 4 or not _BASE64_RE.fullmatch(text):
        return None
    try:
        decoded = base64.b64decode(text, validate=True)
    except binascii.Error:
        return None
    # validate=True still accepts non-zero padding bits ("aGVsbG9=" -> b"hello");
    # only the canonical encoding of the decoded bytes is accepted.
    if base64.b64encode(decoded).decode("ascii") != text:
        return None
    return decoded if _readable(decoded) else None


def hex_candidate(text: str) -> bytes | None:
    if len(text) < HEX_MIN_CHARS or len(text) % 2 or not _HEX_RE.fullmatch(text):
        return None
    if text.isdigit():
        return None
    decoded = bytes.fromhex(text)
    return decoded if _readable(decoded) else None


_DECODERS: dict[TransformName, Callable[[str], bytes | None]] = {
    "base64-strict-v1": base64_candidate,
    "hex-strict-v1": hex_candidate,
}


def decodings(source: StringEvidence) -> list[tuple[TransformName, bytes]]:
    if not source.data.complete:
        return []
    return [
        (name, decoded)
        for name, decode in _DECODERS.items()
        if (decoded := decode(source.data.text)) is not None
    ]


def decoded_data(decoded: bytes) -> DecodedStringData:
    text = decoded.decode("ascii")
    return DecodedStringData(
        encoding="ascii",
        text=text,
        raw_hex=decoded.hex(),
        characters=len(text),
        complete=True,
        total_characters=len(text),
    )


def candidates(source: StringEvidence, next_id: Callable[[], str]) -> list[DecodedStringEvidence]:
    return [
        DecodedStringEvidence(
            id=next_id(),
            component="decode_strings",
            location=source.location,
            provenance=Provenance(evidence_ids=(source.id,)),
            transform=Transform(name=name),
            data=decoded_data(decoded),
        )
        for name, decoded in decodings(source)
    ]


def verify(evidence: DecodedStringEvidence, source: StringEvidence, data: bytes) -> None:
    decode = _DECODERS.get(evidence.transform.name)
    if decode is None:
        raise ValueError("not a Base64/hex decoding")
    if evidence.provenance.evidence_ids != (source.id,) or evidence.location != source.location:
        raise ValueError("decoding does not cite the string at its own location")
    offset, length = source.location.offset, source.location.length
    if offset is None or length is None or offset + length > len(data):
        raise ValueError("source string lies outside the sample")
    if data[offset : offset + length].hex() != source.data.raw_hex:
        raise ValueError("source string differs from the sample bytes")
    decoded = decode(source.data.text)
    if decoded is None or decoded.hex() != evidence.data.raw_hex:
        raise ValueError("the published decoding cannot be reproduced")
