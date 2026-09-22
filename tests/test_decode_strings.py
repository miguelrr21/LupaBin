import base64

import pytest

from dissect.evidence.facts import StringEvidence
from dissect.evidence.primitives import Location
from dissect.extractors.decode_strings import base64_candidate, candidates, hex_candidate


def string_evidence(text, *, encoding="ascii", complete=True, evidence_id="E1"):
    raw = text.encode(encoding)
    return StringEvidence(
        id=evidence_id,
        source="strings",
        component="ascii" if encoding == "ascii" else "utf16le",
        location=Location(offset=100, length=len(raw)),
        data={
            "encoding": encoding,
            "text": text,
            "raw_hex": raw.hex(),
            "characters": len(text),
            "complete": complete,
            "total_characters": len(text) if complete else len(text) + 10,
        },
    )


def counter(start=1):
    n = start

    def next_id():
        nonlocal n
        value = f"E{n}"
        n += 1
        return value

    return next_id


# "hello world!" (12 chars) -> canonical base64 with padding
HELLO_B64 = base64.b64encode(b"hello world!").decode()


@pytest.mark.parametrize(
    "text,expected",
    [
        (HELLO_B64, b"hello world!"),
        ("QQ==", None),  # decodes to 1 byte, below the 4-byte floor
        ("not-base64!!", None),  # invalid alphabet
        ("QQE", None),  # not a multiple of 4
        (base64.b64encode(bytes(range(4))).decode(), None),  # decodes to non-printable bytes
    ],
)
def test_base64_candidate(text, expected):
    assert base64_candidate(text) == expected


def test_base64_candidate_rejects_non_canonical_padding():
    # "aGVsbG9=" decodes under relaxed rules to b"hello" (Python's own
    # validate=True does not catch this), but re-encoding b"hello" produces
    # "aGVsbG8=", not this string: the padding bits are non-canonical.
    assert base64.b64decode("aGVsbG9=", validate=True) == b"hello"
    assert base64_candidate("aGVsbG9=") is None


HELLO_HEX = b"hello world!".hex()


@pytest.mark.parametrize(
    "text,expected",
    [
        (HELLO_HEX, b"hello world!"),
        ("deadbeef", None),  # valid hex, non-printable decoded bytes
        ("abc", None),  # odd length
        ("zz00zz00", None),  # invalid hex digits
        ("41414141", b"AAAA"),  # 4 printable bytes, right at the floor
    ],
)
def test_hex_candidate(text, expected):
    assert hex_candidate(text) == expected


def test_candidates_base64_source():
    source = string_evidence(HELLO_B64)
    results = candidates(source, counter())
    assert [r.transform.name for r in results] == ["base64-strict-v1"]
    assert results[0].data.text == "hello world!"
    assert results[0].provenance.evidence_ids == ("E1",)
    assert results[0].location == source.location
    assert results[0].confidence == "inferred"


def test_candidates_hex_source():
    source = string_evidence(HELLO_HEX)
    results = candidates(source, counter())
    assert [r.transform.name for r in results] == ["hex-strict-v1"]
    assert results[0].data.text == "hello world!"


def test_candidates_empty_when_nothing_qualifies():
    source = string_evidence("just a plain sentence")
    assert candidates(source, counter()) == []


def test_candidates_skip_truncated_sources():
    source = string_evidence(HELLO_B64, complete=False)
    assert candidates(source, counter()) == []


def test_candidates_work_on_utf16le_sources_via_decoded_text():
    source = string_evidence(HELLO_B64, encoding="utf-16-le")
    results = candidates(source, counter())
    assert [r.transform.name for r in results] == ["base64-strict-v1"]
    assert results[0].data.text == "hello world!"


def test_candidates_assign_ids_only_for_qualifying_transforms():
    source = string_evidence("just a plain sentence")
    calls = []
    candidates(source, lambda: calls.append(1) or "E1")
    assert calls == []
