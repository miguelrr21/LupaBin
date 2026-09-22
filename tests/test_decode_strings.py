import base64

import pytest

from dissect.evidence.facts import StringEvidence
from dissect.evidence.primitives import Location
from dissect.extractors.decode_strings import base64_candidate, candidates, hex_candidate, verify


def string_evidence(text, *, encoding="ascii", complete=True, evidence_id="E1", offset=100):
    raw = text.encode(encoding)
    return StringEvidence(
        id=evidence_id,
        source="strings",
        component="ascii" if encoding == "ascii" else "utf16le",
        location=Location(offset=offset, length=len(raw)),
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


HELLO_B64 = base64.b64encode(b"hello world!").decode()  # 16 chars, no padding
HELLO_HEX = b"hello world!".hex()


@pytest.mark.parametrize(
    "text,expected",
    [
        (HELLO_B64, b"hello world!"),
        ("cGFzc3dvcmQ=", b"password"),  # 12 chars with padding: the accepted minimum
        ("aGVsbG8gd29ybGQ=", b"hello world"),
        ("not-base64!!", None),  # alphabet
        ("aGVsbG8gd29ybG", None),  # not a multiple of 4
        (base64.b64encode(bytes(range(12))).decode(), None),  # decodes to control bytes
    ],
)
def test_base64_candidate(text, expected):
    assert base64_candidate(text) == expected


@pytest.mark.parametrize(
    "identifier",
    # every Base64 false positive measured on benign binaries was 8 characters
    ["fileType", "OnEventW", "REFCOUNT", "PipeList", "ZzZzZzZz"],
)
def test_base64_candidate_ignores_short_identifiers(identifier):
    assert base64.b64decode(identifier, validate=True)  # valid Base64 syntax...
    assert base64_candidate(identifier) is None  # ...but below the 12-character minimum


def test_unpadded_base64_needs_sixteen_characters():
    # identifiers never carry "=": SystemEventW (12) decodes to b"K+-za/z{V"
    assert base64.b64decode("SystemEventW", validate=True)
    assert base64_candidate("SystemEventW") is None
    assert base64_candidate(base64.b64encode(b"hello!123").decode()) is None  # 12, unpadded
    assert base64_candidate("cGFzc3dvcmQ=") == b"password"  # 12, padded


@pytest.mark.parametrize("number", ["2147483647", "2147483650", "49312658", "26622221"])
def test_hex_candidate_ignores_decimal_numbers(number):
    # every hex hit in 4,516 benign files that was noise came from a decimal number
    assert all(0x20 <= b <= 0x7E for b in bytes.fromhex(number))
    assert hex_candidate(number) is None


def test_base64_candidate_rejects_non_canonical_padding():
    # validate=True still accepts padding bits that do not round-trip: this decodes
    # to b"hello world" but the canonical encoding of that is "aGVsbG8gd29ybGQ=".
    assert base64.b64decode("aGVsbG8gd29ybGR=", validate=True) == b"hello world"
    assert base64_candidate("aGVsbG8gd29ybGR=") is None


def test_base64_candidate_rejects_low_diversity_output():
    assert base64_candidate(base64.b64encode(b"AAAAAAAAA").decode()) is None


@pytest.mark.parametrize(
    "text,expected",
    [
        (HELLO_HEX, b"hello world!"),
        ("636d642e657865", b"cmd.exe"),
        ("deadbeef", None),  # non-printable bytes
        ("abc", None),  # odd length
        ("zz00zz00", None),  # invalid digits
        ("414243", None),  # fewer than 4 decoded bytes
    ],
)
def test_hex_candidate(text, expected):
    assert hex_candidate(text) == expected


@pytest.mark.parametrize(
    # every hex false positive measured on benign binaries was repetitive filler
    "filler",
    ["33333333", "3333333333333331", "44444444444444", "66666664", "41414141"],
)
def test_hex_candidate_ignores_repetitive_numeric_filler(filler):
    assert all(0x20 <= b <= 0x7E for b in bytes.fromhex(filler))  # would be "printable"...
    assert hex_candidate(filler) is None  # ...but has fewer than 4 distinct characters


def test_candidates_base64_source():
    source = string_evidence(HELLO_B64)
    [result] = candidates(source, counter())
    assert result.transform.name == "base64-strict-v1"
    assert result.component == "decode_strings"
    assert result.data.text == "hello world!"
    assert result.provenance.evidence_ids == ("E1",)
    assert result.location == source.location
    assert result.confidence == "inferred"


def test_candidates_hex_source():
    [result] = candidates(string_evidence(HELLO_HEX), counter())
    assert result.transform.name == "hex-strict-v1"
    assert result.data.text == "hello world!"


def test_candidates_empty_when_nothing_qualifies():
    assert candidates(string_evidence("just a plain sentence"), counter()) == []


def test_candidates_skip_truncated_sources():
    assert candidates(string_evidence(HELLO_B64, complete=False), counter()) == []


def test_candidates_work_on_utf16le_sources_via_decoded_text():
    [result] = candidates(string_evidence(HELLO_B64, encoding="utf-16-le"), counter())
    assert result.data.text == "hello world!"


def test_candidates_assign_ids_only_for_qualifying_transforms():
    calls = []
    candidates(string_evidence("just a plain sentence"), lambda: calls.append(1) or "E1")
    assert calls == []


def sample_with(source):
    data = bytearray(b"\x90" * 400)
    raw = bytes.fromhex(source.data.raw_hex)
    data[source.location.offset : source.location.offset + len(raw)] = raw
    return bytes(data)


@pytest.mark.parametrize("encoding", ["ascii", "utf-16-le"])
def test_verify_accepts_a_reproducible_decoding(encoding):
    source = string_evidence(HELLO_B64, encoding=encoding)
    [result] = candidates(source, counter(start=2))
    verify(result, source, sample_with(source))


def test_verify_rejects_a_tampered_decoding():
    source = string_evidence(HELLO_B64)
    [result] = candidates(source, counter(start=2))
    forged_data = result.data.model_copy(
        update={"text": "hello world?", "raw_hex": b"hello world?".hex()}
    )
    forged = result.model_copy(update={"data": forged_data})
    with pytest.raises(ValueError, match="reproduced"):
        verify(forged, source, sample_with(source))


def test_verify_rejects_a_source_string_absent_from_the_sample():
    source = string_evidence(HELLO_B64)
    [result] = candidates(source, counter(start=2))
    with pytest.raises(ValueError, match="differs"):
        verify(result, source, b"\x90" * 400)


def test_verify_rejects_a_decoding_citing_another_string():
    source = string_evidence(HELLO_B64)
    other = string_evidence(HELLO_B64, evidence_id="E7", offset=200)
    [result] = candidates(source, counter(start=2))
    with pytest.raises(ValueError, match="cite"):
        verify(result, other, sample_with(other))
