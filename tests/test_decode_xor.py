from dissect.evidence.facts import StringEvidence
from dissect.evidence.primitives import Location
from dissect.extractors.decode_xor import (
    candidates,
    full_coverage_encoding,
    single_byte_xor_candidates,
)


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


def test_full_coverage_encoding_ascii():
    assert full_coverage_encoding(b"flag: xor test!") == "ascii"


def test_full_coverage_encoding_utf16le():
    data = "flag test".encode("utf-16-le")
    assert full_coverage_encoding(data) == "utf-16-le"


def test_full_coverage_encoding_rejects_partial_match():
    # printable in the middle, but not the whole buffer (leading control byte)
    assert full_coverage_encoding(b"\x01good text!") is None


def test_full_coverage_encoding_rejects_too_short():
    assert full_coverage_encoding(b"ab") is None


def test_full_coverage_encoding_misaligned_utf16_never_covers_from_zero():
    # a run that only exists at odd alignment cannot start at offset 0
    data = b"\x00" + "hi there".encode("utf-16-le")
    assert full_coverage_encoding(data) is None


# XOR(b"flag: xor test!", 0x11) is itself printable ASCII, so it is a valid
# ciphertext-as-observed-string source.
SOURCE_BYTES = bytes(b ^ 0x11 for b in b"flag: xor test!")


def test_single_byte_xor_candidates_finds_the_planted_key():
    results = single_byte_xor_candidates(SOURCE_BYTES)
    assert (bytes([0x11]), "ascii") in results
    decoded = bytes(b ^ 0x11 for b in SOURCE_BYTES)
    assert decoded == b"flag: xor test!"


def test_single_byte_xor_candidates_excludes_the_identity_key():
    assert all(key != b"\x00" for key, _ in single_byte_xor_candidates(SOURCE_BYTES))


def test_single_byte_xor_candidates_empty_when_bytes_are_too_spread_out():
    # 0x00 and 0xFF differ by more than the printable range's width (0x5F),
    # so no single XOR key can land both inside 0x20-0x7e at once.
    data = bytes([0x00, 0xFF, 0x10, 0xEE])
    assert single_byte_xor_candidates(data) == []


def test_candidates_recovers_the_planted_plaintext():
    source = string_evidence(SOURCE_BYTES.decode("ascii"))
    results = candidates(source, counter())
    matches = [r for r in results if r.transform.key_hex == "11"]
    assert len(matches) == 1
    evidence = matches[0]
    assert evidence.data.text == "flag: xor test!"
    assert evidence.transform.name == "xor-repeating-v1"
    assert evidence.provenance.evidence_ids == ("E1",)
    assert evidence.location == source.location
    assert evidence.confidence == "inferred"


def test_candidates_skip_truncated_sources():
    source = string_evidence(SOURCE_BYTES.decode("ascii"), complete=False)
    assert candidates(source, counter()) == []


def test_candidates_empty_when_no_key_qualifies():
    source = string_evidence("just a plain sentence with no hidden key")
    # sanity: extremely unlikely any single byte key turns this into a full
    # printable run of a different encoding by coincidence for this fixture
    results = candidates(source, counter())
    for evidence in results:
        key = bytes.fromhex(evidence.transform.key_hex)
        raw = source.data.text.encode(source.data.encoding)
        decoded = bytes(b ^ key[0] for b in raw)
        assert decoded.decode(evidence.data.encoding) == evidence.data.text
