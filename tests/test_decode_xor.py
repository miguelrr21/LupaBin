import hashlib

import pytest

from dissect.evidence.facts import DecodedStringData, DecodedStringEvidence, XorAnchor
from dissect.evidence.primitives import Location, Transform, minimal_period
from dissect.extractors import decode_xor as x

LONG = "This program cannot be run in DOS mode."  # contains a crib verifying periods 1-8


def noise(size, seed):
    """Deterministic, reproducible background bytes (not a security primitive)."""
    blocks = (hashlib.sha256(f"{seed}:{n}".encode()).digest() for n in range(size // 32 + 1))
    return b"".join(blocks)[:size]


def high_key(length, seed):
    """A key whose bytes are >= 0x80, so XOR'd ASCII text is never itself text."""
    key = bytes(byte | 0x80 for byte in noise(length, f"key:{seed}"))
    assert minimal_period(key) == key
    return key


def plant(text, key, *, encoding="ascii", offset=1000, size=4000, seed=0):
    """Embed NUL + text + NUL, XOR'd as one stream, in random background bytes.

    The NUL terminators decode to 0x00, so the decoded run ends exactly at the text.
    Returns the data and the expected (start, end, key aligned to start).
    """
    pad = "\x00".encode(encoding)
    stream = pad + text.encode(encoding) + pad
    data = bytearray(noise(size, seed))
    data[offset : offset + len(stream)] = bytes(b ^ key[i % len(key)] for i, b in enumerate(stream))
    start = offset + len(pad)
    shift = len(pad) % len(key)
    return (
        bytes(data),
        start,
        start + len(stream) - 2 * len(pad),
        minimal_period(key[shift:] + key[:shift]),
    )


# --- catalog ---------------------------------------------------------------


def test_catalog_digest_is_pinned_to_its_version():
    assert x.catalog_digest() == x.CATALOG_SHA256, (
        "the crib catalog changed: give it a new CATALOG_ID and pin the new digest"
    )


def test_cribs_are_unique_printable_and_fit_the_anchor_model():
    assert len(set(x.CRIBS)) == len(x.CRIBS)
    for crib in x.CRIBS:
        assert 5 <= len(crib) <= 64
        assert all(32 <= ord(c) <= 126 for c in crib)


@pytest.mark.parametrize("encoding", x.ENCODINGS)
def test_every_crib_verifies_at_least_single_byte_keys(encoding):
    for crib in x.CRIBS:
        assert 1 in x.covered_periods(crib, encoding), crib


def test_plans_only_use_informative_patterns():
    for plan in x.PLANS:
        assert sum(1 for b in plan.pattern if b) >= x.MIN_VERIFIED_BYTES
        assert 1 <= plan.lag <= x.MAX_KEY_LENGTH


def test_short_crib_coverage_is_bounded_by_its_length():
    # "cmd.exe" in ASCII has only 7 bytes: no lag above 1 leaves 5 non-zero bytes.
    assert x.covered_periods("cmd.exe", "ascii") == frozenset({1})
    assert x.covered_periods(LONG[:-1], "ascii") == frozenset(range(1, 9))


def test_lag_xor_matches_the_naive_definition():
    data = noise(5000, 3)
    for lag in (1, 3, 8):
        assert x.lag_xor(data, lag) == bytes(a ^ b for a, b in zip(data, data[lag:], strict=False))
    assert x.lag_xor(b"ab", 8) == b""


# --- recovery --------------------------------------------------------------


@pytest.mark.parametrize("encoding", x.ENCODINGS)
@pytest.mark.parametrize("length", range(1, 9))
def test_recovers_the_exact_key_and_text(length, encoding):
    key = high_key(length, seed=length)
    data, start, end, expected_key = plant(LONG, key, encoding=encoding)
    result = x.scan(data)
    [hit] = [h for h in result.hits if h.start == start]
    assert (hit.end, hit.key, hit.encoding) == (end, expected_key, encoding)
    assert hit.plaintext.decode(encoding) == LONG
    assert hit.crib == "This program cannot be run in DOS mode"
    assert hit.crib_offset == 0
    assert hit.complete


def test_recovers_text_around_the_crib():
    text = "GET /x HTTP/1.1 Mozilla/5.0 (Windows NT 10.0; Win64) trailing"
    data, start, end, key = plant(text, high_key(4, seed=9))
    [hit] = x.scan(data).hits
    assert (hit.start, hit.end, hit.key) == (start, end, key)
    decoded = hit.plaintext.decode()
    assert decoded == text
    assert decoded[hit.crib_offset :].startswith(hit.crib)


def test_several_cribs_in_one_run_yield_one_hit():
    text = "Mozilla/5.0 (Windows NT 10.0) http://x.invalid/kernel32.dll"
    data, start, end, key = plant(text, high_key(2, seed=5))
    hits = x.scan(data).hits
    assert [(h.start, h.end, h.key) for h in hits] == [(start, end, key)]
    # earliest anchor in the run; "Mozilla/" and "Mozilla/5.0 (Windows NT " start at
    # the same offset and the tie goes to catalog order
    assert hits[0].crib == "Mozilla/"


def test_single_byte_key_at_the_documented_boundary():
    data, start, end, key = plant(LONG, b"\x80")
    [hit] = x.scan(data).hits
    assert (hit.start, hit.end, hit.key) == (start, end, b"\x80")


# --- abstention ------------------------------------------------------------


def test_plain_crib_is_not_a_decoding():
    data = b"\x90" * 100 + b"\x00http://example.invalid/\x00" + b"\x90" * 100
    assert x.scan(data).hits == ()


def test_text_xor_text_artifact_is_rejected():
    # the dominant false-positive class measured on benign binaries: plain name
    # tables whose shifted copies share a crib's differential
    names = [b"kernel32.dll", b"ntdll.dll", b"user32.dll", b"advapi32.dll", b"ws2_32.dll"]
    table = b"\x00".join(names * 40)
    assert x.scan(b"\xcc" * 64 + table + b"\xcc" * 64).hits == ()


def test_small_key_that_keeps_ciphertext_textual_is_not_published():
    # documented abstention: indistinguishable from text XOR text without scoring
    data, *_ = plant(LONG, b"\x05")
    assert x.scan(data).hits == ()


def test_text_without_any_crib_is_not_found():
    data, *_ = plant("a secret that contains no catalog anchor", high_key(1, seed=2))
    assert x.scan(data).hits == ()


def test_constant_regions_never_match():
    assert x.scan(b"\x00" * 20000 + b"\xff" * 20000).hits == ()


def test_period_the_crib_cannot_verify_is_not_claimed():
    # "cmd.exe" (ASCII) verifies only 1-byte keys; a 2-byte key is out of its reach
    data, *_ = plant("cmd.exe", high_key(2, seed=4))
    assert x.scan(data).hits == ()


# --- extension, limits, determinism ----------------------------------------


def test_long_run_is_capped_and_marked_incomplete():
    text = LONG + " " + "A" * 3000
    data, start, _, key = plant(text, high_key(3, seed=6), size=8000)
    [hit] = x.scan(data, max_chars=200).hits
    assert not hit.complete
    assert len(hit.plaintext) == 200
    assert hit.plaintext.decode()[hit.crib_offset :].startswith(hit.crib)


def test_hit_limit_keeps_the_lowest_offsets():
    rng_key = high_key(1, seed=8)
    data = bytearray(noise(20000, 1))
    starts = []
    for n, offset in enumerate(range(500, 20000, 3000)):
        stream = b"\x00" + f"{n} {LONG}".encode() + b"\x00"
        data[offset : offset + len(stream)] = bytes(b ^ rng_key[0] for b in stream)
        starts.append(offset + 1)
    result = x.scan(bytes(data), max_hits=3)
    assert result.hit_limit
    assert [h.start for h in result.hits] == starts[:3]


def test_examined_limit_turns_a_flood_into_a_declared_limit():
    unit = bytes(b ^ 0xA5 for b in b"\x00http://\x00")
    result = x.scan(unit * 5000, max_examined=10)
    assert result.examined_limit
    assert result.examined == 10


def test_scan_is_deterministic():
    data, *_ = plant(LONG, high_key(5, seed=11))
    assert x.scan(data) == x.scan(data)


def test_max_chars_must_fit_the_longest_crib():
    with pytest.raises(ValueError):
        x.scan(b"", max_chars=10)


# --- evidence and host-side verification ------------------------------------


@pytest.mark.parametrize("encoding", x.ENCODINGS)
def test_evidence_round_trips_and_verifies(encoding):
    data, *_ = plant(LONG, high_key(4, seed=12), encoding=encoding)
    [hit] = x.scan(data).hits
    evidence = x.evidence(hit, "E5")
    assert evidence.component == "decode_xor"
    assert evidence.confidence == "inferred"
    assert evidence.provenance.evidence_ids == ()
    assert evidence.data.text == LONG
    x.verify(evidence, data)


def _evidence(**changes):
    data, *_ = plant(LONG, high_key(4, seed=13))
    [hit] = x.scan(data).hits
    evidence = x.evidence(hit, "E5")
    return evidence.model_copy(update=changes), data


def test_verify_rejects_a_wrong_key():
    evidence, data = _evidence()
    forged = evidence.model_copy(
        update={"transform": evidence.transform.model_copy(update={"key_hex": "01020304"})}
    )
    with pytest.raises(ValueError, match="reproduced"):
        x.verify(forged, data)


def test_verify_rejects_modified_sample_bytes():
    evidence, data = _evidence()
    tampered = bytearray(data)
    tampered[evidence.location.offset + 3] ^= 0xFF
    with pytest.raises(ValueError, match="reproduced"):
        x.verify(evidence, bytes(tampered))


def test_verify_rejects_a_region_outside_the_sample():
    evidence, data = _evidence()
    with pytest.raises(ValueError, match="outside"):
        x.verify(evidence, data[: evidence.location.offset + 4])


def test_verify_rejects_a_truncated_run_declared_complete():
    evidence, data = _evidence()
    shorter = evidence.location.model_copy(update={"length": evidence.location.length - 1})
    text = evidence.data.text[:-1]
    forged = evidence.model_copy(
        update={
            "location": shorter,
            "data": evidence.data.model_copy(
                update={"text": text, "raw_hex": text.encode().hex(), "characters": len(text)}
            ),
        }
    )
    with pytest.raises(ValueError, match="continues"):
        x.verify(forged, data)


def test_verify_rejects_an_anchor_outside_the_catalog():
    evidence, data = _evidence()
    forged = evidence.model_copy(
        update={"anchor": evidence.anchor.model_copy(update={"crib": "This program"})}
    )
    with pytest.raises(ValueError, match="catalog"):
        x.verify(forged, data)


def test_verify_rejects_a_period_the_crib_cannot_verify():
    data, *_ = plant("cmd.exe /c x", b"\xa5")
    [hit] = x.scan(data).hits
    evidence = x.evidence(hit, "E1")
    key = high_key(2, seed=14)
    region = bytes.fromhex(evidence.data.raw_hex)
    tampered = bytearray(data)
    start = evidence.location.offset
    tampered[start : start + len(region)] = bytes(b ^ key[i % 2] for i, b in enumerate(region))
    forged = evidence.model_copy(
        update={"transform": evidence.transform.model_copy(update={"key_hex": key.hex()})}
    )
    with pytest.raises(ValueError, match="period"):
        x.verify(forged, bytes(tampered))


def test_verify_rejects_a_textual_anchor_window():
    # a worker claiming a small-key decoding the method itself never publishes
    data, start, end, _ = plant(LONG, b"\x05")
    forged = DecodedStringEvidence(
        id="E1",
        component="decode_xor",
        location=Location(offset=start, length=end - start),
        transform=Transform(name="xor-repeating-v1", key_hex="05"),
        anchor=XorAnchor(catalog=x.CATALOG_ID, crib=LONG[:-1], crib_offset=0),
        data=DecodedStringData(
            encoding="ascii",
            text=LONG,
            raw_hex=LONG.encode().hex(),
            characters=len(LONG),
            complete=True,
            total_characters=len(LONG),
        ),
    )
    with pytest.raises(ValueError, match="plain text"):
        x.verify(forged, data)
