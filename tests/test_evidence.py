import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from dissect.evidence.facts import (
    DecodedStringData,
    DecodedStringEvidence,
    ImportEvidence,
    XorAnchor,
)
from dissect.evidence.models import (
    Analysis,
    ComponentRun,
    ImportData,
    Location,
    Name,
    Report,
    Run,
    Sample,
)
from dissect.evidence.primitives import COMPONENTS, Provenance, Transform, minimal_period


def report_dict():
    return {
        "schema_version": "0.3.0",
        "analysis": {
            "started_at": "2026-09-20T12:00:00Z",
            "finished_at": "2026-09-20T12:00:01Z",
            "status": "completed",
        },
        "sample": {"sha256": "a" * 64, "md5": "b" * 32, "size": 4096, "type": "PE32"},
        "evidence": [
            {
                "id": "E1",
                "kind": "import",
                "source": "pe",
                "component": "imports_normal",
                "data": {
                    "dll": {"raw_hex": b"kernel32.dll".hex(), "text": "kernel32.dll"},
                    "function": {"raw_hex": b"ExitProcess".hex(), "text": "ExitProcess"},
                    "table": "normal",
                },
                "location": {"offset": 512, "rva": 4096, "length": 4},
                "confidence": "observed",
            }
        ],
        "extractor_runs": [
            {
                "source": "pe",
                "version": "2024.8.26",
                "status": "completed",
                "evidence_count": 1,
                "components": [
                    {
                        "name": name,
                        "status": "complete",
                        "evidence_count": int(name == "imports_normal"),
                    }
                    for name in COMPONENTS["pe"]
                ],
            }
        ],
    }


def validate(data):
    return Report.model_validate_json(json.dumps(data))


def test_round_trip():
    report = validate(report_dict())
    assert Report.model_validate_json(report.model_dump_json()) == report


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(schema_version="9.0.0"),
        lambda d: d.update(schema_version="0.1.0"),
        lambda d: d.update(schema_version="0.2.0"),
        lambda d: d.update(verdict="safe"),
        lambda d: d["sample"].update(path="C:/private/sample.exe"),
        lambda d: d["sample"].update(size=-1),
        lambda d: d["sample"].update(size=True),
        lambda d: d["sample"].update(sha256="bad"),
        lambda d: d["analysis"].update(started_at="2026-09-20T12:00:00"),
        lambda d: d["analysis"].update(finished_at="2026-09-19T12:00:00Z"),
        lambda d: d["evidence"].append(d["evidence"][0].copy()),
        lambda d: d["evidence"][0].update(source="missing"),
        lambda d: d["evidence"][0].update(kind="entropy"),
        lambda d: d["evidence"][0].update(component="exports"),
        lambda d: d["evidence"][0].update(confidence="inferred"),
        lambda d: d["evidence"][0]["data"].update(ordinal=1),
        lambda d: d["evidence"][0]["data"].update(function=None),
        lambda d: d["evidence"][0]["location"].update(offset=4096),
        lambda d: d["evidence"][0].update(provenance={"evidence_ids": ["E99"]}),
        lambda d: d["evidence"][0].update(provenance={"evidence_ids": ["E1"]}),
        lambda d: d["extractor_runs"][0].update(status="failed"),
        lambda d: d["extractor_runs"][0]["components"][0].update(status="blocked"),
        lambda d: d["evidence"][0]["data"]["dll"].update(text="other.dll"),
    ],
)
def test_rejects_unverifiable_or_inconsistent_data(change):
    data = report_dict()
    change(data)
    with pytest.raises(ValidationError):
        validate(data)


def test_rejects_reference_cycle():
    data = report_dict()
    second = json.loads(json.dumps(data["evidence"][0]))
    second.update(id="E2", provenance={"evidence_ids": ["E1"]})
    data["evidence"][0]["provenance"] = {"evidence_ids": ["E2"]}
    data["evidence"].append(second)
    data["extractor_runs"][0]["evidence_count"] = 2
    data["extractor_runs"][0]["components"][3]["evidence_count"] = 2
    with pytest.raises(ValidationError, match="cyclic"):
        validate(data)


def test_non_ascii_name_preserves_bytes_without_guessing():
    value = Name.from_bytes(b"\xffname")
    assert value.text is None
    assert value.raw_hex == "ff6e616d65"


def test_empty_imports_can_only_describe_extraction_not_safety():
    data = report_dict()
    data["evidence"] = []
    data["extractor_runs"][0]["evidence_count"] = 0
    data["extractor_runs"][0]["components"][3]["evidence_count"] = 0
    report = validate(data)
    assert report.analysis.status == "completed"
    assert "verdict" not in report.model_dump()


def test_ordinal_zero_is_representable():
    data = report_dict()
    data["evidence"][0]["data"].update(function=None, ordinal=0)
    assert validate(data).evidence[0].data.ordinal == 0


def test_python_construction():
    now = datetime.now(UTC)
    report = Report(
        analysis=Analysis(started_at=now, finished_at=now, status="completed"),
        sample=Sample(sha256="a" * 64, md5="b" * 32, size=4096, type="PE32"),
        evidence=(
            ImportEvidence(
                id="E1",
                source="pe",
                component="imports_normal",
                location=Location(offset=512, length=4),
                data=ImportData(
                    dll=Name.from_bytes(b"x.dll"), function=Name.from_bytes(b"f"), table="normal"
                ),
            ),
        ),
        extractor_runs=(
            Run(
                source="pe",
                version="1",
                status="completed",
                evidence_count=1,
                components=tuple(
                    ComponentRun(
                        name=name, status="complete", evidence_count=int(name == "imports_normal")
                    )
                    for name in COMPONENTS["pe"]
                ),
            ),
        ),
    )
    assert report.evidence[0].confidence == "observed"


def test_existing_evidence_kinds_cannot_claim_inferred_confidence():
    data = report_dict()
    data["evidence"][0].update(confidence="inferred")
    with pytest.raises(ValidationError):
        validate(data)


@pytest.mark.parametrize(
    "transform",
    [
        dict(name="base64-strict-v1"),
        dict(name="hex-strict-v1"),
        dict(name="xor-repeating-v1", key_hex="2a"),
        dict(name="xor-repeating-v1", key_hex="0102030405060708"),
        dict(name="xor-repeating-v1", key_hex="00ff"),
    ],
)
def test_transform_accepts_valid_combinations(transform):
    Transform(**transform)


@pytest.mark.parametrize(
    "transform",
    [
        dict(name="xor-repeating-v1"),
        dict(name="base64-strict-v1", key_hex="2a"),
        dict(name="hex-strict-v1", key_hex="2a"),
        dict(name="xor-repeating-v1", key_hex="0102030405060708" + "09"),
        dict(name="xor-repeating-v1", key_hex=""),
        # identity key: would "decode" plain text into itself
        dict(name="xor-repeating-v1", key_hex="00"),
        dict(name="xor-repeating-v1", key_hex="0000"),
        # non-canonical: the same decoding as the 1-byte key 2a
        dict(name="xor-repeating-v1", key_hex="2a" * 8),
        dict(name="xor-repeating-v1", key_hex="abcdabcd"),
    ],
)
def test_transform_rejects_keys_that_are_missing_identity_or_not_minimal(transform):
    with pytest.raises(ValidationError):
        Transform(**transform)


@pytest.mark.parametrize(
    "key,period",
    [
        (b"\x2a", b"\x2a"),
        (b"\x2a" * 8, b"\x2a"),
        (b"abab", b"ab"),
        (b"abcabc", b"abc"),
        (b"abca", b"abca"),
    ],
)
def test_minimal_period(key, period):
    assert minimal_period(key) == period


def decoded_string_data(**overrides):
    defaults = dict(
        encoding="ascii",
        text="http://x",
        raw_hex=b"http://x".hex(),
        characters=8,
        complete=True,
        total_characters=8,
    )
    return DecodedStringData(**{**defaults, **overrides})


def test_decoded_string_data_round_trips_bytes():
    data = decoded_string_data()
    assert bytes.fromhex(data.raw_hex).decode(data.encoding) == data.text


@pytest.mark.parametrize(
    "overrides",
    [
        dict(text="different"),
        dict(raw_hex="00" * 8),
        dict(characters=7),
        dict(complete=True, total_characters=7),
        dict(complete=False, total_characters=8),
        dict(text="\x01\x02\x03\x04"),
    ],
)
def test_decoded_string_data_rejects_unfaithful_payloads(overrides):
    with pytest.raises(ValidationError):
        decoded_string_data(**overrides)


def decoded_string_evidence(**overrides):
    defaults = dict(
        id="E9",
        component="decode_strings",
        location=Location(offset=100, length=16),
        provenance=Provenance(evidence_ids=("E1",)),
        transform=Transform(name="hex-strict-v1"),
        data=decoded_string_data(),
    )
    return DecodedStringEvidence(**{**defaults, **overrides})


def xor_evidence(**overrides):
    defaults = dict(
        id="E9",
        component="decode_xor",
        location=Location(offset=100, length=8),
        transform=Transform(name="xor-repeating-v1", key_hex="a5"),
        anchor=XorAnchor(catalog="dissect-xor-cribs-v1", crib="http://", crib_offset=0),
        data=decoded_string_data(),
    )
    return DecodedStringEvidence(**{**defaults, **overrides})


@pytest.mark.parametrize("factory", [decoded_string_evidence, xor_evidence])
def test_decoded_string_evidence_round_trips(factory):
    evidence = factory()
    assert evidence.confidence == "inferred"
    assert DecodedStringEvidence.model_validate_json(evidence.model_dump_json()) == evidence


def test_decoded_string_evidence_requires_a_transform():
    with pytest.raises(ValidationError):
        DecodedStringEvidence(
            id="E9",
            component="decode_strings",
            location=Location(offset=100, length=8),
            provenance=Provenance(evidence_ids=("E1",)),
            data=decoded_string_data(),
        )


@pytest.mark.parametrize("evidence_ids", [(), ("E1", "E2")])
def test_text_decoding_requires_exactly_one_source(evidence_ids):
    with pytest.raises(ValidationError):
        decoded_string_evidence(provenance=Provenance(evidence_ids=evidence_ids))


@pytest.mark.parametrize("factory", [decoded_string_evidence, xor_evidence])
def test_decoded_string_evidence_confidence_cannot_be_observed(factory):
    with pytest.raises(ValidationError):
        factory(confidence="observed")


@pytest.mark.parametrize(
    "overrides",
    [
        dict(component="decode_xor"),
        dict(anchor=XorAnchor(catalog="dissect-xor-cribs-v1", crib="http://", crib_offset=0)),
        dict(location=Location()),
    ],
)
def test_text_decoding_rejects_xor_only_fields(overrides):
    with pytest.raises(ValidationError):
        decoded_string_evidence(**overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        dict(component="decode_strings"),
        dict(anchor=None),
        dict(provenance=Provenance(evidence_ids=("E1",))),
        dict(location=Location(offset=100, length=9)),
        dict(location=Location(offset=100)),
        dict(anchor=XorAnchor(catalog="dissect-xor-cribs-v1", crib="http://", crib_offset=1)),
        dict(anchor=XorAnchor(catalog="dissect-xor-cribs-v1", crib="https://", crib_offset=0)),
    ],
)
def test_xor_decoding_rejects_incoherent_fields(overrides):
    with pytest.raises(ValidationError):
        xor_evidence(**overrides)


def test_xor_anchor_rejects_unknown_catalog_and_unprintable_crib():
    with pytest.raises(ValidationError):
        XorAnchor(catalog="other", crib="http://", crib_offset=0)
    with pytest.raises(ValidationError):
        XorAnchor(catalog="dissect-xor-cribs-v1", crib="http\x00//", crib_offset=0)
