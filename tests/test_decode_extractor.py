import asyncio
import json

import pytest
from jsonschema import Draft202012Validator

from dissect.analysis import analyze_bytes
from dissect.errors import DissectError
from dissect.evidence.models import Limits, Report
from dissect.evidence.schema import schema_text
from dissect.extractors.decode import verify_decodings
from dissect.runner import run_isolated
from tests.fixtures.pe_builder import DECODE_DEMO, build_decode_demo, build_pe, xor_stream
from tests.test_runner import FakeDocker

EXPECTED = [
    ("decode_strings", "base64-strict-v1", None, "https://training.invalid/decode/base64"),
    ("decode_strings", "hex-strict-v1", None, "cmd.exe /c echo dissect-hex"),
    ("decode_xor", "xor-repeating-v1", "a5", "https://training.invalid/decode/xor-1"),
    # the 4-byte key is published rotated to the region start (after the NUL pad)
    ("decode_xor", "xor-repeating-v1", "c381f79e", "User-Agent: DissectTraining/1.0"),
    ("decode_xor", "xor-repeating-v1", "b7d2", "kernel32.dll!DissectTraining"),
    ("decode_xor", "xor-repeating-v1", "c381f79e", "http://training.invalid/decode/reuse"),
]


def decoded(report):
    return [fact for fact in report.evidence if fact.kind == "decoded_string"]


def decode_run(report):
    return next(run for run in report.extractor_runs if run.source == "decode")


def limitation_codes(report):
    return {reason.code for reason in report.limitations if reason.source == "decode"}


def test_pipeline_publishes_each_planted_decoding():
    report = analyze_bytes(build_decode_demo())
    assert report.schema_version == "0.5.0"
    assert [run.source for run in report.extractor_runs] == ["pe", "strings", "yara", "decode"]
    assert report.analysis.status == "completed"
    assert [
        (f.component, f.transform.name, f.transform.key_hex, f.data.text) for f in decoded(report)
    ] == EXPECTED
    assert all(f.confidence == "inferred" for f in decoded(report))
    assert len(DECODE_DEMO) == len(EXPECTED)


def test_text_decodings_cite_the_string_holding_their_bytes():
    report = analyze_bytes(build_decode_demo())
    facts = {fact.id: fact for fact in report.evidence}
    for fact in decoded(report):
        if fact.component == "decode_strings":
            [ref] = fact.provenance.evidence_ids
            assert facts[ref].kind == "string"
            assert facts[ref].location == fact.location
        else:
            assert fact.anchor.catalog == "dissect-xor-cribs-v3"
            if fact.anchor.crib == "http://":  # reused key: cites the decoding that set it
                [ref] = fact.provenance.evidence_ids
                assert facts[ref].transform.key_hex == fact.transform.key_hex
                assert facts[ref].provenance.evidence_ids == ()
            else:
                assert fact.provenance.evidence_ids == ()


def test_decode_runs_last_and_its_ids_follow_earlier_sources():
    report = analyze_bytes(build_decode_demo())
    kinds = [fact.kind for fact in report.evidence]
    first = kinds.index("decoded_string")
    assert all(kind == "decoded_string" for kind in kinds[first:])


def test_every_published_decoding_reverifies_against_the_input():
    data = build_decode_demo()
    verify_decodings(analyze_bytes(data).evidence, data)


def test_report_with_decodings_conforms_to_the_exported_schema():
    payload = json.loads(analyze_bytes(build_decode_demo()).model_dump_json())
    Draft202012Validator(json.loads(schema_text())).validate(payload)


def test_no_candidate_is_complete_coverage_not_a_verdict():
    report = analyze_bytes(build_pe())
    assert decoded(report) == []
    assert decode_run(report).status == "completed"
    assert "verdict" not in report.model_dump()


def test_decoding_works_on_bytes_of_unknown_format():
    data = b"\x90" * 32 + xor_stream("https://training.invalid/raw", b"\xa5") + b"\x90" * 32
    report = analyze_bytes(data)
    assert report.sample.type == "unknown"
    assert [f.data.text for f in decoded(report)] == ["https://training.invalid/raw"]


# --- limits become declared limitations -------------------------------------


def test_text_decoding_quota_is_declared():
    limits = Limits.model_validate({"decode": {"strings": 1}})
    report = analyze_bytes(build_decode_demo(), limits)
    assert sum(f.component == "decode_strings" for f in decoded(report)) == 1
    assert "decode_strings_limit" in limitation_codes(report)
    assert decode_run(report).status == "partial"


def test_xor_quota_is_declared():
    limits = Limits.model_validate({"decode": {"xor": 2}})
    report = analyze_bytes(build_decode_demo(), limits)
    assert sum(f.component == "decode_xor" for f in decoded(report)) == 2
    assert "decode_xor_limit" in limitation_codes(report)


def test_examined_budget_is_declared():
    limits = Limits.model_validate({"decode": {"xor_examined": 1}})
    report = analyze_bytes(build_decode_demo(), limits)
    assert "decode_xor_examined_limit" in limitation_codes(report)
    assert decode_run(report).status == "partial"


def test_truncated_decoded_run_is_declared():
    long = "https://training.invalid/" + "a" * 200
    data = xor_stream(long, b"\xa5") + b"\x90" * 16
    report = analyze_bytes(data, Limits.model_validate({"string_characters": 100}))
    [fact] = decoded(report)
    assert not fact.data.complete and fact.data.characters == 100
    assert "decoded_length_limit" in limitation_codes(report)


def test_character_limit_too_small_for_any_crib_blocks_xor():
    report = analyze_bytes(build_decode_demo(), Limits.model_validate({"string_characters": 32}))
    xor_part = next(p for p in decode_run(report).components if p.name == "decode_xor")
    assert xor_part.status == "blocked"
    assert not any(f.component == "decode_xor" for f in decoded(report))


def test_engine_failure_keeps_other_sources(monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("simulated")

    monkeypatch.setattr("dissect.extractors.decode_xor.scan", broken)
    report = analyze_bytes(build_decode_demo())
    assert report.analysis.status == "partial"
    assert {"pe_header", "string", "import"} <= {f.kind for f in report.evidence}
    assert any(r.code == "extractor_failure" for r in report.extractor_errors)


# --- the public contract rejects incoherent decodings -----------------------


def payload():
    return json.loads(analyze_bytes(build_decode_demo()).model_dump_json())


def first(data, component):
    return next(f for f in data["evidence"] if f.get("component") == component)


@pytest.mark.parametrize(
    "tamper,reason",
    [
        (
            lambda d: first(d, "decode_strings").update(provenance={"evidence_ids": ["E1"]}),
            "cite the string at its own location",  # E1 is the PE header
        ),
        (
            lambda d: first(d, "decode_strings")["location"].update(offset=4000),
            "cite the string at its own location",
        ),
        (
            lambda d: first(d, "decode_xor")["location"].update(offset=10**6),
            "exceeds sample bounds",
        ),
        (
            lambda d: d["analysis"]["limits"]["decode"].update(xor=1),
            "decoded evidence exceeds effective quota",
        ),
    ],
)
def test_report_rejects_incoherent_decodings(tamper, reason):
    data = payload()
    tamper(data)
    with pytest.raises(ValueError, match=reason):
        Report.model_validate_json(json.dumps(data))


# --- the host does not trust the worker --------------------------------------


def forged_output(tamper):
    data = payload()
    tamper(data)
    report = Report.model_validate_json(json.dumps(data))  # still a valid report...
    return report.model_dump_json().encode()


@pytest.mark.parametrize(
    "tamper",
    [
        # a different, well-formed key for the same region
        lambda d: first(d, "decode_xor")["transform"].update(key_hex="a6"),
        # a well-formed decoded text of the same length that the bytes do not produce
        lambda d: first(d, "decode_strings")["data"].update(
            text="https://training.invalid/decode/base65",
            raw_hex=b"https://training.invalid/decode/base65".hex(),
        ),
    ],
)
def test_runner_rejects_decodings_that_do_not_reproduce(tamper):
    docker = FakeDocker(output=forged_output(tamper))
    with pytest.raises(DissectError) as caught:
        asyncio.run(run_isolated(build_decode_demo(), Limits(), docker))
    assert caught.value.code == "invalid_worker_output"


def test_runner_accepts_genuine_decodings():
    report = asyncio.run(run_isolated(build_decode_demo(), Limits(), FakeDocker()))
    assert len(decoded(report)) == len(EXPECTED)


def reused(data):
    return next(f for f in data["evidence"] if f.get("anchor") and f["anchor"]["crib"] == "http://")


@pytest.mark.parametrize(
    "tamper",
    [
        # cites a Base64 decoding instead of the XOR decoding that set the key
        lambda d: reused(d).update(provenance={"evidence_ids": [first(d, "decode_strings")["id"]]}),
        # cites an XOR decoding with a different key (the 1-byte a5 one)
        lambda d: reused(d).update(
            provenance={
                "evidence_ids": [
                    next(
                        f["id"]
                        for f in d["evidence"]
                        if f.get("transform", {}).get("key_hex") == "a5"
                    )
                ]
            }
        ),
    ],
)
def test_report_rejects_reused_keys_citing_the_wrong_decoding(tamper):
    data = payload()
    tamper(data)
    with pytest.raises(ValueError, match="reused XOR key must cite the decoding that set it"):
        Report.model_validate_json(json.dumps(data))
