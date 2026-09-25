import json

import pytest

from lupabin.analysis import analyze_bytes
from lupabin.evidence.models import Limits, Report
from tests.fixtures.pe_builder import build_demo, build_pe


def yara_run(report):
    return next(run for run in report.extractor_runs if run.source == "yara")


def yara_payload(payload):
    return next(run for run in payload["extractor_runs"] if run["source"] == "yara")


def test_default_pipeline_has_five_sources_and_yara_evidence():
    report = analyze_bytes(build_demo())
    assert report.schema_version == "0.7.0"
    assert [run.source for run in report.extractor_runs] == [
        "pe",
        "strings",
        "yara",
        "decode",
        "code",
    ]
    assert report.analysis.status == "completed"
    match = next(f for f in report.evidence if f.kind == "yara_match")
    assert match.location is None
    assert match.provenance.evidence_ids == ()
    assert match.data.rule_id == "lupabin_training_marker"
    assert match.data.instances[0].offset == 2304
    assert report.yara_context.catalog.ruleset_sha256 == match.data.ruleset_sha256


def test_no_match_is_success_not_security_verdict():
    report = analyze_bytes(build_pe())
    assert yara_run(report).status == "completed"
    assert not any(f.kind == "yara_match" for f in report.evidence)
    assert report.yara_context.catalog
    assert "verdict" not in report.model_dump()


def test_native_failure_keeps_previous_extractors(monkeypatch):
    from lupabin.rules.process import YaraProcessError

    async def failed(*args, **kwargs):
        raise YaraProcessError("yara_timeout")

    monkeypatch.setattr("lupabin.extractors.yara.scan_child", failed)
    report = analyze_bytes(build_demo())
    assert report.analysis.status == "partial"
    assert {"pe_header", "string", "import"} <= {f.kind for f in report.evidence}
    assert not any(f.kind == "yara_match" for f in report.evidence)
    assert yara_run(report).status == "failed"
    assert all(part.examined is None for part in yara_run(report).components)
    assert report.yara_context.module_version is None


def test_unknown_type_can_have_rule_matches_without_claiming_pe_support():
    report = analyze_bytes(b"LUPABIN PRACTICE")
    assert report.sample.type == "unknown"
    assert report.analysis.status == "partial"
    assert any(f.kind == "yara_match" for f in report.evidence)


def test_limited_representation_is_partial():
    limits = Limits.model_validate_json('{"yara":{"instances":1}}')
    report = analyze_bytes(build_pe() + b"LUPABIN PRACTICE\0" * 20, limits)
    match = next(f for f in report.evidence if f.kind == "yara_match")
    assert match.data.omitted_instances == 19
    assert report.analysis.status == "partial"
    assert any(r.code == "yara_instance_limit" for r in report.limitations)


def test_interrupted_scan_cannot_publish_yara_matches():
    payload = json.loads(analyze_bytes(build_demo()).model_dump_json())
    payload["analysis"]["status"] = "partial"
    run = yara_payload(payload)
    run["status"] = "partial"
    run["components"][1]["status"] = "partial"
    payload["extractor_errors"].append(
        {"source": "yara", "component": "yara_scan", "code": "yara_timeout"}
    )
    with pytest.raises(ValueError):
        Report.model_validate_json(json.dumps(payload))


def test_complete_scan_count_must_match_catalog_inventory():
    payload = json.loads(analyze_bytes(build_demo()).model_dump_json())
    yara_payload(payload)["components"][1]["examined"] = 0
    with pytest.raises(ValueError):
        Report.model_validate_json(json.dumps(payload))


def test_public_contract_rejects_fabricated_rule_identity():
    payload = json.loads(analyze_bytes(build_demo()).model_dump_json())
    item = next(f for f in payload["evidence"] if f["kind"] == "yara_match")
    item["data"]["source_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        Report.model_validate_json(json.dumps(payload))
