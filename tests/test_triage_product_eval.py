import asyncio
import hashlib
import json
from pathlib import Path

import pytest

from lupabin.analysis import analyze_bytes
from lupabin.errors import LupaBinError
from lupabin.evidence.models import Limits, Report
from lupabin.evidence.triage_checks import verify_triage
from lupabin.explain.engine import explain
from lupabin.extractors.pe import PEExtractor
from lupabin.glossary.catalog import load_glossary
from lupabin.transport import Completed
from tests import triage_product_eval as evaluation
from tests.fixtures.pe_builder import build_demo
from tests.test_pe_resources import _block
from tests.test_pe_triage import _certificate
from tests.test_triage import _gap_certificate, build, changed

SETTINGS = evaluation.config(2, 48)
LIMITS = Limits()
IMAGE_ID = "sha256:" + "a" * 64


def synthetic(data):
    report = analyze_bytes(data, extractors=[PEExtractor()])
    return report, evaluation.reference_payload(data, LIMITS, SETTINGS)


def without_fact(report, kind):
    document = report.model_dump(mode="json")
    removed = next(f for f in document["evidence"] if f["kind"] == kind)
    document["evidence"].remove(removed)
    ids = {fact["id"]: f"E{index}" for index, fact in enumerate(document["evidence"], 1)}
    for fact in document["evidence"]:
        fact["id"] = ids[fact["id"]]
        fact["provenance"]["evidence_ids"] = [
            ids[ref] for ref in fact["provenance"]["evidence_ids"]
        ]
    for run in document["extractor_runs"]:
        if run["source"] == removed["source"]:
            run["evidence_count"] -= 1
            for part in run["components"]:
                if part["name"] == removed["component"]:
                    part["evidence_count"] -= 1
    return Report.model_validate_json(json.dumps(document))


def test_certificate_without_independent_oracle_never_reports_zero():
    report, payload = synthetic(build())
    result = evaluation.assess(report, payload, SETTINGS)
    assert result["exit_code"] == 2
    assert result["differences"] == 0
    assert set(payload["readers"]["groups"]) == set(evaluation.readers.GROUPS)
    assert payload["readers"]["groups"]["certificate_oracle"]["status"] == "unavailable"
    assert result["groups"]["certificate_entry"]["product_rows"] == 1
    assert evaluation.check_explanations(report)["independent_oracle"] is False


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("count", [1, 2])
def test_gap_certificate_abstention_is_a_form_omission_not_a_difference(bits, count):
    data = bytes(_gap_certificate(bits, _certificate(b"invented") * count).data)
    report, payload = synthetic(data)
    result = evaluation.assess(report, payload, SETTINGS)
    row = result["groups"]["certificate_entry"]
    assert row["differences"] == 0
    assert row["exit_code"] == 2
    assert row["product_rows"] == 0
    assert row["form_omissions"] == count
    assert row["coverage"]["status"] == "partial"
    assert row["reasons"] == ["triage_unreadable"]
    assert not row["coverage_difference"]
    assert result["groups"]["overlay"]["differences"] == 0


def test_empty_unsigned_triage_is_comparable_not_missing():
    report, payload = synthetic(build_demo())
    result = evaluation.assess(report, payload, SETTINGS)
    assert result["exit_code"] == 0
    assert result["differences"] == 0
    assert all(group["product_rows"] == 0 for group in result["groups"].values())


@pytest.mark.parametrize(
    "kind,changes",
    [
        ("pdb_reference", {"data.debug_index": 1}),
        ("version_string", {"data.language": 0x0C0A}),
        ("certificate_entry", {"data.content_sha256": "0" * 64}),
        ("overlay", {"data.sha256": "0" * 64}),
    ],
)
def test_altered_valid_fact_is_a_difference_and_host_rejects(kind, changes):
    data = build()
    report, payload = synthetic(data)
    altered = Report.model_validate_json(changed(report, kind, **changes))
    with pytest.raises(ValueError):
        verify_triage(altered.evidence, data, LIMITS.string_characters)
    result = evaluation.assess(altered, payload, SETTINGS)
    assert result["exit_code"] == 1
    assert result["groups"][kind]["differences"] > 0


@pytest.mark.parametrize("kind", tuple(evaluation.PARTS))
def test_omitted_fact_is_detected_even_when_host_membership_verification_passes(kind):
    data = build()
    report, payload = synthetic(data)
    altered = without_fact(report, kind)
    verify_triage(altered.evidence, data, LIMITS.string_characters)
    result = evaluation.assess(altered, payload, SETTINGS)
    assert result["exit_code"] == 1
    assert result["groups"][kind]["same_reader_completeness"]["differences"] > 0


def test_quota_omission_is_not_a_false_difference_or_complete_measurement():
    data = build(strings=tuple((f"Key{i}", "value") for i in range(65)))
    report, payload = synthetic(data)
    result = evaluation.assess(report, payload, SETTINGS)
    row = result["groups"]["version_string"]
    assert (row["product_rows"], row["reader_candidates"], row["quota_omitted"]) == (64, 65, 1)
    assert row["coverage"]["status"] == "partial"
    assert row["exit_code"] == 2
    assert row["differences"] == 0
    assert not row["coverage_difference"]


@pytest.mark.parametrize("kind,quota", tuple(evaluation.QUOTAS.items()))
def test_each_fixed_product_quota_is_recorded_with_explicit_omission(kind, quota):
    report, payload = synthetic(build_demo())
    rows = [dict(offset=i, length=1) for i in range(quota + 1)]
    payload["expected"][kind]["rows"] = rows
    payload["reference"][kind]["status"] = "unavailable"
    result = evaluation.assess(report, payload, SETTINGS)
    assert result["groups"][kind]["quota"] == quota
    assert result["groups"][kind]["quota_omitted"] == 1
    assert result["groups"][kind]["coverage_difference"]
    assert result["exit_code"] == 1


def test_exact_form_and_unread_version_remain_explicit():
    bad = _block("Comments", "no terminator".encode("utf-16-le"))
    report, payload = synthetic(build(raw_strings=(bad,)))
    row = evaluation.assess(report, payload, SETTINGS)["groups"]["version_string"]
    assert row["exit_code"] == 2
    assert row["form_omissions"] == 1
    assert row["reader_status"] == "incomplete"
    assert row["same_reader_completeness"] is None
    assert row["differences"] == 0


def test_long_version_value_is_a_form_omission_not_a_mismatch():
    report, payload = synthetic(build(strings=(("Comments", "x" * 1025),)))
    row = evaluation.assess(report, payload, SETTINGS)["groups"]["version_string"]
    assert row["product_rows"] == 0
    assert row["form_omissions"] == 1
    assert row["exit_code"] == 2
    assert row["differences"] == 0


def test_missing_reference_is_not_independent_confirmation():
    report, payload = synthetic(build_demo())
    payload["reference"]["overlay"].update(status="unavailable", reasons=["no_reference"])
    result = evaluation.assess(report, payload, SETTINGS)
    assert result["exit_code"] == 2
    assert result["groups"]["overlay"]["independent_published_fields"] is None


def test_reference_alteration_is_not_hidden_by_same_reader_agreement():
    report, payload = synthetic(build())
    payload["reference"]["pdb_reference"]["rows"][0]["age"] += 1
    result = evaluation.assess(report, payload, SETTINGS)
    row = result["groups"]["pdb_reference"]
    assert row["same_reader_completeness"]["differences"] == 0
    assert row["independent_published_fields"]["differences"] == 1
    assert result["exit_code"] == 1


def test_extractor_failure_is_failure_not_an_empty_match():
    report, payload = synthetic(build_demo())
    document = report.model_dump(mode="json")
    document["extractor_errors"].append(
        dict(
            source="pe",
            component="debug_info",
            code="extractor_failure",
        )
    )
    document["analysis"]["status"] = "partial"
    document["extractor_runs"][0]["status"] = "partial"
    for part in document["extractor_runs"][0]["components"]:
        if part["name"] == "debug_info":
            part["status"] = "blocked"
    result = evaluation.assess(Report.model_validate_json(json.dumps(document)), payload, SETTINGS)
    assert result["exit_code"] == 1
    assert result["groups"]["pdb_reference"]["differences"] == 0
    assert "extractor_failure" in result["groups"]["pdb_reference"]["reasons"]


def test_existing_citation_without_support_fails_regeneration():
    report, _ = synthetic(build())
    explanation = explain(report, load_glossary())
    item = next(i for i in explanation.items if i.rule == "debug.pdb@1")
    unrelated = next(f.id for f in report.evidence if f.kind == "overlay")
    altered = explanation.model_copy(
        update={
            "items": tuple(
                i.model_copy(update={"evidence_ids": (*i.evidence_ids, unrelated)})
                if i.id == item.id
                else i
                for i in explanation.items
            )
        }
    )
    with pytest.raises(ValueError):
        evaluation.check_explanations(report, altered)


def test_existing_citations_do_not_validate_an_altered_statement():
    report, _ = synthetic(build())
    explanation = explain(report, load_glossary())
    target = next(i for i in explanation.items if i.rule == "debug.pdb@1")
    altered = explanation.model_copy(
        update={
            "items": tuple(
                item.model_copy(update={"statement": "Unsupported invented claim"})
                if item.id == target.id
                else item
                for item in explanation.items
            )
        }
    )
    with pytest.raises(ValueError, match="not_supported_by_citations"):
        evaluation.check_explanations(report, altered)


class TransportDouble:
    def __init__(self, payload=None, fail=False):
        self.calls = []
        self.payload = payload
        self.fail = fail

    async def run(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args[0] == "create":
            self.name = args[args.index("--name") + 1]
        if args[:2] == ("container", "inspect"):
            return Completed(0, self.name.encode(), b"")
        if args[0] == "start":
            return Completed(1 if self.fail else 0, json.dumps(self.payload).encode(), b"")
        return Completed(0, b"", b"")


def test_isolated_reference_keeps_resource_network_user_and_read_only_controls():
    args = evaluation.reference_args("lupabin-test", IMAGE_ID, LIMITS, SETTINGS)
    for flag in (
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--user=65532:65532",
        "--memory=536870912",
        "--memory-swap=536870912",
        "--cpus=1",
        "--pids-limit=64",
    ):
        assert flag in args
    prefix = evaluation.container_args("lupabin-test", IMAGE_ID, LIMITS)[:-3]
    assert args[: len(prefix)] == prefix
    mounts = [args[index + 1] for index, value in enumerate(args) if value == "--mount"]
    directory = Path(evaluation.__file__).resolve().parent
    assert mounts == [
        f"type=bind,source={directory / name},target=/evaluation/tests/{name},readonly"
        for name in ("__init__.py", "triage_eval.py", "triage_product_eval.py")
    ]
    assert not any("docker.sock" in value or "artifacts" in value for value in args)
    assert "--volume" not in args and "-v" not in args
    assert "--entrypoint" in args
    assert IMAGE_ID in args
    assert args[-1] == str(SETTINGS.max_detail_bytes)


@pytest.mark.parametrize("tamper", ["sha256", "fingerprints", "limits", "configuration"])
def test_reference_identity_failure_is_not_accepted_and_container_is_removed(tamper):
    data = build_demo()
    _, payload = synthetic(data)
    payload[tamper] = None
    transport = TransportDouble(payload)
    with pytest.raises(ValueError, match="identity_mismatch"):
        asyncio.run(evaluation.isolated_reference(data, LIMITS, SETTINGS, transport, IMAGE_ID))
    assert transport.calls[-1][0][:3] == ("container", "rm", "--force")


@pytest.mark.parametrize("image", [evaluation.IMAGE, "sha256:short", "", "a" * 64])
def test_reference_requires_image_digest_before_any_container_call(image):
    transport = TransportDouble()
    with pytest.raises(ValueError, match="image_digest_required"):
        asyncio.run(evaluation.isolated_reference(b"synthetic", LIMITS, SETTINGS, transport, image))
    assert transport.calls == []


def test_reference_keeps_metadata_from_a_different_interpreter():
    data = build_demo()
    _, payload = synthetic(data)
    payload["versions"]["python"] = "3.13.0-synthetic"
    payload["versions"]["pydantic"] = "2.11.0-synthetic"
    transport = TransportDouble(payload)
    accepted = asyncio.run(
        evaluation.isolated_reference(data, LIMITS, SETTINGS, transport, IMAGE_ID)
    )
    assert accepted["versions"] == payload["versions"]
    assert accepted["fingerprints"] == evaluation.fingerprint()
    start = next(kwargs for args, kwargs in transport.calls if args[0] == "start")
    assert start == dict(data=data, timeout=LIMITS.timeout_seconds, limit=LIMITS.output_bytes)
    assert transport.calls[-1][0][:3] == ("container", "rm", "--force")


def test_reference_failure_never_falls_back_to_host(monkeypatch):
    def forbidden(*args):
        pytest.fail("host reference parser called")

    monkeypatch.setattr(evaluation, "reference_payload", forbidden)
    transport = TransportDouble(fail=True)
    with pytest.raises(RuntimeError, match="reference_worker_failed"):
        asyncio.run(
            evaluation.isolated_reference(b"synthetic", LIMITS, SETTINGS, transport, IMAGE_ID)
        )
    assert transport.calls[-1][0][:3] == ("container", "rm", "--force")


def test_product_failure_is_recorded_without_bypassing_run_isolated(monkeypatch):
    async def failed(*args):
        raise LupaBinError("invalid_worker_output")

    def forbidden(*args):
        pytest.fail("host parser called")

    monkeypatch.setattr(evaluation, "run_isolated", failed)
    monkeypatch.setattr(evaluation, "reference_payload", forbidden)
    result = asyncio.run(evaluation.evaluate(b"synthetic", LIMITS, SETTINGS, TransportDouble()))
    assert result["exit_code"] == 1
    assert result["failure"]["code"] == "invalid_worker_output"
    assert result["failure"]["stage"] == "production_report_and_host_verification"
    assert result["compared"] == 0 and result["differences"] == 0
    assert result["host_verification"]["status"] == "not_completed"
    assert result["sha256"] == hashlib.sha256(b"synthetic").hexdigest()


def test_real_file_interface_only_calls_production_api_and_isolated_reference(monkeypatch):
    data = build_demo()
    report, payload = synthetic(data)
    payload["versions"]["python"] = "3.13.0-synthetic"
    calls = []

    async def product(raw, limits, transport):
        calls.append(("product", raw))
        transport.image_ids.append(IMAGE_ID)
        return report

    async def reference(raw, *args):
        calls.append(("reference", raw))
        return payload

    monkeypatch.setattr(evaluation, "run_isolated", product)
    monkeypatch.setattr(evaluation, "isolated_reference", reference)
    result = asyncio.run(evaluation.evaluate(data, LIMITS, SETTINGS, TransportDouble()))
    assert calls == [("product", data), ("reference", data)]
    assert result["exit_code"] == 0
    assert result["image_id"] == IMAGE_ID
    assert result["reference_versions"]["python"] == "3.13.0-synthetic"
    assert result["host_verification"]["independent_oracle"] is False
    assert result["explanations"]["status"] == "validated_by_regeneration"


def test_oversized_input_does_not_invoke_production_or_reference(monkeypatch):
    async def forbidden(*args):
        pytest.fail("worker called for oversized input")

    monkeypatch.setattr(evaluation, "run_isolated", forbidden)
    monkeypatch.setattr(evaluation, "isolated_reference", forbidden)
    limits = Limits(input_bytes=2)
    result = asyncio.run(evaluation.evaluate(b"three", limits, SETTINGS, TransportDouble()))
    assert result["exit_code"] == 2
    assert result["sha256"] is None
    assert result["compared"] == 0


def test_exclusive_output_happens_before_provenance(tmp_path, monkeypatch):
    output = tmp_path / "keep.jsonl"
    output.write_text("keep", encoding="utf-8")

    def forbidden(*args):
        pytest.fail("provenance before exclusive output")

    monkeypatch.setattr(evaluation, "provenance", forbidden)
    with pytest.raises(FileExistsError):
        asyncio.run(evaluation.run([tmp_path / "x"], output, SETTINGS, LIMITS))
    assert output.read_text(encoding="utf-8") == "keep"


def test_unreadable_file_is_logged_and_makes_run_fail(tmp_path):
    output = tmp_path / "new.jsonl"
    assert asyncio.run(evaluation.run([tmp_path / "missing"], output, SETTINGS, LIMITS)) == 1
    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [row["type"] for row in records] == ["config", "file", "summary"]
    assert records[1]["sha256"] is None
    assert records[1]["compared"] == 0
    assert records[1]["exit_code"] == 1
    assert set(records[0]["fingerprints"]) == {"triage", "resources", "reference", "evaluator"}
    assert records[0]["quotas"] == evaluation.QUOTAS
    assert records[0]["budgets_measured"] is False


def test_summary_distinguishes_two_io_failures_from_missing_oracle_and_differences(
    tmp_path,
    monkeypatch,
):
    paths = [tmp_path / name for name in ("vanished.bin", "denied.bin", "no-oracle.bin")]
    for path in paths:
        path.write_bytes(b"synthetic")
    original = Path.open

    def guarded(path, *args, **kwargs):
        if path == paths[0]:
            raise FileNotFoundError("synthetic removal")
        if path == paths[1]:
            raise PermissionError("synthetic access denial")
        return original(path, *args, **kwargs)

    async def unavailable(data, *args):
        return dict(
            exit_code=2,
            sha256=hashlib.sha256(data).hexdigest(),
            reason="pefile_has_no_certificate_parser",
            compared=4,
            differences=0,
        )

    monkeypatch.setattr(Path, "open", guarded)
    monkeypatch.setattr(evaluation, "DockerCLI", TransportDouble)
    monkeypatch.setattr(evaluation, "evaluate", unavailable)
    output = tmp_path / "mixed.jsonl"
    assert asyncio.run(evaluation.run(paths, output, SETTINGS, LIMITS)) == 1
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [row["reason"] for row in rows[1:4]] == [
        "FileNotFoundError",
        "PermissionError",
        "pefile_has_no_certificate_parser",
    ]
    assert [row["exit_code"] for row in rows[1:4]] == [1, 1, 2]
    assert rows[-1]["statuses"] == {"1": 2, "2": 1}
    assert rows[-1]["exit_code"] == 1
    assert rows[-1]["differences"] == 0
    assert rows[-1]["compared"] == 4


def test_saved_review_never_opens_recorded_sample_and_keeps_truncation(tmp_path, monkeypatch):
    source = tmp_path / "saved.jsonl"
    group = dict(
        status="unavailable",
        reader_status="incomplete",
        reference_status="complete",
        reader_rows=0,
        reference_rows=8,
        compared=0,
        reasons_omitted=5,
        reasons=[dict(text="resource[3]:version_payload:92:invalid_version_container")],
    )
    source.write_text(
        json.dumps(
            dict(
                type="file",
                index=1,
                path="Z:\\DO_NOT_OPEN.exe",
                sha256="a" * 64,
                groups=dict(version_strings=group),
            )
        )
        + "\n",
        encoding="utf-8",
    )
    original = Path.open

    def guarded(path, *args, **kwargs):
        assert path == source
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded)
    result = evaluation.review_saved(source)
    assert result["cases"] == 1
    assert result["causes"] == {"invalid_version_container": 1}
    assert result["reasons_omitted"] == 5
    assert result["records"][0]["compared"] == 0


def test_reference_worker_cli_is_not_an_unisolated_parser_option(monkeypatch):
    monkeypatch.delenv("LUPABIN_WORKER", raising=False)
    with pytest.raises(SystemExit) as error:
        evaluation.main(
            [
                "--reference-worker",
                "--limits-json",
                "{}",
                "--max-details",
                "2",
                "--max-detail-bytes",
                "48",
            ]
        )
    assert error.value.code == 2
