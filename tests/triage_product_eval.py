import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
from collections import Counter
from dataclasses import asdict
from importlib.metadata import version
from pathlib import Path
from typing import Any
from uuid import uuid4

from lupabin.evidence import triage
from lupabin.evidence.models import Limits, Report
from lupabin.explain.engine import explain, validate
from lupabin.glossary.catalog import load_glossary
from lupabin.runner import IMAGE, container_args, remove_owned_container, run_isolated
from lupabin.transport import DockerCLI, Transport
from tests import triage_eval as readers

PARTS = {
    "pdb_reference": "debug_info",
    "certificate_entry": "certificates",
    "overlay": "overlay",
    "version_string": "version_info",
}
QUOTAS = {
    "pdb_reference": triage.PDBS,
    "certificate_entry": triage.CERTIFICATES,
    "overlay": triage.OVERLAYS,
    "version_string": triage.VERSION_STRINGS,
}
REFERENCE_GROUPS = {
    "pdb_reference": "codeview",
    "certificate_entry": "certificate_structure",
    "overlay": "overlay",
    "version_string": "version_strings",
}
MODULES = (
    "lupabin.evidence.triage",
    "lupabin.evidence.triage_checks",
    "lupabin.evidence.facts",
    "lupabin.evidence.models",
    "lupabin.evidence.primitives",
    "lupabin.evidence.collector",
    "lupabin.extractors.pe_triage",
    "lupabin.extractors.pe",
    "lupabin.runner",
    "lupabin.worker",
    "lupabin.explain.engine",
    "lupabin.explain.rules",
    "lupabin.explain.models",
)
RULES = {
    "debug.pdb@1",
    "debug.pdb_unnamed@1",
    "signature.certificates@1",
    "overlay.data@1",
    "version.strings@1",
}


def config(max_details: int, max_detail_bytes: int) -> readers.Config:
    return readers.Config(triage.BUDGETS, triage.RESOURCE_LIMITS, max_details, max_detail_bytes)


def fingerprint() -> dict[str, str]:
    root = Path(triage.__file__).resolve().parents[1]
    paths = {name: root.joinpath(*name.split(".")[1:]).with_suffix(".py") for name in MODULES}
    paths["product_evaluator"] = __file__
    paths["reader_evaluator"] = readers.__file__
    paths["triage_reader"] = readers.triage.__file__
    paths["resource_reader"] = readers.resources.__file__
    paths["pefile"] = readers.pefile.__file__
    return {key: hashlib.sha256(Path(path).read_bytes()).hexdigest() for key, path in paths.items()}


def combine(codes: list[int]) -> int:
    return 1 if 1 in codes else (2 if not codes or 2 in codes else 0)


def normalize_report(report: Report) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {kind: [] for kind in PARTS}
    for fact in report.evidence:
        if fact.kind not in PARTS:
            continue
        row = dict(offset=fact.location.offset, length=fact.location.length)
        data = fact.data.model_dump(mode="json")
        if fact.kind == "pdb_reference":
            row.update(
                index=data["debug_index"],
                guid=data["guid"],
                age=data["age"],
                path_hex=None if data["path"] is None else data["path"]["raw_hex"],
            )
        elif fact.kind == "certificate_entry":
            row.update(
                {
                    key: data[key]
                    for key in (
                        "index",
                        "revision",
                        "certificate_type",
                        "content_sha256",
                        "padding",
                    )
                }
            )
        elif fact.kind == "overlay":
            row["sha256"] = data["sha256"]
        else:
            row.update(
                {key: data[key] for key in ("language", "codepage", "key", "value", "raw_hex")}
            )
        result[fact.kind].append(row)
    return result


def projected(kind: str, rows: list[Any]) -> list[dict[str, Any]]:
    if kind == "pdb_reference":
        return [
            dict(
                offset=r["debug"]["pointer_to_raw_data"],
                length=r["record_length"],
                index=r["debug"]["index"],
                guid=r["guid"],
                age=r["age"],
                path_hex=r["path_raw"].hex() if r["path_raw"] else None,
            )
            for r in rows
        ]
    if kind == "certificate_entry":
        return [
            dict(
                offset=r["offset"],
                length=r["length"],
                index=r["index"],
                revision=r["revision"],
                certificate_type=r["certificate_type"],
                content_sha256=r["payload"]["sha256"],
                padding=r["padding_length"],
            )
            for r in rows
        ]
    if kind == "version_string":
        return [
            dict(
                offset=r["key_offset"] - 6,
                language=r["language"],
                codepage=r["codepage"],
                key=r["key_utf8"].decode("utf-8"),
                value=r["value_utf8"].decode("utf-8"),
            )
            for r in rows
        ]
    return rows


def expectations(data: bytes, limits: Limits, snapshot: readers.Snapshot) -> dict[str, Any]:
    result = {}
    for kind, group in REFERENCE_GROUPS.items():
        if kind == "version_string":
            continue
        observation = snapshot[group]
        result[kind] = dict(
            rows=[] if observation.value is None else projected(kind, observation.value),
            status=observation.status,
            reasons=list(observation.reasons),
            form_omissions=0,
        )
    read = readers.triage.read(data, budgets=triage.BUDGETS)
    if (
        read.layout is not None
        and read.certificates.status == "complete"
        and read.layout.security.address < read.layout.tail_offset
    ):
        result["certificate_entry"].update(
            rows=[],
            status="incomplete",
            reasons=["certificate_before_section_tail"],
            form_omissions=len(read.certificates.items),
        )
    parsed = triage.read_resources(data, read)
    if parsed is None:
        result["version_string"] = dict(
            rows=[],
            status="unavailable",
            reasons=["layout_unavailable"],
            form_omissions=None,
        )
    else:
        texts = triage.version_texts(data, parsed, limits.string_characters)
        found = [
            dict(
                offset=text.offset,
                length=len(text.raw),
                language=text.language,
                codepage=text.codepage,
                key=text.key,
                value=text.value,
                raw_hex=text.raw.hex(),
            )
            for text in texts.found
        ]
        result["version_string"] = dict(
            rows=found,
            status="incomplete" if texts.unread or texts.limited else "complete",
            reasons=list(snapshot["version_strings"].reasons),
            form_omissions=sum(len(v.strings) for v in parsed.versions) - len(found),
            unread=texts.unread,
            limited=texts.limited,
        )
    if snapshot["certificate_structure"].status != "complete":
        result["certificate_entry"]["rows"] = []
    return result


def reference_payload(data: bytes, limits: Limits, settings: readers.Config) -> dict[str, Any]:
    mine = readers.reader_snapshot(data, settings)
    theirs = readers.reference_snapshot(data, settings)
    reference = {}
    for kind, group in REFERENCE_GROUPS.items():
        observation = theirs[group]
        try:
            rows = [] if observation.value is None else projected(kind, observation.value)
            reference[kind] = dict(
                rows=rows, status=observation.status, reasons=observation.reasons
            )
        except (ValueError, TypeError, AttributeError):
            reference[kind] = dict(
                rows=[], status="unavailable", reasons=["projection_unavailable"]
            )
    return dict(
        sha256=hashlib.sha256(data).hexdigest(),
        fingerprints=fingerprint(),
        versions=dict(
            pefile=readers.pefile.__version__,
            report=Report.model_fields["schema_version"].default,
            python=readers.platform.python_version(),
            pydantic=version("pydantic"),
        ),
        readers=readers.compare(mine, theirs, settings),
        expected=expectations(data, limits, mine),
        reference=reference,
        limits=limits.model_dump(mode="json"),
        configuration=asdict(settings),
    )


def compare_rows(left: Any, right: Any, settings: readers.Config) -> dict[str, Any]:
    empty = {key: readers.Observation([]) for key in readers.GROUPS}
    mine, theirs = dict(empty), dict(empty)
    mine["overlay"] = readers.Observation(left)
    theirs["overlay"] = readers.Observation(right)
    return readers.compare(mine, theirs, settings)["groups"]["overlay"]


def assess(report: Report, payload: dict[str, Any], settings: readers.Config) -> dict[str, Any]:
    actual = normalize_report(report)
    coverage = {
        part.name: part.model_dump(mode="json")
        for run in report.extractor_runs
        if run.source == "pe"
        for part in run.components
    }
    groups = {}
    codes = [payload["readers"]["exit_code"]]
    for kind, component in PARTS.items():
        expected = payload["expected"][kind]
        reference = payload["reference"][kind]
        reasons = [
            issue.code
            for issue in (*report.extractor_errors, *report.limitations)
            if issue.source == "pe" and issue.component == component
        ]
        errors = [
            issue.code
            for issue in report.extractor_errors
            if issue.source == "pe" and issue.component == component
        ]
        rows = expected["rows"][: QUOTAS[kind]]
        quota_omitted = max(0, len(expected["rows"]) - len(rows))
        budget = any(reason in ("evidence_budget", "output_limit") for reason in reasons)
        comparable = expected["status"] == "complete" and not budget and not errors
        same = compare_rows(actual[kind], rows, settings) if comparable else None
        unexpected = []
        for item in actual[kind]:
            if item not in expected["rows"]:
                unexpected.append(item)
        independent = None
        if reference["status"] == "complete":
            by_offset = {item["offset"]: item for item in reference["rows"]}
            published = [
                {key: value for key, value in item.items() if key not in ("raw_hex", "length")}
                if kind == "version_string"
                else item
                for item in actual[kind]
            ]
            independent = compare_rows(
                published,
                [by_offset.get(item["offset"], {}) for item in actual[kind]],
                settings,
            )
        expected_partial = expected["status"] != "complete" or quota_omitted > 0 or budget
        part = coverage.get(component)
        coverage_difference = (
            part is None
            or (not errors and part["status"] == "complete" and expected_partial)
            or (not errors and not expected_partial and part["status"] != "complete")
        )
        differences = (
            (same["differences"] if same is not None else len(unexpected))
            + (independent["differences"] if independent else 0)
            + int(coverage_difference)
        )
        incomplete = (
            not comparable
            or expected_partial
            or reference["status"] != "complete"
            or part is None
            or part["status"] != "complete"
        )
        code = 1 if differences or errors else (2 if incomplete else 0)
        codes.append(code)
        groups[kind] = dict(
            exit_code=code,
            differences=differences,
            compared=(same["compared"] if same else 0)
            + (independent["compared"] if independent else 0),
            product_rows=len(actual[kind]),
            reader_candidates=len(expected["rows"]),
            reference_rows=len(reference["rows"]),
            quota=QUOTAS[kind],
            quota_omitted=quota_omitted,
            form_omissions=expected["form_omissions"],
            coverage=part,
            coverage_difference=coverage_difference,
            reasons=reasons,
            reader_status=expected["status"],
            reference_status=reference["status"],
            reader_reasons=[
                readers.detail(r, settings.max_detail_bytes)
                for r in expected["reasons"][: settings.max_details]
            ],
            reader_reasons_omitted=max(0, len(expected["reasons"]) - settings.max_details),
            reference_reasons=[
                readers.detail(r, settings.max_detail_bytes)
                for r in reference["reasons"][: settings.max_details]
            ],
            reference_reasons_omitted=max(0, len(reference["reasons"]) - settings.max_details),
            same_reader_completeness=same,
            independent_published_fields=independent,
            unexpected_rows=len(unexpected),
            reference_unpublished=max(0, len(reference["rows"]) - len(actual[kind])),
        )
    return dict(
        exit_code=combine(codes),
        groups=groups,
        compared=sum(g["compared"] for g in groups.values()),
        differences=sum(g["differences"] for g in groups.values()),
    )


def check_explanations(report: Report, explanation: Any = None) -> dict[str, Any]:
    glossary = load_glossary()
    explanation = explain(report, glossary) if explanation is None else explanation
    regenerated = validate(explanation, report, glossary)
    if len(regenerated) != len(explanation.items):
        raise ValueError("explanation_items_not_supported_by_citations")
    wanted = {fact.id for fact in report.evidence if fact.kind in PARTS}
    cited = {ref for item in explanation.items if item.rule in RULES for ref in item.evidence_ids}
    if wanted != cited:
        raise ValueError("triage_explanation_coverage")
    return dict(
        status="validated_by_regeneration",
        independent_oracle=False,
        items=sum(item.rule in RULES for item in explanation.items),
        facts=len(wanted),
        cited_facts=len(cited),
        glossary=explanation.glossary.model_dump(mode="json"),
    )


class RecordingTransport:
    def __init__(self, delegate: Transport):
        self.delegate = delegate
        self.image_ids: list[str] = []

    async def run(self, args: tuple[str, ...], **kwargs: Any) -> Any:
        result = await self.delegate.run(args, **kwargs)
        if args[:2] == ("image", "inspect") and result.code == 0:
            self.image_ids.append(result.stdout.strip().decode("ascii"))
        return result


def reference_args(
    name: str, image: str, limits: Limits, settings: readers.Config
) -> tuple[str, ...]:
    prefix = container_args(name, image, limits)[:-3]
    mounts = []
    for filename in ("__init__.py", "triage_eval.py", "triage_product_eval.py"):
        path = Path(__file__).resolve().parent / filename
        if "," in str(path):
            raise ValueError("mount_path_contains_comma")
        mounts.extend(
            ("--mount", f"type=bind,source={path},target=/evaluation/tests/{filename},readonly")
        )
    return (
        *prefix,
        *mounts,
        "--env",
        "PYTHONPATH=/evaluation",
        "--entrypoint",
        "/app/.venv/bin/python",
        image,
        "-m",
        "tests.triage_product_eval",
        "--reference-worker",
        "--limits-json",
        limits.model_dump_json(),
        "--max-details",
        str(settings.max_details),
        "--max-detail-bytes",
        str(settings.max_detail_bytes),
    )


async def isolated_reference(
    data: bytes,
    limits: Limits,
    settings: readers.Config,
    transport: Transport,
    image: str,
) -> dict[str, Any]:
    if re.fullmatch(r"sha256:[a-f0-9]{64}", image) is None:
        raise ValueError("image_digest_required")
    name = "lupabin-" + uuid4().hex
    try:
        created = await transport.run(reference_args(name, image, limits, settings))
        if created.code != 0:
            raise RuntimeError("reference_worker_create_failed")
        response = await transport.run(
            ("start", "--attach", "--interactive", name),
            data=data,
            timeout=limits.timeout_seconds,
            limit=limits.output_bytes,
        )
        if response.code != 0:
            raise RuntimeError("reference_worker_failed")
        payload = json.loads(response.stdout)
        if (
            payload["sha256"] != hashlib.sha256(data).hexdigest()
            or payload["fingerprints"] != fingerprint()
            or payload["limits"] != limits.model_dump(mode="json")
            or payload["configuration"] != asdict(settings)
        ):
            raise ValueError("reference_identity_mismatch")
        return payload
    finally:
        await remove_owned_container(transport, name)


async def evaluate(
    data: bytes,
    limits: Limits,
    settings: readers.Config,
    transport: Transport,
) -> dict[str, Any]:
    if len(data) > min(limits.input_bytes, settings.triage.max_input_bytes):
        return dict(exit_code=2, sha256=None, reason="input_bytes_limit", compared=0, differences=0)
    digest = hashlib.sha256(data).hexdigest()
    recording = RecordingTransport(transport)
    result: dict[str, Any] = dict(
        sha256=digest,
        compared=0,
        differences=0,
        exit_code=1,
        host_verification=dict(status="not_completed", independent_oracle=False),
    )
    stage = "production_report_and_host_verification"
    try:
        report = await run_isolated(data, limits, recording)
        result["host_verification"]["status"] = "passed_in_run_isolated"
        result["report"] = dict(
            sha256=hashlib.sha256(report.model_dump_json().encode()).hexdigest(),
            schema_version=report.schema_version,
            analysis_status=report.analysis.status,
            extractor_runs=[run.model_dump(mode="json") for run in report.extractor_runs],
            extractor_errors=[item.model_dump(mode="json") for item in report.extractor_errors],
            limitations=[item.model_dump(mode="json") for item in report.limitations],
        )
        stage = "explanations"
        result["explanations"] = check_explanations(report)
        image = recording.image_ids[-1]
        result["image_id"] = image
        stage = "isolated_reference"
        payload = await isolated_reference(data, limits, settings, recording, image)
        stage = "product_comparison"
        result["readers"] = payload["readers"]
        result["reference_versions"] = payload["versions"]
        product = assess(report, payload, settings)
        result["product"] = product
        result["compared"] = product["compared"] + payload["readers"]["compared"]
        result["differences"] = product["differences"] + payload["readers"]["differences"]
        result["exit_code"] = combine(
            [
                product["exit_code"],
                1
                if report.extractor_errors
                else (2 if report.analysis.status != "completed" else 0),
            ]
        )
    except Exception as error:
        result["failure"] = dict(
            stage=stage,
            type=type(error).__name__,
            code=getattr(error, "code", None),
            reason=readers.detail(str(error), settings.max_detail_bytes),
        )
        result["exit_code"] = 1
    if recording.image_ids:
        result["image_id"] = recording.image_ids[-1]
    return result


def provenance(settings: readers.Config, limits: Limits, selected: list[Path]) -> dict[str, Any]:
    result = readers.provenance(settings, selected)
    result.update(
        mode="product",
        product_fingerprints=fingerprint(),
        limits=limits.model_dump(mode="json"),
        product_versions=dict(
            schema=Report.model_fields["schema_version"].default,
            pydantic=version("pydantic"),
        ),
        image=IMAGE,
        quotas=QUOTAS,
        exact_forms=dict(
            version_key_characters=triage.VERSION_KEY_CHARACTERS,
            version_block_bytes=triage.VERSION_BLOCK_BYTES,
            version_value_characters=limits.string_characters,
        ),
        comparison_scope=dict(
            host="production run_isolated verification; same readers, not independent",
            completeness="same-reader exact forms and quotas; not an independent policy oracle",
            reference=(
                "pefile published fields; certificates structural only, no certificate oracle"
            ),
            version_reference_excluded=[
                "raw block grammar",
                "block length",
                "resource/table identity",
            ],
            explanations="regeneration and citation coverage; not independent semantic review",
            execution=(
                "sequential production worker then isolated reference worker; "
                "no host parser fallback"
            ),
        ),
    )
    return result


async def run(
    selected: list[Path],
    output: Path,
    settings: readers.Config,
    limits: Limits,
) -> int:
    if not selected or output.resolve() in [p.resolve() for p in selected]:
        raise ValueError("explicit inputs and a distinct new output are required")
    counts: Counter[int] = Counter()
    compared = differences = 0
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(provenance(settings, limits, selected), ensure_ascii=True) + "\n")
        for index, path in enumerate(selected):
            size = None
            digest = None
            try:
                if not path.is_file():
                    raise OSError("not_a_regular_file")
                size = path.stat().st_size
                cap = min(limits.input_bytes, settings.triage.max_input_bytes)
                if size > cap:
                    result = dict(
                        exit_code=2,
                        sha256=None,
                        reason="input_bytes_limit",
                        compared=0,
                        differences=0,
                    )
                else:
                    with path.open("rb") as source:
                        data = source.read(cap + 1)
                    if len(data) > cap:
                        result = dict(
                            exit_code=2,
                            sha256=None,
                            reason="input_bytes_limit",
                            compared=0,
                            differences=0,
                        )
                    else:
                        digest = hashlib.sha256(data).hexdigest()
                        result = await evaluate(data, limits, settings, DockerCLI())
            except Exception as error:
                result = dict(
                    exit_code=1,
                    sha256=digest,
                    reason=type(error).__name__,
                    compared=0,
                    differences=0,
                )
            counts[result["exit_code"]] += 1
            compared += result["compared"]
            differences += result["differences"]
            stream.write(
                json.dumps(
                    dict(
                        type="file",
                        index=index,
                        path=str(path.resolve()),
                        size=size,
                        **result,
                    ),
                    ensure_ascii=True,
                )
                + "\n"
            )
            stream.flush()
        code = combine(list(counts))
        stream.write(
            json.dumps(
                dict(
                    type="summary",
                    exit_code=code,
                    files=len(selected),
                    statuses=dict(counts),
                    compared=compared,
                    differences=differences,
                )
            )
            + "\n"
        )
    return code


def review_saved(path: Path) -> dict[str, Any]:
    causes: Counter[str] = Counter()
    cases = []
    omitted = 0
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for line in stream:
            digest.update(line)
            record = json.loads(line)
            if record.get("type") != "file":
                continue
            group = record.get("groups", {}).get("version_strings")
            if group is None or group["status"] == "match":
                continue
            reasons = [r.get("text", "") for r in group["reasons"]]
            kinds = sorted({r.rsplit(":", 1)[-1] for r in reasons})
            causes.update(kinds)
            omitted += group["reasons_omitted"]
            cases.append(
                dict(
                    index=record["index"],
                    name=record["path"].replace("\\", "/").rsplit("/", 1)[-1],
                    sha256=record.get("sha256"),
                    reader=group["reader_status"],
                    reference=group["reference_status"],
                    reader_rows=group["reader_rows"],
                    reference_rows=group["reference_rows"],
                    reasons=reasons,
                    reasons_omitted=group["reasons_omitted"],
                    compared=group["compared"],
                )
            )
    return dict(
        source_sha256=digest.hexdigest(),
        cases=len(cases),
        causes=dict(causes),
        reasons_omitted=omitted,
        records=cases,
        scope="saved JSONL only; no sample access, no product measurement",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Isolated product triage evaluation; no execution of samples."
    )
    parser.add_argument("--files", nargs="+", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--limits-json")
    parser.add_argument("--max-details", type=int)
    parser.add_argument("--max-detail-bytes", type=int)
    parser.add_argument("--reference-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--review-jsonl", type=Path)
    args = parser.parse_args(argv)
    if args.review_jsonl:
        summary = review_saved(args.review_jsonl)
        summary["records"] = [
            {key: value for key, value in row.items() if key not in ("sha256",)}
            for row in summary["records"]
        ]
        print(json.dumps(summary, ensure_ascii=True))
        return 0
    if args.limits_json is None or args.max_details is None or args.max_detail_bytes is None:
        parser.error("explicit --limits-json, --max-details and --max-detail-bytes are required")
    settings = config(args.max_details, args.max_detail_bytes)
    limits = Limits.model_validate_json(args.limits_json)
    if args.reference_worker:
        if (
            sys.platform != "linux"
            or os.environ.get("LUPABIN_WORKER") != "1"
            or os.getuid() == 0
            or not Path("/.dockerenv").exists()
        ):
            parser.error("reference parsing requires the isolated non-root Docker worker")
        data = sys.stdin.buffer.read(min(limits.input_bytes, settings.triage.max_input_bytes) + 1)
        if len(data) > min(limits.input_bytes, settings.triage.max_input_bytes):
            return 2
        print(json.dumps(reference_payload(data, limits, settings), ensure_ascii=True))
        return 0
    if not args.files or args.output is None:
        parser.error("--files and --output are required")
    return asyncio.run(run(args.files, args.output, settings, limits))


if __name__ == "__main__":
    raise SystemExit(main())
