import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from dissect.evidence.facts import ImportEvidence
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
from dissect.evidence.primitives import COMPONENTS


def report_dict():
    return {
        "schema_version": "0.2.0",
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
