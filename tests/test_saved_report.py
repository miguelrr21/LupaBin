import asyncio
import json

import pytest

from lupabin.analysis import analyze_bytes
from lupabin.errors import LupaBinError
from lupabin.evidence.models import Limits, Report
from lupabin.ingest.reader import from_bytes
from lupabin.runner import run_isolated
from lupabin.saved_report import check_against_sample
from tests.fixtures.pe_builder import DOTNET_URL, build_dotnet_demo, build_pe
from tests.test_runner import FakeDocker


@pytest.mark.parametrize("encoding", ["ascii", "utf-16-le"])
@pytest.mark.parametrize("entrypoint", ["saved", "worker"])
def test_literal_bytes_are_verified_even_when_a_forged_report_is_structurally_valid(
    encoding, entrypoint
):
    literal = "LUPABIN LITERAL PROOF"
    data = build_pe() + b"\0\0" + literal.encode(encoding) + b"\0\0"
    report = analyze_bytes(data)
    document = report.model_dump(mode="json")
    fact = next(
        item
        for item in document["evidence"]
        if item["kind"] == "string" and item["data"]["text"] == literal
    )
    fact["data"]["text"] = "Z" * len(literal)
    fact["data"]["raw_hex"] = fact["data"]["text"].encode(encoding).hex()
    forged = Report.model_validate_json(json.dumps(document))
    with pytest.raises(LupaBinError) as caught:
        if entrypoint == "saved":
            check_against_sample(forged, from_bytes(data, Limits()))
        else:
            asyncio.run(
                run_isolated(data, Limits(), FakeDocker(output=forged.model_dump_json().encode()))
            )
    assert caught.value.code == (
        "report_mismatch" if entrypoint == "saved" else "invalid_worker_output"
    )


@pytest.fixture(scope="module")
def dotnet_report():
    data = build_dotnet_demo()
    report = analyze_bytes(data)
    assert report.analysis.status == "completed"
    return data, report


@pytest.mark.parametrize("entrypoint", ["saved", "worker"])
@pytest.mark.parametrize(
    ("kind", "changes"),
    [
        ("dotnet_metadata", {"flags": 0}),
        (
            "dotnet_pinvoke",
            {"function": {"raw_hex": b"MessageBoxA".hex(), "text": "MessageBoxA"}},
        ),
        ("dotnet_member", {"member": "field"}),
        ("dotnet_type", {"flags": 1}),
        (
            "dotnet_string",
            {
                "text": "Z" * len(DOTNET_URL),
                "raw_hex": ("Z" * len(DOTNET_URL)).encode("utf-16-le").hex(),
            },
        ),
    ],
)
def test_dotnet_bytes_are_verified_by_both_report_entrypoints(
    dotnet_report, entrypoint, kind, changes
):
    data, report = dotnet_report
    document = report.model_dump(mode="json")
    fact = next(item for item in document["evidence"] if item["kind"] == kind)
    fact["data"].update(changes)
    forged = Report.model_validate_json(json.dumps(document))
    assert forged.sample == report.sample
    with pytest.raises(LupaBinError) as caught:
        if entrypoint == "saved":
            check_against_sample(forged, from_bytes(data, Limits()))
        else:
            asyncio.run(
                run_isolated(data, Limits(), FakeDocker(output=forged.model_dump_json().encode()))
            )
    assert caught.value.code == (
        "report_mismatch" if entrypoint == "saved" else "invalid_worker_output"
    )


@pytest.mark.parametrize("entrypoint", ["saved", "worker"])
def test_genuine_dotnet_report_still_verifies_after_serialization(dotnet_report, entrypoint):
    data, report = dotnet_report
    restored = Report.model_validate_json(report.model_dump_json())
    if entrypoint == "saved":
        check_against_sample(restored, from_bytes(data, Limits()))
    else:
        checked = asyncio.run(
            run_isolated(data, Limits(), FakeDocker(output=restored.model_dump_json().encode()))
        )
        assert checked == restored


@pytest.mark.parametrize("encoding", ["ascii", "utf-16-le"])
def test_genuine_complete_and_truncated_literals_still_verify(encoding):
    for literal in ("LUPABIN LITERAL PROOF", "X " * 1500):
        data = build_pe() + b"\0\0" + literal.encode(encoding) + b"\0\0"
        report = analyze_bytes(data)
        (fact,) = tuple(
            item
            for item in report.evidence
            if item.kind == "string"
            and item.data.encoding == encoding
            and item.location.offset == len(build_pe()) + 2
        )
        assert fact.data.text == literal[: Limits().string_characters]
        assert fact.data.complete == (len(literal) <= Limits().string_characters)
        check_against_sample(report, from_bytes(data, Limits()))
