"""Constant call arguments: the contract re-derives each one from the bytes it cites."""

import asyncio
import copy
import json

import pytest

from dissect.analysis import analyze_bytes
from dissect.errors import DissectError
from dissect.evidence.code import verify_calls
from dissect.evidence.models import Limits, Report
from dissect.runner import run_isolated
from tests.fixtures.pe_builder import ARGS_STRING_RVA, ARGS_SUBKEY, build_args_demo
from tests.test_runner import FakeDocker


def arguments(report):
    return {fact.data.name: fact for fact in report.evidence if fact.kind == "call_argument"}


def payload(bits=32):
    return json.loads(analyze_bytes(build_args_demo(bits=bits)).model_dump_json())


def argument(data, name):
    return next(
        f
        for f in data["evidence"]
        if f.get("kind") == "call_argument" and f["data"]["name"] == name
    )


@pytest.mark.parametrize("bits", [32, 64])
def test_constant_arguments_of_a_catalog_call_are_published(bits):
    data = build_args_demo(bits=bits)
    report = analyze_bytes(data)
    found = arguments(report)
    assert set(found) == {"hKey", "lpSubKey", "samDesired"}  # ulOptions is not interpreted
    key, subkey, access = found["hKey"].data, found["lpSubKey"].data, found["samDesired"].data
    assert key.constant == "HKEY_CURRENT_USER"
    assert key.value == (0x80000001 if bits == 32 else 0xFFFFFFFF80000001)
    assert subkey.string is not None and subkey.string.text == ARGS_SUBKEY
    assert subkey.string.rva == ARGS_STRING_RVA
    assert access.value == 0x20019
    [call] = [fact for fact in report.evidence if fact.kind == "api_call"]
    for fact in found.values():
        assert fact.confidence == "inferred" and fact.provenance.evidence_ids == (call.id,)
    verify_calls(report.evidence, data)


def moved_after_the_call(data):
    fact = argument(data, "samDesired")
    call = next(f for f in data["evidence"] if f.get("kind") == "api_call")
    shift = call["location"]["rva"] + 6 - fact["location"]["rva"]
    fact["location"].update(rva=fact["location"]["rva"] + shift)
    fact["location"].update(offset=fact["location"]["offset"] + shift)


def duplicated(data):
    copy_ = copy.deepcopy(argument(data, "hKey"))
    copy_["id"] = "E99"
    data["evidence"].append(copy_)
    run = next(r for r in data["extractor_runs"] if r["source"] == "code")
    run["components"][2]["evidence_count"] += 1
    run["evidence_count"] += 1


@pytest.mark.parametrize(
    "tamper,reason",
    [
        (
            lambda d: argument(d, "samDesired")["data"].update(value=0xF003F),
            "integer argument disagrees with its bytes",
        ),
        (
            lambda d: argument(d, "hKey")["data"].update(constant="HKEY_LOCAL_MACHINE"),
            "the predefined key its bytes set",
        ),
        (
            lambda d: argument(d, "hKey")["data"].update(raw_hex="6802000080"),
            "the predefined key its bytes set",  # push 0x80000002 with the old value
        ),
        (
            lambda d: argument(d, "samDesired")["data"].update(name="ulOptions"),
            "disagrees with the catalog",
        ),
        (
            lambda d: argument(d, "samDesired")["data"].update(position=2, name="ulOptions"),
            "a parameter the catalog interprets",
        ),
        (
            lambda d: argument(d, "samDesired")["data"].update(raw_hex="68ffffffff"),
            "integer argument disagrees",
        ),
        (
            lambda d: argument(d, "samDesired")["data"].update(raw_hex="b819000200"),
            "not a canonical setting",  # mov eax, 0x20019 pushes nothing
        ),
        (
            lambda d: argument(d, "lpSubKey")["data"]["string"].update(text="Software"),
            "argument string differs from its bytes",
        ),
        (
            lambda d: argument(d, "lpSubKey")["data"]["string"].update(
                rva=ARGS_STRING_RVA + 2,
                offset=argument(d, "lpSubKey")["data"]["string"]["offset"] + 2,
            ),
            "must point to its string",
        ),
        (
            lambda d: argument(d, "hKey").update(provenance={"evidence_ids": ["E1"]}),
            "must cite a call",
        ),
        (moved_after_the_call, "set before its call"),
        (duplicated, "one value per argument"),
        (
            lambda d: d["analysis"]["limits"]["code"].update(arguments=2),
            "evidence exceeds effective quota",
        ),
        (
            lambda d: argument(d, "hKey").update(confidence="observed"),
            "inferred",
        ),
    ],
)
def test_report_rejects_arguments_its_bytes_do_not_support(tamper, reason):
    data = payload()
    tamper(data)
    with pytest.raises(ValueError, match=reason):
        Report.model_validate_json(json.dumps(data))


def test_x64_setter_of_another_register_is_not_that_argument():
    data = payload(bits=64)
    # mov rdx, 0xffffffff80000001: the right key in the wrong register
    argument(data, "hKey")["data"].update(raw_hex="48c7c201000080")
    with pytest.raises(ValueError, match="not a canonical setting of that parameter"):
        Report.model_validate_json(json.dumps(data))


def test_complete_arguments_require_complete_calls():
    data = payload()
    run = next(r for r in data["extractor_runs"] if r["source"] == "code")
    run["components"][1]["status"] = "partial"
    run["status"] = "partial"
    data["analysis"]["status"] = "partial"
    data["limitations"].append(
        {"source": "code", "component": "api_calls", "code": "api_call_limit"}
    )
    with pytest.raises(ValueError, match="complete argument coverage needs complete call"):
        Report.model_validate_json(json.dumps(data))


def test_host_rejects_argument_bytes_that_are_not_in_the_sample():
    sample = build_args_demo()
    data = payload()
    forged = "Software\\Dissect\\Trainin!"
    string = argument(data, "lpSubKey")["data"]["string"]
    string.update(text=forged, raw_hex=(forged.encode("utf-16-le") + b"\0\0").hex())
    report = Report.model_validate_json(json.dumps(data))  # coherent by itself...
    with pytest.raises(ValueError, match="code evidence bytes differ from the sample"):
        verify_calls(report.evidence, sample)
    docker = FakeDocker(output=report.model_dump_json().encode())
    with pytest.raises(DissectError) as caught:
        asyncio.run(run_isolated(sample, Limits(), docker))
    assert caught.value.code == "invalid_worker_output"


def test_runner_accepts_genuine_arguments():
    report = asyncio.run(run_isolated(build_args_demo(bits=64), Limits(), FakeDocker()))
    assert set(arguments(report)) == {"hKey", "lpSubKey", "samDesired"}


# --- what the worker declines to publish ------------------------------------------


def test_a_string_in_a_writable_section_is_not_published():
    report = analyze_bytes(build_args_demo(writable=True))
    assert set(arguments(report)) == {"hKey", "samDesired"}


def test_functions_from_dlls_that_do_not_export_them_are_not_interpreted():
    report = analyze_bytes(build_args_demo(dll=b"training.dll"))
    assert arguments(report) == {}
    run = next(r for r in report.extractor_runs if r.source == "code")
    assert run.components[2].examined == 0 and run.components[2].status == "complete"


def test_a_zero_extended_key_in_x64_is_not_a_predefined_key():
    from tests.fixtures.pe_builder import args_demo_bytes

    code = args_demo_bytes(64, hkey=b"\xb9\x01\x00\x00\x80")  # mov ecx, 0x80000001
    report = analyze_bytes(build_args_demo(bits=64, code=code))
    assert "hKey" not in arguments(report)
