"""Constant call arguments: the contract re-derives each one from the bytes it cites."""

import asyncio
import copy
import json
import struct

import pytest

from dissect.analysis import analyze_bytes
from dissect.errors import DissectError
from dissect.evidence.code import verify_calls
from dissect.evidence.models import Limits, Report
from dissect.evidence.primitives import CodeLimits
from dissect.runner import run_isolated
from tests.fixtures.pe_builder import (
    ARGS_STRING_RVA,
    ARGS_SUBKEY,
    HKCU32,
    HKCU64,
    RESOLVE_NAME,
    args_demo_bytes,
    build_args_demo,
    build_code_demo,
    build_code_pe,
    build_resolve_demo,
    with_load_config,
)
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
    code = args_demo_bytes(64, hkey=b"\xb9\x01\x00\x00\x80")  # mov ecx, 0x80000001
    report = analyze_bytes(build_args_demo(bits=64, code=code))
    assert "hKey" not in arguments(report)


# --- the walk's rules, end to end: overwrites, other entries, stack shape ---------


def by_name(data, limits=None):
    return arguments(analyze_bytes(data, limits))


def test_an_overwrite_between_setter_and_call_forgets_that_argument():
    # x64: mov rcx, [rax] after rcx was set; rdx and r9 keep their constants
    code = args_demo_bytes(64, before=b"\x48\x8b\x08")
    assert set(by_name(build_args_demo(bits=64, code=code))) == {"lpSubKey", "samDesired"}
    # x86: mov [esp], eax rewrites the stack the pushes built
    code = args_demo_bytes(32, before=b"\x89\x04\x24")
    assert by_name(build_args_demo(bits=32, code=code)) == {}


def test_another_entry_after_the_setters_leaves_every_argument_unknown():
    # x64 body: lea (7) + mov rcx (7) + mov r9d (6) + xor r8d (3), then the nop at 0x2017
    code = args_demo_bytes(64, before=b"\x90")
    data = with_load_config(build_args_demo(bits=64, code=code), bits=64, guard=(0x2017,))
    report = analyze_bytes(data)
    assert [f.kind for f in report.evidence if f.source == "code"] == ["api_call"]
    # the same bytes without that entry
    assert len(by_name(build_args_demo(bits=64, code=code))) == 3


def test_x86_pushes_that_are_missing_leave_those_arguments_unknown():
    call = b"\xff\x15" + struct.pack("<I", 0x400000 + 0x1140)
    code = b"\x68\x01\x00\x00\x80" + call + b"\xc3"  # only hKey is pushed
    assert set(by_name(build_args_demo(bits=32, code=code))) == {"hKey"}


def test_the_argument_budget_leaves_the_component_partial_and_says_so():
    report = analyze_bytes(build_args_demo(), Limits(code=CodeLimits(argument_instructions=1)))
    assert arguments(report) == {}
    parts = {
        p.name: p for p in next(r for r in report.extractor_runs if r.source == "code").components
    }
    assert parts["call_arguments"].status == "partial"
    assert [(r.component, r.code) for r in report.limitations] == [
        ("call_arguments", "argument_instruction_limit")
    ]


def test_calls_to_functions_outside_the_catalog_are_not_examined():
    report = analyze_bytes(build_code_demo())
    parts = {
        p.name: p for p in next(r for r in report.extractor_runs if r.source == "code").components
    }
    assert parts["call_arguments"].status == "complete"
    assert parts["call_arguments"].examined == 0 and arguments(report) == {}


def test_the_fixture_generator_writes_the_arguments_demo(tmp_path, monkeypatch):
    import sys

    from tests.fixtures import pe_builder

    path = tmp_path / "args.bin"
    monkeypatch.setattr(
        sys,
        "argv",
        ["pe_builder", "--scenario", "args-demo", "--bits", "64", "--output", str(path)],
    )
    pe_builder.main()
    assert path.read_bytes() == build_args_demo(bits=64)


# --- RegCreateKeyExW: arguments past the fourth are on the stack in x64 ----------


def registry_create(bits, stack=True):
    """RegCreateKeyExW(HKCU, subkey, 0, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &k, NULL).

    In x64 the fifth and later arguments go to the stack: samDesired as an immediate
    store, dwOptions through esi (`stack=False` leaves them out)."""
    slot = 0x1140
    if bits == 32:
        body = bytes.fromhex("6a00506a00")  # lpdwDisposition, phkResult, lpSecurityAttributes
        body += bytes.fromhex("68") + struct.pack("<I", 0x20006)  # samDesired = KEY_WRITE
        body += bytes.fromhex("6a016a006a00")  # dwOptions = 1, lpClass, Reserved
        body += bytes.fromhex("68") + struct.pack("<I", 0x400000 + ARGS_STRING_RVA) + HKCU32
        body += bytes.fromhex("ff15") + struct.pack("<I", 0x400000 + slot)
    else:
        body = bytes.fromhex("488d15") + struct.pack("<i", ARGS_STRING_RVA - (0x2000 + 7))
        body += HKCU64 + bytes.fromhex("4533c04533c9")  # Reserved, lpClass
        if stack:
            body += bytes.fromhex("be01000000")  # mov esi, REG_OPTION_VOLATILE
            body += bytes.fromhex("c744242806000200")  # mov dword ptr [rsp+0x28], KEY_WRITE
            body += bytes.fromhex("89742420")  # mov dword ptr [rsp+0x20], esi
        body += bytes.fromhex("ff15") + struct.pack("<i", slot - (0x2000 + len(body) + 6))
    code = body + bytes.fromhex("c3")
    return build_args_demo(bits=bits, code=code, function=b"RegCreateKeyExW")


def test_registry_create_arguments_in_x86_come_from_all_nine_pushes():
    found = arguments(analyze_bytes(registry_create(32)))
    assert {name: fact.data.value for name, fact in found.items() if name != "lpSubKey"} == {
        "hKey": 0x80000001,
        "dwOptions": 1,
        "samDesired": 0x20006,
    }
    assert found["lpSubKey"].data.string.text == ARGS_SUBKEY


def test_registry_create_stack_arguments_are_recovered_in_x64():
    found = arguments(analyze_bytes(registry_create(64)))
    assert {name: fact.data.method for name, fact in found.items()} == {
        "hKey": "block-constant-v1",
        "lpSubKey": "block-constant-v1",
        "dwOptions": "stack-slot-v1",
        "samDesired": "stack-slot-v1",
    }
    assert found["dwOptions"].data.value == 1 and found["dwOptions"].data.source is not None
    assert found["samDesired"].data.value == 0x20006 and found["samDesired"].data.source is None
    without = arguments(analyze_bytes(registry_create(64, stack=False)))
    assert set(without) == {"hKey", "lpSubKey"}


def create64_payload():
    return json.loads(analyze_bytes(registry_create(64)).model_dump_json())


@pytest.mark.parametrize(
    "tamper,reason",
    [
        (
            lambda d: argument(d, "dwOptions")["data"]["source"].update(raw_hex="bf01000000"),
            "not a canonical setting",  # mov edi, 1: not the register that is stored
        ),
        (
            lambda d: argument(d, "samDesired")["data"].update(raw_hex="c744243006000200"),
            "not a canonical setting",  # [rsp+0x30] is slot 6, not samDesired's 5
        ),
        (
            lambda d: argument(d, "samDesired")["data"].update(method="block-constant-v1"),
            "not a canonical setting",
        ),
        (
            lambda d: argument(d, "hKey")["data"].update(
                source=argument(d, "dwOptions")["data"]["source"]
            ),
            "only a stack slot copies a register",
        ),
        (
            lambda d: argument(d, "dwOptions")["data"]["source"].update(
                rva=argument(d, "dwOptions")["location"]["rva"] + 4,
                offset=argument(d, "dwOptions")["location"]["offset"] + 4,
            ),
            "set before the store",
        ),
    ],
)
def test_report_rejects_stack_arguments_its_bytes_do_not_support(tamper, reason):
    data = create64_payload()
    tamper(data)
    with pytest.raises(ValueError, match=reason):
        Report.model_validate_json(json.dumps(data))


def test_host_compares_the_copied_register_setter_with_the_sample():
    sample = registry_create(64)
    data = create64_payload()
    source = argument(data, "dwOptions")["data"]["source"]
    source["raw_hex"] = "be04000000"  # mov esi, 4: coherent, but not the sample's bytes
    argument(data, "dwOptions")["data"]["value"] = 4
    report = Report.model_validate_json(json.dumps(data))
    with pytest.raises(ValueError, match="code evidence bytes differ from the sample"):
        verify_calls(report.evidence, sample)


# --- GetProcAddress: a name, or an ordinal that is not one --------------------------


@pytest.mark.parametrize("bits", [32, 64])
def test_get_proc_address_names_are_published_and_ordinals_are_not(bits):
    data = build_resolve_demo(bits=bits)
    report = analyze_bytes(data)
    calls = [fact for fact in report.evidence if fact.kind == "api_call"]
    names = [fact for fact in report.evidence if fact.kind == "call_argument"]
    assert len(calls) == 2  # by name, then by ordinal 5
    assert [(f.data.name, f.data.string.text) for f in names] == [("lpProcName", RESOLVE_NAME)]
    assert names[0].provenance.evidence_ids == (calls[0].id,)
    verify_calls(report.evidence, data)


# --- CreateServiceW: strings in registers and on the x64 stack ---------------------

SERVICE_STRINGS = {
    0x1A00: "DissectTraining",
    0x1A80: "Dissect Training",
    0x1B00: r"C:\Dissect\training.exe",
}


def create_service(bits):
    """CreateServiceW(scm, name, display, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
    SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, path, NULL, NULL, NULL, NULL, NULL)."""
    slot = 0x1140
    if bits == 32:
        body = bytes.fromhex("6a00" * 5)  # lpPassword ... lpLoadOrderGroup
        body += bytes.fromhex("68") + struct.pack("<I", 0x400000 + 0x1B00)  # path
        body += bytes.fromhex("6a016a026a10")  # error control, start type, type
        body += bytes.fromhex("68ff010f00")  # SERVICE_ALL_ACCESS
        body += bytes.fromhex("68") + struct.pack("<I", 0x400000 + 0x1A80)  # display name
        body += bytes.fromhex("68") + struct.pack("<I", 0x400000 + 0x1A00)  # name
        body += bytes.fromhex("56ff15") + struct.pack("<I", 0x400000 + slot)
    else:

        def rip(prefix, target):
            at = 0x2000 + len(body)
            return bytes.fromhex(prefix) + struct.pack("<i", target - (at + 7))

        body = b""
        body += rip("488d15", 0x1A00)  # lea rdx, name
        body += rip("4c8d05", 0x1A80)  # lea r8, display name
        body += bytes.fromhex("41b9ff010f00")  # mov r9d, SERVICE_ALL_ACCESS
        body += bytes.fromhex("c744242010000000")  # [rsp+0x20] = SERVICE_WIN32_OWN_PROCESS
        body += bytes.fromhex("c744242802000000")  # [rsp+0x28] = SERVICE_AUTO_START
        body += bytes.fromhex("c744243001000000")  # [rsp+0x30] = SERVICE_ERROR_NORMAL
        body += rip("488d05", 0x1B00)  # lea rax, path
        body += bytes.fromhex("4889442438")  # mov [rsp+0x38], rax
        body += bytes.fromhex("488bcbff15")  # mov rcx, rbx (scm); call
        body += struct.pack("<i", slot - (0x2000 + len(body) + 4))
    data = bytearray(
        build_code_pe(
            body + bytes.fromhex("c3"), bits=bits, dll=b"advapi32.dll", function=b"CreateServiceW"
        )
    )
    for rva, text in SERVICE_STRINGS.items():
        raw = text.encode("utf-16-le") + bytes(2)
        data[0x200 + rva - 0x1000 : 0x200 + rva - 0x1000 + len(raw)] = raw
    return bytes(data)


@pytest.mark.parametrize("bits", [32, 64])
def test_create_service_arguments_include_the_binary_path(bits):
    data = create_service(bits)
    report = analyze_bytes(data)
    found = arguments(report)
    shown = {
        name: (fact.data.string.text if fact.data.string else fact.data.value)
        for name, fact in found.items()
    }
    assert shown == {
        "lpServiceName": "DissectTraining",
        "lpDisplayName": "Dissect Training",
        "dwDesiredAccess": 0xF01FF,
        "dwServiceType": 0x10,
        "dwStartType": 2,
        "lpBinaryPathName": SERVICE_STRINGS[0x1B00],
    }
    if bits == 64:  # the path reaches its stack slot through rax
        path = found["lpBinaryPathName"].data
        assert path.method == "stack-slot-v1" and path.source is not None
    verify_calls(report.evidence, data)
