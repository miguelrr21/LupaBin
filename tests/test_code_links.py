"""A key that one call leaves in a local variable and a later call passes: the link, its
checks in the report and its explanation."""

import json

import pytest

from lupabin.analysis import analyze_bytes
from lupabin.evidence import local_forms
from lupabin.evidence.code import verify_calls
from lupabin.evidence.facts import LocalLinkEvidence
from lupabin.evidence.models import Limits, Report
from lupabin.explain.engine import explain
from lupabin.glossary.catalog import load_glossary
from tests.fixtures.pe_builder import build_local_link_demo, build_same_function_demo


def links(report):
    return [fact for fact in report.evidence if isinstance(fact, LocalLinkEvidence)]


def rules(report):
    return {item.rule: item for item in explain(report, load_glossary()).items}


# --- canonical forms ------------------------------------------------------------------


def test_x86_forms_name_ebp_slots():
    assert local_forms.x86_lea(bytes.fromhex("8d45f8")) == local_forms.Named(
        local_forms.Slot("ebp", -8), 0
    )
    assert local_forms.x86_lea(bytes.fromhex("8d8570fdffff")).slot.displacement == -0x290
    assert local_forms.x86_push_register(b"\x50") == 0
    assert local_forms.x86_push_register(b"\x54") is None  # esp
    assert local_forms.x86_push_value(bytes.fromhex("ff75f8")).slot == local_forms.Slot("ebp", -8)
    assert local_forms.x86_lea(bytes.fromhex("8d442404")) is None  # esp-based: moves with pushes


def test_x64_forms_name_rsp_and_rbp_slots():
    assert local_forms.x64_lea(bytes.fromhex("488d442430")) == local_forms.Named(
        local_forms.Slot("rsp", 0x30), 0
    )
    assert local_forms.x64_lea(bytes.fromhex("488d45f0")).slot == local_forms.Slot("rbp", -0x10)
    assert local_forms.x64_load(bytes.fromhex("488b4c2430")) == local_forms.Named(
        local_forms.Slot("rsp", 0x30), 1
    )
    assert local_forms.x64_load(bytes.fromhex("498b4c2430")) is None  # REX.B: r12, not rsp
    assert local_forms.x64_lea(bytes.fromhex("488d0424")) is None  # [rsp] without displacement


def test_the_x64_home_area_does_not_keep_a_value_across_calls():
    assert not local_forms.keeps_across_calls(local_forms.Slot("rsp", 0x18))
    assert local_forms.keeps_across_calls(local_forms.Slot("rsp", 0x20))
    assert local_forms.keeps_across_calls(local_forms.Slot("rbp", -8))


# --- the worker's rule ------------------------------------------------------------------


def test_x86_key_passes_through_an_ebp_variable():
    report = analyze_bytes(build_local_link_demo(), Limits())
    (link,) = links(report)
    assert (link.data.slot.frame, link.data.slot.displacement) == ("ebp", -8)
    assert (link.data.writer_name, link.data.reader_name) == ("phkResult", "hKey")
    Report.model_validate_json(report.model_dump_json())


def test_x64_key_passes_through_an_rsp_variable():
    report = analyze_bytes(build_same_function_demo(), Limits())
    (link,) = links(report)
    assert (link.data.slot.frame, link.data.slot.displacement) == ("rsp", 0x30)


@pytest.mark.parametrize(
    "variant",
    [
        {"between": bytes.fromhex("c745f800000000")},  # mov dword ptr [ebp-8], 0
        {"between": bytes.fromhex("8bec")},  # mov ebp, esp: another frame
        {"between": bytes.fromhex("8d45f8")},  # lea eax, [ebp-8]: its address again
        {"between": bytes.fromhex("c7042400000000")},  # a store through esp may alias it
        {"enter": True},  # another path reaches the second call
    ],
)
def test_no_link_when_the_path_may_change_the_variable(variant):
    assert links(analyze_bytes(build_local_link_demo(**variant), Limits())) == []


def test_no_link_when_the_second_call_reads_another_variable():
    other = bytes.fromhex("488b4c2438")  # mov rcx, [rsp+0x38]
    assert links(analyze_bytes(build_same_function_demo(set_key=other), Limits())) == []


# --- the report's checks ------------------------------------------------------------------


def tampered(report, change):
    dumped = json.loads(report.model_dump_json())
    link = next(fact for fact in dumped["evidence"] if fact["kind"] == "local_link")
    change(link)
    return json.dumps(dumped)


@pytest.mark.parametrize(
    "change",
    [
        lambda link: link["data"]["slot"].update(displacement=-12),  # not what the bytes say
        lambda link: link["data"].update(writer_position=3),  # not phkResult
        lambda link: link["data"].update(reader_name="lpValueName"),
        lambda link: link["provenance"]["evidence_ids"].reverse(),  # the reader first
    ],
)
def test_the_report_rejects_a_link_its_bytes_do_not_support(change):
    report = analyze_bytes(build_local_link_demo(), Limits())
    with pytest.raises(ValueError):
        Report.model_validate_json(tampered(report, change))


def test_the_host_compares_the_link_bytes_with_the_sample():
    data = build_local_link_demo()
    report = analyze_bytes(data, Limits())
    verify_calls(report.evidence, data)
    (link,) = links(report)
    changed = bytearray(data)
    changed[link.data.address.offset + 2] ^= 0x04  # [ebp-8] -> [ebp-12]
    with pytest.raises(ValueError):
        verify_calls(report.evidence, bytes(changed))


# --- explanation ---------------------------------------------------------------------------


def test_the_link_is_explained():
    item = rules(analyze_bytes(build_local_link_demo(), Limits()))["code.local_link@1"]
    assert item.level == "inferred"
    assert "variable local [ebp-0x8]" in item.statement
    assert "«RegOpenKeyExW»" in item.statement and "«RegSetValueExW»" in item.statement
