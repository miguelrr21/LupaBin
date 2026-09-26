"""x64 .pdata function ranges (contract 0.6.0) and the capabilities that
pair a key opened for writing with RegSetValueEx in the same range."""

import copy
import json
import struct

import pytest

from lupabin.analysis import analyze_bytes
from lupabin.evidence.code import verify_calls
from lupabin.evidence.models import Report
from lupabin.explain.engine import explain
from lupabin.glossary.catalog import load_glossary
from tests.fixtures.pe_builder import (
    CODE_RVA,
    HKCU64,
    PDATA_RVA,
    build_code_demo,
    build_same_function_demo,
)

GLOSSARY = load_glossary()
WINLOGON = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"


def facts(report, kind):
    return [fact for fact in report.evidence if fact.kind == kind]


def items(data):
    report = analyze_bytes(data)
    explanation = explain(report, GLOSSARY)
    return report, {i.rule: i for i in explanation.items}


# --- the fact ------------------------------------------------------------------------------


def test_the_pdata_entry_that_holds_a_catalog_call_is_published_and_verified():
    data = build_same_function_demo()
    report = analyze_bytes(data)
    (function,) = facts(report, "code_function")
    assert function.location.rva == PDATA_RVA and function.location.length == 12
    assert function.data.begin == CODE_RVA and function.confidence == "observed"
    calls = facts(report, "api_call")
    assert all(function.data.begin <= c.location.rva < function.data.end for c in calls)
    verify_calls(report.evidence, data)


def test_no_range_without_pdata_or_in_x86():
    assert facts(analyze_bytes(build_same_function_demo(pdata=())), "code_function") == []
    assert facts(analyze_bytes(build_code_demo(bits=32)), "code_function") == []


def test_overlapping_entries_make_the_whole_table_unusable():
    data = build_same_function_demo(pdata=((0, None), (0x10, None)))
    assert facts(analyze_bytes(data), "code_function") == []


def test_calls_outside_every_range_publish_none_for_themselves():
    data = build_same_function_demo(pdata=((0, 0x28),))  # only the opening call
    (function,) = facts(analyze_bytes(data), "code_function")
    assert function.data.end == CODE_RVA + 0x28


def payload():
    return json.loads(analyze_bytes(build_same_function_demo()).model_dump_json())


def function_fact(data):
    return next(f for f in data["evidence"] if f["kind"] == "code_function")


@pytest.mark.parametrize(
    "tamper",
    [
        lambda f, d: f["data"].update(end=f["data"]["begin"] + 1),  # bytes say otherwise
        lambda f, d: f["data"].update(  # a range that holds no published call
            begin=0x3000,
            end=0x3010,
            raw_hex=struct.pack("<III", 0x3000, 0x3010, f["data"]["unwind"]).hex(),
        ),
        lambda f, d: f["location"].update(length=8),
        lambda f, d: f["provenance"].update(evidence_ids=["E1"]),
        lambda f, d: d["evidence"].append(dict(copy.deepcopy(f), id="E99")),  # published twice
    ],
)
def test_the_report_rejects_ranges_its_own_data_do_not_support(tamper):
    data = payload()
    tamper(function_fact(data), data)
    with pytest.raises(ValueError):
        Report.model_validate_json(json.dumps(data))


def test_the_host_rejects_range_bytes_that_are_not_in_the_sample():
    data = bytearray(build_same_function_demo())
    report = analyze_bytes(bytes(data))
    data[0x200 + PDATA_RVA - 0x1000] ^= 1
    with pytest.raises(ValueError):
        verify_calls(report.evidence, bytes(data))


def test_every_range_is_explained_in_one_item():
    report, found = items(build_same_function_demo())
    item = found["code.functions@1"]
    assert item.evidence_ids == tuple(f.id for f in facts(report, "code_function"))
    assert item.slots["ranges"] == ("0x00002000-0x00002043",)
    assert item.level == "observed" and "code.function_range" in item.glossary_ids


# --- the capabilities ----------------------------------------------------------------------


# The write reads another variable than the one the opening call fills, so no link says
# which key it uses: only the .pdata range pairs the two calls.
UNLINKED = bytes.fromhex("488b4c2438")  # mov rcx, [rsp+0x38]


def test_opening_run_and_setting_a_value_in_one_range_is_one_case():
    report, found = items(build_same_function_demo(set_key=UNLINKED))
    item = found["capability.run_key_open_and_set@1"]
    (case,) = item.slots["cases"]
    assert case.startswith("0x00002000-0x00002043 (rango de .pdata): abre RegOpenKeyExW")
    assert "Escribe con RegSetValueExW en 0x0000203c (valor «LupaBinTraining»)" in case
    assert case.endswith("No se sabe si la escritura usa la clave abierta (T1547.001)")
    function = facts(report, "code_function")[0]
    assert item.evidence_ids[0] == function.id
    cited = set(item.evidence_ids)
    assert {f.id for f in facts(report, "api_call") + facts(report, "call_argument")} <= cited
    assert item.slots["noun"] == "rango de función" and item.level == "inferred"


@pytest.mark.parametrize(("value", "technique"), [("Shell", True), ("AutoAdminLogon", False)])
def test_winlogon_pairs_carry_t1547_004_only_for_its_values(value, technique):
    _, found = items(build_same_function_demo(subkey=WINLOGON, value=value, set_key=UNLINKED))
    (case,) = found["capability.winlogon_open_and_set@1"].slots["cases"]
    assert case.endswith(" (T1547.004)") == technique
    assert "capability.run_key_open_and_set@1" not in found


@pytest.mark.parametrize(
    "variant",
    [
        {"pdata": ()},  # no ranges: nothing says the calls share a function
        {"pdata": ((0, 0x28),)},  # the write is outside the opening call's range
        {"pdata": ((0, 0x28), (0x28, None))},  # two ranges, one call in each
        {"set_key": HKCU64},  # the write names a predefined key: it goes elsewhere
        {"subkey": r"Software\LupaBin\Training"},  # not a Run key
    ],
)
def test_no_pair_when_the_range_or_the_key_does_not_support_it(variant):
    _, found = items(build_same_function_demo(**variant))
    assert "capability.run_key_open_and_set@1" not in found
    assert "capability.winlogon_open_and_set@1" not in found
