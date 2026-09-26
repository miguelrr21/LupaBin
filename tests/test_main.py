import json

import pytest
from pydantic import ValidationError

from lupabin.analysis import analyze_bytes
from lupabin.evidence.code import verify_calls
from lupabin.evidence.models import Report
from lupabin.evidence.primitives import CodeLimits, Limits
from lupabin.explain.engine import explain, validate
from lupabin.glossary.catalog import load_glossary
from lupabin.render.document import main_line
from tests.fixtures.pe_builder import MAIN_RVA, MAIN_VARIABLES, build_main_demo

GLOSSARY = load_glossary()


def kinds(report, kind):
    return [fact for fact in report.evidence if fact.kind == kind]


def component(report):
    run = next(run for run in report.extractor_runs if run.source == "code")
    return next(part for part in run.components if part.name == "main_function")


def called(report, reach):
    facts = {fact.id: fact for fact in report.evidence}
    return [facts[facts[i].provenance.evidence_ids[0]].data.function.text for i in reach.data.calls]


@pytest.mark.parametrize("bits", [64, 32])
def test_the_startup_enters_main_with_the_variables_getmainargs_filled(bits):
    data = build_main_demo(bits=bits)
    report = analyze_bytes(data)
    (main,) = kinds(report, "main_call")
    assert main.data.target == MAIN_RVA
    assert main.confidence == "inferred"
    anchor = next(f for f in report.evidence if f.id == main.provenance.evidence_ids[0])
    assert anchor.kind == "api_call"
    assert all(s.rva < anchor.location.rva for s in main.data.setters)
    assert all(load.rva < main.location.rva for load in main.data.loads)
    reaches = {fact.data.root: fact for fact in kinds(report, "code_reach")}
    assert called(report, reaches["main"]) == ["puts"]
    assert called(report, reaches["startup"]) == ["__getmainargs", "exit"]
    assert component(report).status == "complete"
    assert component(report).examined == 1
    verify_calls(report.evidence, data)


@pytest.mark.parametrize(
    "variant",
    [
        {"twice": True},
        {"bits": 32, "twice": True},
        {"dll": b"ucrtbase.dll"},
        {"loads": (MAIN_VARIABLES[0], 0x1A18, MAIN_VARIABLES[2])},
        {"bits": 32, "loads": (MAIN_VARIABLES[0], 0x1A18, MAIN_VARIABLES[2])},
        {"clobber": b"\x31\xc9"},  # xor ecx, ecx: argc is no longer the variable
        {"bits": 32, "clobber": b"\x83\xc4\x04"},  # add esp, 4: the pushes are gone
    ],
)
def test_nothing_is_claimed_without_exactly_one_matching_call(variant):
    report = analyze_bytes(build_main_demo(**variant))
    assert not kinds(report, "main_call") and not kinds(report, "code_reach")
    assert component(report).status == "complete"


def test_a_cut_list_of_published_calls_keeps_main_but_not_the_reaches():
    # the walk is complete, so main is still the one candidate; the reaches would list
    # only some of the calls, and their counts would mislead
    limits = Limits(code=CodeLimits(calls=1))
    report = analyze_bytes(build_main_demo(), limits)
    assert [main.data.target for main in kinds(report, "main_call")] == [MAIN_RVA]
    assert not kinds(report, "code_reach")
    assert component(report).status == "partial"
    assert any(
        r.component == "main_function" and r.code == "dependency_omitted"
        for r in report.limitations
    )


def test_an_incomplete_walk_leaves_main_unclaimed():
    limits = Limits(code=CodeLimits(instructions=5))
    report = analyze_bytes(build_main_demo(), limits)
    assert not kinds(report, "main_call") and not kinds(report, "code_reach")
    assert component(report).status == "partial"
    assert any(
        r.component == "main_function" and r.code == "dependency_omitted"
        for r in report.limitations
    )


def test_the_host_rejects_changed_bytes():
    data = build_main_demo()
    report = analyze_bytes(data)
    (main,) = kinds(report, "main_call")
    changed = bytearray(data)
    changed[main.data.loads[1].offset + 3] ^= 1
    with pytest.raises(ValueError, match="differ"):
        verify_calls(report.evidence, bytes(changed))


def tampered(report, change):
    document = json.loads(report.model_dump_json())
    change(document["evidence"])
    return json.dumps(document)


def first(evidence, kind, **match):
    return next(
        fact
        for fact in evidence
        if fact["kind"] == kind and all(fact["data"].get(k) == v for k, v in match.items())
    )


def test_the_report_rejects_a_target_its_bytes_do_not_say():
    report = analyze_bytes(build_main_demo())

    def change(evidence):
        first(evidence, "main_call")["data"]["target"] = MAIN_RVA + 1

    with pytest.raises(ValidationError, match="target"):
        Report.model_validate_json(tampered(report, change))


def test_the_report_rejects_loads_of_other_variables():
    report = analyze_bytes(build_main_demo())

    def change(evidence):
        main = first(evidence, "main_call")
        main["data"]["loads"][1], main["data"]["loads"][2] = (
            main["data"]["loads"][2],
            main["data"]["loads"][1],
        )

    with pytest.raises(ValidationError, match="variables|first three"):
        Report.model_validate_json(tampered(report, change))


def test_the_report_rejects_a_main_call_that_cites_another_import():
    report = analyze_bytes(build_main_demo())
    calls = [fact for fact in report.evidence if fact.kind == "api_call"]
    facts = {fact.id: fact for fact in report.evidence}
    puts = next(
        c for c in calls if facts[c.provenance.evidence_ids[0]].data.function.text == "puts"
    )

    def change(evidence):
        first(evidence, "main_call")["provenance"]["evidence_ids"] = [puts.id]

    with pytest.raises(ValidationError, match="__getmainargs"):
        Report.model_validate_json(tampered(report, change))


def test_the_report_rejects_a_call_in_both_reaches():
    report = analyze_bytes(build_main_demo())

    def change(evidence):
        main_reach = first(evidence, "code_reach", root="main")
        startup = first(evidence, "code_reach", root="startup")
        startup["data"]["calls"] = sorted(
            set(startup["data"]["calls"]) | set(main_reach["data"]["calls"]),
            key=lambda ref: int(ref[1:]),
        )

    with pytest.raises(ValidationError, match="startup"):
        Report.model_validate_json(tampered(report, change))


def test_the_report_rejects_a_reach_of_something_that_is_not_a_call():
    report = analyze_bytes(build_main_demo())

    def change(evidence):
        first(evidence, "code_reach", root="main")["data"]["calls"] = ["E1"]

    with pytest.raises(ValidationError, match="published calls"):
        Report.model_validate_json(tampered(report, change))


@pytest.mark.parametrize("bits", [64, 32])
def test_main_and_the_reaches_are_explained_and_in_the_header(bits):
    report = analyze_bytes(build_main_demo(bits=bits))
    explanation = explain(report, GLOSSARY)
    items = validate(explanation, report, GLOSSARY)
    rules = {item.rule: item for item in items}
    assert {"code.main_call@1", "code.reach_main@1", "code.reach_startup@1"} <= set(rules)
    assert rules["code.reach_main@1"].slots["functions"] == ("puts",)
    assert rules["code.reach_startup@1"].slots["functions"] == ("__getmainargs", "exit")
    main = rules["code.main_call@1"]
    assert main.level == "inferred"
    assert main_line(items) == (
        f"0x00002100 ({main.id}) · 1 llamada alcanzable desde main "
        f"({rules['code.reach_main@1'].id}) · 2 solo del arranque "
        f"({rules['code.reach_startup@1'].id})"
    )
