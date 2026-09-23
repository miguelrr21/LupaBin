import hashlib
import struct
from typing import get_args

import pytest

from dissect.analysis import analyze_bytes
from dissect.evidence.models import ErrorCode
from dissect.evidence.yara import YaraReason
from dissect.explain.engine import ExplanationError, check_item, explain, notes, validate
from dissect.explain.models import Explanation
from dissect.explain.rules import RULES
from dissect.explain.text import MESSAGES
from dissect.glossary.catalog import load_glossary
from tests.fixtures.pe_builder import build_decode_demo, build_demo, build_pe

GLOSSARY = load_glossary()


def writable_executable():
    data = bytearray(build_pe())
    struct.pack_into("<I", data, 0x98 + 224 + 36, 0xE0000040)
    return bytes(data)


def high_entropy(size=0x1000):
    data = bytearray(build_pe(imports=False))
    section = 0x98 + 224
    struct.pack_into("<I", data, section + 8, size)
    struct.pack_into("<I", data, section + 16, size)
    noise = b"".join(hashlib.sha256(bytes([n, m])).digest() for n in range(16) for m in range(8))
    data[0x200 : 0x200 + size] = noise[:size]
    return bytes(data)


def patched_demo(offset, value):
    data = bytearray(build_demo())
    struct.pack_into("<I", data, offset, value)
    return bytes(data)


SAMPLES = {
    "raw-overlap": lambda: patched_demo(0x1A0 + 20, 0x200),
    "virtual-overlap": lambda: patched_demo(0x1A0 + 12, 0x1000),
    "exceeds-image": lambda: patched_demo(0x1A0 + 8, 0x5000),
    "entry-outside": lambda: patched_demo(0x98 + 16, 0xFFFF),
    "demo": build_demo,
    "demo64": lambda: build_demo(bits=64),
    "corrupt": lambda: build_demo(corrupt=True),
    "decode": build_decode_demo,
    "delay": lambda: build_pe(delay=True),
    "ordinal": lambda: build_pe(ordinal=17),
    "runtime": lambda: build_pe(function=b"GetProcAddress"),
    "wx": writable_executable,
    "high-entropy": high_entropy,
    "not-pe": lambda: b"just some text, not a PE file at all " * 4,
}


@pytest.fixture(scope="module")
def reports():
    return {name: analyze_bytes(build()) for name, build in SAMPLES.items()}


def rules_used(explanation):
    return {item.rule for item in explanation.items}


@pytest.mark.parametrize("sample", SAMPLES)
def test_every_fact_is_explained_and_every_item_regenerates(reports, sample):
    report = reports[sample]
    explanation = explain(report, GLOSSARY)
    assert validate(explanation, report, GLOSSARY) == explanation.items
    cited = {ref for item in explanation.items for ref in item.evidence_ids}
    assert cited == {fact.id for fact in report.evidence}
    for item in explanation.items:
        assert set(item.glossary_ids) <= GLOSSARY.entries.keys()
        assert item.not_proven


@pytest.mark.parametrize("sample", SAMPLES)
def test_explanations_are_deterministic_and_round_trip(reports, sample):
    one = explain(reports[sample], GLOSSARY)
    assert one == explain(reports[sample], GLOSSARY)
    assert Explanation.model_validate_json(one.model_dump_json()) == one


def test_the_fixtures_exercise_every_rule(reports):
    used = set().union(*(rules_used(explain(r, GLOSSARY)) for r in reports.values()))
    assert used == set(RULES)


def test_every_report_code_has_reviewed_wording():
    assert set(get_args(get_args(ErrorCode)[0])) | set(get_args(YaraReason)) == set(MESSAGES)


def test_coverage_notes_come_from_every_run_and_issue(reports):
    report = reports["not-pe"]
    explanation = explain(report, GLOSSARY)
    assert explanation.status == report.analysis.status != "completed"
    assert [n.source for n in explanation.notes if n.rule == "run.status@1"] == [
        run.source for run in report.extractor_runs
    ]
    codes = {n.code for n in explanation.notes if n.rule == "issue@1"}
    assert {e.code for e in (*report.extractor_errors, *report.limitations)} == codes
    assert "unsupported_format" in codes


def test_levels_follow_the_weakest_citation(reports):
    explanation = explain(reports["decode"], GLOSSARY)
    for item in explanation.items:
        assert (item.level == "inferred") == item.rule.startswith("decoded.")


def test_key_reuse_cites_the_decoding_that_set_the_key(reports):
    report = reports["decode"]
    explanation = explain(report, GLOSSARY)
    [reused] = [item for item in explanation.items if item.rule == "decoded.xor_reused@1"]
    assert reused.slots["verifier"] == reused.evidence_ids[1]
    assert "decode.key_reuse" in reused.glossary_ids


def test_glossary_links_depend_on_the_facts(reports):
    def links(sample):
        [item] = [i for i in explain(reports[sample], GLOSSARY).items if i.rule == "imports.dll@1"]
        return item.glossary_ids

    assert links("demo") == ("pe.imports",)
    assert "pe.imports.delay" in links("delay")
    assert "pe.imports.ordinal" in links("ordinal")
    assert "pe.imports.runtime_linking" in links("runtime")


def test_writable_executable_section_is_explained_with_its_caveat(reports):
    [item] = [
        i
        for i in explain(reports["wx"], GLOSSARY).items
        if i.rule == "pe.section.writable_executable@1"
    ]
    assert "escritura y de ejecución" in item.statement
    assert "No demuestra" in item.not_proven


# --- manipulated explanations -----------------------------------------------------


def tampered(explanation, index, **changes):
    items = list(explanation.items)
    items[index] = items[index].model_copy(update=changes)
    return explanation.model_copy(update={"items": tuple(items)})


def first(explanation, rule):
    return next(n for n, item in enumerate(explanation.items) if item.rule == rule)


@pytest.mark.parametrize(
    "changes",
    [
        {"statement": "La tabla de imports declara 99 funciones de «kernel32.dll»."},
        {"slots": {"table": "tabla de imports", "dll": "evil.dll", "count": 1}},
        {"level": "inferred"},
        {"not_proven": "Demuestra que el programa es malicioso."},
        {"glossary_ids": ("pe.exports",)},
        {"rule": "exports.table@1"},
    ],
    ids=["statement", "slots", "level", "not-proven", "glossary", "rule"],
)
def test_an_altered_item_does_not_validate(reports, changes):
    report = reports["demo"]
    explanation = explain(report, GLOSSARY)
    index = first(explanation, "imports.dll@1")
    bad = tampered(explanation, index, **changes)
    assert check_item(bad.items[index], report, GLOSSARY) is not None
    assert bad.items[index] not in validate(bad, report, GLOSSARY)


def test_citing_only_part_of_a_group_does_not_validate(reports):
    report = reports["demo"]
    explanation = explain(report, GLOSSARY)
    index = first(explanation, "strings.summary@1")
    item = explanation.items[index]
    bad = tampered(explanation, index, evidence_ids=item.evidence_ids[:1])
    assert check_item(bad.items[index], report, GLOSSARY) is not None


def test_citing_missing_or_unrelated_evidence_does_not_validate(reports):
    report = reports["demo"]
    explanation = explain(report, GLOSSARY)
    index = first(explanation, "pe.header@1")
    for ids in (("E99999",), (explanation.items[index + 1].evidence_ids[0],)):
        bad = tampered(explanation, index, evidence_ids=ids)
        assert check_item(bad.items[index], report, GLOSSARY) is not None


def test_hiding_evidence_or_coverage_is_rejected(reports):
    report = reports["corrupt"]
    explanation = explain(report, GLOSSARY)
    hidden = explanation.model_copy(update={"items": explanation.items[1:]})
    with pytest.raises(ExplanationError):
        validate(hidden, report, GLOSSARY)
    silent = explanation.model_copy(update={"notes": notes(report)[:1]})
    with pytest.raises(ExplanationError):
        validate(silent, report, GLOSSARY)
    rosy = explanation.model_copy(update={"status": "completed"})
    with pytest.raises(ExplanationError):
        validate(rosy, report, GLOSSARY)


def test_an_explanation_belongs_to_one_report_and_glossary(reports):
    explanation = explain(reports["demo"], GLOSSARY)
    with pytest.raises(ExplanationError):
        validate(explanation, reports["demo64"], GLOSSARY)
    other = explanation.model_copy(
        update={"glossary": GLOSSARY.info.model_copy(update={"revision": "9.9.9"})}
    )
    with pytest.raises(ExplanationError):
        validate(other, reports["demo"], GLOSSARY)


def test_published_explanation_schema_is_current():
    from pathlib import Path

    from dissect.explain.schema import schema_text

    assert Path("docs/explanation-schema.json").read_text(encoding="utf-8") == schema_text()


def test_high_entropy_note_needs_both_the_value_and_enough_bytes(reports):
    [item] = [
        i for i in explain(reports["high-entropy"], GLOSSARY).items if i.rule == "entropy.high@1"
    ]
    assert "0,34 %" in item.statement
    small = analyze_bytes(high_entropy(size=0x200))
    assert "entropy.high@1" not in rules_used(explain(small, GLOSSARY))
    assert "entropy.high@1" not in rules_used(explain(reports["demo"], GLOSSARY))


def test_api_families_are_pinned_disjoint_measured_and_documented():
    from dissect.explain.families import (
        FAMILIES,
        FAMILIES_SHA256,
        PREVALENCE,
        families_digest,
    )

    assert families_digest() == FAMILIES_SHA256, "new FAMILIES_ID, digest and measurement"
    names = [name for _, members in FAMILIES.values() for name in members]
    assert len(names) == len(set(names))
    assert set(PREVALENCE) == set(FAMILIES)
    assert {f"api.family.{family}" for family in FAMILIES} <= GLOSSARY.entries.keys()


def test_family_items_cite_the_whole_family_and_its_benign_prevalence(reports):
    report = reports["runtime"]
    explanation = explain(report, GLOSSARY)
    index = first(explanation, "imports.family@1")
    item = explanation.items[index]
    assert item.slots["functions"] == ("GetProcAddress",)
    assert "34,8 %" in item.statement
    assert item.glossary_ids == ("api.family.dynamic_loading", "pe.imports")
    assert "imports.family@1" not in rules_used(explain(reports["demo"], GLOSSARY))
