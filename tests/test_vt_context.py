from datetime import UTC, datetime

import pytest

from lupabin.analysis import analyze_bytes
from lupabin.evidence.models import Limits
from lupabin.evidence.primitives import CodeLimits
from lupabin.virustotal import contrast, labels
from lupabin.virustotal.models import Behaviour, Detection, Technique, VirusTotalReport
from tests.fixtures.pe_builder import build_call_demo, build_pe


def external(sha, *ids):
    return VirusTotalReport(
        sample_sha256=sha,
        retrieved_at=datetime(2026, 9, 27, tzinfo=UTC),
        status="found",
        permalink="https://www.virustotal.com/gui/file/" + sha,
        behaviour=Behaviour(mitre_attack_techniques=tuple(Technique(id=t) for t in ids)),
    )


@pytest.mark.parametrize(
    ("engine", "label", "rule"),
    [
        ("Microsoft", "Behavior:Win32/Execution.A!ml", "microsoft.behavior_ml"),
        ("Microsoft", "Trojan:Win32/Wacatac.B!ml", "microsoft.internal_suffix"),
        ("F-Secure", "Generic.malware.123", "fsecure.generic"),
        ("F-Secure", "Gen:Variant.Graftor.461736", "fsecure.generic"),
        ("F-Secure", "Gen:Heur", "fsecure.heuristic"),
        ("McAfee", "ti!123456789ABC", None),
        ("Unknown", "Behavior:Win32/Execution.A!ml", None),
        ("Microsoft", "Behavior:Win32/Undocumented.A!ml", "microsoft.internal_suffix"),
        ("Microsoft", "Behavior:Win32/Execution.A!ml\n", None),
        ("F-Secure", "Generic", None),
        ("F-Secure", "Gen:Heur\x1b[2J", None),
        ("Microsoft", None, None),
        ("F-Secure", "Generic." + "x" * 2040, None),
    ],
)
def test_only_documented_vendor_label_pairs_are_explained(engine, label, rule):
    result = labels.interpret(Detection(engine=engine, category="malicious", result=label))
    assert result.rule == rule
    assert bool(result.sources) == (rule is not None)
    assert result.not_proven
    if rule is None:
        assert "catálogo" in result.statement


def test_catalog_and_comparison_wording_are_pinned():
    assert labels.catalog_digest() == labels.CATALOG_SHA256
    assert contrast.method_digest() == contrast.METHOD_SHA256


def test_views_keep_vendor_knowledge_and_technique_citations_outside_facts():
    from lupabin.explain.engine import explain
    from lupabin.glossary.catalog import load_glossary
    from lupabin.render import document
    from lupabin.render import external as rendering
    from lupabin.web import view

    report = analyze_bytes(build_call_demo("WinExec", {0: "cmd.exe /c echo training", 1: 0}))
    before = report.model_dump_json()
    glossary = load_glossary()
    explanation = explain(report, glossary)
    vt = external(report.sample.sha256, "T1059.003").model_copy(
        update={
            "detections": (Detection(engine="F-Secure", category="malicious", result="Gen:Heur"),)
        }
    )
    for render in (document.to_text, document.to_markdown):
        shown = render(explanation, explanation.items, report, glossary, external=vt)
        assert "F-Secure" in shown and "https://www.f-secure.com/v-descs/heuristic" in shown
        assert "Contraste T1059.003" in shown.replace("\\.", ".") and "Evidencias locales" in shown
    shown = view.build(report, explanation, explanation.items, glossary, vt)
    assert shown["vt_local_context"]["techniques"]["T1059.003"]["status"] == "static_match"
    assert rendering.structured(vt)["context"]["labels"][0]["rule"] == "fsecure.heuristic"
    assert report.model_dump_json() == before


def test_hostile_labels_are_not_interpreted_and_are_neutralised():
    from lupabin.web.view import virustotal

    vt = external("a" * 64).model_copy(
        update={
            "detections": (Detection(engine="Microsoft", category="malicious", result="x\x1b[2J"),)
        }
    )
    item = virustotal(vt)["context"]["labels"][0]
    assert item["rule"] is None
    assert "\x1b" not in item["label"]


def test_a_suffix_does_not_establish_a_general_machine_learning_rule():
    result = labels.interpret(
        Detection(engine="Microsoft", category="malicious", result="Trojan:Win32/X.A!ml")
    )
    assert result.category == "internal"
    assert "interno" in result.statement
    assert "aprendizaje automático" not in result.statement


def test_context_cites_the_exact_local_mechanism_not_just_an_import():
    report = analyze_bytes(
        build_call_demo(
            "RegSetKeyValueW",
            {0: 0x80000001, 1: r"Software\Microsoft\Windows\CurrentVersion\Run", 2: "Training"},
        )
    )
    context = contrast.local_context(report)
    vt = external(report.sample.sha256, "T1547.001", "T1059", "T1547.001x")
    rows = contrast.compare(vt, context)
    assert [r.status for r in rows] == ["static_match", "unsupported", "invalid_id"]
    assert rows[0].evidence
    facts = {e.id: e for e in report.evidence}
    assert {facts[e].kind for e in rows[0].evidence} >= {"api_call", "call_argument"}
    assert not rows[1].evidence and not rows[2].evidence
    assert "no demuestra" in contrast.LIMIT


def test_an_import_or_call_without_the_required_arguments_is_not_a_match():
    for data in (
        build_pe(dll=b"advapi32.dll", function=b"RegSetKeyValueW"),
        build_call_demo("RegSetKeyValueW", {0: 0x80000001}),
    ):
        report = analyze_bytes(data)
        rows = contrast.compare(
            external(report.sample.sha256, "T1547.001"), contrast.local_context(report)
        )
        assert rows[0].status == "not_observed" and not rows[0].evidence


def test_comparison_keeps_the_limits_of_same_function_cases():
    from tests.fixtures.pe_builder import build_same_function_demo
    from tests.test_same_function import UNLINKED

    report = analyze_bytes(build_same_function_demo(set_key=UNLINKED))
    (row,) = contrast.compare(
        external(report.sample.sha256, "T1547.001"), contrast.local_context(report)
    )
    assert row.status == "static_match"
    assert "No se sabe si la escritura usa la clave abierta" in " ".join(row.details)


def test_no_static_match_is_not_a_refutation():
    report = analyze_bytes(build_pe())
    rows = contrast.compare(
        external(report.sample.sha256, "T1547.001"), contrast.local_context(report)
    )
    assert rows[0].status == "not_observed"
    assert not rows[0].evidence
    assert "no descarta" in rows[0].statement


def test_partial_code_does_not_claim_the_technique_was_fully_checked():
    report = analyze_bytes(
        build_call_demo("RegSetKeyValueW", {0: 0x80000001, 1: "Training"}),
        Limits(code=CodeLimits(instructions=1)),
    )
    rows = contrast.compare(
        external(report.sample.sha256, "T1547.001"), contrast.local_context(report)
    )
    assert rows[0].status == "incomplete"


def test_identity_and_missing_report_prevent_local_attribution():
    report = analyze_bytes(build_pe())
    vt = external("a" * 64, "T1547.001")
    assert contrast.compare(vt, None)[0].status == "no_local_report"
    row = contrast.compare(vt, contrast.local_context(report))[0]
    assert row.status == "identity_mismatch" and not row.evidence


def test_unavailable_external_report_does_not_reuse_techniques():
    report = analyze_bytes(build_pe())
    vt = external(report.sample.sha256, "T1547.001").model_copy(update={"status": "unavailable"})
    assert contrast.compare(vt, contrast.local_context(report)) == ()
