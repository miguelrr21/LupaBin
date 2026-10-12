import base64
import hashlib
import inspect
import json
from collections import Counter
from datetime import UTC, date, datetime
from html import escape
from html.parser import HTMLParser

import pytest
from pydantic import ValidationError

from lupabin.analysis import analyze_bytes
from lupabin.evidence.models import Limits
from lupabin.explain.engine import explain, validate
from lupabin.extractors.code import CodeExtractor
from lupabin.extractors.decode import DecodeExtractor
from lupabin.extractors.pe import PEExtractor
from lupabin.extractors.strings import StringsExtractor
from lupabin.glossary.catalog import load_glossary
from lupabin.glossary.models import Source
from lupabin.render import document
from lupabin.render import html as renderer
from lupabin.render.html import STYLE, HtmlExportError, HtmlLimitError, _source, to_html
from lupabin.render.safe import visible
from lupabin.virustotal.models import Behaviour, Detection, VirusTotalReport
from tests.fixtures.pe_builder import (
    build_capability_demo,
    build_code_pe,
    build_decode_demo,
    build_pe,
)
from tests.test_triage import PDB_PATH, RECORD_AT
from tests.test_triage import build as build_triage

NOW = datetime(2026, 1, 1, tzinfo=UTC)
GLOSSARY = load_glossary()
TRIAGE_RULES = (
    "debug.pdb@1",
    "debug.pdb_unnamed@1",
    "version.strings@1",
    "signature.certificates@1",
    "overlay.data@1",
)


class Page(HTMLParser):
    def __init__(self, output):
        super().__init__(convert_charrefs=True)
        self.elements = []
        self.text = []
        self.ids = []
        self.links = []
        self.feed(output)
        self.close()

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        self.elements.append((tag, attributes))
        if "id" in attributes:
            self.ids.append(attributes["id"])
        if tag == "a":
            self.links.append(attributes["href"])

    def handle_data(self, data):
        self.text.append(data)

    @property
    def content(self):
        return "".join(self.text)


def prepared(data, *, limits=None, decode=False, code=False):
    extractors = [PEExtractor(), StringsExtractor()]
    if decode:
        extractors.append(DecodeExtractor())
    if code:
        extractors.append(CodeExtractor())
    report = analyze_bytes(data, limits=limits, extractors=extractors, clock=lambda: NOW)
    explanation = explain(report, GLOSSARY)
    items = validate(explanation, report, GLOSSARY)
    assert items == explanation.items
    return explanation, items, report, GLOSSARY


@pytest.fixture(scope="module")
def trusted():
    strings = b"\0".join(f"offline-entry-{n:02d}".encode() for n in range(20))
    return prepared(build_decode_demo() + b"\0" + strings + b"\0", decode=True)


def test_structure_ids_and_citations_resolve_without_filters(trusted):
    explanation, items, report, _ = trusted
    output = to_html(*trusted)
    page = Page(output)
    assert output.startswith("<!doctype html>")
    assert output.endswith("</html>\n")
    tags = Counter(tag for tag, _ in page.elements)
    assert tags["html"] == tags["head"] == tags["body"] == tags["main"] == 1
    assert tags["h1"] == tags["nav"] == 1
    assert len(page.ids) == len(set(page.ids))
    assert all(link[1:] in page.ids for link in page.links if link.startswith("#"))
    selected = renderer._select(items)
    assert {f"item-{item.id}" for item in selected} == {
        ref for ref in page.ids if ref.startswith("item-")
    }
    refs = {ref for item in selected for ref in item.evidence_ids[: renderer.MAX_CITATIONS]}
    assert {f"evidence-{ref}" for ref in refs} == {
        ref for ref in page.ids if ref.startswith("evidence-")
    }
    assert len(refs) < len(report.evidence)
    for item in selected:
        assert visible(item.statement) in page.content
        assert visible(item.not_proven) in page.content
        for ref in item.evidence_ids[: renderer.MAX_CITATIONS]:
            assert f"#evidence-{ref}" in page.links
    for note in explanation.notes[: renderer.MAX_NOTES]:
        assert visible(note.statement) in page.content
    assert to_html(*trusted) == output


def test_levels_provenance_hashes_and_glossary_remain_readable(trusted):
    explanation, items, report, glossary = trusted
    page = Page(to_html(*trusted, origin="Informe guardado; no se repitió el análisis."))
    assert {item.level for item in items} == {"observed", "inferred"}
    titles = ["Qué se pudo analizar", "Lectura seleccionada", "Glosario breve"]
    positions = [page.content.index(title) for title in titles]
    assert positions == sorted(positions)
    for value in (
        report.sample.sha256,
        "Informe guardado; no se repitió el análisis.",
        "Límite (not_proven)",
        document.ABSENCE,
    ):
        assert value in page.content
    for ref in page.ids:
        if ref.startswith("glossary-"):
            entry = glossary.entries[ref.removeprefix("glossary-")]
            assert visible(entry.summary) in page.content
            assert visible(entry.body) not in page.content
    assert "Metadatos completos" not in page.content
    assert "Presupuestos del análisis" not in page.content


def test_csp_permits_only_exact_static_css_and_no_active_elements(trusted):
    page = Page(to_html(*trusted))
    allowed = {
        "html",
        "head",
        "meta",
        "title",
        "style",
        "body",
        "header",
        "h1",
        "h2",
        "h3",
        "h4",
        "p",
        "dl",
        "dt",
        "dd",
        "nav",
        "ul",
        "li",
        "a",
        "main",
        "section",
        "article",
        "strong",
        "table",
        "caption",
        "thead",
        "tr",
        "th",
        "tbody",
        "td",
        "details",
        "summary",
        "pre",
        "footer",
    }
    assert {tag for tag, _ in page.elements} <= allowed
    for tag, attrs in page.elements:
        assert not any(name.startswith("on") for name in attrs)
        assert not {"src", "srcset", "style", "action", "formaction", "srcdoc"} & attrs.keys()
        if tag == "details":
            assert "open" in attrs
    policy = next(attrs["content"] for tag, attrs in page.elements if attrs.get("http-equiv"))
    for directive in ("default-src", "base-uri", "form-action", "script-src", "connect-src"):
        assert f"{directive} 'none'" in policy
    digest = base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()
    assert f"style-src 'sha256-{digest}'" in policy
    assert "unsafe-inline" not in policy
    assert "@media print" in STYLE
    assert "url(" not in STYLE and "@import" not in STYLE
    for link in page.links:
        assert link.startswith(("#", "https://", "http://"))


def test_sample_text_and_origin_cannot_create_markup_links_or_controls():
    hostile = '<script>alert("x")</script><img src=x onerror="bad()">&\' https://evil.invalid'
    origin = hostile + "\u202e\x1b\x00"
    data = build_pe(function=hostile.encode()) + b"\0" + origin.encode("utf-16-le") + b"\0\0"
    output = to_html(*prepared(data), origin=origin)
    page = Page(output)
    assert hostile in page.content
    assert visible(origin) in page.content
    assert not {"script", "img"} & {tag for tag, _ in page.elements}
    assert "&lt;script&gt;" in output and "&quot;" in output and "&#x27;" in output
    assert "\u202e" not in output and "\x1b" not in output and "\x00" not in output
    assert all("evil.invalid" not in link for link in page.links)


def test_partial_coverage_notes_and_omitted_items_are_explicit():
    args = prepared(build_pe(), limits=Limits(strings=1))
    explanation, items, report, glossary = args
    assert report.analysis.status == "partial"
    assert explanation.notes
    assert report.limitations
    page = Page(to_html(explanation, items[1:], report, glossary))
    assert "parcial" in page.content
    assert "partial" in page.content
    assert "1 explicaciones se omitieron porque no superaron la validación." in page.content
    for note in explanation.notes:
        assert visible(note.statement) in page.content
    for issue in report.limitations:
        assert issue.code in page.content
    assert f"item-{items[0].id}" not in page.ids


def test_non_pe_report_and_absent_external_data_do_not_invent_results():
    args = prepared(b"just text, not an executable " * 4)
    page = Page(to_html(*args))
    assert "no tiene formato PE" in page.content
    assert "blocked" in page.content
    assert "No se incluyen datos de VirusTotal en este documento." in page.content
    assert "no hay clave" not in page.content
    assert "Motores" not in page.content
    assert document.NO_CODE in page.content
    assert document.ABSENCE in page.content


def test_glossary_urls_are_reviewed_https_and_document_paths_are_plain_text():
    source = Source(
        title="Fuente revisada",
        publisher="Editor",
        url="https://example.invalid/?a=1&b=2",
        verified_on=date(2026, 1, 1),
    )
    page = Page(_source(source))
    assert page.links == [source.url]
    assert source.url in page.content
    local = Source(
        title="Documento local",
        publisher="LupaBin",
        document="docs/metodo.md#limites",
        verified_on=date(2026, 1, 1),
    )
    page = Page(_source(local))
    assert not page.links
    assert local.document in page.content
    bidi = Source(
        title="Fuente con dirección no visible",
        publisher="Editor",
        url="https://example.invalid/\u202etext",
        verified_on=date(2026, 1, 1),
    )
    page = Page(_source(bidi))
    assert not page.links
    assert visible(bidi.url) in page.content


@pytest.mark.parametrize(
    "url", ["javascript:alert(1)", "data:text/html,x", "file:///tmp/x", "//evil.invalid"]
)
def test_glossary_model_rejects_active_or_unreviewed_url_schemes(url):
    with pytest.raises(ValidationError):
        Source(title="Fuente", publisher="Editor", url=url, verified_on=date(2026, 1, 1))


def test_external_results_are_separate_inert_brief_and_attributed(trusted):
    report = trusted[2]
    external = VirusTotalReport(
        sample_sha256=report.sample.sha256,
        retrieved_at=NOW,
        status="found",
        permalink=f"https://www.virustotal.com/gui/file/{report.sample.sha256}",
        detections=tuple(
            Detection(engine=f"Engine-{i}", category="malicious", result=f"label-{i}")
            for i in range(18)
        ),
        detections_omitted=2,
        meaningful_name='<script src="https://evil.invalid"></script>\u202e',
        behaviour=Behaviour(
            command_executions=tuple(f"cmd-{i}" for i in range(18)),
            files_written=("https://evil.invalid/sample",),
            omitted=3,
        ),
    )
    output = to_html(*trusted, external=external)
    page = Page(output)
    assert "Fuente externa: VirusTotal (no verificada por LupaBin)" in page.content
    assert "Total de motores: no disponible" in page.content
    assert "Estos datos vienen de VirusTotal, no de LupaBin" in page.content
    assert "3 entradas omitidas por formato o límite." in page.content
    assert "label-17" not in page.content and "cmd-17" not in page.content
    assert "15 etiquetas externas omitidas en este HTML" in page.content
    assert "15 entradas de Comandos ejecutados omitidas en este HTML" in page.content
    assert visible(external.meaningful_name) in page.content
    assert "script" not in {tag for tag, _ in page.elements}
    assert all("evil.invalid" not in link for link in page.links)
    assert "\u202e" not in output
    assert "No se incluyen datos de VirusTotal" not in page.content
    assert "pre" not in {tag for tag, _ in page.elements}
    assert "Los datos externos no forman parte del JSON de hechos" in page.content


def test_external_empty_behaviour_keeps_omission_notice(trusted):
    sha256 = trusted[2].sample.sha256
    external = VirusTotalReport(
        sample_sha256=sha256,
        retrieved_at=NOW,
        status="found",
        permalink=f"https://www.virustotal.com/gui/file/{sha256}",
        behaviour=Behaviour(omitted=2),
    )
    assert (
        "2 entradas omitidas por formato o límite."
        in Page(to_html(*trusted, external=external)).content
    )


def test_external_report_of_another_sample_is_rejected(trusted, monkeypatch):
    monkeypatch.setattr(renderer, "MAX_HTML_BYTES", 0)
    external = VirusTotalReport(
        sample_sha256="0" * 64,
        retrieved_at=NOW,
        status="not_found",
        permalink="https://www.virustotal.com/gui/file/" + "0" * 64,
    )
    with pytest.raises(ValueError, match="another sample") as caught:
        to_html(*trusted, external=external)
    assert not isinstance(caught.value, HtmlExportError)


def test_public_signature_matches_markdown_and_limit_is_fixed():
    assert inspect.signature(to_html) == inspect.signature(document.to_markdown)
    assert renderer.MAX_HTML_BYTES == 32 * 1024 * 1024


def test_many_strings_stay_in_report_json_but_not_in_brief_html():
    texts = tuple(f"private-fixture-string-{n:04d}" for n in range(400))
    args = prepared(build_pe() + b"\0" + b"\0".join(t.encode() for t in texts) + b"\0")
    explanation, items, report, _ = args
    before = report.model_dump_json()
    output = to_html(*args)
    page = Page(output)
    assert all(text in before and text not in output for text in texts)
    assert report.model_dump_json() == before
    assert len(json.loads(before)["evidence"]) == len(report.evidence)
    selected = renderer._select(items)
    shown = sum(ref.startswith("evidence-") for ref in page.ids)
    assert f"{len(items) - len(selected)} explicaciones validadas omitidas" in page.content
    assert f"{len(report.evidence) - shown} evidencias sin ficha en este HTML" in page.content
    assert "El JSON de hechos conserva todas las evidencias" in page.content
    assert "La web permite consultar todas las explicaciones validadas" in page.content
    assert not {"pre", "details"} & {tag for tag, _ in page.elements}
    assert "raw_hex" not in output
    assert len(output.encode()) < len(before.encode())
    assert len(explanation.items) == len(items)


def test_selection_is_bounded_deterministic_and_deduplicated(trusted):
    base = trusted[1][0]
    items = tuple(
        base.model_copy(update={"id": f"X{n}", "rule": "anomaly.test@1"}) for n in range(1, 31)
    )
    assert renderer._select(items + items) == items[: renderer.MAX_ITEMS]
    assert renderer._select(items + items) == renderer._select(items + items)
    calls = base.model_copy(update={"id": "X31", "rule": "code.calls@1"})
    assert calls not in renderer._select((calls, *items))


@pytest.fixture(scope="module")
def triage_reports():
    return {path: prepared(build_triage(path=path)) for path in (PDB_PATH, b"")}


@pytest.mark.parametrize("path", [PDB_PATH, b""])
def test_validated_triage_context_keeps_limits_citations_and_brief_output(triage_reports, path):
    args = triage_reports[path]
    _, items, report, glossary = args
    before = report.model_dump_json()
    selected = renderer._select(items)
    triage = tuple(item for item in selected if item.rule in TRIAGE_RULES)
    pdb_rule = "debug.pdb@1" if path else "debug.pdb_unnamed@1"
    assert tuple(item.rule for item in triage) == (
        pdb_rule,
        "version.strings@1",
        "signature.certificates@1",
        "overlay.data@1",
    )
    output = to_html(*args)
    page = Page(output)
    assert len(selected) <= renderer.MAX_ITEMS == 16
    assert report.model_dump_json() == before
    for item in triage:
        assert item.level == "observed"
        assert visible(item.statement) in page.content
        assert visible(item.not_proven) in page.content
        assert page.ids.count(f"item-{item.id}") == 1
        for ref in item.evidence_ids[: renderer.MAX_CITATIONS]:
            assert f"#evidence-{ref}" in page.links
    assert "no descodifica ni valida" in page.content
    assert "cualquiera puede poner el nombre de otra empresa" in page.content
    assert "LupaBin no interpreta esos bytes" in page.content
    assert "no de gravedad ni de peligrosidad" in page.content
    assert len(page.ids) == len(set(page.ids))
    assert all(link[1:] in page.ids for link in page.links if link.startswith("#"))
    refs = {ref for item in selected for ref in item.evidence_ids[: renderer.MAX_CITATIONS]}
    assert f"{len(items) - len(selected)} explicaciones validadas omitidas" in page.content
    assert f"{len(report.evidence) - len(refs)} evidencias sin ficha" in page.content
    assert not {"pre", "details", "script"} & {tag for tag, _ in page.elements}
    assert "raw_hex" not in output
    for ref in page.ids:
        if ref.startswith("glossary-"):
            assert visible(glossary.entries[ref.removeprefix("glossary-")].body) not in page.content


@pytest.mark.parametrize("data", [build_pe(), b"not a PE"])
def test_absent_triage_data_do_not_create_context(data):
    args = prepared(data)
    assert not any(item.rule in TRIAGE_RULES for item in args[1])
    page = Page(to_html(*args))
    assert all(rule not in page.content for rule in TRIAGE_RULES)
    assert document.ABSENCE in page.content


@pytest.mark.parametrize("rule", TRIAGE_RULES)
def test_rejected_triage_items_are_not_recovered_from_unvalidated_explanation(triage_reports, rule):
    path = b"" if rule == "debug.pdb_unnamed@1" else PDB_PATH
    explanation, items, report, glossary = triage_reports[path]
    target = next(item for item in items if item.rule == rule)
    changed = target.model_copy(update={"statement": "UNSUPPORTED_TRIAGE_CLAIM"})
    altered = explanation.model_copy(
        update={"items": tuple(changed if item == target else item for item in items)}
    )
    valid = validate(altered, report, glossary)
    assert valid == tuple(item for item in items if item != target)
    page = Page(to_html(altered, valid, report, glossary))
    assert f"item-{target.id}" not in page.ids
    assert "UNSUPPORTED_TRIAGE_CLAIM" not in page.content
    assert rule not in page.content
    assert "1 explicaciones se omitieron porque no superaron la validación." in page.content
    assert all(link[1:] in page.ids for link in page.links if link.startswith("#"))


@pytest.mark.parametrize("rule", TRIAGE_RULES)
@pytest.mark.parametrize("occupied", [15, 16])
def test_triage_context_respects_full_quota_and_report_order(triage_reports, rule, occupied):
    path = b"" if rule == "debug.pdb_unnamed@1" else PDB_PATH
    explanation, items, report, glossary = triage_reports[path]
    target = next(item for item in items if item.rule == rule)
    header = next(item for item in items if item.rule == "pe.header@1")
    prefix = (header,) * occupied
    ordered = tuple(
        item.model_copy(update={"id": f"X{n}"})
        for n, item in enumerate((*prefix, target, *(item for item in items if item != target)), 1)
    )
    explanation = explanation.model_validate(explanation.model_dump() | {"items": ordered})
    valid = validate(explanation, report, glossary)
    assert valid == ordered
    expected = ordered[:16]
    assert tuple(item.rule for item in expected) == ("pe.header@1",) * occupied + (
        (rule,) if occupied == 15 else ()
    )
    assert renderer._select(valid) == expected
    page = Page(to_html(explanation, valid, report, glossary))
    assert [ref for ref in page.ids if ref.startswith("item-")] == [
        f"item-{item.id}" for item in expected
    ]
    assert f"{len(valid) - 16} explicaciones validadas omitidas" in page.content
    assert f"16 mostradas de {len(valid)}" in page.content
    refs = {ref for item in expected for ref in item.evidence_ids[: renderer.MAX_CITATIONS]}
    assert f"{len(report.evidence) - len(refs)} evidencias sin ficha" in page.content
    assert all(link[1:] in page.ids for link in page.links if link.startswith("#"))


def test_triage_context_does_not_displace_a_validated_anomaly():
    data = bytearray(build_triage())
    data[0xA8:0xAC] = (0xFFFFFFFF).to_bytes(4, "little")
    explanation, items, report, glossary = prepared(bytes(data))
    target = next(item for item in items if item.rule == "debug.pdb@1")
    ordered = tuple(
        item.model_copy(update={"id": f"X{n}"})
        for n, item in enumerate((*(target,) * 16, *items), 1)
    )
    explanation = explanation.model_validate(explanation.model_dump() | {"items": ordered})
    valid = validate(explanation, report, glossary)
    assert valid == ordered
    warning = next(item for item in valid if item.rule.startswith("anomaly."))
    selected = renderer._select(valid)
    assert selected == (warning, *ordered[:15])
    page = Page(to_html(explanation, valid, report, glossary))
    assert visible(warning.statement) in page.content
    assert visible(warning.not_proven) in page.content
    assert all(link[1:] in page.ids for link in page.links if link.startswith("#"))


def test_unreadable_triage_data_are_not_selected_as_facts():
    data = bytearray(build_triage(strings=(("Comments", "x" * 1025),), table=b"\0" * 16))
    data[RECORD_AT : RECORD_AT + 4] = b"BAD!"
    args = prepared(bytes(data))
    assert not any(item.rule in TRIAGE_RULES for item in args[1])
    page = Page(to_html(*args))
    assert all(rule not in page.content for rule in TRIAGE_RULES)
    assert "triage_unreadable" in page.content
    assert "triage_limit" in page.content
    assert "partial" in page.content
    assert document.ABSENCE in page.content


def test_triage_many_version_citations_have_exact_omissions():
    args = prepared(build_triage(strings=tuple((f"Key{n}", "x" * 200) for n in range(14))))
    item = next(item for item in args[1] if item.rule == "version.strings@1")
    assert len(item.evidence_ids) == 14
    page = Page(to_html(*args))
    assert visible(item.statement) in page.content
    assert visible(item.not_proven) in page.content
    assert "8 citas de evidencia omitidas en este HTML" in page.content
    for ref in item.evidence_ids[: renderer.MAX_CITATIONS]:
        assert f"#evidence-{ref}" in page.links
    for ref in item.evidence_ids[renderer.MAX_CITATIONS :]:
        assert f"evidence-{ref}" not in page.ids
    assert all(link[1:] in page.ids for link in page.links if link.startswith("#"))


def test_triage_sample_metadata_remain_inert_text():
    hostile = '<script>alert("x")</script><img src=x onerror="bad()">https://evil.invalid'
    value = hostile + "\u202e\x1b"
    args = prepared(build_triage(path=hostile.encode(), strings=(("CompanyName", value),)))
    selected = renderer._select(args[1])
    assert {"debug.pdb@1", "version.strings@1"} <= {item.rule for item in selected}
    output = to_html(*args)
    page = Page(output)
    for item in selected:
        assert visible(item.statement) in page.content
        assert visible(item.not_proven) in page.content
    assert hostile in page.content
    assert not {"script", "img"} & {tag for tag, _ in page.elements}
    assert all("evil.invalid" not in link for link in page.links)
    assert "\u202e" not in output and "\x1b" not in output
    policy = next(attrs["content"] for _, attrs in page.elements if attrs.get("http-equiv"))
    assert "script-src 'none'" in policy and "connect-src 'none'" in policy


def test_citations_extras_and_glossary_are_bounded_with_exact_omissions(trusted):
    explanation, items, report, glossary = trusted
    base = items[0]
    refs = tuple(f.id for f in report.evidence)
    terms = tuple(glossary.entries)[:8]
    item = base.model_copy(
        update={
            "evidence_ids": refs,
            "glossary_ids": terms,
            "slots": {
                "texts": tuple("a" * 200 + str(i) for i in range(9)),
                "untouched": ("NEVER_PRESENT_AS_POSITIVE",),
            },
        }
    )
    output = to_html(explanation, (item,), report, glossary)
    page = Page(output)
    assert visible(item.statement) in page.content
    assert visible(item.not_proven) in page.content
    assert f"{len(refs) - renderer.MAX_CITATIONS} citas de evidencia omitidas" in page.content
    assert "6 valores omitidos" in page.content
    assert "41 caracteres del valor original omitidos" in page.content
    assert "1 valores de familias sin llamadas omitidos" in page.content
    assert "NEVER_PRESENT_AS_POSITIVE" not in page.content
    assert len([x for x in page.ids if x.startswith("glossary-")]) <= renderer.MAX_GLOSSARY
    assert all(link[1:] in page.ids for link in page.links if link.startswith("#"))


def test_real_validated_capabilities_keep_statements_limits_and_citations():
    args = prepared(build_capability_demo(), code=True)
    page = Page(to_html(*args))
    selected = renderer._select(args[1])
    capabilities = [item for item in selected if item.rule.startswith("capability.")]
    assert capabilities
    for item in capabilities:
        assert visible(item.statement) in page.content
        assert visible(item.not_proven) in page.content
        assert page.ids.count(f"item-{item.id}") == 1
    assert all(link[1:] in page.ids for link in page.links if link.startswith("#"))
    assert document.NO_CAPABILITY not in page.content


def test_no_capabilities_is_not_presented_as_safety():
    args = prepared(build_code_pe(b"\xc3"), code=True)
    assert not any(item.rule.startswith("capability.") for item in args[1])
    page = Page(to_html(*args))
    assert document.NO_CAPABILITY in page.content
    assert document.ABSENCE in page.content


def test_notes_prioritize_recorded_issues_and_count_omissions():
    args = prepared(b"not a PE")
    explanation = args[0]
    assert len(explanation.notes) > renderer.MAX_NOTES
    page = Page(to_html(*args))
    assert "no tiene formato PE" in page.content
    assert (
        f"{len(explanation.notes) - renderer.MAX_NOTES} notas de cobertura omitidas" in page.content
    )


def test_complete_coverage_has_no_component_dump(trusted):
    args = prepared(build_pe())
    assert all(
        part.status == "complete" for run in args[2].extractor_runs for part in run.components
    )
    output = to_html(*args)
    coverage = output.split('<section id="coverage">')[1].split("</section>")[0]
    assert "componentes con cobertura completa registrada" in coverage
    assert "imports_normal" not in coverage
    assert "<table>" not in coverage


def test_glossary_and_extra_field_omissions_are_exact(trusted):
    explanation, items, report, glossary = trusted
    terms = tuple(glossary.entries)[:12]
    slots = {key: ("value",) for key in tuple(document.EXTRA)[:6]}
    first = items[0].model_copy(update={"glossary_ids": terms[:8], "slots": slots})
    second = first.model_copy(update={"id": "X999", "glossary_ids": terms[8:]})
    page = Page(to_html(explanation, (first, second), report, glossary))
    assert "4 términos citados omitidos" in page.content
    assert "4 citas de glosario omitidas" in page.content
    assert "2 campos extra omitidos" in page.content
    assert len([ref for ref in page.ids if ref.startswith("glossary-")]) == 8
    assert all(link[1:] in page.ids for link in page.links if link.startswith("#"))


def test_density_warning_is_selected_even_after_many_findings(trusted):
    base = trusted[1][0]
    findings = tuple(
        base.model_copy(update={"id": f"X{n}", "rule": "anomaly.test@1"}) for n in range(1, 30)
    )
    warning = base.model_copy(update={"id": "X30", "rule": "code.walk_density@1"})
    assert renderer._select((*findings, warning))[0] == warning


def test_brief_evidence_locations_are_not_invented(trusted):
    explanation, items, report, glossary = trusted
    refs = tuple(fact.id for fact in report.evidence[: renderer.MAX_CITATIONS])
    item = items[0].model_copy(update={"evidence_ids": refs})
    output = to_html(explanation, (item,), report, glossary)
    for fact in report.evidence[: renderer.MAX_CITATIONS]:
        row = output.split(f'<tr id="evidence-{fact.id}">')[1].split("</tr>")[0]
        location = fact.location
        for field in ("offset", "rva"):
            value = getattr(location, field, None)
            assert (f"0x{value:x}" if value is not None else "no determinado") in row
    assert "raw_hex" not in output


def test_truncated_extra_text_is_neutralized(trusted):
    explanation, items, report, glossary = trusted
    hostile = '<img src=x onerror="bad()">\u202e\x00' + "x" * 200
    item = items[0].model_copy(update={"slots": {"text": hostile, "complete": False}})
    output = to_html(explanation, (item,), report, glossary)
    page = Page(output)
    assert visible(hostile[: renderer.MAX_VALUE_CHARS]) in page.content
    assert "caracteres del valor original omitidos" in page.content and "recortado" in page.content
    assert "img" not in {tag for tag, _ in page.elements}
    assert "\u202e" not in output and "\x00" not in output


def test_headings_and_navigation_have_no_inherited_numbering(trusted):
    output = to_html(*trusted)
    for title in (
        "Qué se pudo analizar",
        "Lectura seleccionada",
        "Glosario breve",
        "Fuente externa: VirusTotal (no verificada por LupaBin)",
    ):
        assert f"<h2>{title}</h2>" in output
    for number in (1, 3, 4, 5):
        assert f"<h2>{number}. " not in output
    assert "sección 1" not in output and "sección 3" not in output
    page = Page(output)
    assert all(link[1:] in page.ids for link in page.links if link.startswith("#"))


def test_all_families_touched_does_not_count_none_sentinel_as_omitted(trusted):
    explanation, items, report, glossary = trusted
    item = items[0].model_copy(
        update={
            "rule": "code.areas@1",
            "slots": {
                "count": 9,
                "total": 9,
                "touched": tuple(f"family-{n}" for n in range(9)),
                "untouched": ("ninguna",),
            },
        }
    )
    page = Page(to_html(explanation, (item,), report, glossary))
    assert "valores de familias sin llamadas omitidos" not in page.content
    assert visible(item.not_proven) in page.content


def test_main_texts_are_shown_once_with_limits_and_citations(trusted):
    explanation, items, report, glossary = trusted
    texts = tuple(f"main-reading-text-{n}" for n in range(4))
    item = items[0].model_copy(
        update={
            "rule": "strings.from_main@1",
            "slots": {"texts": texts},
        }
    )
    assert renderer._select((item,)) == (item,)
    output = to_html(explanation, (item,), report, glossary)
    page = Page(output)
    header = output.split("</header>")[0]
    for text in texts[:3]:
        assert page.content.count(text) == 1
        assert text not in header
    assert texts[3] not in output
    assert "1 valores omitidos" in page.content
    assert visible(item.not_proven) in page.content
    for ref in item.evidence_ids[: renderer.MAX_CITATIONS]:
        assert f"#evidence-{ref}" in page.links
    assert all(link[1:] in page.ids for link in page.links if link.startswith("#"))


def test_main_text_preview_prefers_words_over_decorative_lines(trusted):
    explanation, items, report, glossary = trusted
    texts = ("«================»", "«Taller practico»", "«Introduzca el pin»", "«Enhorabuena»")
    item = items[0].model_copy(update={"rule": "strings.from_main@1", "slots": {"texts": texts}})
    output = Page(to_html(explanation, (item,), report, glossary)).content
    assert texts[0] not in output
    assert all(text in output for text in texts[1:])
    assert "1 valores omitidos" in output
    assert visible(item.not_proven) in output


def test_brief_counts_original_characters_before_neutralizing():
    value = "\u202e" * (renderer.MAX_VALUE_CHARS + 2)
    brief = renderer._brief(value)
    assert brief == value[: renderer.MAX_VALUE_CHARS] + (
        "… [2 caracteres del valor original omitidos]"
    )
    assert (
        visible(value[: renderer.MAX_VALUE_CHARS])
        in Page(renderer._collect(renderer._text_chunks(brief), 100_000)).content
    )


def test_full_document_limit_counts_final_utf8_bytes_and_accepts_exact_fit(trusted, monkeypatch):
    output = to_html(*trusted, origin="á<&\"'\u202e\U00020000")
    size = len(output.encode("utf-8"))
    assert size > len(output)
    monkeypatch.setattr(renderer, "MAX_HTML_BYTES", size)
    assert to_html(*trusted, origin="á<&\"'\u202e\U00020000") == output
    monkeypatch.setattr(renderer, "MAX_HTML_BYTES", size - 1)
    with pytest.raises(HtmlLimitError) as caught:
        to_html(*trusted, origin="á<&\"'\u202e\U00020000")
    assert caught.value.max_bytes == size - 1
    assert isinstance(caught.value, HtmlExportError)
    assert not isinstance(caught.value, ValueError)
    assert str(size - 1) in str(caught.value)
    assert "UTF-8" in str(caught.value)


def test_collect_stops_at_first_overflow_without_consuming_remaining_fragments():
    visited = []

    def fragments():
        visited.append("first")
        yield "á"
        visited.append("overflow")
        yield "界"
        pytest.fail("fragments after overflow must not be requested")

    with pytest.raises(HtmlLimitError):
        renderer._collect(fragments(), 4)
    assert visited == ["first", "overflow"]
    assert renderer._collect(("á", "界"), 5) == "á界"
    assert renderer._collect((), 0) == ""
    with pytest.raises(HtmlLimitError):
        renderer._collect(("a",), 0)


def test_collect_encodes_only_bounded_slices_of_each_fragment():
    slices = []

    class Fragment(str):
        def encode(self, *args, **kwargs):
            pytest.fail("the whole fragment must not be encoded before checking the budget")

        def __getitem__(self, key):
            assert isinstance(key, slice)
            assert key.stop - key.start <= renderer.TEXT_CHUNK
            slices.append(key)
            return super().__getitem__(key)

    value = Fragment("á" * (renderer.TEXT_CHUNK * 4))
    with pytest.raises(HtmlLimitError):
        renderer._collect((value,), 1)
    assert slices == [slice(0, renderer.TEXT_CHUNK)]


@pytest.mark.parametrize("limit", [-1, True, False, 1.5, "32", None])
def test_invalid_limit_is_not_reported_as_export_overflow(limit):
    def fragments():
        pytest.fail("invalid limit must be rejected before requesting fragments")
        yield "unused"

    with pytest.raises(ValueError, match="non-negative integer") as caught:
        renderer._collect(fragments(), limit)
    assert not isinstance(caught.value, HtmlExportError)


@pytest.mark.parametrize("chunk_size", [1, 2, 7, 1024])
def test_unicode_chunk_boundaries_preserve_visible_escaped_text(monkeypatch, chunk_size):
    monkeypatch.setattr(renderer, "TEXT_CHUNK", chunk_size)
    value = ("x" * 1023 + "á\U00020000\u202e\ud800\x00<&\"'\\\n") * 2
    expected = escape(visible(value), quote=True)
    size = len(expected.encode("utf-8"))
    assert renderer._collect(renderer._text_chunks(value), size) == expected
    with pytest.raises(HtmlLimitError):
        renderer._collect(renderer._text_chunks(value), size - 1)


def test_text_is_neutralized_in_bounded_chunks_before_budget_check(monkeypatch):
    calls = []

    def checked_visible(value):
        calls.append(len(value))
        assert len(value) <= renderer.TEXT_CHUNK
        return visible(value)

    monkeypatch.setattr(renderer, "visible", checked_visible)
    text = "\x00" * (renderer.TEXT_CHUNK * 4)
    with pytest.raises(HtmlLimitError):
        renderer._collect(renderer._text_chunks(text), 1)
    assert calls == [renderer.TEXT_CHUNK]


def test_tuple_values_are_not_joined_before_budget_check():
    class Unvisited:
        def __str__(self):
            pytest.fail("tuple values must not be joined eagerly")

    with pytest.raises(HtmlLimitError):
        renderer._collect(renderer._value(("first", Unvisited())), 1)
    assert renderer._collect(renderer._value(("á", "<&")), 100) == "á, &lt;&amp;"


def test_public_renderer_stops_before_later_values(trusted, monkeypatch):
    def fragments(*args):
        yield "oversized"
        pytest.fail("to_html must not collect all fragments before checking the budget")

    monkeypatch.setattr(renderer, "MAX_HTML_BYTES", 1)
    monkeypatch.setattr(renderer, "_fragments", fragments)
    with pytest.raises(HtmlLimitError):
        to_html(*trusted)
