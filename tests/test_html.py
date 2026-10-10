import base64
import hashlib
import inspect
import json
import re
from collections import Counter
from datetime import UTC, date, datetime
from html import escape, unescape
from html.parser import HTMLParser

import pytest
from pydantic import ValidationError

from lupabin.analysis import analyze_bytes
from lupabin.evidence.models import Limits
from lupabin.explain.engine import explain, validate
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
from tests.fixtures.pe_builder import build_decode_demo, build_pe

NOW = datetime(2026, 1, 1, tzinfo=UTC)
GLOSSARY = load_glossary()


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


def prepared(data, *, limits=None, decode=False):
    extractors = [PEExtractor(), StringsExtractor()]
    if decode:
        extractors.append(DecodeExtractor())
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
    assert {f"item-{item.id}" for item in items} <= set(page.ids)
    assert {f"evidence-{fact.id}" for fact in report.evidence} <= set(page.ids)
    assert max(len(item.evidence_ids) for item in items) > 12
    for item in items:
        assert visible(item.statement) in page.content
        assert visible(item.not_proven) in page.content
        for label, value in document._extras(item):
            shown = ", ".join(value) if isinstance(value, tuple) else str(value)
            assert visible(shown) in page.content
            assert label in page.content
        for ref in item.evidence_ids:
            assert f"#evidence-{ref}" in page.links
        for ref in item.glossary_ids:
            assert f"#glossary-{ref}" in page.links
    for note in explanation.notes:
        assert visible(note.statement) in page.content
    assert to_html(*trusted) == output


def test_levels_provenance_hashes_and_glossary_remain_readable(trusted):
    explanation, items, report, glossary = trusted
    page = Page(to_html(*trusted, origin="Informe guardado; no se repitió el análisis."))
    assert {item.level for item in items} == {"observed", "inferred"}
    titles = ["1. Qué se pudo", "2. Hechos observados", "3. Inferencias", "4. Glosario"]
    positions = [page.content.index(title) for title in titles]
    assert positions == sorted(positions)
    for value in (
        report.sample.sha256,
        report.sample.md5,
        report.schema_version,
        report.analysis.version,
        NOW.isoformat(),
        explanation.glossary.digest,
        "Informe guardado; no se repitió el análisis.",
        "Límite (not_proven)",
        document.ABSENCE,
    ):
        assert value in page.content
    for run in report.extractor_runs:
        for part in run.components:
            assert part.name in page.content
            assert part.status in page.content
    for ref in document._glossary_order(explanation, items):
        entry = glossary.entries[ref]
        for paragraph in entry.body.split("\n\n"):
            assert visible(paragraph) in page.content
        for source in entry.sources:
            assert visible(source.url or source.document) in page.content


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


def test_external_results_are_separate_inert_complete_and_attributed(trusted):
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
    assert "label-17" in page.content and "cmd-17" in page.content
    assert visible(external.meaningful_name) in page.content
    assert "script" not in {tag for tag, _ in page.elements}
    assert all("evil.invalid" not in link for link in page.links)
    assert "\u202e" not in output
    assert "No se incluyen datos de VirusTotal" not in page.content
    blocks = [
        json.loads(unescape(block))
        for block in re.findall(r"<pre>(.*?)</pre>", output, flags=re.DOTALL)
    ]
    expected = json.loads(visible(json.dumps(external.model_dump(mode="json"), ensure_ascii=False)))
    assert expected in blocks


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


def test_every_evidence_and_report_metadata_are_exported_without_truncation(trusted):
    report = trusted[2]
    blocks = [
        json.loads(unescape(block))
        for block in re.findall(r"<pre>(.*?)</pre>", to_html(*trusted), flags=re.DOTALL)
    ]
    assert blocks == [
        report.analysis.limits.model_dump(mode="json"),
        report.model_dump(mode="json", exclude={"evidence"}),
        *(fact.model_dump(mode="json") for fact in report.evidence),
    ]


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


def test_json_strings_are_encoded_in_bounded_chunks_and_remain_complete(monkeypatch):
    dumps = json.dumps
    sizes = []

    def checked_dumps(value, **kwargs):
        if isinstance(value, str):
            sizes.append(len(value))
            assert len(value) <= renderer.TEXT_CHUNK
        return dumps(value, **kwargs)

    monkeypatch.setattr(renderer.json, "dumps", checked_dumps)
    value = {"key": ['á\\"\n\U00020000<&' * 400, True, None, 42, 1.5], "empty": {}}
    output = renderer._collect(renderer._json(value), 100_000)
    assert json.loads(unescape(output.removeprefix("<pre>").removesuffix("</pre>\n"))) == value
    assert max(sizes) == renderer.TEXT_CHUNK


def test_json_and_public_renderer_stop_before_later_values(trusted, monkeypatch):
    with pytest.raises(HtmlLimitError):
        renderer._collect(renderer._json(["first", object()]), 10)

    def fragments(*args):
        yield "oversized"
        pytest.fail("to_html must not collect all fragments before checking the budget")

    monkeypatch.setattr(renderer, "MAX_HTML_BYTES", 1)
    monkeypatch.setattr(renderer, "_fragments", fragments)
    with pytest.raises(HtmlLimitError):
        to_html(*trusted)
