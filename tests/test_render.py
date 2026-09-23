import re

import pytest

from dissect.analysis import analyze_bytes
from dissect.explain.engine import explain, validate
from dissect.glossary.catalog import load_glossary
from dissect.render.document import to_markdown, to_text
from dissect.render.safe import code_span, markdown_text, visible
from tests.fixtures.pe_builder import build_decode_demo, build_demo, build_pe

GLOSSARY = load_glossary()
# Sample-controlled names: terminal colour and clear, an OSC 8 hyperlink, a bidi
# override, and Markdown that would become a link and HTML if rendered raw.
HOSTILE_DLL = b"\x1b[31m\x1b]8;;https://evil.invalid\x07x\x1b]8;;\x07\xe2\x80\xae.dll"
HOSTILE_FUNCTION = b"`[click](https://evil.invalid)<img src=x>`\x1b[2J"


def render(data, kind):
    report = analyze_bytes(data)
    explanation = explain(report, GLOSSARY)
    items = validate(explanation, report, GLOSSARY)
    return (to_text if kind == "text" else to_markdown)(explanation, items, report, GLOSSARY)


@pytest.mark.parametrize(
    "raw,shown",
    [
        ("\x1b[31m", "\\x1b[31m"),
        ("a\\x1b", "a\\\\x1b"),
        ("\u202eexe.txt", "\\u202eexe.txt"),
        ("tab\there\nline", "tab\\x09here\\x0aline"),
        ("\x9b", "\\x9b"),
        ("zero\u200bwidth", "zero\\u200bwidth"),
        ("plain text", "plain text"),
    ],
)
def test_visible_neutralises_control_bidi_and_invisible_characters(raw, shown):
    assert visible(raw) == shown


def test_code_spans_cannot_be_closed_from_inside():
    assert code_span("a") == "`a`"
    assert code_span("a`b") == "``a`b``"
    assert code_span("`x``") == "``` `x`` ```"
    assert markdown_text("[a](b) <i>") == "\\[a\\]\\(b\\) \\<i\\>"


@pytest.mark.parametrize("kind", ["text", "markdown"])
def test_hostile_names_reach_no_output_raw(kind):
    data = bytearray(build_pe(dll=HOSTILE_DLL, function=HOSTILE_FUNCTION))
    data[0x98 + 224 : 0x98 + 232] = "\u202eexe.".encode() + b"\0"  # UTF-8 bidi override
    output = render(bytes(data), kind)
    assert "\x1b" not in output and "\x07" not in output and "\u202e" not in output
    assert "\\x1b" in output and "\\u202e" in output
    if kind == "markdown":
        spans = re.findall(r"(`+)(.+?)\1", output)
        outside = re.sub(r"(`+).+?\1", "", output)
        assert "<img" not in outside and "](https://evil" not in outside
        assert any("<img" in body for _, body in spans)


@pytest.mark.parametrize("kind", ["text", "markdown"])
def test_documents_keep_the_designed_order_and_caveats(kind):
    output = render(build_demo(), kind)
    marks = ["1. Qué se pudo", "2. Hechos observados", "3. Inferencias", "4. Glosario"]
    positions = [output.index(mark) for mark in marks]
    assert positions == sorted(positions)
    assert "Límite" in output and "no demuestra" in output.lower()
    assert "no demuestra que no esté" in output


def test_inferences_show_the_decoded_text_and_the_method():
    output = render(build_decode_demo(), "text")
    inferences = " ".join(output.split("3. Inferencias")[1].split("4. Glosario")[0].split())
    assert "«https://training.invalid/decode/base64»" in inferences
    assert "clave c381f79e (4 bytes)" in inferences
    assert "clave a5 (1 byte)" in inferences
    assert "La clave la estableció la decodificación" in inferences


def test_a_failed_analysis_explains_what_was_not_analysed():
    output = render(b"just some text, not a PE file at all " * 4, "text")
    assert "no tiene formato PE" in output
    assert "Análisis  parcial" in output or "Análisis  fallido" in output


def test_omitted_items_are_counted():
    report = analyze_bytes(build_demo())
    explanation = explain(report, GLOSSARY)
    items = explanation.items[1:]
    output = to_text(explanation, items, report, GLOSSARY)
    assert "1 explicaciones se omitieron" in output
