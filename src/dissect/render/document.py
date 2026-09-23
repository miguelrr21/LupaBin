"""Terminal and Markdown views of a validated explanation.

Order is fixed by the design: the sample, what could not be analysed, observed facts,
inferences, and the glossary of the terms used. Only items that regenerate exactly
from their citations are shown; the number of omitted items is stated.
"""

import textwrap
from collections.abc import Iterable

from dissect.evidence.models import Report
from dissect.explain.models import Explanation, Item, SlotValue
from dissect.explain.rules import RULES
from dissect.glossary.catalog import Glossary
from dissect.glossary.models import Entry
from dissect.render.safe import code_span, markdown_text, visible

WIDTH = 100
STATUS = {"completed": "completo", "partial": "parcial", "failed": "fallido"}
ABSENCE = (
    "Recuerda: que algo no aparezca no demuestra que no esté. Solo significa que los "
    "métodos de Dissect no lo encontraron en las partes que pudieron revisar."
)
EXTRA = {
    "functions": "Funciones",
    "names": "Primeros nombres",
    "description": "Qué significa, según el catálogo",
    "text": "Texto",
}


def _extras(item: Item) -> Iterable[tuple[str, SlotValue]]:
    for key, label in EXTRA.items():
        if key in item.slots:
            yield label, item.slots[key]


def _glossary_order(explanation: Explanation, items: tuple[Item, ...]) -> list[str]:
    seen: dict[str, None] = {}
    for note in explanation.notes:
        seen.update(dict.fromkeys(note.glossary_ids))
    for item in items:
        seen.update(dict.fromkeys(item.glossary_ids))
    return list(seen)


def _source_line(entry: Entry) -> list[str]:
    return [
        f"{source.title} ({source.publisher}): {source.url or source.document}"
        for source in entry.sources
    ]


# --- terminal ---------------------------------------------------------------------


def _wrap(text: str, indent: str, first: str | None = None) -> list[str]:
    return textwrap.wrap(
        text,
        WIDTH,
        initial_indent=first if first is not None else indent,
        subsequent_indent=indent,
        break_long_words=True,
        break_on_hyphens=False,
    ) or [first or indent]


def to_text(
    explanation: Explanation, items: tuple[Item, ...], report: Report, glossary: Glossary
) -> str:
    sample = report.sample
    lines = [
        "DISSECT · informe didáctico (análisis estático: la muestra no se ejecutó)",
        "",
        f"Muestra   SHA-256 {sample.sha256}",
        f"          MD5 {sample.md5} (solo como referencia; MD5 admite colisiones)",
        f"          {sample.size} bytes · tipo {sample.type}",
        f"Análisis  {STATUS[explanation.status]}",
        "",
        "1. Qué se pudo analizar",
    ]
    for note in explanation.notes:
        lines += _wrap(visible(note.statement), "     ", "   • ")
    sections = (
        ("2. Hechos observados en los bytes", "observed"),
        ("3. Inferencias: resultados de aplicar una transformación a los bytes", "inferred"),
    )
    for title, level in sections:
        lines += ["", title]
        chosen = [item for item in items if item.level == level]
        if not chosen:
            lines.append("   (ninguno)")
        for item in chosen:
            lines += _wrap(visible(item.statement), "        ", f"   {item.id:<5}")
            for label, value in _extras(item):
                shown = ", ".join(value) if isinstance(value, tuple) else str(value)
                if label == "Texto":
                    shown = f"«{shown}»" + ("" if item.slots.get("complete") else " (recortado)")
                lines += _wrap(visible(f"{label}: {shown}"), "          ", "        ")
            lines += _wrap(visible(f"Límite: {item.not_proven}"), "          ", "        ")
            lines += _wrap(
                f"Evidencia: {', '.join(item.evidence_ids[:12])}"
                + (f" y {len(item.evidence_ids) - 12} más" if len(item.evidence_ids) > 12 else "")
                + f" · Glosario: {', '.join(item.glossary_ids)}",
                "          ",
                "        ",
            )
    omitted = len(explanation.items) - len(items)
    if omitted:
        lines += ["", f"{omitted} explicaciones se omitieron porque no superaron la validación."]
    lines += ["", "4. Glosario de los términos usados"]
    for entry_id in _glossary_order(explanation, items):
        entry = glossary.entries[entry_id]
        lines += _wrap(visible(f"{entry.title} ({entry.id}): {entry.summary}"), "     ", "   • ")
        if entry.not_proven:
            lines += _wrap(visible(f"Límite: {entry.not_proven}"), "       ")
        for source in _source_line(entry):
            lines += _wrap(visible(f"Fuente: {source}"), "         ", "       ")
    lines += ["", *_wrap(ABSENCE, "")]
    return "\n".join(lines) + "\n"


# --- Markdown -----------------------------------------------------------------------


def _markdown_statement(item: Item) -> str:
    """The rule's trusted template, with every slot rendered as an inert code span."""
    template = RULES[item.rule].template
    values = {
        key: code_span(", ".join(value) if isinstance(value, tuple) else str(value))
        for key, value in item.slots.items()
    }
    return template.replace("«", "").replace("»", "").format(**values)


def to_markdown(
    explanation: Explanation, items: tuple[Item, ...], report: Report, glossary: Glossary
) -> str:
    sample = report.sample
    lines = [
        "# Dissect: informe didáctico",
        "",
        "Análisis estático: la muestra no se ejecutó.",
        "",
        f"- **SHA-256**: `{sample.sha256}`",
        f"- **MD5** (solo como referencia; admite colisiones): `{sample.md5}`",
        f"- **Tamaño**: {sample.size} bytes · **tipo**: {sample.type}",
        f"- **Análisis**: {STATUS[explanation.status]}",
        "",
        "## 1. Qué se pudo analizar",
        "",
    ]
    lines += [f"- {markdown_text(note.statement)}" for note in explanation.notes]
    sections = (
        ("## 2. Hechos observados en los bytes", "observed"),
        ("## 3. Inferencias: resultados de aplicar una transformación a los bytes", "inferred"),
    )
    for title, level in sections:
        lines += ["", title, ""]
        chosen = [item for item in items if item.level == level]
        if not chosen:
            lines.append("_(ninguno)_")
        for item in chosen:
            lines.append(f"- **{item.id}**: {_markdown_statement(item)}")
            for label, value in _extras(item):
                shown = ", ".join(value) if isinstance(value, tuple) else str(value)
                lines.append(f"  - {label}: {code_span(shown)}")
            lines.append(f"  - Límite: {markdown_text(item.not_proven)}")
            lines.append(
                f"  - Evidencia: {', '.join(item.evidence_ids)} · Glosario: "
                + ", ".join(markdown_text(ref) for ref in item.glossary_ids)
            )
    omitted = len(explanation.items) - len(items)
    if omitted:
        lines += ["", f"{omitted} explicaciones se omitieron porque no superaron la validación."]
    lines += ["", "## 4. Glosario de los términos usados", ""]
    for entry_id in _glossary_order(explanation, items):
        entry = glossary.entries[entry_id]
        lines += [f"### {markdown_text(entry.title)}", "", markdown_text(entry.summary), ""]
        lines += [markdown_text(paragraph) + "\n" for paragraph in entry.body.split("\n\n")]
        if entry.not_proven:
            lines += [f"**Límite**: {markdown_text(entry.not_proven)}", ""]
        for source in entry.sources:
            # catalog URLs are reviewed and cannot contain spaces, quotes or angle brackets
            where = f"<{source.url}>" if source.url else code_span(source.document or "")
            lines.append(
                f"- {markdown_text(source.title)} ({markdown_text(source.publisher)}): {where}"
            )
        lines.append("")
    lines += [markdown_text(ABSENCE)]
    return "\n".join(lines) + "\n"
