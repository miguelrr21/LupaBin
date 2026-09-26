"""Terminal and Markdown views of a validated explanation.

Order is fixed: the sample, a summary of the code's capabilities, what could not be
analysed, observed facts, inferences, and the glossary
of the terms used. Only items that regenerate exactly
from their citations are shown; the number of omitted items is stated.
"""

import textwrap
from collections.abc import Iterable
from typing import NamedTuple

from lupabin.evidence.facts import ApiCallEvidence, ImportEvidence
from lupabin.evidence.models import Report
from lupabin.explain.capabilities import BY_RULE, CATALOG_ID, TACTICS
from lupabin.explain.models import Explanation, Item, SlotValue
from lupabin.explain.rules import RULES
from lupabin.glossary.catalog import Glossary
from lupabin.glossary.models import Entry
from lupabin.render import external as vt
from lupabin.render.safe import code_span, markdown_text, visible
from lupabin.virustotal.models import VirusTotalReport

WIDTH = 100
STATUS = {"completed": "completo", "partial": "parcial", "failed": "fallido"}
ABSENCE = (
    "Recuerda: que algo no aparezca no demuestra que no esté. Solo significa que los "
    "métodos de LupaBin no lo encontraron en las partes que pudieron revisar."
)
EXTRA = {
    "functions": "Funciones",
    "sites": "Desde (RVA)",
    "cases": "Casos",
    "ranges": "Rangos (RVA)",
    "techniques": "Técnicas de MITRE ATT&CK con el mismo mecanismo",
    "names": "Primeros nombres",
    "unlisted": "Sin import con ese nombre",
    "description": "Qué significa, según el catálogo",
    "text": "Texto",
}


SUMMARY_TITLE = "Resumen: qué contiene el código"
SUMMARY_INTRO = (
    "Capacidades reconocidas a partir de las llamadas del código y de sus argumentos "
    "constantes. Que el código las contenga no demuestra que el programa las use, ni con "
    "qué intención; el detalle y el límite de cada una están en la sección 3."
)
NO_CODE = "El código no se pudo recorrer: no se puede decir qué contiene."
NO_CAPABILITY = (
    f"No se reconoció ninguna capacidad del catálogo {CATALOG_ID}. Eso no demuestra que el "
    "código no las tenga."
)
CODE_PARTS = ("disassembly", "api_calls", "call_arguments")
PARTIAL_CODE = (
    "El recorrido del código, sus llamadas o sus argumentos quedaron incompletos (ver la "
    "sección 1): puede haber capacidades que no aparecen."
)
CREATE_PROCESS_W = (
    "El código llama a CreateProcessW, cuya línea de órdenes LupaBin no lee (tiene que "
    "estar en memoria escribible): lo que ejecuta esa llamada no aparece aquí."
)
ONE_CALL = (
    "Casi todas las capacidades son de una sola llamada. Solo se encadenan llamadas en un "
    "caso: abrir una clave Run o Winlogon y llamar a RegSetValueEx, cuando el identificador "
    "pasa por una variable local en un camino recto o, solo en x64, en el mismo rango de "
    "función de .pdata sin seguirlo. El resto no aparece."
)


# The tool each toolchain explanation names, in the report's order of markers. Fixed
# labels: the line never repeats text from the sample (the items it cites do).
MADE_WITH = {
    "toolchain.rich_header@1": "enlazador de Microsoft",
    "toolchain.gcc_ident@1": "GCC",
    "toolchain.mingw_w64_runtime@1": "MinGW-w64",
    "toolchain.go_buildinfo@1": "Go",
    "toolchain.go_buildinfo_pointer@1": "Go",
    "toolchain.clr_header@1": ".NET",
    "toolchain.pyinstaller_cookie@1": "PyInstaller",
}
MADE_WITH_NOTE = "según las marcas que dejan esas herramientas, que pueden copiarse"


def made_with(items: tuple[Item, ...]) -> str | None:
    """The tools whose markers the validated items show, each with its item, or None."""
    shown = [f"{MADE_WITH[item.rule]} ({item.id})" for item in items if item.rule in MADE_WITH]
    if not shown:
        return None
    return " · ".join(shown) + f", {MADE_WITH_NOTE}."


def main_line(items: tuple[Item, ...]) -> str | None:
    """Where main is and how the published calls split, from the validated items."""
    found = {
        item.rule: item
        for item in items
        if item.rule.startswith(("code.main_call@", "code.reach_"))
    }
    main = found.get("code.main_call@1")
    if main is None:
        return None
    parts = [f"{main.slots['target']} ({main.id})"]
    reach = found.get("code.reach_main@1")
    if reach is not None:
        reachable = "alcanzable" if reach.slots["noun"] == "llamada" else "alcanzables"
        parts.append(
            f"{reach.slots['count']} {reach.slots['noun']} {reachable} desde main ({reach.id})"
        )
    startup = found.get("code.reach_startup@1")
    if startup is not None:
        parts.append(f"{startup.slots['count']} solo del arranque ({startup.id})")
    return " · ".join(parts)


class Summary(NamedTuple):
    groups: list[tuple[str, list[Item]]]  # (tactic, its capability items), design order
    warnings: list[str | Item]  # what limits the summary; an Item is the density note


def summary(items: tuple[Item, ...], report: Report) -> Summary:
    """Capabilities grouped by tactic, then the warnings that limit what they show."""
    run = next((r for r in report.extractor_runs if r.source == "code"), None)
    parts: dict[str, str] = {p.name: p.status for p in (run.components if run else ())}
    if parts.get("disassembly", "blocked") == "blocked":
        return Summary([], [NO_CODE])
    groups = []
    for tactic, label in TACTICS.items():
        chosen = [i for i in items if i.rule in BY_RULE and BY_RULE[i.rule].tactic == tactic]
        if chosen:
            groups.append((label[0].upper() + label[1:], chosen))
    warnings: list[str | Item] = [] if groups else [NO_CAPABILITY]
    warnings += [item for item in items if item.rule == "code.walk_density@1"]
    if any(parts.get(part, "complete") != "complete" for part in CODE_PARTS):
        warnings.append(PARTIAL_CODE)
    facts = {fact.id: fact for fact in report.evidence}
    callees = (
        facts.get(fact.provenance.evidence_ids[0])
        for fact in report.evidence
        if isinstance(fact, ApiCallEvidence)
    )
    if any(
        isinstance(callee, ImportEvidence)
        and callee.data.function is not None
        and callee.data.function.text == "CreateProcessW"
        for callee in callees
    ):
        warnings.append(CREATE_PROCESS_W)
    warnings.append(ONE_CALL)
    return Summary(groups, warnings)


def _techniques(item: Item) -> str | None:
    shown = item.slots.get("techniques")
    if not isinstance(shown, tuple):
        return None
    return "Técnicas de MITRE ATT&CK con el mismo mecanismo: " + ", ".join(shown)


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


def wrap(text: str, indent: str, first: str | None = None) -> list[str]:
    return textwrap.wrap(
        text,
        WIDTH,
        initial_indent=first if first is not None else indent,
        subsequent_indent=indent,
        break_long_words=False,
        break_on_hyphens=False,
    ) or [first or indent]


def to_text(
    explanation: Explanation,
    items: tuple[Item, ...],
    report: Report,
    glossary: Glossary,
    origin: str | None = None,
    external: VirusTotalReport | None = None,
) -> str:
    sample = report.sample
    lines = [
        "LUPABIN · informe didáctico (análisis estático: la muestra no se ejecutó)",
        "",
        f"Muestra   SHA-256 {sample.sha256}",
        f"          MD5 {sample.md5} (solo como referencia; MD5 admite colisiones)",
        f"          {sample.size} bytes · tipo {sample.type}",
        f"Análisis  {STATUS[explanation.status]}",
    ]
    if origin:
        lines += wrap(origin, "          ", "Origen    ")
    tools = made_with(items)
    if tools:
        lines += wrap(tools, "          ", "Hecho con ")
    entered = main_line(items)
    if entered:
        lines += wrap(entered, "          ", "main      ")
    lines += ["", SUMMARY_TITLE, *wrap(SUMMARY_INTRO, "   ")]
    overview = summary(items, report)
    for tactic, chosen in overview.groups:
        lines += ["", f"   {tactic}"]
        for item in chosen:
            lines += wrap(visible(item.statement), "          ", f"   {item.id:<6} ")
            techniques = _techniques(item)
            if techniques:
                lines += wrap(techniques, "          ")
    lines.append("")
    for warning in overview.warnings:
        text = f"{warning.id}: {warning.statement}" if isinstance(warning, Item) else warning
        lines += wrap(visible(text), "     ", "   • ")
    lines += ["", "1. Qué se pudo analizar"]
    for note in explanation.notes:
        lines += wrap(visible(note.statement), "     ", "   • ")
    sections = (
        ("2. Hechos observados en los bytes", "observed"),
        (
            "3. Inferencias: resultados de aplicar un método a los bytes, no lecturas directas",
            "inferred",
        ),
    )
    for title, level in sections:
        lines += ["", title]
        chosen = [item for item in items if item.level == level]
        if not chosen:
            lines.append("   (ninguno)")
        for item in chosen:
            lines += wrap(visible(item.statement), "        ", f"   {item.id:<5}")
            for label, value in _extras(item):
                shown = ", ".join(value) if isinstance(value, tuple) else str(value)
                if label == "Texto":
                    shown = f"«{shown}»" + ("" if item.slots.get("complete") else " (recortado)")
                lines += wrap(visible(f"{label}: {shown}"), "          ", "        ")
            lines += wrap(visible(f"Límite: {item.not_proven}"), "          ", "        ")
            lines += wrap(
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
        lines += wrap(visible(f"{entry.title} ({entry.id}): {entry.summary}"), "     ", "   • ")
        if entry.not_proven:
            lines += wrap(visible(f"Límite: {entry.not_proven}"), "       ")
        for source in _source_line(entry):
            lines += wrap(visible(f"Fuente: {source}"), "         ", "       ")
    if external is not None:
        lines += vt.to_text_lines(external, wrap)
    lines += ["", *wrap(ABSENCE, "")]
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
    explanation: Explanation,
    items: tuple[Item, ...],
    report: Report,
    glossary: Glossary,
    origin: str | None = None,
    external: VirusTotalReport | None = None,
) -> str:
    sample = report.sample
    lines = [
        "# LupaBin: informe didáctico",
        "",
        "Análisis estático: la muestra no se ejecutó.",
        "",
        f"- **SHA-256**: `{sample.sha256}`",
        f"- **MD5** (solo como referencia; admite colisiones): `{sample.md5}`",
        f"- **Tamaño**: {sample.size} bytes · **tipo**: {sample.type}",
        f"- **Análisis**: {STATUS[explanation.status]}",
    ]
    if origin:
        lines.append(f"- **Origen**: {markdown_text(origin)}")
    tools = made_with(items)
    if tools:
        lines.append(f"- **Hecho con**: {markdown_text(tools)}")
    entered = main_line(items)
    if entered:
        lines.append(f"- **main**: {markdown_text(entered)}")
    lines += ["", f"## {SUMMARY_TITLE}", "", markdown_text(SUMMARY_INTRO)]
    overview = summary(items, report)
    for tactic, chosen in overview.groups:
        lines += ["", f"### {markdown_text(tactic)}", ""]
        for item in chosen:
            lines.append(f"- **{item.id}**: {_markdown_statement(item)}")
            techniques = _techniques(item)
            if techniques:
                lines.append(f"  - {markdown_text(techniques)}")
    lines.append("")
    for warning in overview.warnings:
        if isinstance(warning, Item):
            lines.append(f"- **{warning.id}**: {_markdown_statement(warning)}")
        else:
            lines.append(f"- {markdown_text(warning)}")
    lines += ["", "## 1. Qué se pudo analizar", ""]
    lines += [f"- {markdown_text(note.statement)}" for note in explanation.notes]
    sections = (
        ("## 2. Hechos observados en los bytes", "observed"),
        (
            "## 3. Inferencias: resultados de aplicar un método a los bytes, no lecturas directas",
            "inferred",
        ),
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
    if external is not None:
        lines += [*vt.to_markdown_lines(external), ""]
    lines += [markdown_text(ABSENCE)]
    return "\n".join(lines) + "\n"
