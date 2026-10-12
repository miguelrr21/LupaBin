import base64
import hashlib
from collections.abc import Iterable, Iterator
from html import escape
from urllib.parse import urlsplit

from lupabin.evidence.models import Report
from lupabin.explain.capabilities import BY_RULE
from lupabin.explain.models import Explanation, Item
from lupabin.glossary.catalog import Glossary
from lupabin.glossary.models import Source
from lupabin.render import document
from lupabin.render import external as vt
from lupabin.render.safe import visible
from lupabin.virustotal.models import VirusTotalReport

MAX_HTML_BYTES = 32 * 1024 * 1024
TEXT_CHUNK = 1024
MAX_ITEMS = 16
MAX_CITATIONS = 6
MAX_GLOSSARY = 8
MAX_EXTRAS = 4
MAX_VALUES = 3
MAX_VALUE_CHARS = 160
MAX_NOTES = 8
CONTEXT_RULES = frozenset(
    {
        "pe.header@1",
        "debug.pdb@1",
        "debug.pdb_unnamed@1",
        "version.strings@1",
        "signature.certificates@1",
        "overlay.data@1",
        "upx.image@1",
        "upx.image_plain@1",
        "dotnet.metadata@1",
        "code.main_call@1",
        "code.reach_main@1",
        "code.reach_startup@1",
        "code.areas@1",
        "strings.from_main@1",
        "yara.match@1",
        "entropy.high@1",
    }
)

STYLE = """
:root { color-scheme: light; font-family: system-ui, sans-serif; line-height: 1.6; }
body { max-width: 64rem; margin: auto; padding: 1.5rem; color: #182536; background: #fff; }
a { color: #174f93; text-decoration: underline; }
nav ul { display: flex; flex-wrap: wrap; gap: 1.5rem; list-style: none; padding: 0; }
section { margin-block: 2rem; }
article { border: 1px solid #b8c5d4; border-radius: .3rem; padding: 1rem; margin-block: 1rem; }
h1, h2, h3 { line-height: 1.3; }
p, li, dd, td, th, h3 { overflow-wrap: anywhere; }
dt { font-weight: bold; }
dd { margin: 0 0 .6rem 1rem; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #b8c5d4; text-align: left; padding: .4rem; }
.limit { border-left: .25rem solid #8a5b00; padding-left: .75rem; }
:target { outline: 2px solid #174f93; outline-offset: .2rem; }
@media print {
  body { max-width: none; padding: 0; color: #000; font-size: 10pt; }
  nav { display: none; }
  a { color: inherit; }
  h1, h2, h3 { break-after: avoid; }
}
"""


class HtmlExportError(Exception):
    pass


class HtmlLimitError(HtmlExportError):
    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        super().__init__(f"La exportación HTML supera el límite de {max_bytes} bytes UTF-8.")


def _collect(fragments: Iterable[str], max_bytes: int) -> str:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise ValueError("max_bytes must be a non-negative integer")
    output = bytearray()
    for fragment in fragments:
        for offset in range(0, len(fragment), TEXT_CHUNK):
            encoded = fragment[offset : offset + TEXT_CHUNK].encode("utf-8")
            if len(encoded) > max_bytes - len(output):
                output.clear()
                raise HtmlLimitError(max_bytes)
            output.extend(encoded)
    return output.decode("utf-8")


def _text(value: object) -> str:
    return escape(visible(str(value)), quote=True)


def _text_chunks(value: object) -> Iterator[str]:
    text = str(value)
    for offset in range(0, len(text), TEXT_CHUNK):
        yield _text(text[offset : offset + TEXT_CHUNK])


def _value(value: object) -> Iterator[str]:
    if isinstance(value, tuple):
        for index, part in enumerate(value):
            if index:
                yield ", "
            yield from _text_chunks(part)
    else:
        yield from _text_chunks(value)


def _paragraph(value: object) -> Iterator[str]:
    yield "<p>"
    yield from _text_chunks(value)
    yield "</p>\n"


def _row(label: str, value: object) -> Iterator[str]:
    yield "<dt>"
    yield from _text_chunks(label)
    yield "</dt><dd>"
    yield from _value(value)
    yield "</dd>\n"


def _brief(value: object) -> str:
    text = str(value)
    omitted = len(text) - MAX_VALUE_CHARS
    return text[:MAX_VALUE_CHARS] + (
        f"… [{omitted} caracteres del valor original omitidos]" if omitted > 0 else ""
    )


def _links(prefix: str, refs: Iterable[str]) -> Iterator[str]:
    for index, ref in enumerate(refs):
        if index:
            yield ", "
        yield f'<a href="#{_text(prefix + ref)}">{_text(ref)}</a>'


def _citations(label: str, prefix: str, refs: Iterable[str], omitted: int = 0) -> Iterator[str]:
    yield f"<p>{_text(label)}: "
    yield from _links(prefix, refs)
    if omitted:
        yield f" · {omitted} citas de {_text(label.lower())} omitidas en este HTML"
    yield "</p>\n"


def _source(source: Source) -> str:
    where = source.url or source.document or ""
    location = _text(where)
    if source.url and visible(source.url) == source.url:
        try:
            parsed = urlsplit(source.url)
            safe = parsed.scheme in ("http", "https") and bool(parsed.hostname)
        except ValueError:
            safe = False
        if safe:
            location = f'<a href="{_text(source.url)}" rel="noreferrer">{location}</a>'
    return (
        f"<li>{_text(source.title)} ({_text(source.publisher)}): {location}"
        f" · verificada el {_text(source.verified_on)}</li>"
    )


def _select(items: tuple[Item, ...]) -> tuple[Item, ...]:
    chosen: dict[str, Item] = {}
    for group in (0, 1, 2):
        for item in items:
            coverage = item.rule == "code.walk_density@1"
            finding = item.rule in BY_RULE or item.rule.startswith("anomaly.")
            context = item.rule in CONTEXT_RULES or item.rule.startswith("toolchain.")
            if (group == 0 and coverage) or (group == 1 and finding) or (group == 2 and context):
                chosen.setdefault(item.id, item)
                if len(chosen) == MAX_ITEMS:
                    return tuple(chosen.values())
    return tuple(chosen.values())


def _item(item: Item, terms: tuple[str, ...]) -> Iterator[str]:
    yield f'<article id="item-{_text(item.id)}">'
    yield f"<h3>{_text(item.id)} · {_text(item.level)}</h3>"
    yield from _paragraph(item.statement)
    yield "<dl>"
    yield from _row("Regla", item.rule)
    extras = tuple(
        (label, value)
        for label, value in document._extras(item)
        if label != document.EXTRA["untouched"]
    )
    for label, value in extras[:MAX_EXTRAS]:
        values = value if isinstance(value, tuple) else (value,)
        if item.rule == "strings.from_main@1" and label == document.EXTRA["texts"]:
            texts = document.main_texts((item,))
            if texts is not None and isinstance(value, tuple):
                values = tuple(sorted(value, key=lambda part: part not in texts[1]))
        shown = tuple(_brief(part) for part in values[:MAX_VALUES])
        yield from _row(label, shown)
        if len(values) > MAX_VALUES:
            yield from _row(label, f"{len(values) - MAX_VALUES} valores omitidos en este HTML")
        if label == "Texto" and item.slots.get("complete") is False:
            yield "<dt>Integridad del texto</dt><dd>recortado</dd>"
    yield "</dl>"
    if len(extras) > MAX_EXTRAS:
        yield from _paragraph(f"{len(extras) - MAX_EXTRAS} campos extra omitidos en este HTML.")
    untouched = item.slots.get("untouched", ())
    if isinstance(untouched, tuple) and untouched and untouched != ("ninguna",):
        yield from _paragraph(
            f"{len(untouched)} valores de familias sin llamadas omitidos en este HTML."
        )
    yield '<p class="limit"><strong>Límite (not_proven):</strong> '
    yield from _text_chunks(item.not_proven)
    yield "</p>"
    yield from _citations(
        "Evidencia",
        "evidence-",
        item.evidence_ids[:MAX_CITATIONS],
        max(0, len(item.evidence_ids) - MAX_CITATIONS),
    )
    refs = tuple(ref for ref in item.glossary_ids if ref in terms)
    yield from _citations("Glosario", "glossary-", refs, len(item.glossary_ids) - len(refs))
    yield "</article>\n"


def _coverage(explanation: Explanation, report: Report) -> Iterator[str]:
    yield '<section id="coverage"><h2>Qué se pudo analizar</h2>'
    notes = sorted(explanation.notes, key=lambda note: note.code is None)
    for note in notes[:MAX_NOTES]:
        yield from _paragraph(note.statement)
    if len(explanation.notes) > MAX_NOTES:
        yield from _paragraph(
            f"{len(explanation.notes) - MAX_NOTES} notas de cobertura omitidas en este HTML."
        )
    parts = [(run.source, part) for run in report.extractor_runs for part in run.components]
    incomplete = [(source, part) for source, part in parts if part.status != "complete"]
    yield from _paragraph(
        f"{len(parts) - len(incomplete)} de {len(parts)} componentes "
        "con cobertura completa registrada."
    )
    for source, part in incomplete[:MAX_NOTES]:
        yield from _paragraph(f"{source} · {part.name}: {part.status}")
    if len(incomplete) > MAX_NOTES:
        yield from _paragraph(
            f"{len(incomplete) - MAX_NOTES} componentes incompletos omitidos en este HTML."
        )
    for title, errors in (
        ("Errores de extracción", report.extractor_errors),
        ("Limitaciones registradas", report.limitations),
    ):
        if errors:
            yield from _paragraph(f"{title}: {len(errors)}.")
            for error in errors[:MAX_NOTES]:
                yield from _paragraph(f"{error.source} · {error.component}: {error.code}")
            if len(errors) > MAX_NOTES:
                yield from _paragraph(
                    f"{len(errors) - MAX_NOTES} entradas de {title} omitidas en este HTML."
                )
    yield "</section>\n"


def _external(external: VirusTotalReport | None) -> Iterator[str]:
    title = vt.TITLE.removeprefix("5. ")
    yield f'<section id="external"><h2>{_text(title)}</h2>'
    if external is None:
        yield from _paragraph("No se incluyen datos de VirusTotal en este documento.")
        yield "</section>\n"
        return
    yield from _paragraph(vt.DISCLAIMER)
    yield from _paragraph(
        "Los datos externos no forman parte del JSON de hechos; este HTML solo los resume."
    )
    yield "<dl>"
    yield from _row("SHA-256 consultado", external.sample_sha256)
    yield from _row("Consulta", external.retrieved_at.isoformat())
    yield from _row("Estado externo", external.status)
    compact = external.model_copy(
        update={"detections": (), "detections_omitted": 0, "sandbox_verdicts": (), "tags": ()}
    )
    for label, value in vt._facts(compact):
        yield from _row(label, _brief(value))
    for detection in external.detections[:MAX_VALUES]:
        yield from _row(
            "Etiqueta",
            _brief(
                f"{detection.engine} ({detection.category}): {detection.result or '(sin etiqueta)'}"
            ),
        )
    yield "</dl>"
    hidden = max(0, len(external.detections) - MAX_VALUES)
    if hidden:
        yield from _paragraph(f"{hidden} etiquetas externas omitidas en este HTML.")
    if external.detections_omitted:
        yield from _paragraph(
            f"{external.detections_omitted} etiquetas ya omitidas en los datos externos aportados."
        )
    for label, count in (
        ("etiquetas generales", len(external.tags)),
        ("veredictos de sandbox", len(external.sandbox_verdicts)),
    ):
        if count:
            yield from _paragraph(f"{count} {label} omitidos en este HTML.")
    status = vt._status_line(external)
    if status:
        yield from _paragraph(status)
    for name, label in vt.BEHAVIOUR_LABELS:
        values = vt._items(external.behaviour, name)
        if values:
            yield f"<h3>{_text(label)} (VirusTotal)</h3><ul>"
            for value in values[:MAX_VALUES]:
                yield f"<li>{_text(_brief(value))}</li>"
            yield "</ul>"
            if len(values) > MAX_VALUES:
                yield from _paragraph(
                    f"{len(values) - MAX_VALUES} entradas de {label} omitidas en este HTML."
                )
    if external.behaviour.omitted:
        yield from _paragraph(vt._omitted(external.behaviour.omitted) + " por formato o límite.")
    yield "</section>\n"


def _fragments(
    explanation: Explanation,
    items: tuple[Item, ...],
    report: Report,
    glossary: Glossary,
    origin: str | None,
    external: VirusTotalReport | None,
) -> Iterator[str]:
    digest = base64.b64encode(hashlib.sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    policy = (
        "default-src 'none'; base-uri 'none'; form-action 'none'; "
        f"style-src 'sha256-{digest}'; script-src 'none'; connect-src 'none'"
    )
    yield "<!doctype html>\n"
    yield '<html lang="es"><head><meta charset="utf-8">'
    yield f'<meta http-equiv="Content-Security-Policy" content="{escape(policy, quote=True)}">'
    yield '<meta name="viewport" content="width=device-width, initial-scale=1">'
    yield "<title>LupaBin: resumen breve</title>"
    yield f"<style>{STYLE}</style></head><body>"
    yield "<header><h1>LupaBin: resumen breve</h1>"
    yield from _paragraph(
        "Análisis estático: LupaBin no ejecuta la muestra "
        "al analizarla ni al exportar este informe."
    )
    yield "<dl>"
    if origin:
        yield from _row("Origen", origin)
    yield from _row("SHA-256", report.sample.sha256)
    yield from _row("Tamaño", f"{report.sample.size} bytes")
    yield from _row("Análisis", document.STATUS[explanation.status])
    selected = _select(items)
    for label, helper in (
        ("Hecho con", document.made_with),
        ("Empaquetado", document.packed_with),
        ("main", document.main_line),
        ("Familias", document.areas_line),
    ):
        value = helper(selected)
        if value:
            yield from _row(label, value)
    yield "</dl>"
    yield from _paragraph(
        "Este HTML es un resumen de lectura, no una firma de autenticidad ni un diagnóstico "
        "de seguridad. El JSON de hechos conserva todas las evidencias y sus datos completos, "
        "por separado. La web permite consultar todas las explicaciones validadas."
    )
    yield '</header><nav aria-label="Índice"><ul>'
    for target, title in (
        ("overview", "Resumen"),
        ("coverage", "Qué se pudo analizar"),
        ("reading", "Lectura seleccionada"),
        ("glossary", "Glosario breve"),
        ("external", "Fuente externa"),
        ("evidence", "Evidencias citadas"),
    ):
        yield f'<li><a href="#{target}">{title}</a></li>'
    yield "</ul></nav><main>"
    yield f'<section id="overview"><h2>{_text(document.SUMMARY_TITLE)}</h2>'
    yield from _paragraph(
        document.SUMMARY_INTRO.replace("sección 3", "sección Lectura seleccionada")
    )
    overview = document.summary(items, report)
    selected_ids = {item.id for item in selected}
    for tactic, chosen in overview.groups:
        yield f"<h3>{_text(tactic)}: {len(chosen)}</h3>"
        yield from _citations(
            "Lectura", "item-", (item.id for item in chosen if item.id in selected_ids)
        )
        hidden = sum(item.id not in selected_ids for item in chosen)
        if hidden:
            yield from _paragraph(f"{hidden} capacidades sin ficha en este HTML.")
    for warning in overview.warnings:
        if not isinstance(warning, Item):
            yield from _paragraph(
                warning.replace("sección 1", "sección Qué se pudo analizar")
                if warning == document.PARTIAL_CODE
                else warning
            )
    yield "</section>"
    yield from _coverage(explanation, report)
    terms = tuple(dict.fromkeys(ref for item in selected for ref in item.glossary_ids))
    shown_terms = terms[:MAX_GLOSSARY]
    yield '<section id="reading"><h2>Lectura seleccionada</h2>'
    yield from _paragraph(
        f"Hasta {MAX_ITEMS} explicaciones: cobertura del recorrido; capacidades y anomalías; "
        "después, contexto del archivo y del código. Dentro de cada grupo, el orden del informe. "
        "Es un orden de lectura, no de gravedad ni de peligrosidad. "
        f"Hasta {MAX_EXTRAS} campos extra, {MAX_VALUES} valores por campo, "
        f"{MAX_VALUE_CHARS} caracteres por valor y {MAX_CITATIONS} citas de evidencia "
        "por explicación."
    )
    yield from _paragraph(
        f"{len(items) - len(selected)} explicaciones validadas omitidas en este HTML; "
        f"{len(selected)} mostradas de {len(items)}."
    )
    omitted = len(explanation.items) - len(items)
    if omitted:
        yield from _paragraph(
            f"{omitted} explicaciones se omitieron porque no superaron la validación."
        )
    for item in selected:
        yield from _item(item, shown_terms)
    yield "</section>"
    yield '<section id="glossary"><h2>Glosario breve</h2>'
    yield from _paragraph(
        "Conocimiento educativo general; no son afirmaciones sobre la muestra. "
        f"Hasta {MAX_GLOSSARY} términos citados en la lectura; solo resúmenes, "
        "sin los artículos completos."
    )
    if len(terms) > MAX_GLOSSARY:
        yield from _paragraph(
            f"{len(terms) - MAX_GLOSSARY} términos citados omitidos en este HTML."
        )
    for ref in shown_terms:
        entry = glossary.entries[ref]
        yield f'<article id="glossary-{_text(entry.id)}"><h3>{_text(entry.title)}</h3>'
        yield from _paragraph(entry.summary)
        if entry.not_proven:
            yield from _paragraph(entry.not_proven)
        yield "<ul>"
        for source in entry.sources[:1]:
            yield _source(source)
        yield "</ul>"
        if len(entry.sources) > 1:
            yield from _paragraph(f"{len(entry.sources) - 1} fuentes omitidas en este HTML.")
        yield "</article>"
    yield "</section>"
    yield from _external(external)
    refs = {ref for item in selected for ref in item.evidence_ids[:MAX_CITATIONS]}
    yield '<section id="evidence"><h2>Evidencias citadas: fichas breves</h2>'
    yield from _paragraph(
        f"{len(report.evidence) - len(refs)} evidencias sin ficha en este HTML; "
        f"{len(refs)} mostradas de {len(report.evidence)}. "
        "Las fichas no sustituyen los datos ni la procedencia del JSON de hechos."
    )
    yield (
        '<table><thead><tr><th scope="col">ID</th><th scope="col">Tipo</th>'
        '<th scope="col">Confianza</th><th scope="col">Offset</th>'
        '<th scope="col">RVA</th></tr></thead><tbody>'
    )
    for fact in report.evidence:
        if fact.id not in refs:
            continue
        location = fact.location
        offset = (
            f"0x{location.offset:x}"
            if location and location.offset is not None
            else "no determinado"
        )
        rva = f"0x{location.rva:x}" if location and location.rva is not None else "no determinado"
        yield (
            f'<tr id="evidence-{_text(fact.id)}"><th scope="row">{_text(fact.id)}</th>'
            f"<td>{_text(fact.kind)}</td><td>{_text(fact.confidence)}</td>"
            f"<td>{offset}</td><td>{rva}</td></tr>\n"
        )
    yield "</tbody></table></section></main><footer>"
    yield from _paragraph(document.ABSENCE)
    yield "</footer></body></html>\n"


def to_html(
    explanation: Explanation,
    items: tuple[Item, ...],
    report: Report,
    glossary: Glossary,
    origin: str | None = None,
    external: VirusTotalReport | None = None,
) -> str:
    if external is not None and external.sample_sha256 != report.sample.sha256:
        raise ValueError("external report belongs to another sample")
    return _collect(
        _fragments(explanation, items, report, glossary, origin, external), MAX_HTML_BYTES
    )
