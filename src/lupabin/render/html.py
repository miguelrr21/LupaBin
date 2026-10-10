import base64
import hashlib
import json
from collections.abc import Iterable, Iterator
from html import escape
from urllib.parse import urlsplit

from lupabin.evidence.models import Report
from lupabin.explain.models import Explanation, Item
from lupabin.glossary.catalog import Glossary
from lupabin.glossary.models import Source
from lupabin.render import document
from lupabin.render import external as vt
from lupabin.render.safe import visible
from lupabin.virustotal.contrast import local_context
from lupabin.virustotal.models import VirusTotalReport

MAX_HTML_BYTES = 32 * 1024 * 1024
TEXT_CHUNK = 1024

STYLE = """
:root { color-scheme: light; font-family: system-ui, sans-serif; line-height: 1.6; }
body { max-width: 78rem; margin: auto; padding: 1.5rem; color: #182536; background: #fff; }
a { color: #174f93; text-decoration: underline; }
nav ul { display: flex; flex-wrap: wrap; gap: 1.5rem; list-style: none; padding: 0; }
section { margin-block: 2rem; }
article, details { border: 1px solid #b8c5d4; border-radius: .3rem; padding: 1rem;
  margin-block: 1rem; }
summary { cursor: pointer; font-weight: bold; }
h1, h2, h3, h4 { line-height: 1.3; }
pre { white-space: pre-wrap; font-size: .85rem; }
p, li, dd, pre, td, th, h3, summary { overflow-wrap: anywhere; }
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
  h1, h2, h3, h4, summary { break-after: avoid; }
  pre { font-size: 8pt; }
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


def _links(prefix: str, refs: Iterable[str]) -> Iterator[str]:
    for index, ref in enumerate(refs):
        if index:
            yield ", "
        yield f'<a href="#{_text(prefix + ref)}">{_text(ref)}</a>'


def _citations(label: str, prefix: str, refs: Iterable[str]) -> Iterator[str]:
    yield f"<p>{_text(label)}: "
    yield from _links(prefix, refs)
    yield "</p>\n"


def _json_tokens(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield '"'
        for offset in range(0, len(value), TEXT_CHUNK):
            yield json.dumps(value[offset : offset + TEXT_CHUNK], ensure_ascii=False)[1:-1]
        yield '"'
    elif isinstance(value, dict):
        yield "{"
        for index, (key, member) in enumerate(value.items()):
            if index:
                yield ", "
            yield from _json_tokens(key)
            yield ": "
            yield from _json_tokens(member)
        yield "}"
    elif isinstance(value, list | tuple):
        yield "["
        for index, member in enumerate(value):
            if index:
                yield ", "
            yield from _json_tokens(member)
        yield "]"
    else:
        yield json.dumps(value, ensure_ascii=False, allow_nan=False)


def _json(value: object) -> Iterator[str]:
    yield "<pre>"
    for token in _json_tokens(value):
        yield from _text_chunks(token)
    yield "</pre>\n"


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


def _item(item: Item) -> Iterator[str]:
    yield f'<article id="item-{_text(item.id)}">'
    yield f"<h3>{_text(item.id)} · {_text(item.level)}</h3>"
    yield from _paragraph(item.statement)
    yield "<dl>"
    yield from _row("Regla", item.rule)
    for label, value in document._extras(item):
        yield from _row(label, value)
        if label == "Texto" and item.slots.get("complete") is False:
            yield "<dt>Integridad del texto</dt><dd>recortado</dd>"
    yield '</dl><p class="limit"><strong>Límite (not_proven):</strong> '
    yield from _text_chunks(item.not_proven)
    yield "</p>"
    yield from _citations("Evidencia", "evidence-", item.evidence_ids)
    yield from _citations("Glosario", "glossary-", item.glossary_ids)
    yield "</article>\n"


def _coverage(explanation: Explanation, report: Report) -> Iterator[str]:
    yield '<section id="coverage"><h2>1. Qué se pudo analizar</h2>'
    for note in explanation.notes:
        yield from _paragraph(note.statement)
        yield from _citations("Glosario", "glossary-", note.glossary_ids)
    yield "<table><caption>Cobertura por extractor y componente</caption>"
    yield '<thead><tr><th scope="col">Extractor · versión</th>'
    yield '<th scope="col">Componente</th><th scope="col">Cobertura</th>'
    yield '<th scope="col">Examinados</th><th scope="col">Evidencias</th></tr></thead><tbody>'
    for run in report.extractor_runs:
        for part in run.components:
            examined = part.examined if part.examined is not None else "no determinado"
            yield (
                f"<tr><td>{_text(run.source)} · {_text(run.version)}</td>"
                f"<td>{_text(part.name)}</td><td>{_text(part.status)}</td>"
                f"<td>{_text(examined)}</td><td>{_text(part.evidence_count)}</td></tr>"
            )
    yield "</tbody></table>"
    for title, errors in (
        ("Errores de extracción", report.extractor_errors),
        ("Limitaciones registradas", report.limitations),
    ):
        yield f"<h3>{_text(title)}</h3>"
        for error in errors:
            yield from _paragraph(f"{error.source} · {error.component}: {error.code}")
        if not errors:
            yield from _paragraph("Ninguna registrada; no demuestra ausencia de otros límites.")
    yield "<details open><summary>Presupuestos del análisis</summary>"
    yield from _json(report.analysis.limits.model_dump(mode="json"))
    yield "</details></section>\n"


def _external(external: VirusTotalReport | None, report: Report) -> Iterator[str]:
    yield f'<section id="external"><h2>{_text(vt.TITLE)}</h2>'
    if external is None:
        yield from _paragraph("No se incluyen datos de VirusTotal en este documento.")
        yield "</section>\n"
        return
    yield from _paragraph(vt.DISCLAIMER)
    yield "<dl>"
    yield from _row("SHA-256 consultado", external.sample_sha256)
    yield from _row("Consulta", external.retrieved_at.isoformat())
    yield from _row("Estado externo", external.status)
    yield "</dl>"
    status = vt._status_line(external)
    if status:
        yield from _paragraph(status)
    yield "<dl>"
    for label, value in vt._facts(external):
        yield from _row(label, value)
    for label, value in vt._context_rows(external, local_context(report)):
        yield from _row(label, value)
    yield "</dl>"
    if not external.behaviour.empty():
        yield "<h3>Comportamiento observado en los sandboxes de VirusTotal</h3>"
        for name, label in vt.BEHAVIOUR_LABELS:
            values = vt._items(external.behaviour, name)
            if values:
                yield f"<h4>{_text(label)}</h4><ul>"
                for value in values:
                    yield "<li>"
                    yield from _text_chunks(value)
                    yield "</li>"
                yield "</ul>"
    if external.behaviour.omitted:
        yield from _paragraph(vt._omitted(external.behaviour.omitted) + " por formato o límite.")
    yield (
        "<details open><summary>"
        "Datos externos aportados completos (no son hechos locales)</summary>"
    )
    yield from _json(external.model_dump(mode="json"))
    yield "</details></section>\n"


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
    yield "<title>LupaBin: informe didáctico</title>"
    yield f"<style>{STYLE}</style></head><body>"
    yield "<header><h1>LupaBin: informe didáctico</h1>"
    yield from _paragraph(
        "Análisis estático: LupaBin no ejecuta la muestra "
        "al analizarla ni al exportar este informe."
    )
    yield "<dl>"
    if origin:
        yield from _row("Origen", origin)
    yield from _row("SHA-256", report.sample.sha256)
    yield from _row("MD5 (solo como referencia; admite colisiones)", report.sample.md5)
    yield from _row("Tamaño", f"{report.sample.size} bytes")
    yield from _row("Tipo", report.sample.type)
    yield from _row("Análisis", document.STATUS[explanation.status])
    yield from _row("Contrato del informe", report.schema_version)
    yield from _row("Versión del analizador", report.analysis.version)
    yield from _row("Inicio del análisis", report.analysis.started_at.isoformat())
    yield from _row("Fin del análisis", report.analysis.finished_at.isoformat())
    yield from _row("Contrato de explicaciones", explanation.schema_version)
    yield from _row(
        "Glosario", f"{explanation.glossary.catalog_id} · {explanation.glossary.revision}"
    )
    yield from _row("Digest del glosario", explanation.glossary.digest)
    for label, helper in (
        ("Hecho con", document.made_with),
        ("Empaquetado", document.packed_with),
        ("main", document.main_line),
        ("Familias", document.areas_line),
    ):
        value = helper(items)
        if value:
            yield from _row(label, value)
    yield "</dl>"
    yield from _paragraph(
        "Este HTML es una representación del informe; no es una firma de autenticidad."
    )
    yield '</header><nav aria-label="Índice"><ul>'
    for target, title in (
        ("overview", "Resumen"),
        ("coverage", "Cobertura"),
        ("observed", "Hechos observados"),
        ("inferred", "Inferencias"),
        ("glossary", "Glosario"),
        ("external", "Fuente externa"),
        ("evidence", "Evidencias"),
    ):
        yield f'<li><a href="#{target}">{title}</a></li>'
    yield "</ul></nav><main>"
    yield f'<section id="overview"><h2>{_text(document.SUMMARY_TITLE)}</h2>'
    yield from _paragraph(document.SUMMARY_INTRO)
    overview = document.summary(items, report)
    for tactic, chosen in overview.groups:
        yield f"<h3>{_text(tactic)}</h3><ul>"
        for item in chosen:
            yield "<li>"
            yield from _links("item-", (item.id,))
            yield ": "
            yield from _text_chunks(item.statement)
            yield "</li>"
            techniques = document._techniques(item)
            if techniques:
                yield "<li>"
                yield from _text_chunks(techniques)
                yield "</li>"
        yield "</ul>"
    for warning in overview.warnings:
        if isinstance(warning, Item):
            yield "<p>"
            yield from _links("item-", (warning.id,))
            yield ": "
            yield from _text_chunks(warning.statement)
            yield "</p>"
        else:
            yield from _paragraph(warning)
    yield "</section>"
    yield from _coverage(explanation, report)
    for level, title in (
        ("observed", "2. Hechos observados en los bytes"),
        (
            "inferred",
            "3. Inferencias: resultados de aplicar un método a los bytes, no lecturas directas",
        ),
    ):
        yield f'<section id="{level}"><h2>{title}</h2>'
        found = False
        for item in items:
            if item.level == level:
                found = True
                yield from _item(item)
        if not found:
            yield from _paragraph("(ninguno)")
        yield "</section>"
    omitted = len(explanation.items) - len(items)
    if omitted:
        yield from _paragraph(
            f"{omitted} explicaciones se omitieron porque no superaron la validación."
        )
    yield '<section id="glossary"><h2>4. Glosario de los términos usados</h2>'
    yield from _paragraph("Conocimiento educativo general; no son afirmaciones sobre la muestra.")
    for entry_id in document._glossary_order(explanation, items):
        entry = glossary.entries[entry_id]
        yield f'<article id="glossary-{_text(entry.id)}">'
        yield f"<h3>{_text(entry.title)} ({_text(entry.id)})</h3>"
        yield from _paragraph(entry.summary)
        for paragraph in entry.body.split("\n\n"):
            yield from _paragraph(paragraph)
        if entry.not_proven:
            yield '<p class="limit">Límite: '
            yield from _text_chunks(entry.not_proven)
            yield "</p>"
        yield "<h4>Fuentes</h4><ul>"
        for source in entry.sources:
            yield _source(source)
        yield "</ul></article>"
    yield "</section>"
    yield from _external(external, report)
    yield '<section id="evidence"><h2>Evidencias del informe y procedencia</h2>'
    yield "<details open><summary>Metadatos completos del informe</summary>"
    yield from _json(report.model_dump(mode="json", exclude={"evidence"}))
    yield "</details>"
    for fact in report.evidence:
        yield f'<article id="evidence-{_text(fact.id)}">'
        yield f"<h3>{_text(fact.id)} · {_text(fact.kind)} · {_text(fact.confidence)}</h3>"
        yield "<p>Procedencia: "
        if fact.provenance.evidence_ids:
            yield from _links("evidence-", fact.provenance.evidence_ids)
        else:
            yield "sin citas previas"
        yield "</p><details open><summary>Datos completos de la evidencia</summary>"
        yield from _json(fact.model_dump(mode="json"))
        yield "</details></article>"
    yield "</section></main><footer>"
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
