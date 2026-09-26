"""What the web page receives: the didactic report as data.

Only items that regenerate exactly from their citations are sent (engine.validate), in
the same order and with the same wording as the terminal and Markdown views. Every
string, including the text of the sample and what VirusTotal returns, is neutralised
with render.safe.visible before it leaves the server; the page inserts text only as
text.
"""

from typing import Any

from lupabin.evidence.models import Report
from lupabin.explain.models import Explanation, Item
from lupabin.glossary.catalog import Glossary
from lupabin.render import document, external
from lupabin.render.safe import visible
from lupabin.virustotal.models import VirusTotalReport

NOT_FOUND = (
    "VirusTotal no conoce este archivo (se consultó solo su SHA-256). Eso no dice nada sobre "
    "si es peligroso. Si vuelves a analizarlo con la opción de subirlo marcada, se enviará a "
    "VirusTotal, que puede compartir su contenido con sus clientes de pago."
)
KEY_MISSING = "Este servidor no tiene configurada una clave de API de VirusTotal."
QUOTA = (
    "La cuota de VirusTotal de este servidor está agotada por ahora: la comparten todos los "
    "visitantes (con la API pública, 4 consultas por minuto y 500 al día). El análisis de "
    "LupaBin no cambia; puedes volver a intentarlo más tarde."
)
QUEUED = (
    "LupaBin ha subido el archivo a VirusTotal porque no lo conocía, y VirusTotal lo está "
    "analizando; suele tardar unos minutos. La página sigue su análisis y muestra el "
    "resultado en cuanto termine. Lo subido puede compartirse con los clientes de pago de "
    "VirusTotal."
)


def neutral(value: Any) -> Any:
    """Every string in a JSON-like structure, neutralised."""
    if isinstance(value, str):
        return visible(value)
    if isinstance(value, dict):
        return {key: neutral(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [neutral(item) for item in value]
    return value


def _item(item: Item) -> dict[str, Any]:
    extras: list[dict[str, Any]] = []
    for label, value in document._extras(item):
        shown = list(value) if isinstance(value, tuple) else [str(value)]
        extras.append({"label": label, "values": shown})
    return {
        "id": item.id,
        "rule": item.rule,
        "level": item.level,
        "statement": item.statement,
        "extras": extras,
        "not_proven": item.not_proven,
        "evidence": list(item.evidence_ids),
        "glossary": list(item.glossary_ids),
    }


def _summary(items: tuple[Item, ...], report: Report) -> dict[str, Any]:
    overview = document.summary(items, report)
    return {
        "groups": [
            {
                "tactic": tactic,
                "items": [
                    {
                        "id": item.id,
                        "statement": item.statement,
                        "techniques": list(item.slots.get("techniques", ()))  # type: ignore[arg-type]
                        if isinstance(item.slots.get("techniques"), tuple)
                        else [],
                    }
                    for item in chosen
                ],
            }
            for tactic, chosen in overview.groups
        ],
        "warnings": [
            {"id": w.id, "text": w.statement} if isinstance(w, Item) else {"id": None, "text": w}
            for w in overview.warnings
        ],
    }


def _virustotal(report: VirusTotalReport) -> dict[str, Any]:
    shown = external.structured(report)
    shown["sha256"] = report.sample_sha256
    shown["problem"] = report.problem
    if report.status == "not_found":
        shown["note"] = NOT_FOUND
    elif report.status == "queued":
        shown["note"] = QUEUED
    elif report.problem == "key_missing":
        shown["note"] = KEY_MISSING
    elif report.status == "unavailable" and report.problem == "quota_exceeded":
        shown["note"] = QUOTA
    return shown


def virustotal(report: VirusTotalReport) -> dict[str, Any]:
    """The external section on its own, neutralised (the page asks for it separately)."""
    shown: dict[str, Any] = neutral(_virustotal(report))
    return shown


def build(
    report: Report,
    explanation: Explanation,
    items: tuple[Item, ...],
    glossary: Glossary,
    vt: VirusTotalReport | None,
) -> dict[str, Any]:
    used = document._glossary_order(explanation, items)
    view = {
        "sample": {
            "sha256": report.sample.sha256,
            "md5": report.sample.md5,
            "size": report.sample.size,
            "type": report.sample.type,
        },
        "status": explanation.status,
        "made_with": document.made_with(items),
        "main": document.main_line(items),
        "areas": document.areas_line(items),
        "texts": (
            None
            if (texts := document.main_texts(items)) is None
            else f"{' · '.join(texts[1])} ({texts[0]})"
        ),
        "summary": _summary(items, report),
        "notes": [note.statement for note in explanation.notes],
        "items": [_item(item) for item in items],
        "omitted": len(explanation.items) - len(items),
        "glossary": [
            {
                "id": entry.id,
                "title": entry.title,
                "summary": entry.summary,
                "not_proven": entry.not_proven,
                "sources": [
                    {
                        "title": source.title,
                        "publisher": source.publisher,
                        "url": source.url,
                        "document": source.document,
                    }
                    for source in entry.sources
                ],
            }
            for entry in (glossary.entries[ref] for ref in used)
        ],
        "virustotal": None if vt is None else _virustotal(vt),
        "absence": document.ABSENCE,
    }
    shown: dict[str, Any] = neutral(view)
    # the downloads are the documents themselves, byte for byte
    shown["downloads"] = {
        "report": report.model_dump_json(indent=2),
        "markdown": document.to_markdown(explanation, items, report, glossary, None, vt),
    }
    return shown
