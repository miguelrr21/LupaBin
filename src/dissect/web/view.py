"""What the web page receives: the didactic report as data.

Only items that regenerate exactly from their citations are sent (engine.validate), in
the same order and with the same wording as the terminal and Markdown views. Every
string, including the text of the sample and what VirusTotal returns, is neutralised
with render.safe.visible before it leaves the server; the page inserts text only as
text (design of the web, section 6).
"""

from typing import Any

from dissect.evidence.models import Report
from dissect.explain.models import Explanation, Item
from dissect.glossary.catalog import Glossary
from dissect.render import document, external
from dissect.render.safe import visible
from dissect.virustotal.models import VirusTotalReport

NOT_FOUND = (
    "VirusTotal no conoce este archivo (se consultó solo su SHA-256). Eso no dice nada sobre "
    "si es peligroso. Si vuelves a analizarlo con la opción de subirlo marcada, se enviará a "
    "VirusTotal, que puede compartir su contenido con sus clientes de pago."
)
KEY_MISSING = "Este servidor no tiene configurada una clave de API de VirusTotal."


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
    if report.status == "not_found":
        shown["note"] = NOT_FOUND
    elif report.problem == "key_missing":
        shown["note"] = KEY_MISSING
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
