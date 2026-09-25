"""The external-source section: VirusTotal results, attributed and never merged with facts.

Everything VirusTotal returns was chosen by third parties (file names by uploaders,
labels by antivirus vendors, paths and commands by the sample in their sandboxes),
so every value is neutralised exactly like sample text.
"""

from collections.abc import Callable, Iterable

from dissect.render.safe import code_span, markdown_text, visible
from dissect.virustotal.models import Behaviour, VirusTotalReport

TITLE = "5. Fuente externa: VirusTotal (no verificada por Dissect)"
DISCLAIMER = (
    "Estos datos vienen de VirusTotal, no de Dissect. Una etiqueta es la opinión de un motor "
    "antivirus, y el comportamiento se observó al ejecutar el archivo en los sandboxes de "
    "VirusTotal, en su entorno y en su momento, no en tu equipo."
)
PROBLEMS = {
    "key_missing": (
        "no hay clave de API: define la variable de entorno VT_API_KEY o escríbela en un"
        " archivo .env (VT_API_KEY=...). Para no consultar VirusTotal, usa --no-virustotal"
        " o DISSECT_VIRUSTOTAL=off."
    ),
    "auth_failed": "VirusTotal rechazó la clave de API.",
    "quota_exceeded": (
        "se agotó la cuota de la API (la pública permite 4 consultas por minuto y 500 al día)."
    ),
    "network_error": "no se pudo contactar con VirusTotal.",
    "invalid_response": "la respuesta no tenía el formato esperado y se descartó.",
    "too_large": "la respuesta, o el archivo que se quería subir, supera el tamaño máximo.",
}
NOT_FOUND = (
    "VirusTotal no conoce este archivo (se consultó solo su SHA-256). Eso no dice nada sobre si "
    "es peligroso. Puedes enviarlo con --upload-to-virustotal, pero el contenido de los archivos "
    "subidos puede compartirse con los clientes de pago de VirusTotal: no subas documentos ni "
    "programas internos o confidenciales."
)
QUEUED = (
    "Dissect subió el archivo a VirusTotal y el análisis sigue en cola. Vuelve a analizarlo "
    "más tarde: ya solo se consultará por su SHA-256."
)
UPLOADED = (
    "Dissect subió el archivo a VirusTotal porque no lo conocía; estos resultados son de ese "
    "análisis. El contenido subido puede compartirse con los clientes de pago de VirusTotal."
)
BEHAVIOUR_LABELS = (
    ("processes_created", "Procesos creados"),
    ("command_executions", "Comandos ejecutados"),
    ("files_written", "Archivos escritos"),
    ("files_deleted", "Archivos borrados"),
    ("files_dropped", "Archivos soltados"),
    ("registry_keys_set", "Claves de registro escritas"),
    ("dns_lookups", "Consultas DNS"),
    ("ip_traffic", "Tráfico IP"),
    ("http_conversations", "Peticiones HTTP"),
    ("mutexes_created", "Mutex creados"),
    ("services_created", "Servicios creados"),
    ("mitre_attack_techniques", "Técnicas MITRE ATT&CK"),
)
SHOWN = 15
Wrap = Callable[[str, str, str], list[str]]  # render.document.wrap


def _items(behaviour: Behaviour, name: str) -> list[str]:
    values = getattr(behaviour, name)
    if name == "registry_keys_set":
        return [v.key + (f" = {v.value}" if v.value is not None else "") for v in values]
    if name == "dns_lookups":
        return [
            v.hostname + (f" → {', '.join(v.resolved_ips)}" if v.resolved_ips else "")
            for v in values
        ]
    if name == "ip_traffic":
        return [
            " ".join(
                part
                for part in (
                    v.protocol,
                    v.destination_ip
                    + (f":{v.destination_port}" if v.destination_port is not None else ""),
                )
                if part
            )
            for v in values
        ]
    if name == "http_conversations":
        return [f"{v.method or '?'} {v.url}" for v in values]
    if name == "mitre_attack_techniques":
        return [v.id + (f": {v.description}" if v.description else "") for v in values]
    return list(values)


def _omitted(count: int) -> str:
    return "1 entrada omitida" if count == 1 else f"{count} entradas omitidas"


def _facts(report: VirusTotalReport) -> Iterable[tuple[str, str]]:
    stats = report.stats
    if stats:
        total = sum(stats.values())
        yield (
            "Motores",
            f"{stats.get('malicious', 0)} de {total} lo marcan como malicioso y "
            f"{stats.get('suspicious', 0)} como sospechoso.",
        )
    for detection in report.detections[:SHOWN]:
        label = detection.result or "(sin etiqueta)"
        yield "Etiqueta", f"{detection.engine} ({detection.category}): {label}"
    hidden = len(report.detections) - SHOWN + report.detections_omitted
    if hidden > 0:
        yield "Etiqueta", f"… y {hidden} más"
    if report.meaningful_name:
        yield "Nombre más citado", report.meaningful_name
    if report.type_description:
        yield "Tipo según VirusTotal", report.type_description
    if report.first_submission:
        yield "Primer envío", report.first_submission.strftime("%Y-%m-%d")
    if report.last_analysis:
        yield "Último análisis", report.last_analysis.strftime("%Y-%m-%d")
    if report.reputation is not None:
        yield "Reputación (votos de la comunidad)", str(report.reputation)
    if report.tags:
        yield "Etiquetas de VirusTotal", ", ".join(report.tags)
    for verdict in report.sandbox_verdicts:
        detail = f"{verdict.sandbox}: {verdict.category}"
        if verdict.confidence is not None:
            detail += f" (confianza {verdict.confidence})"
        if verdict.classification:
            detail += f", {', '.join(verdict.classification)}"
        yield "Veredicto de sandbox", detail


def _status_line(report: VirusTotalReport) -> str | None:
    if report.status == "unavailable":
        return "No se pudo consultar VirusTotal: " + PROBLEMS[report.problem or "network_error"]
    if report.status == "not_found":
        return NOT_FOUND
    if report.status == "queued":
        return QUEUED
    if report.uploaded:
        return UPLOADED + (
            " El comportamiento no está disponible: " + PROBLEMS[report.problem]
            if report.problem
            else ""
        )
    if report.problem:
        return "El comportamiento no está disponible: " + PROBLEMS[report.problem]
    return None


def to_text_lines(report: VirusTotalReport, wrap: Wrap) -> list[str]:
    lines = ["", TITLE, *wrap(DISCLAIMER, "   ", "   ")]
    status = _status_line(report)
    if status:
        lines += wrap(visible(status), "     ", "   • ")
    for label, value in _facts(report):
        lines += wrap(visible(f"{label}: {value}"), "       ", "   • ")
    behaviour = report.behaviour
    if not behaviour.empty():
        lines += ["   Comportamiento observado en los sandboxes de VirusTotal:"]
        for name, label in BEHAVIOUR_LABELS:
            values = _items(behaviour, name)
            if not values:
                continue
            lines += wrap(visible(f"{label} ({len(values)}):"), "       ", "     ")
            for value in values[:SHOWN]:
                lines += wrap(f"«{visible(value)}»", "           ", "       - ")
            if len(values) > SHOWN:
                lines.append(
                    f"       - … y {len(values) - SHOWN} más (--format json en dissect virustotal)"
                )
        if behaviour.omitted:
            lines.append(f"     ({_omitted(behaviour.omitted)} por formato o límite)")
    if report.status in ("found", "queued"):
        lines += wrap(f"Ficha: {report.permalink}", "     ", "   ")
    return lines


def to_markdown_lines(report: VirusTotalReport) -> list[str]:
    lines = ["", "## " + TITLE, "", markdown_text(DISCLAIMER), ""]
    status = _status_line(report)
    if status:
        lines.append(f"- {markdown_text(status)}")
    for label, value in _facts(report):
        lines.append(f"- {markdown_text(label)}: {code_span(value)}")
    behaviour = report.behaviour
    if not behaviour.empty():
        lines += ["", "### Comportamiento observado en los sandboxes de VirusTotal", ""]
        for name, label in BEHAVIOUR_LABELS:
            values = _items(behaviour, name)
            if values:
                lines.append(f"- {markdown_text(label)}:")
                lines += [f"  - {code_span(value)}" for value in values]
        if behaviour.omitted:
            lines.append(f"- {_omitted(behaviour.omitted).capitalize()} por formato o límite.")
    if report.status in ("found", "queued"):
        lines += ["", f"Ficha: <{report.permalink}>"]
    return lines


def structured(report: VirusTotalReport) -> dict[str, object]:
    """The same content as the text and Markdown sections, as data for the web page.
    Strings are not neutralised here: the web view neutralises every string it sends."""
    return {
        "title": TITLE.split(": ", 1)[1],
        "disclaimer": DISCLAIMER,
        "status": report.status,
        "note": _status_line(report),
        "stats": dict(report.stats),
        "rows": [{"label": label, "value": value} for label, value in _facts(report)],
        "behaviour": [
            {"label": label, "values": values}
            for name, label in BEHAVIOUR_LABELS
            if (values := _items(report.behaviour, name))
        ],
        "omitted": report.behaviour.omitted,
        "uploaded": report.uploaded,
        "permalink": report.permalink if report.status in ("found", "queued") else None,
    }
