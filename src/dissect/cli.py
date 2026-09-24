import json
import os
import re
import sys
from enum import StrEnum
from pathlib import Path
from typing import IO, Annotated

import typer

from dissect.errors import DissectError
from dissect.evidence.models import Limits, Report
from dissect.explain.engine import ExplanationError, explain, validate
from dissect.glossary.catalog import GlossaryError, load_glossary
from dissect.ingest.reader import read_sample
from dissect.render.document import to_markdown, to_text, wrap
from dissect.render.external import to_text_lines
from dissect.runner import analyze_isolated
from dissect.saved_report import CHECKED, FRESH, UNCHECKED, check_against_sample, load_report
from dissect.virustotal import client as virustotal_client
from dissect.virustotal.models import VirusTotalReport

app = typer.Typer(
    help="Tutor de análisis estático basado en evidencias.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    add_completion=False,
)
EXIT = {"completed": 0, "partial": 3, "failed": 1}


class Output(StrEnum):
    text = "text"
    markdown = "markdown"
    json = "json"


def write_utf8(text: str, *, buffer: IO[bytes]) -> None:
    buffer.write(text.encode("utf-8"))
    buffer.write(b"\n")


def fail(error: DissectError) -> typer.Exit:
    write_utf8(
        json.dumps({"error": {"code": error.code, "message": str(error)}}),
        buffer=sys.stderr.buffer,
    )
    return typer.Exit(1)


def emit(
    report: Report,
    output: Output,
    origin: str,
    *,
    report_json: bool,
    external: VirusTotalReport | None = None,
) -> None:
    """Write the requested view; the report JSON needs no glossary."""
    if output is Output.json and report_json:
        write_utf8(report.model_dump_json(indent=2), buffer=sys.stdout.buffer)
        return
    try:
        glossary = load_glossary()
        explanation = explain(report, glossary)
        items = validate(explanation, report, glossary)
    except (GlossaryError, ExplanationError):
        raise fail(DissectError("glossary_invalid")) from None
    if output is Output.json:
        text = explanation.model_dump_json(indent=2)
    elif output is Output.markdown:
        text = to_markdown(explanation, items, report, glossary, origin, external)
        text = text.rstrip("\n")
    else:
        text = to_text(explanation, items, report, glossary, origin, external).rstrip("\n")
    write_utf8(text, buffer=sys.stdout.buffer)


@app.callback()
def main() -> None:
    pass


# VirusTotal is consulted by default (user request, 2026-09-24), by SHA-256 only and
# from the host; without a key it answers "key_missing" without touching the network.
# DISSECT_VIRUSTOTAL=off turns the default off, and --no-virustotal one analysis.
DEFAULT_SWITCH = "DISSECT_VIRUSTOTAL"


def virustotal_default() -> bool:
    return os.environ.get(DEFAULT_SWITCH, "").strip().lower() not in ("0", "off", "no", "false")


@app.command()
def analyze(
    file: Annotated[Path, typer.Argument(help="Archivo a analizar sin ejecutarlo.")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emitir el informe de hechos en JSON validado.")
    ] = False,
    markdown: Annotated[
        bool, typer.Option("--markdown", help="Emitir el informe didáctico en Markdown.")
    ] = False,
    virustotal: Annotated[
        bool | None,
        typer.Option(
            "--virustotal/--no-virustotal",
            help="Consultar VirusTotal por el SHA-256 (clave en VT_API_KEY). Activo por defecto"
            " salvo con --json o DISSECT_VIRUSTOTAL=off. Fuente externa.",
        ),
    ] = None,
    upload: Annotated[
        bool,
        typer.Option(
            "--upload-to-virustotal",
            help="Si VirusTotal no conoce el archivo, subirlo. Lo compartirá con sus clientes.",
        ),
    ] = False,
) -> None:
    """Analiza un archivo en el worker aislado y lo explica paso a paso."""
    if json_output and markdown:
        raise typer.BadParameter("usa solo una de --json y --markdown")
    if json_output and (virustotal or upload):
        raise typer.BadParameter("para el JSON de VirusTotal usa: dissect virustotal --format json")
    if virustotal is None:
        # the JSON output is the fact report; VirusTotal has its own document
        virustotal = not json_output and virustotal_default()
    try:
        limits = Limits()
        blob = read_sample(file, limits)
        report = analyze_isolated(blob.data, limits)
    except DissectError as error:
        raise fail(error) from None
    output = Output.json if json_output else Output.markdown if markdown else Output.text
    external = None
    if virustotal or upload:
        external = virustotal_client.consult(report.sample.sha256, blob.data, upload=upload)
    emit(report, output, FRESH, report_json=True, external=external)
    raise typer.Exit(EXIT[report.analysis.status])


@app.command(name="explain")
def explain_saved(
    report_file: Annotated[Path, typer.Argument(help="Informe JSON guardado con --json.")],
    sample: Annotated[
        Path | None,
        typer.Option("--sample", help="Muestra original, para contrastar el informe con ella."),
    ] = None,
    output: Annotated[Output, typer.Option("--format", help="text, markdown o json.")] = (
        Output.text
    ),
    virustotal: Annotated[
        bool | None,
        typer.Option(
            "--virustotal/--no-virustotal",
            help="Consultar VirusTotal por el SHA-256 del informe (VT_API_KEY). Activo por"
            " defecto salvo con --format json o DISSECT_VIRUSTOTAL=off.",
        ),
    ] = None,
) -> None:
    """Explica un informe guardado sin volver a analizar la muestra.

    Con --format json emite el documento de explicaciones (contrato 0.1.0).
    """
    try:
        limits = Limits()
        report = load_report(report_file, limits)
        origin = UNCHECKED
        if sample is not None:
            check_against_sample(report, read_sample(sample, report.analysis.limits))
            origin = CHECKED
    except DissectError as error:
        raise fail(error) from None
    external = None
    if virustotal is None:
        virustotal = virustotal_default()
    if virustotal and output is not Output.json:
        external = virustotal_client.consult(report.sample.sha256)
    emit(report, output, origin, report_json=False, external=external)
    raise typer.Exit(EXIT[report.analysis.status])


@app.command(name="virustotal")
def virustotal_only(
    file: Annotated[Path | None, typer.Argument(help="Archivo cuyo SHA-256 se consulta.")] = None,
    sha256: Annotated[
        str | None, typer.Option("--sha256", help="Consultar este SHA-256 sin leer ningún archivo.")
    ] = None,
    upload: Annotated[
        bool,
        typer.Option(
            "--upload-to-virustotal",
            help="Si VirusTotal no conoce el archivo, subirlo. Lo compartirá con sus clientes.",
        ),
    ] = False,
    output: Annotated[Output, typer.Option("--format", help="text o json.")] = Output.text,
) -> None:
    """Consulta VirusTotal (fuente externa, no verificada por Dissect) sin analizar el archivo."""
    if (file is None) == (sha256 is None):
        raise typer.BadParameter("indica un archivo o --sha256, no ambos")
    if output is Output.markdown:
        raise typer.BadParameter("este comando emite text o json")
    data = None
    if file is not None:
        try:
            blob = read_sample(file, Limits())
        except DissectError as error:
            raise fail(error) from None
        data, digest = blob.data, blob.sample.sha256
    else:
        digest = (sha256 or "").strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise typer.BadParameter("--sha256 debe tener 64 caracteres hexadecimales")
        if upload:
            raise typer.BadParameter("para subir hace falta el archivo, no solo su hash")
    result = virustotal_client.consult(digest, data, upload=upload)
    if output is Output.json:
        write_utf8(result.model_dump_json(indent=2), buffer=sys.stdout.buffer)
    else:
        write_utf8("\n".join(to_text_lines(result, wrap)).strip("\n"), buffer=sys.stdout.buffer)
    if result.status == "unavailable":
        problem = {"code": f"virustotal_{result.problem}", "message": "VirusTotal no disponible"}
        write_utf8(json.dumps({"error": problem}), buffer=sys.stderr.buffer)
        raise typer.Exit(1)
