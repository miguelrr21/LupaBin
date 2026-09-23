import json
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
from dissect.render.document import to_markdown, to_text
from dissect.runner import analyze_isolated
from dissect.saved_report import CHECKED, FRESH, UNCHECKED, check_against_sample, load_report

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


def emit(report: Report, output: Output, origin: str, *, report_json: bool) -> None:
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
        text = to_markdown(explanation, items, report, glossary, origin).rstrip("\n")
    else:
        text = to_text(explanation, items, report, glossary, origin).rstrip("\n")
    write_utf8(text, buffer=sys.stdout.buffer)


@app.callback()
def main() -> None:
    pass


@app.command()
def analyze(
    file: Annotated[Path, typer.Argument(help="Archivo a analizar sin ejecutarlo.")],
    json_output: Annotated[
        bool, typer.Option("--json", help="Emitir el informe de hechos en JSON validado.")
    ] = False,
    markdown: Annotated[
        bool, typer.Option("--markdown", help="Emitir el informe didáctico en Markdown.")
    ] = False,
) -> None:
    """Analiza un archivo en el worker aislado y lo explica paso a paso."""
    if json_output and markdown:
        raise typer.BadParameter("usa solo una de --json y --markdown")
    try:
        limits = Limits()
        blob = read_sample(file, limits)
        report = analyze_isolated(blob.data, limits)
    except DissectError as error:
        raise fail(error) from None
    output = Output.json if json_output else Output.markdown if markdown else Output.text
    emit(report, output, FRESH, report_json=True)
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
    emit(report, output, origin, report_json=False)
    raise typer.Exit(EXIT[report.analysis.status])
