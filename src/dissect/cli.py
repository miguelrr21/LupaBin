import json
from pathlib import Path
from typing import Annotated

import typer

from dissect.errors import DissectError
from dissect.evidence.models import Limits
from dissect.ingest.reader import read_sample
from dissect.runner import analyze_isolated

app = typer.Typer(
    help="Tutor de análisis estático basado en evidencias.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    add_completion=False,
)


@app.callback()
def main() -> None:
    pass


@app.command()
def analyze(
    file: Annotated[Path, typer.Argument(help="Archivo a analizar sin ejecutarlo.")],
    json_output: Annotated[bool, typer.Option("--json", help="Emitir JSON validado.")] = False,
) -> None:
    try:
        limits = Limits()
        blob = read_sample(file, limits)
        report = analyze_isolated(blob.data, limits)
    except DissectError as error:
        typer.echo(json.dumps({"error": {"code": error.code, "message": str(error)}}), err=True)
        raise typer.Exit(1) from None
    typer.echo(report.model_dump_json(indent=2 if not json_output else None))
    raise typer.Exit({"completed": 0, "partial": 3, "failed": 1}[report.analysis.status])
