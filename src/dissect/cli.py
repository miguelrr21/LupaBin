import json
import sys
from pathlib import Path
from typing import IO, Annotated

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


def write_utf8(text: str, *, buffer: IO[bytes]) -> None:
    buffer.write(text.encode("utf-8"))
    buffer.write(b"\n")


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
        write_utf8(
            json.dumps({"error": {"code": error.code, "message": str(error)}}),
            buffer=sys.stderr.buffer,
        )
        raise typer.Exit(1) from None
    write_utf8(
        report.model_dump_json(indent=2 if not json_output else None), buffer=sys.stdout.buffer
    )
    raise typer.Exit({"completed": 0, "partial": 3, "failed": 1}[report.analysis.status])
