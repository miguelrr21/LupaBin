"""Load a report saved earlier and, if the sample is given, check it against the bytes.

A saved report is a file anyone can edit. Model validation catches incoherent
reports, but only the sample proves that its decodings and YARA matches are real,
so explanations say which of the two checks a loaded report passed.
"""

import os
from pathlib import Path

from pydantic import ValidationError

from dissect.errors import DissectError
from dissect.evidence.models import Limits, Report
from dissect.evidence.yara import validate_matches
from dissect.extractors.decode import verify_decodings
from dissect.ingest.reader import Blob
from dissect.rules.catalog import CatalogError, load_catalog

FRESH = "Informe producido ahora por el worker aislado y verificado por el host."
UNCHECKED = (
    "Informe cargado de un archivo sin contrastarlo con la muestra: su estructura es válida, "
    "pero nada garantiza que sus datos procedan de ella (usa --sample para contrastarlo)."
)
CHECKED = (
    "Informe cargado de un archivo y contrastado con la muestra: coinciden los hashes, cada "
    "decodificación se rederivó de los bytes y cada coincidencia YARA se comprobó."
)


def load_report(path: Path, limits: Limits) -> Report:
    flags = os.O_RDONLY
    for flag in ("O_BINARY", "O_NOFOLLOW"):
        flags |= getattr(os, flag, 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            raw = stream.read(limits.output_bytes + 1)
    except OSError:
        raise DissectError("invalid_report") from None
    if len(raw) > limits.output_bytes:
        raise DissectError("invalid_report")
    try:
        return Report.model_validate_json(raw)
    except (ValidationError, ValueError, RecursionError):
        raise DissectError("invalid_report") from None


def check_against_sample(report: Report, blob: Blob) -> None:
    """The same host-side checks as a fresh analysis, minus the worker round trip."""
    if (report.sample.sha256, report.sample.md5, report.sample.size) != (
        blob.sample.sha256,
        blob.sample.md5,
        blob.sample.size,
    ):
        raise DissectError("report_mismatch")
    try:
        verify_decodings(report.evidence, blob.data)
        context = report.yara_context
        if context is not None and context.catalog is not None:
            limits = report.analysis.limits.yara
            if context.catalog != load_catalog(limits).info:
                raise DissectError("report_mismatch")
            matches = tuple(f.data for f in report.evidence if f.kind == "yara_match")
            validate_matches(matches, context, len(blob.data), limits, blob.data)
    except (ValueError, CatalogError):
        raise DissectError("report_mismatch") from None
