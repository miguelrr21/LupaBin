"""Load a report saved earlier and, if the sample is given, check it against the bytes.

A saved report is a file anyone can edit. Model validation catches incoherent
reports, but only the sample proves that its decodings and YARA matches are real,
so explanations say which of the two checks a loaded report passed.
"""

import os
from pathlib import Path

from pydantic import ValidationError

from lupabin.errors import LupaBinError
from lupabin.evidence.code import verify_calls
from lupabin.evidence.models import Limits, Report
from lupabin.evidence.toolchain_checks import verify_markers
from lupabin.evidence.upx_checks import verify_upx
from lupabin.evidence.yara import validate_matches
from lupabin.extractors.decode import verify_decodings
from lupabin.extractors.strings import verify_strings
from lupabin.ingest.reader import Blob
from lupabin.rules.catalog import CatalogError, load_catalog

FRESH = "Informe producido ahora por el worker aislado y verificado por el host."
UNCHECKED = (
    "Informe cargado de un archivo sin contrastarlo con la muestra: su estructura es válida, "
    "pero nada garantiza que sus datos procedan de ella (usa --sample para contrastarlo)."
)
CHECKED = (
    "Informe cargado de un archivo y contrastado con la muestra: coinciden los hashes, "
    "se cotejaron los bytes conservados de las cadenas literales, cada decodificación "
    "se rederivó de los bytes, cada coincidencia YARA se comprobó y el bloque UPX, si lo hay, "
    "se descomprimió de nuevo."
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
        raise LupaBinError("invalid_report") from None
    if len(raw) > limits.output_bytes:
        raise LupaBinError("invalid_report")
    try:
        return Report.model_validate_json(raw)
    except (ValidationError, ValueError, RecursionError):
        raise LupaBinError("invalid_report") from None


def check_against_sample(report: Report, blob: Blob) -> None:
    """The same host-side checks as a fresh analysis, minus the worker round trip."""
    if (report.sample.sha256, report.sample.md5, report.sample.size) != (
        blob.sample.sha256,
        blob.sample.md5,
        blob.sample.size,
    ):
        raise LupaBinError("report_mismatch")
    try:
        verify_strings(report.evidence, blob.data)
        verify_decodings(report.evidence, blob.data)
        verify_calls(report.evidence, blob.data)
        verify_markers(report.evidence, blob.data)
        verify_upx(report.evidence, blob.data, report.analysis.limits.string_characters)
        context = report.yara_context
        if context is not None and context.catalog is not None:
            limits = report.analysis.limits.yara
            if context.catalog != load_catalog(limits).info:
                raise LupaBinError("report_mismatch")
            matches = tuple(f.data for f in report.evidence if f.kind == "yara_match")
            validate_matches(matches, context, len(blob.data), limits, blob.data)
    except (ValueError, CatalogError):
        raise LupaBinError("report_mismatch") from None
