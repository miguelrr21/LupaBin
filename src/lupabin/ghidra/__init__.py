import hashlib
import io
import json
import zipfile
from importlib.resources import files
from typing import Annotated, Literal

from pydantic import Field

from lupabin.errors import LupaBinError
from lupabin.evidence.models import Evidence, Report
from lupabin.evidence.primitives import EvidenceId, Model, NonNegative, UInt
from lupabin.ingest.reader import from_bytes
from lupabin.render.safe import visible
from lupabin.saved_report import check_against_sample

NOTICE = (
    "Evidencias de análisis estático, no prueba de ejecución, intención ni seguridad. "
    "Los IDs son locales al informe adjunto. Conserva su cobertura, errores y limitaciones. "
    "El hash identifica el archivo; no autentica al autor del informe "
    "ni demuestra sus afirmaciones. "
    "Las ubicaciones son bytes del archivo, no destinos declarados ni texto descifrado en memoria."
)
MAX_DOCUMENT_BYTES = 32 * 1024 * 1024
MAX_CHECK_BYTES = 128 * 1024 * 1024
MAX_ANNOTATIONS = 40000


class Annotation(Model):
    key: Annotated[str, Field(pattern=r"^E[1-9][0-9]*:[0-9]+$")]
    evidence_id: EvidenceId
    kind: Annotated[str, Field(pattern=r"^[a-z_]+$")]
    confidence: Literal["observed", "inferred"]
    offset: NonNegative | None
    length: Annotated[int, Field(gt=0, le=20971520)] | None
    rva: UInt | None
    range_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")] | None
    reason: Literal["location_unavailable"] | None
    text: Annotated[str, Field(max_length=8192)]


class Document(Model):
    schema_version: Literal["1.0.0"] = "1.0.0"
    notice: str = NOTICE
    report: Report
    annotations: Annotated[tuple[Annotation, ...], Field(max_length=40000)]


def _text(fact: Evidence) -> str:
    payload = visible(json.dumps(fact.data.model_dump(mode="json"), ensure_ascii=False))
    payload = payload.replace("{", "⟨U+007B⟩").replace("}", "⟨U+007D⟩")
    if len(payload) > 4096:
        payload = payload[:4096] + " [texto abreviado; datos íntegros en report.evidence]"
    text = f"{fact.id} | {fact.kind} | {fact.confidence}\n{payload}"
    text += "\nProcedencia: " + ", ".join(fact.provenance.evidence_ids)
    if fact.kind == "decoded_string":
        text += "\nUbicación de los bytes codificados, no del texto resultante en memoria."
    return text


def build_document(report: Report, data: bytes) -> Document:
    report = Report.model_validate(report.model_dump())
    check_against_sample(report, from_bytes(data, report.analysis.limits))
    annotations: list[Annotation] = []
    digests: dict[tuple[int, int], str] = {}
    checked_bytes = 0
    document_bytes = len(Document(report=report, annotations=()).model_dump_json().encode("utf-8"))
    if document_bytes > MAX_DOCUMENT_BYTES:
        raise ValueError("Ghidra document exceeds export limit")
    for fact in report.evidence:
        locations: list[tuple[int | None, int | None, int | None]]
        if fact.kind == "yara_match":
            locations = [(i.offset, i.matched_length, None) for i in fact.data.instances]
            if not locations:
                locations = [(None, None, None)]
        else:
            loc = fact.location
            locations = [(loc.offset, loc.length, loc.rva)] if loc else [(None, None, None)]
        if len(annotations) + len(locations) > MAX_ANNOTATIONS:
            raise ValueError("Ghidra annotation count exceeds export limit")
        text = _text(fact)
        for index, (offset, length, rva) in enumerate(locations):
            digest = None
            if offset is not None and length is not None:
                if offset < 0 or length <= 0 or offset + length > len(data):
                    raise ValueError("evidence range outside original file")
                if fact.kind == "string" and data[offset : offset + length] != bytes.fromhex(
                    fact.data.raw_hex
                ):
                    raise LupaBinError("report_mismatch")
                key = (offset, length)
                if key not in digests:
                    checked_bytes += length
                    if checked_bytes > MAX_CHECK_BYTES:
                        raise ValueError("Ghidra range hashing exceeds export limit")
                    digests[key] = hashlib.sha256(
                        memoryview(data)[offset : offset + length]
                    ).hexdigest()
                digest = digests[key]
            annotation = Annotation(
                key=f"{fact.id}:{index}",
                evidence_id=fact.id,
                kind=fact.kind,
                confidence=fact.confidence,
                offset=offset,
                length=length,
                rva=rva,
                range_sha256=digest,
                reason="location_unavailable" if digest is None else None,
                text=text,
            )
            document_bytes += len(annotation.model_dump_json().encode("utf-8")) + bool(annotations)
            if document_bytes > MAX_DOCUMENT_BYTES:
                raise ValueError("Ghidra document exceeds export limit")
            annotations.append(annotation)
    return Document(report=report, annotations=tuple(annotations))


def build_bundle(report: Report, data: bytes) -> bytes:
    document = build_document(report, data).model_dump_json().encode("utf-8")
    if len(document) > MAX_DOCUMENT_BYTES:
        raise ValueError("Ghidra document exceeds export limit")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in (
            ("lupabin-ghidra.json", document),
            ("ImportLupaBin.java", (files("lupabin.ghidra") / "ImportLupaBin.java").read_bytes()),
        ):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, content)
    return output.getvalue()
