"""Packaging of self-contained teaching lab bundles for classrooms and CTFs."""

import io
import json
import zipfile

from lupabin.challenge.engine import generate as challenge_generate
from lupabin.challenge.engine import template as challenge_template
from lupabin.evidence.models import Report
from lupabin.explain.engine import explain, validate
from lupabin.ghidra import build_bundle as ghidra_bundle
from lupabin.glossary.catalog import load_glossary
from lupabin.ingest.reader import from_bytes
from lupabin.render.document import to_markdown
from lupabin.render.html import to_html
from lupabin.saved_report import check_against_sample

FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)


def _write_entry(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(filename=name, date_time=FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    archive.writestr(info, data)


def _teaching_guide(report: Report) -> str:
    sample = report.sample
    return (
        "# Guía de Laboratorio Docente — LupaBin\n\n"
        "## Identificación verificada de la muestra\n\n"
        f"- **SHA-256:** `{sample.sha256}`\n"
        f"- **MD5:** `{sample.md5}`\n"
        f"- **Tamaño:** {sample.size} bytes\n"
        f"- **Formato:** `{sample.type}`\n"
        f"- **Estado del análisis:** `{report.analysis.status}`\n\n"
        "> **Regla de seguridad:** este paquete no contiene ni requiere ejecutar el binario "
        "original en el entorno del alumno. Todos los ejercicios se resuelven mediante "
        "análisis estático basado en evidencias citadas.\n\n"
        "## Contenido del paquete\n\n"
        "- `informe.json`: informe de hechos validado con evidencias, ubicaciones y límites.\n"
        "- `informe.md`: explicación didáctica en Markdown con glosario y citas.\n"
        "- `resumen.html`: cuaderno HTML estático sin JavaScript apto para navegador local.\n"
        "- `reto.json`: cuestionario de práctica con citas y plantilla `answers_template`.\n"
        "- `evidencias-ghidra.zip`: lote verificable (`lupabin-ghidra.json` e "
        "`ImportLupaBin.java`) para importar anotaciones en Ghidra.\n\n"
        "## Práctica guiada paso a paso (15 minutos)\n\n"
        "### 1. Triaje inicial sin ejecución (3 min)\n"
        "Abre `resumen.html` o `informe.md` y localiza el tipo de PE, el número de secciones, "
        "sus permisos de lectura/escritura/ejecución y si existe código alcanzable desde "
        "`main`.\n\n"
        "### 2. Rastreabilidad de evidencias y límites `not_proven` (4 min)\n"
        "Busca una capacidad o llamada a API en `informe.md` y sigue su identificador `E...` "
        "hasta `informe.json`. Comprueba qué argumentos son constantes observadas y qué es lo que "
        "la evidencia declara explícitamente que **no demuestra** (`not_proven`).\n\n"
        "### 3. Autoevaluación local con `reto.json` (5 min)\n"
        "Extrae `answers_template` de `reto.json` a un archivo `respuestas.json`, rellena cada "
        "`option_id` (`A`, `B` o `C`) apoyándote en las citas y corrige tus respuestas localmente "
        "sin red ni LLM:\n\n"
        "```bash\n"
        "lupabin challenge informe.json --answers respuestas.json\n"
        "```\n\n"
        "### 4. Contraste en Ghidra (3 min)\n"
        "Descomprime `evidencias-ghidra.zip`, abre en CodeBrowser el binario original verificando "
        "el SHA-256 (`"
        f"{sample.sha256}"
        "`) y ejecuta únicamente `ImportLupaBin.java` para inspeccionar "
        "la revisión previa antes de aplicar anotaciones.\n"
    )


def build_lab_bundle(report: Report, sample_data: bytes, origin: str) -> bytes:
    """Build a deterministic teaching-lab ZIP verified against `sample_data`."""
    check_against_sample(report, from_bytes(sample_data, report.analysis.limits))
    glossary = load_glossary()
    explanation = explain(report, glossary)
    items = validate(explanation, report, glossary)
    challenge = challenge_generate(report)
    answers = challenge_template(challenge)
    reto_payload = {
        "challenge": challenge.model_dump(mode="json"),
        "answers_template": answers.model_dump(mode="json"),
    }
    entries: tuple[tuple[str, bytes], ...] = (
        ("GUIA_DOCENTE.md", _teaching_guide(report).encode("utf-8")),
        ("evidencias-ghidra.zip", ghidra_bundle(report, sample_data)),
        ("informe.json", (report.model_dump_json(indent=2) + "\n").encode("utf-8")),
        ("informe.md", to_markdown(explanation, items, report, glossary, origin).encode("utf-8")),
        ("resumen.html", to_html(explanation, items, report, glossary, origin).encode("utf-8")),
        (
            "reto.json",
            (json.dumps(reto_payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        ),
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w") as archive:
        for name, data in entries:
            _write_entry(archive, name, data)
    return buffer.getvalue()
