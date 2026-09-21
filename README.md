# Dissect

Tutor de análisis estático de binarios, centrado en evidencias verificables.

**Si no hay evidencia suficiente, no se afirma.** Una importación no demuestra ejecución ni intención maliciosa; un resultado vacío no significa que el archivo sea seguro.

## Estado y alcance

Primera entrega: contrato de evidencias versionado, ingesta acotada, extracción PE32/PE32+ de imports normales y retardados, CLI JSON y worker Docker. No ejecuta ni emula la muestra. No incluye todavía informes didácticos completos, web, LLM, VirusTotal, YARA, capa ni desofuscación.

El código incluye pruebas unitarias y pruebas reales de aislamiento marcadas `docker`. La existencia de estas pruebas o del workflow no implica que hayan pasado en tu entorno. Ejecuta las comprobaciones de aislamiento antes de usar muestras no fiables. Este proyecto es experimental; no es un antivirus ni una garantía de seguridad.

## Requisitos

- uv y Python 3.12; uv puede provisionar el intérprete sin sustituir el Python del sistema.
- Docker con motor Linux; en Windows, Docker Desktop iniciado en modo de contenedores Linux.
- Red para instalar dependencias y construir la imagen inicialmente. El análisis posterior no necesita red ni intenta descargar imágenes.

## Inicio rápido

Desde la raíz del repositorio, con una entrada local disponible:

```text
uv sync --frozen
docker build -f docker/Dockerfile -t dissect-worker:0.1.0 .
uv run --frozen dissect analyze "ruta/al/archivo.exe" --json
```

El parser se ejecuta en un contenedor sin red, sin capacidades adicionales, con usuario no root y raíz de solo lectura. La CLI no ejecuta el parser en el host si Docker falla. La imagen se resuelve a su ID local antes del análisis. No se montan archivos ni el socket Docker en el worker; la muestra se transmite como bytes por stdin.

En el entorno Windows de desarrollo preparado para este repositorio, si uv no está en el PATH se puede sustituir `uv` por `.\.bootstrap\Scripts\uv.exe`. La instalación local `.bootstrap` no forma parte del repositorio distribuido.

Para generar una entrada sintética en lugar de aportar un binario:

```text
uv run python -m tests.fixtures.pe_builder --output samples/practice.bin
uv run --frozen dissect analyze samples/practice.bin --json
```

El generador no sobrescribe archivos existentes. Consulta [la procedencia de los fixtures](samples/README.md). No ejecutes los archivos generados.

## Salida y abstención

La salida es un informe JSON validado con hashes SHA-256/MD5, tamaño, tipo validado, evidencias `E1`, `E2`, etc., estados de extractor, cobertura y errores. Los nombres se conservan en hexadecimal; solo se añade texto si decodifica estrictamente. Los imports por ordinal no se convierten en nombres supuestos.

- `completed`: terminaron las extracciones solicitadas; no es un veredicto de seguridad.
- `partial`: hay hechos respaldados, pero también errores o limitaciones.
- `failed`: no se pudo completar la extracción ni conservar evidencias de imports válidas.

Códigos de salida: 0 completo, 3 parcial, 1 fallo, 2 uso incorrecto. Los errores anteriores al informe se emiten como JSON en stderr, sin rutas locales ni traceback. Las evidencias vacías deben interpretarse junto con `extractor_runs` y `extractor_errors`.

Los límites predeterminados son 20 MiB de entrada, 30 segundos de worker, 512 MiB de memoria, 1 CPU, 64 procesos, 8 MiB de salida y 10.000 imports. La preparación y limpieza del contenedor tienen límites adicionales propios. Si no se puede confirmar la limpieza, la CLI lo comunica; no debe asumirse que el contenedor desapareció.

Se rechazan cabeceras, regiones y tablas ambiguas. Los warnings de pefile impiden declarar una extracción completa. El determinismo aplica a hechos, orden e IDs con versiones/configuración equivalentes; no a timestamps ni a ejecuciones interrumpidas por límites.

## Arquitectura

```text
CLI -> lectura acotada + hashes -> Docker sin red
    -> cabeceras pefile + imports originales -> modelos Pydantic
    -> validación de respuesta en el host -> JSON
```

- [Contrato y diseño](docs/evidence-schema.md).
- [JSON Schema generado](docs/evidence-schema.json).
- [Decisión sobre bytes originales](docs/decisions/001-original-import-bytes.md).
- [Reglas de veracidad](AGENTS.md).

El JSON Schema valida la forma; Pydantic añade invariantes entre campos, referencias y estados. Una cita existente no demuestra por sí sola la veracidad de una afirmación.

## Desarrollo y verificación

```text
uv run --frozen ruff format --check .
uv run --frozen ruff check .
uv run --frozen mypy src
uv run --frozen pytest -m "not docker"
uv run --frozen python -m dissect.evidence.schema --check
uv build
docker compose config --quiet
docker build -f docker/Dockerfile -t dissect-worker:0.1.0 .
uv run --frozen pytest -m docker
```

Las pruebas Docker fallan si se solicitan sin motor o imagen; no se omiten silenciosamente. La suite ordinaria excluye explícitamente ese marcador. `docker compose build worker` es una alternativa de build; el servicio Compose de esta entrega es un worker de consola, no una web. `docker compose up` todavía no ofrece la experiencia web del MVP final.

Para actualizar el esquema tras cambios aprobados en los modelos: `uv run python -m dissect.evidence.schema`. No editar manualmente el JSON generado.

## Contribuir y licencia

Lee [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) y el [código de conducta](CODE_OF_CONDUCT.md). Solo se admiten fixtures sintéticos e inofensivos. El proyecto se distribuye bajo [Apache-2.0](LICENSE); las dependencias conservan sus licencias.
