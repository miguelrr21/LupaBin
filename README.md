# Dissect

Tutor de análisis estático de binarios, centrado en evidencias verificables.

**Si no hay evidencia suficiente, no se afirma.** Una importación no demuestra ejecución ni intención maliciosa; un resultado vacío no significa que el archivo sea seguro.

## Estado y alcance

Fase 1B, contrato 0.3.0: ingesta acotada, cabeceras y secciones PE32/PE32+, entropía de bytes, imports normales/retardados, exports, anomalías estructurales, cadenas literales y coincidencias YARA, mediante CLI JSON y worker Docker. No ejecuta ni emula la muestra. No incluye todavía informes didácticos completos, web, LLM, VirusTotal, capa ni desofuscación.

Cada hecho indica qué se observó y dónde. La entropía no demuestra empaquetado; un export no necesariamente es una función; el timestamp de cabecera no acredita una fecha de compilación; una URL literal no prueba una conexión.

El código incluye pruebas unitarias y pruebas reales de aislamiento marcadas `docker`. La existencia de estas pruebas o del workflow no implica que hayan pasado en tu entorno. Ejecuta las comprobaciones de aislamiento antes de usar muestras no fiables. Este proyecto es experimental; no es un antivirus ni una garantía de seguridad.

## Requisitos

- uv y Python 3.12; uv puede provisionar el intérprete sin sustituir el Python del sistema.
- Docker con motor Linux; en Windows, Docker Desktop iniciado en modo de contenedores Linux.
- Red para instalar dependencias y construir la imagen inicialmente. El análisis posterior no necesita red ni intenta descargar imágenes.

## Inicio rápido

Desde la raíz del repositorio, con una entrada local disponible:

```text
uv sync --frozen
docker build --load -f docker/Dockerfile -t dissect-worker:0.3.0 .
uv run --frozen dissect analyze "ruta/al/archivo.exe" --json
```

El parser se ejecuta en un contenedor sin red, sin capacidades adicionales, con usuario no root y raíz de solo lectura. La CLI no ejecuta el parser en el host si Docker falla. La imagen se resuelve a su ID local antes del análisis. No se montan archivos ni el socket Docker en el worker; la muestra se transmite como bytes por stdin.

En el entorno Windows de desarrollo preparado para este repositorio, si uv no está en el PATH se puede sustituir `uv` por `.\.bootstrap\Scripts\uv.exe`. La instalación local `.bootstrap` no forma parte del repositorio distribuido.

Para generar una entrada sintética en lugar de aportar un binario:

```text
uv run python -m tests.fixtures.pe_builder --scenario demo --output samples/phase1a-complete.bin
uv run --frozen dissect analyze samples/phase1a-complete.bin --json
uv run python -m tests.fixtures.pe_builder --scenario corrupt --output samples/phase1a-partial.bin
uv run --frozen dissect analyze samples/phase1a-partial.bin --json
```

El generador no sobrescribe archivos existentes. Consulta [la procedencia de los fixtures](samples/README.md). No ejecutes los archivos generados.

## Salida y abstención

La salida es un informe JSON validado con hashes SHA-256/MD5, tamaño, tipo validado, evidencias `E1`, `E2`, etc., estados de extractor, cobertura y errores. Los nombres se conservan en hexadecimal; solo se añade texto si decodifica estrictamente. Los imports por ordinal no se convierten en nombres supuestos.

- `completed`: los tres extractores completaron su cobertura declarada; no es un veredicto de seguridad.
- `partial`: una parte se revisó, pero existen componentes bloqueados, errores u omisiones. Puede no haber hallazgos.
- `failed`: los tres extractores quedaron bloqueados, o la infraestructura no pudo producir un informe validado.

La cobertura está en `extractor_runs[].components`, con contadores y estados `complete`, `partial` o `blocked`. `extractor_errors` describe fallos; `limitations` describe cuotas, truncamientos explícitos y warnings. Cero resultados con cobertura completa no equivale a un error ni demuestra seguridad.

Un archivo cuyo PE no pueda interpretarse puede conservar cadenas literales y seguir clasificado como `unknown`; el resultado global será parcial. El barrido reconoce el repertorio ASCII imprimible, directamente y codificado en UTF-16LE, con mínimo de cuatro caracteres. No recupera todo Unicode ni cadenas ofuscadas. Los prefijos acotados llevan `complete=false` y nunca incluyen puntos suspensivos inventados. Una secuencia imprimible puede ser incidental o cruzar campos binarios: no se presume que sea texto intencional del programa.

Códigos de salida: 0 completo, 3 parcial, 1 fallo, 2 uso incorrecto. Los errores anteriores al informe se emiten como JSON en stderr, sin rutas locales ni traceback. Las evidencias vacías deben interpretarse junto con `extractor_runs` y `extractor_errors`.

Los límites predeterminados son 20 MiB de entrada, 30 segundos de worker, 512 MiB de memoria, 1 CPU, 64 procesos, 8 MiB de salida y 10.000 imports. La preparación y limpieza del contenedor tienen límites adicionales propios. Si no se puede confirmar la limpieza, la CLI lo comunica; no debe asumirse que el contenedor desapareció.

También se acotan secciones (96), entradas EAT (5.000), asociaciones de nombres exportados (10.000), cadenas (5.000 y 1.024 caracteres por prefijo), anomalías (128) y bytes acumulados de entropía (20 MiB). Se reserva espacio de salida para explicar las omisiones. Las cuotas efectivas aparecen en el JSON.

Ante un mapa de regiones ambiguo se bloquean las lecturas que dependan de él, sin borrar las cabeceras y descriptores comprobados. Los warnings de pefile impiden declarar una extracción completa. El determinismo aplica a hechos, orden e IDs con versiones/configuración equivalentes; no a timestamps ni a ejecuciones interrumpidas por límites.

La CLI 0.3.0 exige el esquema 0.3.0 y un catálogo compatible del worker; una discrepancia produce `incompatible_worker`. Los esquemas 0.1.0 y 0.2.0 se conservan en `docs/schemas/`, pero no hay conversión automática de informes. Los IDs pueden cambiar entre versiones.

Si aparece `image_unavailable`, la CLI no pudo verificar la imagen, lo que no demuestra por sí solo que haya sido borrada. Comprueba en la misma terminal `docker context show` y `docker image inspect --format '{{.Id}}' dissect-worker:0.3.0`; construye la imagen con `--load` en ese contexto si no está disponible. No se cambia el contexto ni se descarga una imagen durante el análisis.

## Qué aporta YARA

El catálogo propio incluye cuatro reglas: texto del stub DOS, presencia conjunta de tres nombres de APIs, marcadores `RSDS`/`.pdb` y el marcador sintético `DISSECT PRACTICE`. Ninguna identifica una familia ni prueba ejecución, imports, inyección o actividad de red.

Cada `yara_match` contiene regla, namespace, revisión, hashes de fuente/conjunto, versiones observadas e instancias con offsets y bytes originales. Su `location` global es nula porque una regla puede depender de varios intervalos; consulta `data.instances`. `yara_context` identifica el catálogo incluso cuando no hay coincidencias.

El motor nativo corre en un hijo dentro del worker. Usa solo el buffer recibido, sin rutas, PIDs ni reglas externas. Los límites iniciales son 5 segundos de matching, 10 segundos de proceso, 32 reglas publicadas, 16 instancias por regla y 256 bytes por instancia. Los bytes o apariciones omitidos se marcan como parciales. Un timeout, warning nativo o respuesta inválida descarta los matches YARA, conservando PE/strings cuando el padre sigue operativo.

Para probar representación limitada con datos sintéticos:

```text
uv run python -m tests.fixtures.pe_builder --scenario yara-limited --output samples/yara-limited.bin
uv run --frozen dissect analyze samples/yara-limited.bin --json
```

El fixture contiene veinte apariciones ASCII del marcador. Con los límites predeterminados el informe debe conservar dieciséis e indicar cuatro omitidas, con salida 3. `--scenario demo` ofrece un positivo y `--scenario basic` un caso sin coincidencias de este catálogo. No ejecutes ninguno como programa.

## Arquitectura

```text
CLI -> lectura acotada + hashes -> Docker sin red
    -> PE (cabeceras, secciones, entropía, imports, exports, anomalías)
    -> cadenas literales independientes -> hijo YARA con catálogo propio
    -> presupuesto y modelos Pydantic
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
uv run --frozen python -m tests.check_yara_distribution
docker compose config --quiet
docker build --load -f docker/Dockerfile -t dissect-worker:0.3.0 .
uv run --frozen pytest -m docker
```

Las pruebas Docker fallan si se solicitan sin motor o imagen; no se omiten silenciosamente. La suite ordinaria excluye explícitamente ese marcador. `docker compose build worker` es una alternativa de build; el servicio Compose de esta entrega es un worker de consola, no una web. `docker compose up` todavía no ofrece la experiencia web del MVP final.

Para actualizar el esquema tras cambios aprobados en los modelos: `uv run python -m dissect.evidence.schema`. No editar manualmente el JSON generado.

## Contribuir y licencia

Lee [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) y el [código de conducta](CODE_OF_CONDUCT.md). Solo se admiten fixtures sintéticos e inofensivos. El proyecto se distribuye bajo [Apache-2.0](LICENSE); las dependencias conservan sus licencias.
