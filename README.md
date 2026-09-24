# Dissect

Tutor de análisis estático de binarios, centrado en evidencias verificables.

**Si no hay evidencia suficiente, no se afirma.** Una importación no demuestra ejecución ni intención maliciosa; un resultado vacío no significa que el archivo sea seguro.

## Estado y alcance

Contrato de hechos 0.5.0 (Fases 1A, 1B, 2 y primera entrega de la 4): ingesta acotada, cabeceras y secciones PE32/PE32+, entropía de bytes, imports normales/retardados, exports, anomalías estructurales, cadenas literales, coincidencias YARA, decodificación estática acotada (Base64/hex y XOR de clave repetida de 1 a 8 bytes) y, en la rama `feat/static-api-calls`, qué funciones importadas llama el código x86/x64 y desde qué instrucción, producidos en un worker Docker aislado. Fase 3 (en la rama `feat/didactic-glossary`): un informe didáctico legible por defecto, con explicaciones deterministas que citan cada evidencia, dicen lo que no demuestran y enlazan un glosario de 39 entradas con fuentes verificadas. No ejecuta ni emula la muestra. No incluye todavía web, LLM, VirusTotal, capa, FLOSS ni desempaquetado.

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
docker build --load -f docker/Dockerfile -t dissect-worker:0.5.0 .
uv run --frozen dissect analyze "ruta/al/archivo.exe"
```

Por defecto se muestra el informe didáctico. `--json` emite el informe de hechos validado (para guardarlo o procesarlo) y `--markdown` el informe didáctico en Markdown. Un informe guardado se puede explicar sin repetir el análisis:

```text
uv run --frozen dissect analyze "ruta/al/archivo.exe" --json > informe.json
uv run --frozen dissect explain informe.json --sample "ruta/al/archivo.exe"
```

Con `--sample`, el host repite sus comprobaciones contra la muestra (hashes, cada decodificación y cada coincidencia YARA) y rechaza un informe que los bytes contradigan. Sin `--sample`, el informe explicado lleva un aviso visible: su estructura es válida, pero nada garantiza que proceda de la muestra. `--format json` emite el documento de explicaciones (contrato 0.1.0).

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

## Qué aporta el informe didáctico

El informe legible sigue siempre el mismo orden: la muestra (hashes, tamaño, tipo y si el informe se acaba de producir o se cargó de un archivo), **qué no se pudo analizar**, los hechos observados, las inferencias (resultados de aplicar una transformación) y el glosario de los términos usados, con sus fuentes.

- Cada frase la genera una regla determinista a partir de las evidencias que cita (`X1`, `X2`… citan `E1`, `E2`…). Antes de mostrarla, el validador la regenera desde esas citas y exige que coincida exactamente; una frase alterada no se muestra, y se dice cuántas se omitieron.
- Cada frase lleva su **límite**: lo que ese hecho no demuestra. Por ejemplo, una sección con permisos de escritura y ejecución no demuestra que se ejecute código escrito en ella.
- Las cifras de contexto están medidas. Una entropía de 7,2 o más solo la alcanza el 0,34 % de las secciones de 4 KiB o más en 55.313 binarios benignos. Los imports se agrupan en nueve familias curadas con su prevalencia benigna: por ejemplo, el 32,2 % de los binarios benignos importa alguna función de comprobación de depuradores.
- Todo texto que procede de la muestra (nombres, cadenas, textos decodificados) se neutraliza antes de mostrarse: los caracteres de control, de escape de terminal y bidi se convierten en escapes visibles, y en Markdown van en bloques de código inertes.

Diseño y mediciones: [Fase 3](docs/superpowers/specs/2026-09-23-didactic-glossary-design.md).

## Qué aporta VirusTotal (opcional)

Con una clave de API en la variable de entorno `VT_API_KEY`, o en un archivo `.env` en la carpeta desde la que lo ejecutas (`VT_API_KEY=...`, ignorado por git y excluido de la imagen Docker y del paquete), Dissect puede añadir los resultados de VirusTotal como **fuente externa, no verificada por Dissect**: cuántos motores antivirus marcan el archivo y con qué etiqueta, veredictos de sus sandboxes y el comportamiento que observaron al ejecutarlo allí (procesos, comandos, archivos, registro, red, mutex, servicios y técnicas MITRE ATT&CK).

```text
uv run --frozen dissect analyze "ruta/al/archivo.exe" --virustotal
uv run --frozen dissect virustotal --sha256 <sha256> --format json
```

- Por defecto solo se envía el SHA-256, nunca el archivo. `--upload-to-virustotal` lo sube solo si VirusTotal no lo conoce, con el nombre genérico `sample`. Según su documentación, el contenido subido puede compartirse con sus clientes de pago: no subas archivos internos o confidenciales.
- Todo ocurre en el host: el worker sigue sin red. Una etiqueta es la opinión de un motor, y el comportamiento se observó en los sandboxes de VirusTotal, no en tu equipo. "VirusTotal no conoce este archivo" no dice nada sobre su peligrosidad.
- La API pública admite 500 consultas al día y 4 por minuto, y no puede usarse en productos o servicios comerciales.

Diseño: [integración con VirusTotal](docs/superpowers/specs/2026-09-23-virustotal-design.md).

## Salida y abstención

La salida `--json` es un informe JSON validado con hashes SHA-256/MD5, tamaño, tipo validado, evidencias `E1`, `E2`, etc., estados de extractor, cobertura y errores. Los nombres se conservan en hexadecimal; solo se añade texto si decodifica estrictamente. Los imports por ordinal no se convierten en nombres supuestos.

- `completed`: los cuatro extractores completaron su cobertura declarada; no es un veredicto de seguridad.
- `partial`: una parte se revisó, pero existen componentes bloqueados, errores u omisiones. Puede no haber hallazgos.
- `failed`: los cuatro extractores quedaron bloqueados, o la infraestructura no pudo producir un informe validado.

La cobertura está en `extractor_runs[].components`, con contadores y estados `complete`, `partial` o `blocked`. `extractor_errors` describe fallos; `limitations` describe cuotas, truncamientos explícitos y warnings. Cero resultados con cobertura completa no equivale a un error ni demuestra seguridad.

Un archivo cuyo PE no pueda interpretarse puede conservar cadenas literales y seguir clasificado como `unknown`; el resultado global será parcial. El barrido reconoce el repertorio ASCII imprimible, directamente y codificado en UTF-16LE, con mínimo de cuatro caracteres. No recupera todo Unicode ni cadenas ofuscadas. Los prefijos acotados llevan `complete=false` y nunca incluyen puntos suspensivos inventados. Una secuencia imprimible puede ser incidental o cruzar campos binarios: no se presume que sea texto intencional del programa.

Códigos de salida: 0 completo, 3 parcial, 1 fallo, 2 uso incorrecto. Los errores anteriores al informe se emiten como JSON en stderr, sin rutas locales ni traceback. Las evidencias vacías deben interpretarse junto con `extractor_runs` y `extractor_errors`.

Los límites predeterminados son 20 MiB de entrada, 30 segundos de worker, 512 MiB de memoria, 1 CPU, 64 procesos, 8 MiB de salida y 10.000 imports. La preparación y limpieza del contenedor tienen límites adicionales propios. Si no se puede confirmar la limpieza, la CLI lo comunica; no debe asumirse que el contenedor desapareció.

También se acotan secciones (96), entradas EAT (5.000), asociaciones de nombres exportados (10.000), cadenas (5.000 y 1.024 caracteres por prefijo), anomalías (128) y bytes acumulados de entropía (20 MiB). Se reserva espacio de salida para explicar las omisiones. Las cuotas efectivas aparecen en el JSON.

Ante un mapa de regiones ambiguo se bloquean las lecturas que dependan de él, sin borrar las cabeceras y descriptores comprobados. Los warnings de pefile impiden declarar una extracción completa. El determinismo aplica a hechos, orden e IDs con versiones/configuración equivalentes; no a timestamps ni a ejecuciones interrumpidas por límites.

La CLI 0.5.0 exige el esquema 0.5.0 y un catálogo compatible del worker; una discrepancia produce `incompatible_worker`. Los esquemas 0.1.0 a 0.4.0 se conservan en `docs/schemas/`, pero no hay conversión automática de informes. Los IDs pueden cambiar entre versiones.

Si aparece `image_unavailable`, la CLI no pudo verificar la imagen, lo que no demuestra por sí solo que haya sido borrada. Comprueba en la misma terminal `docker context show` y `docker image inspect --format '{{.Id}}' dissect-worker:0.5.0`; construye la imagen con `--load` en ese contexto si no está disponible. No se cambia el contexto ni se descarga una imagen durante el análisis.

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

## Qué aporta la decodificación

Cada `decoded_string` dice exactamente esto: "estos bytes, transformados con este algoritmo y estos parámetros, producen este texto". Es siempre `confidence: "inferred"`. No afirma que el programa realice la transformación, que el texto sea el que pretendía su autor ni que tenga significado (una URL decodificada no prueba una conexión).

- **Base64 y hexadecimal** (`component: decode_strings`): sobre las cadenas ya extraídas, con validación estricta (Base64 canónico de al menos 12 caracteres si lleva relleno `=` o 16 si no; hexadecimal que no sea solo dígitos decimales, porque un número como `2147483647` también es hexadecimal válido; el texto resultante debe ser imprimible y tener al menos 4 caracteres distintos). Citan en `provenance` la cadena que contiene los bytes codificados.
- **XOR de clave repetida de 1 a 8 bytes** (`component: decode_xor`): sobre los bytes crudos, anclado en un catálogo versionado de cadenas de referencia (`anchor`, p. ej. `http://`, `kernel32.dll`, `\Registry\Machine\`; 62 en la versión 3). La clave no se elige entre candidatas: se deriva de los bytes y se publica en `transform.key_hex`, alineada con el inicio de `location`. Cualquiera puede comprobarla: `texto[i] = bytes[inicio + i] XOR clave[i mod longitud]`. Si una cadena usa una clave ya verificada en otro punto de la muestra (lo habitual en tablas de cadenas cifradas), también se descifra aunque su ancla sea corta, y cita en `provenance` la decodificación que estableció la clave.

Límites honestos del método, medidos sobre más de 30.000 archivos benignos de Windows y programas instalados (0 decodificaciones espurias; todas las encontradas eran ofuscación real y se revisaron a mano) y documentados en [el diseño de la Fase 2](docs/superpowers/specs/2026-09-22-static-decoding-design.md):

- Un texto cifrado que **no contenga ninguna cadena del catálogo no se encuentra**.
- Si la clave deja el texto cifrado todavía legible (claves pequeñas, típicamente `< 0x20`), **no se publica**: sin puntuar plausibilidad es indistinguible de texto normal. Esos bytes siguen visibles como `string`.
- Una ancla corta solo verifica por sí sola claves cortas (`http://`, 7 bytes, nunca una clave de 8). Con claves de 8 bytes la cobertura medida es del 37 % para una cadena aislada y del 92 % cuando otra cadena de la muestra comparte la clave (el techo alcanzable en el conjunto de prueba es del 86 %: el resto no contiene ninguna ancla).
- No hay desempaquetado, compresión, RC4, XOR rodante ni emulación.

El host no confía en el worker: vuelve a derivar cada decodificación desde los bytes originales y rechaza la respuesta si alguna no se reproduce. Una muestra con millones de patrones candidatos termina como limitación declarada (`decode_xor_examined_limit`), no como timeout.

```text
uv run python -m tests.fixtures.pe_builder --scenario decode-demo --output samples/decode-demo.bin
uv run --frozen dissect analyze samples/decode-demo.bin --json
```

El fixture contiene un Base64, un hexadecimal y cuatro textos cifrados con XOR (clave de 1 byte, de 4 bytes, una cadena UTF-16LE y una URL que reutiliza la clave de 4 bytes) sobre el dominio reservado `.invalid`. El informe debe mostrar seis `decoded_string` y estado completo; la URL cita en `provenance` la decodificación que estableció su clave.

## Arquitectura

```text
CLI -> lectura acotada + hashes -> Docker sin red
    -> PE (cabeceras, secciones, entropía, imports, exports, anomalías)
    -> cadenas literales independientes -> hijo YARA con catálogo propio
    -> decodificación: Base64/hex sobre cadenas, XOR anclado sobre bytes
    -> presupuesto y modelos Pydantic
    -> validación de respuesta y reverificación de decodificaciones en el host -> JSON
    -> explicaciones deterministas (host) + glosario con fuentes
    -> validación por regeneración -> texto / Markdown con texto de la muestra neutralizado
```

- [Contrato y diseño](docs/evidence-schema.md).
- [JSON Schema generado](docs/evidence-schema.json) y [el de las explicaciones](docs/explanation-schema.json).
- [Diseño de la Fase 3: explicaciones y glosario](docs/superpowers/specs/2026-09-23-didactic-glossary-design.md).
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
uv run --frozen python -m dissect.explain.schema --check
uv build
uv run --frozen python -m tests.check_yara_distribution
docker compose config --quiet
docker build --load -f docker/Dockerfile -t dissect-worker:0.5.0 .
uv run --frozen pytest -m docker
```

Las pruebas Docker fallan si se solicitan sin motor o imagen; no se omiten silenciosamente. La suite ordinaria excluye explícitamente ese marcador. `docker compose build worker` es una alternativa de build; el servicio Compose de esta entrega es un worker de consola, no una web. `docker compose up` todavía no ofrece la experiencia web del MVP final.

Para actualizar los esquemas tras cambios aprobados en los modelos: `uv run python -m dissect.evidence.schema` y `uv run python -m dissect.explain.schema`. No editar manualmente el JSON generado. `uv run python -m tests.check_glossary_sources` comprueba con red que las fuentes del glosario y sus anclas siguen existiendo; no forma parte de la CI.

Para repetir las mediciones de falsos positivos, cobertura y tiempo de la decodificación sobre un directorio de binarios benignos propio (solo se leen como bytes; no forma parte de la CI):

```text
uv run python -m tests.decode_eval false-positives <directorio>
uv run python -m tests.decode_eval recall <directorio>
uv run python -m tests.decode_eval timing
```

## Contribuir y licencia

Lee [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) y el [código de conducta](CODE_OF_CONDUCT.md). Solo se admiten fixtures sintéticos e inofensivos. El proyecto se distribuye bajo [Apache-2.0](LICENSE); las dependencias conservan sus licencias.
