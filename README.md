# LupaBin

Tutor de análisis estático de binarios, centrado en evidencias verificables. Creado por [Miguel Ángel Rodríguez Romero](https://github.com/miguelrr21). *English overview: [README.en.md](README.en.md).*

**Si no hay evidencia suficiente, no se afirma.** Una importación no demuestra ejecución ni intención maliciosa; un resultado vacío no significa que el archivo sea seguro.

## Estado y alcance

Contrato de hechos 0.9.0: ingesta acotada, cabeceras y secciones PE32/PE32+, entropía de bytes, imports normales/retardados, exports, anomalías estructurales, marcas de compilador (cabecera Rich del enlazador de Microsoft, GCC y MinGW-w64, Go, .NET y PyInstaller), cadenas literales, coincidencias YARA, decodificación estática acotada (Base64/hex y XOR de clave repetida de 1 a 8 bytes) y qué funciones importadas llama el código x86/x64, desde qué instrucción y con qué argumentos constantes (72 funciones de registro, servicios, procesos, bibliotecas, archivos, red, sincronización, memoria y criptografía), producidos en un worker Docker aislado. Un informe didáctico legible por defecto, con explicaciones deterministas que citan cada evidencia, dicen lo que no demuestran y enlazan un glosario con fuentes verificadas. Un resumen de lo que contiene el código (capacidades como crear un servicio, escribir en una clave `Run` o pedir memoria ejecutable y escribible), con la técnica de MITRE ATT&CK solo donde el mecanismo coincide y su frecuencia en binarios benignos. VirusTotal se consulta por defecto como fuente externa (ver más abajo), y hay una web con el mismo análisis. No ejecuta ni emula la muestra. No incluye LLM, capa, FLOSS ni desempaquetado.

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
docker build --load -f docker/Dockerfile -t lupabin-worker:0.9.0 .
uv run --frozen lupabin analyze "ruta/al/archivo.exe"
```

Por defecto se muestra el informe didáctico. `--json` emite el informe de hechos validado (para guardarlo o procesarlo) y `--markdown` el informe didáctico en Markdown. Un informe guardado se puede explicar sin repetir el análisis:

```text
uv run --frozen lupabin analyze "ruta/al/archivo.exe" --json > informe.json
uv run --frozen lupabin explain informe.json --sample "ruta/al/archivo.exe"
```

Con `--sample`, el host repite sus comprobaciones contra la muestra (hashes, cada decodificación, coincidencia YARA, llamada, argumento y rango de función) y rechaza un informe que los bytes contradigan. Sin `--sample`, el informe explicado lleva un aviso visible: su estructura es válida, pero nada garantiza que proceda de la muestra. `--format json` emite el documento de explicaciones (contrato 0.1.0).

El parser se ejecuta en un contenedor sin red, sin capacidades adicionales, con usuario no root y raíz de solo lectura. La CLI no ejecuta el parser en el host si Docker falla. La imagen se resuelve a su ID local antes del análisis. No se montan archivos ni el socket Docker en el worker; la muestra se transmite como bytes por stdin.

Para generar una entrada sintética en lugar de aportar un binario:

```text
uv run python -m tests.fixtures.pe_builder --scenario demo --output samples/demo.bin
uv run --frozen lupabin analyze samples/demo.bin --json
uv run python -m tests.fixtures.pe_builder --scenario corrupt --output samples/partial.bin
uv run --frozen lupabin analyze samples/partial.bin --json
```

El generador no sobrescribe archivos existentes. Consulta [la procedencia de los fixtures](samples/README.md). No ejecutes los archivos generados.

## Qué aporta el informe didáctico

El informe legible sigue siempre el mismo orden: la muestra (hashes, tamaño, tipo y si el informe se acaba de producir o se cargó de un archivo), un **resumen de lo que contiene el código** (capacidades agrupadas por táctica y los avisos que lo limitan), **qué no se pudo analizar**, los hechos observados, las inferencias (resultados de aplicar una transformación) y el glosario de los términos usados, con sus fuentes.

- Cada frase la genera una regla determinista a partir de las evidencias que cita (`X1`, `X2`… citan `E1`, `E2`…). Antes de mostrarla, el validador la regenera desde esas citas y exige que coincida exactamente; una frase alterada no se muestra, y se dice cuántas se omitieron.
- Cada frase lleva su **límite**: lo que ese hecho no demuestra. Por ejemplo, una sección con permisos de escritura y ejecución no demuestra que se ejecute código escrito en ella.
- Las cifras de contexto están medidas. Una entropía de 7,2 o más solo la alcanza el 0,34 % de las secciones de 4 KiB o más en 55.313 binarios benignos. Los imports se agrupan en nueve familias curadas con su prevalencia benigna: por ejemplo, el 32,2 % de los binarios benignos importa alguna función de comprobación de depuradores.
- Todo texto que procede de la muestra (nombres, cadenas, textos decodificados) se neutraliza antes de mostrarse: los caracteres de control, de escape de terminal y bidi se convierten en escapes visibles, y en Markdown van en bloques de código inertes.

- Las marcas de compilador dicen con qué herramienta se hizo el archivo, solo cuando sus bytes tienen la forma exacta y están donde la herramienta los pone: por ejemplo, la cabecera Rich del enlazador de Microsoft con su checksum comprobado, o el mensaje del código de arranque de MinGW-w64, que explica por qué un programa compilado con GCC llama a `VirtualProtect`. Se midió en casi 55.000 binarios benignos, revisando a mano los casos dudosos: la firma de Go, por ejemplo, también aparece dentro de programas de Git escritos en C, y se descarta porque no está alineada como la pone Go. Una marca puede copiarse, y el informe lo dice.

- Las capacidades juntan una llamada y sus argumentos constantes en una frase como «el código contiene 1 llamada de este tipo: crear un servicio de Windows», con los casos (`servicio «X», binario «Y», inicio SERVICE_AUTO_START`). Dicen lo que el código contiene, no que el programa lo haga, y dan su frecuencia en 3.090 binarios benignos: por ejemplo, el 2,36 % contiene memoria ejecutable y escribible. Si no sabe algo (la raíz de una clave, el proceso de destino), lo dice.

Método y mediciones: [cómo trabaja LupaBin](docs/metodo.md).

## La web

`lupabin-web` sirve el mismo análisis aislado y el mismo informe didáctico en el navegador: se sube un archivo y la página muestra el resumen de capacidades, los hechos, las inferencias, la cobertura, VirusTotal y el glosario, con la descarga del informe en JSON y en Markdown. No guarda ni la muestra ni el informe, y aplica límites de tamaño y de análisis por IP. Todo texto de la muestra se neutraliza en el servidor y la página lo inserta solo como texto.

Para probarla en tu equipo (con Docker y la imagen construida):

```text
uv sync --extra web
uv run lupabin-web
```

y abre `http://127.0.0.1:8080`. Para desplegarla en un servidor (Oracle Cloud Free Tier, Hetzner u otro VPS, en x86_64 o ARM64), con HTTPS gratuito mediante un dominio de DuckDNS, sigue [la guía](docs/deploy.md). Usa un servidor dedicado: el servicio controla Docker.

## Qué aporta VirusTotal (activo por defecto, desactivable)

Con una clave de API en la variable de entorno `VT_API_KEY`, o en un archivo `.env` en la carpeta desde la que lo ejecutas (`VT_API_KEY=...`, ignorado por git y excluido de la imagen Docker y del paquete), LupaBin añade por defecto los resultados de VirusTotal como **fuente externa, no verificada por LupaBin**: cuántos motores antivirus marcan el archivo y con qué etiqueta, veredictos de sus sandboxes y el comportamiento que observaron al ejecutarlo allí (procesos, comandos, archivos, registro, red, mutex, servicios y técnicas MITRE ATT&CK).

```text
uv run --frozen lupabin analyze "ruta/al/archivo.exe"
uv run --frozen lupabin analyze "ruta/al/archivo.exe" --no-virustotal
uv run --frozen lupabin virustotal --sha256 <sha256> --format json
```

- `analyze` y `explain` consultan VirusTotal sin opciones. No lo hacen con `--no-virustotal`, con la variable `LUPABIN_VIRUSTOTAL=off` ni con `--json`, que emite el informe de hechos; el documento de VirusTotal se obtiene con `lupabin virustotal --format json`. Sin clave, la sección explica cómo configurarla y no se conecta a nada; sin red, dice por qué no hay datos. En los dos casos el análisis local no cambia.

- Primero se consulta solo el SHA-256. Si VirusTotal no conoce el archivo, **LupaBin lo sube automáticamente**, con el nombre genérico `sample`, y espera su análisis hasta 3 minutos. Según su documentación, el contenido subido puede compartirse con sus clientes de pago: para archivos internos o confidenciales usa `--no-upload-to-virustotal`, o `LUPABIN_VIRUSTOTAL_UPLOAD=off` para no subir nunca.
- Todo ocurre en el host: el worker sigue sin red. Una etiqueta es la opinión de un motor, y el comportamiento se observó en los sandboxes de VirusTotal, no en tu equipo. "VirusTotal no conoce este archivo" no dice nada sobre su peligrosidad.
- La API pública admite 500 consultas al día y 4 por minuto, y no puede usarse en productos o servicios comerciales.

Más detalle: [VirusTotal](docs/metodo.md#virustotal).

## Salida y abstención

La salida `--json` es un informe JSON validado con hashes SHA-256/MD5, tamaño, tipo validado, evidencias `E1`, `E2`, etc., estados de extractor, cobertura y errores. Los nombres se conservan en hexadecimal; solo se añade texto si decodifica estrictamente. Los imports por ordinal no se convierten en nombres supuestos.

- `completed`: las cinco fuentes (`pe`, `strings`, `yara`, `decode` y `code`) completaron su cobertura declarada; no es un veredicto de seguridad.
- `partial`: una parte se revisó, pero existen componentes bloqueados, errores u omisiones. Puede no haber hallazgos.
- `failed`: las cinco fuentes quedaron bloqueadas, o la infraestructura no pudo producir un informe validado.

La cobertura está en `extractor_runs[].components`, con contadores y estados `complete`, `partial` o `blocked`. `extractor_errors` describe fallos; `limitations` describe cuotas, truncamientos explícitos y warnings. Cero resultados con cobertura completa no equivale a un error ni demuestra seguridad.

Un archivo cuyo PE no pueda interpretarse puede conservar cadenas literales y seguir clasificado como `unknown`; el resultado global será parcial. El barrido reconoce el repertorio ASCII imprimible, directamente y codificado en UTF-16LE, con mínimo de cuatro caracteres. No recupera todo Unicode ni cadenas ofuscadas. Los prefijos acotados llevan `complete=false` y nunca incluyen puntos suspensivos inventados. Una secuencia imprimible puede ser incidental o cruzar campos binarios: no se presume que sea texto intencional del programa.

Códigos de salida: 0 completo, 3 parcial, 1 fallo, 2 uso incorrecto. Los errores anteriores al informe se emiten como JSON en stderr, sin rutas locales ni traceback. Las evidencias vacías deben interpretarse junto con `extractor_runs` y `extractor_errors`.

Los límites predeterminados son 20 MiB de entrada, 30 segundos de worker, 512 MiB de memoria, 1 CPU, 64 procesos, 8 MiB de salida y 10.000 imports. La preparación y limpieza del contenedor tienen límites adicionales propios. Si no se puede confirmar la limpieza, la CLI lo comunica; no debe asumirse que el contenedor desapareció.

También se acotan secciones (96), entradas EAT (5.000), asociaciones de nombres exportados (10.000), cadenas (5.000 y 1.024 caracteres por prefijo), anomalías (128) y bytes acumulados de entropía (20 MiB). Se reserva espacio de salida para explicar las omisiones. Las cuotas efectivas aparecen en el JSON.

Ante un mapa de regiones ambiguo se bloquean las lecturas que dependan de él, sin borrar las cabeceras y descriptores comprobados. Los warnings de pefile impiden declarar una extracción completa. El determinismo aplica a hechos, orden e IDs con versiones/configuración equivalentes; no a timestamps ni a ejecuciones interrumpidas por límites.

La CLI 0.9.0 exige el esquema 0.9.0 y un catálogo compatible del worker; una discrepancia produce `incompatible_worker`. Los esquemas 0.1.0 a 0.8.0 se conservan en `docs/schemas/`, pero no hay conversión automática de informes. Los IDs pueden cambiar entre versiones.

Si aparece `image_unavailable`, la CLI no pudo verificar la imagen, lo que no demuestra por sí solo que haya sido borrada. Comprueba en la misma terminal `docker context show` y `docker image inspect --format '{{.Id}}' lupabin-worker:0.9.0`; construye la imagen con `--load` en ese contexto si no está disponible. No se cambia el contexto ni se descarga una imagen durante el análisis.

## Qué aporta YARA

El catálogo propio incluye cuatro reglas: texto del stub DOS, presencia conjunta de tres nombres de APIs, marcadores `RSDS`/`.pdb` y el marcador sintético `LUPABIN PRACTICE`. Ninguna identifica una familia ni prueba ejecución, imports, inyección o actividad de red.

Cada `yara_match` contiene regla, namespace, revisión, hashes de fuente/conjunto, versiones observadas e instancias con offsets y bytes originales. Su `location` global es nula porque una regla puede depender de varios intervalos; consulta `data.instances`. `yara_context` identifica el catálogo incluso cuando no hay coincidencias.

El motor nativo corre en un hijo dentro del worker. Usa solo el buffer recibido, sin rutas, PIDs ni reglas externas. Los límites iniciales son 5 segundos de matching, 10 segundos de proceso, 32 reglas publicadas, 16 instancias por regla y 256 bytes por instancia. Los bytes o apariciones omitidos se marcan como parciales. Un timeout, warning nativo o respuesta inválida descarta los matches YARA, conservando PE/strings cuando el padre sigue operativo.

Para probar representación limitada con datos sintéticos:

```text
uv run python -m tests.fixtures.pe_builder --scenario yara-limited --output samples/yara-limited.bin
uv run --frozen lupabin analyze samples/yara-limited.bin --json
```

El fixture contiene veinte apariciones ASCII del marcador. Con los límites predeterminados el informe debe conservar dieciséis e indicar cuatro omitidas, con salida 3. `--scenario demo` ofrece un positivo y `--scenario basic` un caso sin coincidencias de este catálogo. No ejecutes ninguno como programa.

## Qué aporta la decodificación

Cada `decoded_string` dice exactamente esto: "estos bytes, transformados con este algoritmo y estos parámetros, producen este texto". Es siempre `confidence: "inferred"`. No afirma que el programa realice la transformación, que el texto sea el que pretendía su autor ni que tenga significado (una URL decodificada no prueba una conexión).

- **Base64 y hexadecimal** (`component: decode_strings`): sobre las cadenas ya extraídas, con validación estricta (Base64 canónico de al menos 12 caracteres si lleva relleno `=` o 16 si no; hexadecimal que no sea solo dígitos decimales, porque un número como `2147483647` también es hexadecimal válido; el texto resultante debe ser imprimible y tener al menos 4 caracteres distintos). Citan en `provenance` la cadena que contiene los bytes codificados.
- **XOR de clave repetida de 1 a 8 bytes** (`component: decode_xor`): sobre los bytes crudos, anclado en un catálogo versionado de cadenas de referencia (`anchor`, p. ej. `http://`, `kernel32.dll`, `\Registry\Machine\`; 62 en la versión 3). La clave no se elige entre candidatas: se deriva de los bytes y se publica en `transform.key_hex`, alineada con el inicio de `location`. Cualquiera puede comprobarla: `texto[i] = bytes[inicio + i] XOR clave[i mod longitud]`. Si una cadena usa una clave ya verificada en otro punto de la muestra (lo habitual en tablas de cadenas cifradas), también se descifra aunque su ancla sea corta, y cita en `provenance` la decodificación que estableció la clave.

Límites honestos del método, medidos sobre más de 30.000 archivos benignos de Windows y programas instalados (0 decodificaciones espurias; todas las encontradas eran ofuscación real y se revisaron a mano) y documentados en [el método](docs/metodo.md#decodificación):

- Un texto cifrado que **no contenga ninguna cadena del catálogo no se encuentra**.
- Si la clave deja el texto cifrado todavía legible (claves pequeñas, típicamente `< 0x20`), **no se publica**: sin puntuar plausibilidad es indistinguible de texto normal. Esos bytes siguen visibles como `string`.
- Una ancla corta solo verifica por sí sola claves cortas (`http://`, 7 bytes, nunca una clave de 8). Con claves de 8 bytes la cobertura medida es del 37 % para una cadena aislada y del 92 % cuando otra cadena de la muestra comparte la clave (el techo alcanzable en el conjunto de prueba es del 86 %: el resto no contiene ninguna ancla).
- No hay desempaquetado, compresión, RC4, XOR rodante ni emulación.

El host no confía en el worker: vuelve a derivar cada decodificación desde los bytes originales y rechaza la respuesta si alguna no se reproduce. Una muestra con millones de patrones candidatos termina como limitación declarada (`decode_xor_examined_limit`), no como timeout.

```text
uv run python -m tests.fixtures.pe_builder --scenario decode-demo --output samples/decode-demo.bin
uv run --frozen lupabin analyze samples/decode-demo.bin --json
```

El fixture contiene un Base64, un hexadecimal y cuatro textos cifrados con XOR (clave de 1 byte, de 4 bytes, una cadena UTF-16LE y una URL que reutiliza la clave de 4 bytes) sobre el dominio reservado `.invalid`. El informe debe mostrar seis `decoded_string` y estado completo; la URL cita en `provenance` la decodificación que estableció su clave.

## Arquitectura

```text
CLI -> lectura acotada + hashes -> Docker sin red
    -> PE (cabeceras, secciones, entropía, imports, exports, anomalías)
    -> cadenas literales independientes -> hijo YARA con catálogo propio
    -> decodificación: Base64/hex sobre cadenas, XOR anclado sobre bytes
    -> código x86/x64: llamadas a imports, argumentos constantes y rangos de .pdata
    -> presupuesto y modelos Pydantic
    -> validación de respuesta y reverificación de bytes en el host -> JSON
    -> explicaciones deterministas (host) + glosario con fuentes
    -> validación por regeneración -> texto / Markdown con texto de la muestra neutralizado
```

- [Contrato de evidencias](docs/evidence-schema.md).
- [Cómo trabaja LupaBin: método y límites medidos](docs/metodo.md).
- [JSON Schema generado](docs/evidence-schema.json) y [el de las explicaciones](docs/explanation-schema.json).
- [Despliegue de la web](docs/deploy.md).

El JSON Schema valida la forma; Pydantic añade invariantes entre campos, referencias y estados. Una cita existente no demuestra por sí sola la veracidad de una afirmación.

## Desarrollo y verificación

```text
uv run --frozen ruff format --check .
uv run --frozen ruff check .
uv run --frozen mypy src
uv run --frozen pytest -m "not docker"
uv run --frozen python -m lupabin.evidence.schema --check
uv run --frozen python -m lupabin.explain.schema --check
uv build
uv run --frozen python -m tests.check_yara_distribution
docker compose config --quiet
docker build --load -f docker/Dockerfile -t lupabin-worker:0.9.0 .
uv run --frozen pytest -m docker
```

Las pruebas Docker fallan si se solicitan sin motor o imagen; no se omiten silenciosamente. La suite ordinaria excluye explícitamente ese marcador. `docker compose build worker` es una alternativa de build; el servicio Compose es el worker de consola. La web se sirve con `lupabin-web` (ver más arriba).

Para actualizar los esquemas tras cambiar los modelos: `uv run python -m lupabin.evidence.schema` y `uv run python -m lupabin.explain.schema`. No editar manualmente el JSON generado. `uv run python -m tests.check_glossary_sources` comprueba con red que las fuentes del glosario y sus anclas siguen existiendo; no forma parte de la CI.

Para repetir las mediciones sobre un directorio de binarios benignos propio (solo se leen como bytes; no forma parte de la CI; ver [el método](docs/metodo.md#repetir-las-mediciones)):

```text
uv run python -m tests.decode_eval false-positives <directorio>
uv run python -m tests.decode_eval recall <directorio>
uv run python -m tests.decode_eval timing
```

## Contribuir y licencia

Lee [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) y el [código de conducta](CODE_OF_CONDUCT.md). Solo se admiten fixtures sintéticos e inofensivos. LupaBin es obra de Miguel Ángel Rodríguez Romero y se distribuye con la licencia [Apache-2.0](LICENSE): puedes usarlo, modificarlo, hacer fork y comercializarlo, siempre que conserves el archivo [NOTICE](NOTICE) y nombres al autor (*"Basado en LupaBin, de Miguel Ángel Rodríguez Romero"*). El nombre y el logo están reservados ([TRADEMARKS.md](TRADEMARKS.md)), y las contribuciones requieren aceptar el [acuerdo de contribución](CLA.md). Las dependencias conservan sus licencias.
