# Dissect: contrato de evidencias

## Contrato activo 0.5.0

La Fase 4 añade al contrato 0.4.0 una quinta fuente, `code`, con el tipo `api_call` (primera entrega: qué funciones importadas llama el código y desde dónde) y el tipo `call_argument` (segunda entrega: argumentos constantes de las llamadas a las funciones del catálogo). La versión 0.5.0 no se había publicado cuando se añadió `call_argument`, así que ambos forman parte de ella, como preveía la sección 5 del diseño. La CLI, el paquete y la imagen esperada usan 0.5.0; el esquema 0.4.0 se conserva en `docs/schemas/`. Diseño, mediciones y límites: [Fase 4](superpowers/specs/2026-09-23-static-api-calls-design.md).

Cambio en un tipo existente: `import` gana `iat_rva`, la dirección de su casilla en la tabla de direcciones de import (IAT), que es adonde apuntan las llamadas. `location` sigue siendo la entrada de la tabla de búsqueda que contiene el nombre u ordinal.

`api_call` es `observed`: afirma que en esos bytes hay una instrucción, alcanzada por el recorrido del código, que llama a la casilla de ese import. No afirma que se ejecute. Campos:

| Campo | Contenido |
| --- | --- |
| `component` | `api_calls`. |
| `location` | La instrucción de llamada: `offset`, `rva`, `length` y `section`, que debe ser la única sección ejecutable que contiene esos bytes en disco. |
| `data.via` | `direct` (`call [casilla]`), `thunk` (`call rel32` a un `jmp [casilla]`) o `register` (`mov reg, [casilla]` inmediatamente antes de `call reg`). |
| `data.raw_hex` | Los bytes de la instrucción de llamada. |
| `data.helper` | Solo `thunk` y `register`: el `jmp` del thunk o la carga del registro, con `offset`, `rva` y `raw_hex`. |
| `provenance.evidence_ids` | Exactamente el `import` al que llama. |

**Verificación en el propio informe.** Sin la muestra, el modelo ya vuelve a derivar la casilla desde los bytes citados con las formas canónicas de `src/dissect/evidence/call_forms.py` y exige que sea el `iat_rva` del import citado. En x86 la dirección es absoluta (menos la base de imagen de la cabecera); en x64, relativa a la instrucción siguiente. En un thunk, el destino del `call` debe ser el `jmp` citado; en la vía por registro, la carga debe terminar justo donde empieza la llamada y usar el mismo registro. También comprueba que cada `offset` corresponde a su `rva` según la tabla de secciones.

**Verificación en el host.** El launcher y `dissect explain --sample` comparan los bytes de cada instrucción citada con los de la muestra. El host no lleva desensamblador: una prueba comprueba que ni la CLI ni el runner cargan capstone. Lo que ninguna comprobación puede demostrar es que el recorrido llegó a esa instrucción (y no a unos bytes que solo lo parecen). Eso es una regla del worker, probada con casos negativos y medida en binarios benignos.

`call_argument` (entrega 2) es `inferred`: afirma que una instrucción del mismo tramo lineal que la llamada, anterior a ella, fija ese argumento a una constante, y que el recorrido no vio nada que lo cambie antes de la llamada. Solo se publica para las funciones del catálogo `dissect-api-semantics-v1` (`src/dissect/evidence/api_catalog.py`; por ahora `RegOpenKeyExA/W`, importadas de una DLL que Microsoft Learn declara como exportadora) y solo si el valor es del tipo del parámetro. Campos:

| Campo | Contenido |
| --- | --- |
| `component` | `call_arguments`. |
| `location` | La instrucción que fija el argumento, en la misma sección ejecutable que la llamada y antes de ella. |
| `data.catalog`, `data.method` | `dissect-api-semantics-v1` y `block-constant-v1`. |
| `data.position`, `data.name`, `data.type` | Posición (desde 0), nombre y tipo del parámetro según el catálogo: `hkey`, `string` o `integer`. |
| `data.value` | `hkey`: el valor tal como se fija (en x64, extendido con signo: `0xffffffff80000001`). `integer`: módulo el ancho del parámetro (32 bits para `REGSAM`). `string`: el puntero tal como se fija (dirección absoluta en x86, RVA de un `lea` relativo a rip en x64). |
| `data.raw_hex` | Los bytes de la instrucción que lo fija: `lea r64, [rip+disp32]`, `mov r32, imm32`, `mov r64, simm32` o `xor r32, r32` en x64; `push imm32` o `push imm8` en x86 (`src/dissect/evidence/argument_forms.py`). |
| `data.constant` | Solo `hkey`: el nombre de la clave predefinida. Se aceptan las cinco que Learn lista para `hKey` (`HKEY_CLASSES_ROOT`, `HKEY_CURRENT_USER`, `HKEY_LOCAL_MACHINE`, `HKEY_USERS`, `HKEY_CURRENT_CONFIG`). |
| `data.string` | Solo `string`: `offset`, `rva`, `raw_hex` (texto más su terminador NUL) y `text` imprimible ASCII, en una sección que no se puede escribir: el programa podría cambiar una cadena escribible antes de la llamada. |
| `provenance.evidence_ids` | Exactamente el `api_call` al que pertenece. |

**Verificación.** El modelo vuelve a derivar el valor desde `raw_hex` con las formas canónicas, exige que en x64 el registro fijado sea el del parámetro, que la clave sea una de las aceptadas, que el entero coincida, que el puntero lleve exactamente a la cadena citada y que la cadena decodifique sus bytes con su terminador. También exige que la función llamada y el parámetro estén en el catálogo, y que no haya dos valores para el mismo argumento de una llamada. El host compara además con la muestra los bytes de la instrucción y de la cadena. Lo que no puede comprobar sin desensamblar es que ninguna instrucción intermedia cambie el valor, ni que otro camino no entre en medio. Por eso el hecho es `inferred`, y el método es una regla del worker probada con casos negativos (`tests/test_code_args.py`).

Componentes y limitaciones de `code`:

| Componente | Revisa | Limitaciones propias |
| --- | --- | --- |
| `disassembly` | Instrucciones decodificadas por descenso recursivo en secciones ejecutables (`examined`) | `code_instruction_limit` (8.000.000), `call_site_limit` (1.048.576 llamadas examinadas), `code_entry_limit` (262.144 puntos de partida), `code_time_limit` (el análisis lleva 15 s, o la mitad de `timeout_seconds`) |
| `api_calls` | Instrucciones `call` examinadas (`examined`) | Las del recorrido, más `api_call_limit` (4.096 publicadas) y `dependency_omitted` si la tabla de imports no se leyó completa |
| `call_arguments` | Llamadas publicadas a funciones del catálogo cuyo tramo se examinó (`examined`) | `argument_instruction_limit` (65.536 instrucciones en modo detallado, en total), `code_time_limit` (la misma marca que el recorrido), `call_argument_limit` (4.096 publicados) y `dependency_omitted` si `api_calls` no es completo |

Los puntos de partida del recorrido son el punto de entrada, los exports y tablas que escribe el compilador o el enlazador: callbacks TLS, `.pdata` (x64), la tabla de funciones de Control Flow Guard y los manejadores SafeSEH (x86). Ninguno se adivina.

**Límites de tiempo.** La búsqueda XOR y el recorrido del código se detienen al llegar a su marca de tiempo, contada desde el inicio del análisis (`analysis.limits.decode.seconds` y `analysis.limits.code.seconds`), y lo declaran con su código. Así una máquina lenta o una entrada diseñada contra ellos deja el informe parcial en vez de agotar el tiempo del worker y perderlo entero. Consecuencia: en una máquina más lenta, el mismo archivo puede dar un resultado parcial distinto. Lo publicado sigue siendo cierto, pero ya no es idéntico entre máquinas cuando aparece uno de estos códigos.

`api_calls` solo puede ser completo si también lo son `disassembly` y los dos componentes de imports, y `call_arguments` solo si lo es `api_calls`. Un argumento ausente con cobertura completa significa que ninguna instrucción del tramo lo fija con una forma canónica, no que no tenga valor. Con la cuota agotada, se publica primero la primera llamada de cada import y después las repetidas, para cubrir el máximo de funciones distintas. Arquitecturas distintas de x86/x64 bloquean la fuente (`unsupported_architecture`), igual que las correspondencias ambiguas entre memoria y archivo (`unsafe_mapping`) y las entradas que no son PE. Cero llamadas con cobertura completa no demuestra que el programa no llame a nada: el código al que solo se llega por saltos indirectos no se recorre.

## Antecedente: contrato 0.4.0

La Fase 2 añadió al contrato 0.3.0 una cuarta fuente, `decode`, y el tipo `decoded_string`. Su esquema histórico está en `docs/schemas/0.4.0.json`; sus reglas siguen vigentes en 0.5.0. Diseño, mediciones y límites: [Fase 2](superpowers/specs/2026-09-22-static-decoding-design.md).

`decoded_string` es la única evidencia con `confidence="inferred"`: afirma que unos bytes, transformados con un algoritmo y unos parámetros exactos, producen un texto. No afirma que el programa realice la transformación ni que el texto tenga significado. Campos:

| Campo | Contenido |
| --- | --- |
| `component` | `decode_strings` (Base64/hex) o `decode_xor`. |
| `location` | Dónde están los bytes codificados. Para Base64/hex coincide con la cadena fuente; para XOR es la región cifrada, de la misma longitud que el texto resultante. |
| `transform` | `base64-strict-v1`, `hex-strict-v1` o `xor-repeating-v1`; solo XOR lleva `key_hex` (1–8 bytes, en su periodo mínimo, no nula, alineada con el inicio de `location`). |
| `anchor` | Solo XOR: catálogo `dissect-xor-cribs-v3`, cadena de referencia y su desplazamiento en caracteres dentro del texto. |
| `provenance.evidence_ids` | Base64/hex: exactamente la cadena fuente. XOR: vacío si la propia ancla verificó la clave; o la única decodificación XOR, verificada por sí misma, que estableció esa misma clave en otro punto de la muestra (reutilización de clave: permite descifrar anclas demasiado cortas para verificar una clave larga por sí solas). |
| `data` | Mismas reglas de fidelidad que `string`: `text`, `raw_hex` del texto resultante, `characters`, `complete`. |

El modelo rechaza combinaciones incoherentes: XOR sin ancla o con más de una cita, una clave reutilizada que no cite una decodificación XOR autoverificada con la misma clave, Base64/hex con clave o ancla, una cita que no sea la cadena ubicada en los mismos bytes, una ancla que no aparece en su desplazamiento, claves nulas o no canónicas, regiones fuera de la muestra y cuotas superadas por componente.

**Reverificación en el host.** El launcher vuelve a derivar cada `decoded_string` desde el buffer original: Base64/hex desde los bytes de la cadena citada; XOR aplicando la clave a la región, comprobando que la ancla pertenece al catálogo, que su ventana no era ya texto, que la ancla puede verificar ese periodo de clave (o, si la clave es reutilizada, que la decodificación citada tiene la misma clave y se reproduce a su vez) y que un texto declarado completo no continúa más allá de sus límites. Una evidencia que no se reproduce invalida toda la respuesta (`invalid_worker_output`).

Componentes y limitaciones de `decode`:

| Componente | Revisa | Limitaciones propias |
| --- | --- | --- |
| `decode_strings` | Todas las cadenas extraídas y completas | `decode_strings_limit` (2.000 resultados) |
| `decode_xor` | Todas las apariciones de los patrones del catálogo en los bytes | `decode_xor_limit` (256 resultados), `decode_xor_examined_limit` (200.000 apariciones examinadas), `decoded_length_limit` (texto recortado a 1.024 caracteres), `decode_time_limit` (desde 0.5.0: el análisis lleva 10 s, o un tercio de `timeout_seconds`) |

Los límites efectivos aparecen en `analysis.limits.decode`. Cero decodificaciones con cobertura completa es el caso habitual y no significa nada sobre la muestra. El estado global considera las cuatro fuentes con la regla existente.

## Antecedente: contrato 0.3.0

La Fase 1B añadió YARA al contrato 0.2.0. Su esquema histórico está en `docs/schemas/0.3.0.json`. Esta sección describe esa entrega; sus reglas sobre YARA siguen vigentes en 0.4.0.

El informe incluye las fuentes `pe`, `strings`, `yara` y un `yara_context` tipado con catálogo, hashes de las fuentes y versiones realmente observadas. Una versión nativa que no se pudo obtener queda nula; no se sustituye por la versión esperada. El catálogo propio se distribuye como recurso del paquete y no depende del cwd.

`yara_match` conserva identidad, revisión, licencia y descripción editorial de la regla, digest del catálogo, versiones e instancias de patrones. `location` es nulo exclusivamente para este tipo: los intervalos están en `data.instances`, con `offset`, `matched_length`, `captured_length`, `raw_hex` y `complete`. El padre valida esos bytes contra el buffer original. Las descripciones no son afirmaciones de comportamiento.

Los componentes YARA son `yara_rules`, `yara_scan` y `yara_evidence`. `examined` puede ser nulo en componentes YARA incompletos cuando no hay un total conocido. Una cobertura completa debe concordar con el inventario y los resultados conservados. No se admiten matches de un escaneo interrumpido ni una cobertura completa con instancias recortadas. Los otros tipos conservan sus requisitos de ubicación y contadores.

YARA corre en un subproceso dentro del contenedor. Si falla o se interrumpe, no publica coincidencias; se conservan PE/strings si el padre sigue operativo. Si el scan termina pero la representación se acota, las omisiones se declaran en `limitations`, `instances_status` y `omitted_instances`. Cero coincidencias con cobertura completa no es un veredicto de seguridad.

En 0.3.0 el estado global consideraba tres fuentes: completo si todas completan, fallido si todas quedan bloqueadas y parcial en los demás casos. Los límites exteriores no se amplían. El diseño aprobado y el plan están en [Fase 1B](superpowers/specs/2026-09-20-yara-evidence-design.md).

## Antecedente: contrato 0.2.0

La Fase 1A amplió el contrato inicial. Su esquema histórico está en `docs/schemas/0.2.0.json`, junto al de 0.1.0. Esta subsección describe la CLI y la imagen de aquella entrega, no las versiones activas.

El diseño y los límites completos están en [Fase 1A](superpowers/specs/2026-09-20-static-evidence-design.md). El resto de este documento conserva el diseño histórico de la primera entrega; sus campos y reglas 0.1.0 no sustituyen los de esta sección.

| Campo | Contrato 0.2.0 (histórico) |
| --- | --- |
| `schema_version` | Literal `0.2.0`; versiones distintas se rechazan. |
| `sample` | Hashes, tamaño y tipo reconocido (`PE32`, `PE32+`, `unknown`), sin ruta local. |
| `analysis` | Versión, timestamps del análisis, límites efectivos y estado global. |
| `evidence` | Unión discriminada por `kind`: `import`, `pe_header`, `section`, `entropy`, `export`, `string`, `header_anomaly`. |
| `extractor_runs` | Fuentes `pe`/`strings`, versión y componentes tipados con cobertura y contadores. |
| `extractor_errors` | Motivos de fallo, con fuente, componente y código estable. |
| `limitations` | Cuotas, omisiones, prefijos acotados y warnings, separados de los fallos. |

Cada evidencia tiene `id`, `source`, `component`, `kind`, payload tipado, intervalo real `location`, `confidence=observed` y referencias de procedencia. Las direcciones meramente declaradas se guardan en el payload, no como offsets comprobados. Los IDs son locales al informe y pueden cambiar entre versiones.

Las entropías indican método, bytes medidos y sección de origen. El modelo verifica que sus intervalos coincidan; los tests verifican los cálculos. Las anomalías deben estar respaldadas por los valores de las cabeceras/secciones que citan, no solo por IDs existentes. Los exports conservan símbolos, nombres/ordinales y forwarders sin resolver DLLs. Las strings conservan el texto exacto y bytes, con repertorio ASCII imprimible explícito para ASCII/UTF-16LE.

La cobertura de un componente es `complete`, `partial` o `blocked`. Un extractor completado puede tener cero hallazgos. El estado global es `completed` si ambos completan, `failed` si ambos quedan bloqueados y `partial` en los otros casos. Si falla la infraestructura antes de validar un informe, se emite un error separado; no se fabrica un informe. El análisis de bytes literales puede conservar resultados aunque falle PE, sin afirmar soporte de su formato.

Un `completed` no es un veredicto de seguridad. El timestamp de cabecera es un entero declarado, no fecha de compilación acreditada; la entropía no demuestra empaquetado y una URL no demuestra una conexión. El JSON Schema comprueba estructura; las relaciones entre hechos también se validan mediante Pydantic. Ninguna de estas comprobaciones garantiza veracidad absoluta ante un parser comprometido.

## Diseño histórico de la primera entrega (0.1.0)

Estado histórico: diseño y plan aprobados por el usuario el 20 de septiembre de 2026. Las secciones siguientes se conservan como antecedentes; consultar arriba el contrato activo.

## Objetivo y alcance

Dissect es un tutor defensivo de análisis estático de binarios. Su prioridad es enseñar con información verificable, no producir el mayor número de hallazgos. Está dirigido a estudiantes, docentes y analistas junior. El proyecto usará licencia Apache-2.0.

La primera entrega comprende el andamiaje, el esquema de evidencias y `dissect analyze <archivo> --json`: hashes SHA-256/MD5, tamaño, clasificación PE validada y evidencias de imports. Incluye documentación inicial, pruebas sintéticas, configuración de calidad, Docker endurecido y workflow de CI.

No incluye todavía web, LLM, VirusTotal, capa, YARA, FLOSS, decodificadores, desempaquetado ni informes didácticos completos. Preparar interfaces para estas funciones no significa implementarlas en esta entrega.

## Regla principal: no inventar datos

1. Ningún dato de análisis se publica sin una fuente identificable y trazable.
2. Un fallo, límite o formato no soportado se comunica como análisis incompleto o imposibilidad de determinar el dato. Nunca se sustituye por un valor plausible.
3. Una lista de hallazgos vacía no demuestra ausencia de comportamiento malicioso. Hay que mostrar el estado y la cobertura del extractor.
4. Las observaciones y las inferencias son categorías distintas. No se promoverá una hipótesis a hecho por su plausibilidad, por repetición o por una respuesta del LLM.
5. Una importación demuestra la presencia de una entrada en una tabla, no que una función se ejecute ni que se use con fines maliciosos.
6. Las citas existentes son una condición necesaria, no suficiente: una afirmación también debe estar respaldada por el contenido citado. Un verificador de IDs no garantiza veracidad semántica.
7. En futuras explicaciones, las afirmaciones sobre la muestra procederán de hechos estructurados y reglas deterministas verificables. La redacción libre del LLM no se considerará una fuente. Si no se puede validar una afirmación, se omitirá y se usará la explicación determinista o una abstención explícita.
8. El conocimiento general del glosario se distinguirá de los hechos de la muestra y tendrá fuentes editoriales. Las cadenas de la muestra son datos no fiables, nunca instrucciones para un LLM.
9. No se asignarán probabilidades, puntuaciones de riesgo ni etiquetas de malware sin un método definido y evidencia suficiente.

La abstención no es un error del producto: es un resultado válido y preferible a una afirmación falsa. No se promete una garantía matemática de ausencia de errores; se exige trazabilidad, validación, pruebas negativas y comunicación de límites.

## Arquitectura de la primera entrega

Flujo: CLI -> lectura acotada de bytes y hashes -> worker aislado -> clasificación y extracción PE -> validación y asignación de IDs -> JSON.

- `ingest`: lee una entrada regular con límite efectivo durante la lectura, calcula hashes sobre los mismos bytes que se analizan y rechaza entradas inválidas. No incluye rutas locales en el resultado.
- `extractors`: interfaz independiente; extractor PE basado en `pefile`, sin cargar ni ejecutar el binario. Los resultados del extractor no asignan IDs globales ni dependen del reloj.
- `evidence`: modelos Pydantic v2, payloads discriminados por `kind`, validaciones entre campos y exportación de JSON Schema.
- `runner`: controla aislamiento, límites y timeout; trata la salida del worker como entrada no fiable y la valida.
- `cli`: Typer; JSON en stdout y diagnósticos sanitizados en stderr. No mezcla mensajes de progreso con JSON.

Se usará Python 3.12 con uv y dependencias fijadas en lockfile. El núcleo tendrá mypy estricto. La extracción de imports no incorporará LIEF, FLOSS ni otras dependencias pesadas.

### Alternativas consideradas

- Parser en el proceso de la CLI: simple, pero no proporciona el aislamiento exigido para muestras no fiables. Descartado como ruta normal de análisis.
- Worker en contenedor con núcleo modular: recomendado; separa la superficie de ataque y permite probar el núcleo con fixtures sintéticos.
- API, cola y workers desde el inicio: añade complejidad fuera de esta entrega. Pospuesto.

## Aislamiento y límites

La ruta pública de análisis ejecutará el parser en un contenedor Linux, no directamente en el host. Si Docker o la imagen no están disponibles, se comunicará el problema; no habrá fallback silencioso a un parser sin aislamiento. Las pruebas unitarias podrán invocar el núcleo directamente sobre fixtures sintéticos.

El worker no tendrá red, capacidades Linux adicionales, privilegios de root, socket Docker ni montajes del host. Recibirá bytes por stdin y emitirá una respuesta acotada por stdout. El sistema de archivos raíz será de solo lectura; cualquier espacio temporal necesario será acotado. La imagen no contendrá muestras reales ni credenciales.

Límites iniciales propuestos: entrada de 20 MiB, 30 segundos de análisis, 512 MiB de memoria, 1 CPU, 64 procesos y respuesta de 8 MiB. El número de imports estará limitado a 10.000. Si se alcanza un límite, se registrará explícitamente que el resultado no está completo. El timeout debe detener y limpiar el contenedor, no solo el cliente Docker.

Los límites efectivos se incluirán en los metadatos. Estos controles reducen el riesgo; no convierten Docker ni los parsers en una garantía de seguridad absoluta.

El Dockerfile define la imagen; los límites de ejecución y la ausencia de red se aplican en el launcher y la configuración de Compose. El servicio web de `docker compose up` pertenece a una fase posterior; esta entrega proporciona el worker CLI y su configuración endurecida.

## Contrato del informe: versión 0.1.0

El esquema se generará desde los modelos, no se mantendrá una segunda definición manual. El archivo previsto es `docs/evidence-schema.json`.

### Campos principales

| Campo | Contenido |
| --- | --- |
| `schema_version` | Versión explícita del contrato, inicialmente `0.1.0`. |
| `analysis` | Versión de Dissect, inicio/fin UTC, estado global y límites efectivos. |
| `sample` | SHA-256, MD5, tamaño y tipo validado o `unknown`; nunca ruta local. |
| `evidence` | Evidencias tipadas con IDs únicos dentro del informe. |
| `extractor_runs` | Extractor, versión, configuración relevante, estado y cobertura. |
| `extractor_errors` | Errores sanitizados, estructurados y atribuibles a un extractor. |

SHA-256 identifica los bytes analizados. MD5 se incluye únicamente para interoperabilidad, no como garantía criptográfica de integridad.

Los estados globales son `completed`, `partial` y `failed`. `completed` significa que finalizaron las operaciones solicitadas, no que se haya demostrado seguridad ni comprendido todo el programa. Los estados de extractor son `completed`, `partial`, `failed` y `not_applicable`.

El análisis no requiere red; la imagen debe estar construida o provisionada de antemano y el launcher no intentará descargarla durante el análisis. La ausencia de Docker o de la imagen, y los fallos anteriores a la lectura completa, producen un diagnóstico estructurado y una salida no exitosa; no se fabrica un informe con hashes vacíos o datos parciales presentados como completos.

### Evidencia

| Campo | Regla |
| --- | --- |
| `id` | Patrón `E[1-9][0-9]*`, único en el informe. |
| `kind` | Discriminador de un payload tipado; inicialmente `import`. |
| `source` | Extractor que produjo la evidencia, enlazado con `extractor_runs`. |
| `data` | Payload correspondiente a `kind`; se rechazan campos extra. |
| `location` | Offset, RVA y sección cuando se conocen; no inventar equivalencias. |
| `confidence` | `observed` o `inferred`; no es una probabilidad. |
| `provenance` | Referencias a evidencias de origen y transformación cuando existan. |

Los offsets y RVA serán enteros no negativos. Una dirección virtual no se etiquetará como RVA; las conversiones deberán usar la base de imagen validada. Un offset publicado debe estar dentro de los bytes originales. No se rellenarán ubicaciones desconocidas con cero.

La procedencia derivada tendrá un modelo explícito: evidencias de origen, nombre y versión de la transformación, parámetros tipados y región de entrada. El modelo inicial admitirá esa relación, pero no aceptará transformaciones arbitrarias o plugins no implementados como si ya estuvieran soportados. Las referencias deberán existir, no podrán autorreferenciarse ni formar ciclos.

Los tipos futuros (`string`, `section`, `capability`, `yara_match`, `header_anomaly`) se introducirán con sus propios payloads y pruebas, no con un diccionario genérico de valores sin validar.

### Payload `import`

- Biblioteca declarada por el PE, preservando sus bytes originales.
- Nombre de función o ordinal; exactamente una de las dos formas.
- Tabla de origen: importación normal o retardada.
- Ubicación disponible de la entrada; sin confundir el thunk/IAT con el código de la función importada.

Las cadenas válidas tendrán representación textual y representación hexadecimal de los bytes originales. Si la codificación no puede interpretarse de forma estricta, se conserva la representación hexadecimal y el texto queda sin determinar; no se usan caracteres de sustitución que aparenten un nombre real.

El extractor deberá cubrir explícitamente tablas normales y retardadas, imports por nombre y por ordinal. Una tabla corrupta no debe confundirse con una tabla ausente. Los warnings relevantes del parser se evaluarán y reflejarán como limitaciones o errores, no se descartarán silenciosamente.

Los imports son `observed` respecto al contenido del archivo, nunca evidencia directa de ejecución o intención.

### Tipos de muestra y errores

La extensión y el prefijo `MZ` no bastan para afirmar que una entrada es PE32 o PE32+. Se validarán las cabeceras y sus límites. Si la clasificación no puede establecerse, el tipo será `unknown` y se comunicará el motivo.

Errores previstos: `invalid_pe`, `unsupported_format`, `timeout`, `resource_limit`, `output_limit` y `extractor_failure`. El extractor se identifica de forma estable; los mensajes públicos no incluyen rutas, tracebacks, secretos ni fragmentos binarios arbitrarios.

Los errores fatales de ingesta no son fallos de un extractor. Los fallos de un extractor no eliminan las evidencias válidas de otros extractores; si se conserva un resultado parcial, se explicita su cobertura.

### Determinismo y compatibilidad

Para los mismos bytes, versión de extractor, reglas y configuración, las extracciones que completan deben producir los mismos hechos y el mismo orden. Los IDs se asignarán tras ordenar canónicamente los resultados. Son referencias locales al informe, no identificadores estables entre versiones distintas.

Los timestamps y las duraciones no forman parte de los hechos deterministas. Los límites de tiempo pueden producir resultados incompletos según el entorno; esa diferencia debe ser visible, no ocultarse bajo la promesa de determinismo.

Los consumidores rechazarán versiones de esquema no soportadas. Los cambios incompatibles requerirán una nueva versión explícita y pruebas de compatibilidad.

## Desofuscación en una etapa posterior

Se mantiene la prohibición de ejecutar o emular instrucciones de la muestra. Se permite transformar datos mediante algoritmos propios auditados, con regiones, parámetros y recursos delimitados.

La primera ampliación propuesta es extracción de cadenas y decodificación estricta de Base64/hexadecimal, más candidatos XOR sencillos. Una transformación reproducible demuestra el resultado de esa operación, no que el programa la efectúe ni use el texto resultante. Las hipótesis sobre su significado serán `inferred` y no se mostrarán como hechos confirmados.

FLOSS solo podría integrarse con las rutas emulativas desactivadas, versión fijada y pruebas que intercepten cualquier intento de construir el workspace emulativo. Comprobar únicamente los tipos de salida no basta para garantizar que no hubo emulación. Binary Refinery queda como opción futura para transformaciones permitidas individualmente, no como motor indiscriminado.

No se promete desofuscación general de código, descifrado sin claves recuperables ni desempaquetado arbitrario. Cuando no sea posible, el informe lo dirá.

## Criterios de aceptación y pruebas

- Fixtures PE sintéticos generados por el proyecto; ninguna muestra maliciosa descargada, ejecutada o versionada.
- Pruebas de hashes conocidos, tamaños, entradas vacías, truncadas, sobredimensionadas y no regulares.
- Pruebas PE32/PE32+, imports normales/retardados, por nombre/ordinal, sin tabla y con tabla corrupta.
- Pruebas de nombres no decodificables, RVA/offsets fuera de límites y warnings del parser.
- Igualdad de hechos e IDs entre ejecuciones completas equivalentes; timestamps comprobados por separado.
- Validación de IDs únicos, referencias existentes, ausencia de ciclos, payloads tipados y rechazo de campos inesperados.
- Pruebas negativas: un fallo de parsing no se convierte en una lista de imports completa; un import no genera una afirmación de comportamiento; `unknown` no se sustituye por una conjetura.
- Contrato JSON coherente con el JSON Schema generado; CI detecta si el esquema versionado se queda desactualizado.
- Pruebas CLI de stdout JSON, stderr separado y códigos de salida para éxito, análisis incompleto y fallo.
- Pruebas de aislamiento efectivo: usuario no root, red deshabilitada, raíz de solo lectura, límites y finalización del worker al vencer el timeout.
- Ruff, mypy estricto en el núcleo, pytest, build de paquete y build/prueba de imagen en CI.

La documentación inicial incluirá README, CONTRIBUTING, SECURITY, licencia y procedencia de fixtures. AGENTS.md recogerá las reglas de veracidad, no ejecución y verificaciones para futuros cambios.

## Verificación y publicación

El informe de entrega distinguirá comprobaciones locales, comprobaciones en contenedor y resultados remotos de GitHub Actions. Tener un workflow escrito no significa tener CI en verde. No se declarará un test o build exitoso si no se ha ejecutado y observado su resultado.

El repositorio local existe en `C:\Users\migue\orca\projects\Dissect`. Crear un remoto o publicar requiere confirmar propietario y visibilidad. No se hará push sin autorización explícita.

## Plan de implementación de la primera entrega

Estado: aprobado. Ejecución acordada: secuencial en esta sesión, sin subagentes adicionales. Cada bloque funcional comienza con pruebas que fallen por el comportamiento ausente, continúa con la implementación mínima y termina con verificación y un commit pequeño. No se habilitan funciones de fases posteriores.

Los archivos y comandos siguientes son objetivos del plan, no archivos existentes ni verificaciones ya realizadas.

### 1. Entorno y andamiaje

Archivos: `pyproject.toml`, `uv.lock`, `.python-version`, `.gitignore`, `.pre-commit-config.yaml`, `src/dissect/__init__.py`, `src/dissect/py.typed` y configuración inicial de pytest.

- Provisionar uv y Python 3.12 sin cambiar el Python por defecto ni la configuración Git del usuario. Crear un entorno virtual local aislado.
- Usar un nombre de distribución diferenciado, `dissect-tutor`, conservando el paquete y el comando `dissect`; no publicar en un índice de paquetes.
- Añadir dependencias mediante uv con versiones verificadas y publicadas al menos siete días antes: Pydantic v2, Typer y pefile. Incorporar pytest, Ruff, mypy y las herramientas de build/pre-commit necesarias como dependencias de desarrollo.
- Configurar layout `src`, build de wheel/sdist, mypy estricto y detección de tests. No desactivar validaciones globales para acomodar una dependencia sin tipos: limitar esa frontera a un adaptador del parser.
- Prueba inicial: importación del paquete y versión; confirmar que wheel/sdist se construyen y contienen el código y el marcador de tipos.

Comandos previstos: `uv sync --frozen`, `uv run pytest tests/test_package.py`, `uv run ruff check .`, `uv run mypy src`, `uv build`.

### 2. Modelos y JSON Schema

Archivos: `src/dissect/evidence/models.py`, `src/dissect/evidence/schema.py`, `tests/test_evidence.py`, `tests/test_schema.py` y `docs/evidence-schema.json`.

- Escribir primero pruebas de round-trip JSON, versión no soportada, campos extra, hashes/tamaños inválidos, timestamps sin zona horaria o desordenados, IDs repetidos y referencias inválidas.
- Implementar los modelos tipados del contrato, coherencia de estados y relación entre evidencias, ejecuciones y errores.
- Representar los nombres importados mediante bytes originales en hexadecimal y texto ASCII estricto opcional. La exclusión nombre/ordinal se valida sobre la representación original, no sobre el texto decodificado opcional.
- Mantener la procedencia directa de imports. No habilitar transformaciones aún no implementadas. Validar referencias de origen existentes y acíclicas en los campos admitidos.
- Exportar el esquema de manera determinista con `python -m dissect.evidence.schema`. Proporcionar `--check` para comparar el esquema versionado sin sobrescribirlo; una diferencia debe hacer fallar la verificación.
- Aclarar que algunas invariantes entre campos requieren validación Pydantic y no son expresables únicamente mediante JSON Schema.

Comandos previstos: `uv run pytest tests/test_evidence.py tests/test_schema.py`, `uv run python -m dissect.evidence.schema --check`.

### 3. Ingesta y fixtures inofensivos

Archivos: `src/dissect/ingest/reader.py`, `tests/fixtures/pe_builder.py`, `tests/test_ingest.py` y `samples/README.md`.

- Construir fixtures mínimos en bytes con la biblioteca estándar, sin compilar ni ejecutar código de muestra. Cubrir PE32 y PE32+, imports por nombre/ordinal y tablas normales/retardadas. No versionar ejecutables.
- Probar primero lectura acotada, entrada vacía, directorios/dispositivos, tamaño justo en el límite y un byte por encima, y modificación del tamaño durante la lectura.
- Abrir y comprobar el descriptor para evitar confiar exclusivamente en un `stat` previo. Calcular hashes y tamaño sobre el buffer definitivo, que será el mismo enviado al worker.
- Mantener errores públicos tipados y sin rutas locales. Distinguir los fallos de ingesta de los fallos del extractor.
- Documentar la procedencia de los fixtures y su uso exclusivo como datos de prueba.

Comando previsto: `uv run pytest tests/test_ingest.py`.

### 4. Extractor PE y ensamblado del informe

Archivos: `src/dissect/extractors/base.py`, `src/dissect/extractors/pe.py`, `src/dissect/analysis.py`, `tests/test_pe.py` y `tests/test_analysis.py`.

- Escribir primero tests que fallen para clasificación real de cabeceras, imports normales/retardados, ordinales, nombres no ASCII, ausencia de tabla, tabla corrupta, offsets inválidos y truncamientos.
- Usar pefile con parsing selectivo y límites explícitos. No desensamblar ni emular código, ni cargar DLLs de la muestra.
- Examinar cómo la versión fijada de pefile trata errores y warnings. Traducirlos a códigos y mensajes propios; ante una condición no clasificada, abstenerse de afirmar que la extracción está completa.
- Conservar solo hallazgos cuyo origen sea validable. Marcar cobertura parcial si hay resultados válidos junto con errores. Si no hay resultados respaldados, no fabricar evidencias para llenar el informe.
- Ordenar canónicamente resultados y asignar IDs. Separar el reloj de los extractores e inyectarlo en pruebas.
- Probar que un extractor fallido no borra resultados válidos de otro usando extractores simulados; no añadir integraciones nuevas para demostrarlo.
- Probar que el límite de imports produce una limitación explícita, no una lista aparentemente completa.

Comandos previstos: `uv run pytest tests/test_pe.py tests/test_analysis.py`, `uv run mypy src`.

### 5. Worker aislado y CLI

Archivos: `src/dissect/worker.py`, `src/dissect/runner.py`, `src/dissect/cli.py`, `docker/Dockerfile`, `compose.yaml`, `.dockerignore`, `tests/test_worker.py`, `tests/test_runner.py` y `tests/test_cli.py`.

- Probar primero, con un cliente Docker simulado, falta de motor/imagen, timeout, respuesta excesiva, JSON corrupto, informe inconsistente y limpieza tras fallo/interrupción.
- Construir un launcher que solo use una imagen local conocida y nunca descargue durante el análisis. Pasar argumentos sin shell y no permitir que nombres de archivo se conviertan en argumentos del worker.
- Crear un contenedor identificado de forma inequívoca antes de arrancarlo; transmitir bytes por stdin con stdout/stderr acotados. Terminar y retirar exclusivamente ese contenedor al acabar o fallar, sin operaciones globales de limpieza Docker.
- Aplicar usuario no root, `network=none`, raíz de solo lectura, eliminación de capacidades, `no-new-privileges` y los límites del contrato. No montar directorios del host ni el socket Docker.
- Verificar el resultado del worker en el host, incluyendo hashes/tamaño respecto al buffer original. Rechazar respuestas inválidas en vez de repararlas con conjeturas.
- Exponer `dissect analyze <archivo> --json`. Códigos de salida: 0 para análisis solicitado completo, 3 para parcial, 1 para fallo y 2 para uso incorrecto de la CLI. Los códigos no representan un veredicto de seguridad.
- Construir la imagen con las dependencias runtime fijadas; mantener herramientas de desarrollo fuera de la imagen final. Evitar incluir el repositorio completo en el contexto efectivo de la imagen.

Comandos previstos: `uv run pytest tests/test_worker.py tests/test_runner.py tests/test_cli.py`, `docker compose config --quiet`, `docker build -f docker/Dockerfile -t dissect-worker:0.1.0 .`.

### 6. Pruebas reales de aislamiento y CI

Archivos: `tests/integration/test_docker.py` y `.github/workflows/ci.yml`.

- Añadir pruebas reales que inspeccionen la configuración del contenedor y comprueben usuario, ausencia de acceso de red, raíz no escribible, límites y timeout con terminación efectiva.
- Probar el recorrido completo fixture sintético -> CLI -> worker -> JSON validado. Ninguna prueba ejecutará el fixture como programa.
- Separar las pruebas Docker con un marcador. La suite de integración debe fallar si se solicita explícitamente sin Docker disponible; no producir un éxito aparente por omitirlas todas.
- Configurar CI con Python 3.12: formato/lint, tipos, tests unitarios, coherencia del esquema, build de paquete y build/pruebas Docker. Añadir pruebas unitarias en Windows para el launcher y la ingesta.
- Fijar versiones de dependencias y revisar procedencia de acciones; usar permisos mínimos y no incluir secretos ni muestras reales.
- Si el motor Linux local sigue sin estar disponible, reportar el bloqueo exacto. No declarar aislamiento probado ni CI remota en verde hasta observar las ejecuciones correspondientes.

Comandos previstos: `uv run ruff format --check .`, `uv run ruff check .`, `uv run mypy src`, `uv run pytest -m "not docker"`, `uv run pytest -m docker`, `uv run python -m dissect.evidence.schema --check`, `uv build`.

### 7. Documentación, revisión y entrega

Archivos: `README.md`, `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, actualización de este documento y `AGENTS.md`.

- Añadir licencia Apache-2.0 y guías mínimas de uso, contribución, seguridad y procedencia de fixtures.
- Mostrar un ejemplo reproducible generado por el programa, no un informe inventado. Indicar explícitamente que no hay detección concluyente de malware, desofuscación general, web ni LLM en esta entrega.
- Documentar instalación, build previo de la imagen, análisis sin red y estados/códigos de salida. Describir exactamente qué cubren y qué no cubren las pruebas.
- Registrar en AGENTS.md los comandos que realmente hayan sido configurados y verificados.
- Revisar diffs, secretos accidentales y coherencia del contrato; ejecutar la batería final y comunicar resultados y bloqueos sin generalizaciones.
- Mantener commits convencionales pequeños. No publicar paquetes ni crear releases. Cualquier push requiere autorización explícita; la concedida para esta entrega consta a continuación.

El usuario ha autorizado crear `miguelrr21/Dissect` como repositorio privado, subir el código y ejecutar GitHub Actions. La publicación y sus verificaciones se realizan por separado de las comprobaciones locales; no se confundirá tener repositorio remoto con tener CI ejecutada.
