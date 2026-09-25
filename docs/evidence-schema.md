# LupaBin: contrato de evidencias

El informe de hechos que produce `lupabin analyze --json` sigue el contrato **0.7.0**. Su JSON Schema se genera desde los modelos (`docs/evidence-schema.json`) y los esquemas de versiones anteriores se conservan en `docs/schemas/`. Cómo se obtiene cada hecho y qué se midió para fijar sus umbrales está en [Cómo trabaja LupaBin](metodo.md).

## Regla principal: no inventar datos

1. Ningún dato de análisis se publica sin una fuente identificable y trazable.
2. Un fallo, límite o formato no soportado se comunica como análisis incompleto o imposibilidad de determinar el dato. Nunca se sustituye por un valor plausible.
3. Una lista de hallazgos vacía no demuestra ausencia de comportamiento malicioso. Hay que mostrar el estado y la cobertura del extractor.
4. Las observaciones y las inferencias son categorías distintas. No se promueve una hipótesis a hecho por su plausibilidad, por repetición ni por la respuesta de un modelo de lenguaje.
5. Una importación demuestra la presencia de una entrada en una tabla, no que una función se ejecute ni que se use con fines maliciosos.
6. Las citas existentes son una condición necesaria, no suficiente: una afirmación también debe estar respaldada por el contenido citado. Un verificador de IDs no garantiza veracidad semántica.
7. Las afirmaciones sobre la muestra proceden de hechos estructurados y reglas deterministas verificables. Si no se puede validar una afirmación, se omite y se usa una abstención explícita.
8. El conocimiento general del glosario se distingue de los hechos de la muestra y tiene fuentes editoriales. Las cadenas de la muestra son datos no fiables, nunca instrucciones.
9. No se asignan probabilidades, puntuaciones de riesgo ni etiquetas de malware.

La abstención no es un error del producto: es un resultado válido y preferible a una afirmación falsa. No se promete una garantía matemática de ausencia de errores; se exige trazabilidad, validación, pruebas negativas y comunicación de límites.

## Aislamiento y límites

El análisis corre en un contenedor Linux, no en el host. Si Docker o la imagen no están disponibles, se comunica el problema; no hay un análisis de reserva sin aislamiento. Las pruebas unitarias invocan el núcleo directamente sobre fixtures sintéticos.

El worker no tiene red, capacidades Linux adicionales, privilegios de root, socket de Docker ni montajes del host. Recibe los bytes por stdin y emite una respuesta acotada por stdout. El sistema de archivos raíz es de solo lectura. La imagen no contiene muestras reales ni credenciales.

Límites: entrada de 20 MiB, 30 segundos de análisis, 512 MiB de memoria, 1 CPU, 64 procesos y respuesta de 8 MiB. Si se alcanza un límite, se registra explícitamente que el resultado no está completo. El timeout detiene y retira el contenedor, no solo el cliente de Docker. Los límites efectivos aparecen en los metadatos del informe. Estos controles reducen el riesgo; no convierten Docker ni los parsers en una garantía de seguridad absoluta.

El host trata la respuesta del worker como entrada no fiable: la valida, comprueba hashes y tamaño contra el buffer original y vuelve a comprobar contra la muestra los bytes que citan las decodificaciones, las llamadas, los argumentos y los rangos de función.

## Estructura del informe

| Campo | Contenido |
| --- | --- |
| `schema_version` | Literal `0.7.0`; versiones distintas se rechazan. |
| `sample` | SHA-256, MD5, tamaño y tipo reconocido (`PE32`, `PE32+`, `unknown`), sin ruta local. MD5 se incluye solo por interoperabilidad. |
| `analysis` | Versión, timestamps del análisis, límites efectivos y estado global. |
| `evidence` | Unión discriminada por `kind`: `import`, `pe_header`, `section`, `entropy`, `export`, `string`, `header_anomaly`, `yara_match`, `decoded_string`, `api_call`, `call_argument` y `code_function`. |
| `extractor_runs` | Fuentes `pe`, `strings`, `yara`, `decode` y `code`, con su versión y componentes tipados con cobertura y contadores. |
| `extractor_errors` | Motivos de fallo, con fuente, componente y código estable. |
| `limitations` | Cuotas, omisiones, prefijos acotados y warnings, separados de los fallos. |

Cada evidencia tiene `id` (`E1`, `E2`…, único y local al informe), `source`, `component`, `kind`, un payload tipado (`data`), su intervalo real en el archivo (`location`), `confidence` (`observed` o `inferred`; no es una probabilidad) y `provenance` (las evidencias de las que deriva). Las direcciones meramente declaradas se guardan en el payload, no como ubicaciones comprobadas. Una dirección virtual no se etiqueta como RVA, y una ubicación desconocida no se rellena con cero. Las referencias deben existir, no pueden apuntar a sí mismas ni formar ciclos.

**Estados.** La cobertura de un componente es `complete`, `partial` o `blocked`. Un extractor completado puede tener cero hallazgos. El estado global es `completed` si todas las fuentes completan, `failed` si todas quedan bloqueadas y `partial` en los demás casos. `completed` no es un veredicto de seguridad: significa que terminaron las operaciones solicitadas. Si falla la infraestructura antes de validar un informe, se emite un error separado; no se fabrica un informe. Códigos de salida de la CLI: 0 completo, 3 parcial, 1 fallo y 2 uso incorrecto.

**Determinismo.** Para los mismos bytes, versiones, reglas y configuración, las extracciones que completan producen los mismos hechos, en el mismo orden y con los mismos IDs. Los timestamps y las duraciones no forman parte de los hechos. Los límites de tiempo (ver «Componentes y límites del código») pueden producir resultados parciales distintos en una máquina más lenta: lo publicado sigue siendo cierto, y la diferencia se declara con su código.

## Hechos del PE y cadenas

- **`pe_header`**: los enteros declarados de la cabecera. El timestamp es un entero declarado, no una fecha de compilación acreditada.
- **`section`**: índice, los ocho bytes originales del nombre, RVA, tamaños y flags declarados. La ubicación apunta al descriptor, no al rango de datos que declara.
- **`entropy`**: entropía de Shannon por sección (`shannon-byte-v1`), citando la `section` que define su intervalo. No demuestra empaquetado.
- **`import`**: biblioteca y nombre u ordinal, tabla normal o retardada, bytes originales y `iat_rva`, la dirección de su casilla en la tabla de direcciones de import (IAT), que es adonde apuntan las llamadas. `location` es la entrada de la tabla de búsqueda.
- **`export`**: índice en la tabla de direcciones de exportación, ordinal, nombres y destino declarado o forwarder, sin resolver otras DLL.
- **`string`**: texto ASCII o UTF-16LE exacto y sus bytes, con repertorio ASCII imprimible explícito. Una URL no demuestra una conexión.
- **`header_anomaly`**: una comprobación estructural que se cumple sobre los valores de las cabeceras y secciones que cita, no solo sobre sus IDs.

## Coincidencias YARA (`yara_match`)

El informe incluye un `yara_context` tipado con catálogo, hashes de las fuentes y versiones realmente observadas. Una versión nativa que no se pudo obtener queda nula; no se sustituye por la versión esperada.

`yara_match` conserva identidad, revisión, licencia y descripción editorial de la regla, digest del catálogo, versiones e instancias de patrones. `location` es nulo solo para este tipo: los intervalos están en `data.instances`, con `offset`, `matched_length`, `captured_length`, `raw_hex` y `complete`. El host valida esos bytes contra el buffer original. Las descripciones de las reglas no son afirmaciones de comportamiento.

Los componentes son `yara_rules`, `yara_scan` y `yara_evidence`. YARA corre en un subproceso dentro del contenedor; si falla o se interrumpe, no publica coincidencias y se conservan los demás hechos. Si la representación se acota, las omisiones se declaran en `limitations`, `instances_status` y `omitted_instances`. Cero coincidencias con cobertura completa no es un veredicto de seguridad.

## Decodificaciones (`decoded_string`)

`decoded_string` es `inferred`: afirma que unos bytes, transformados con un algoritmo y unos parámetros exactos, producen un texto. No afirma que el programa realice la transformación ni que el texto tenga significado. Campos:

| Campo | Contenido |
| --- | --- |
| `component` | `decode_strings` (Base64/hex) o `decode_xor`. |
| `location` | Dónde están los bytes codificados. Para Base64/hex coincide con la cadena fuente; para XOR es la región cifrada, de la misma longitud que el texto resultante. |
| `transform` | `base64-strict-v1`, `hex-strict-v1` o `xor-repeating-v1`; solo XOR lleva `key_hex` (1–8 bytes, en su periodo mínimo, no nula, alineada con el inicio de `location`). |
| `anchor` | Solo XOR: catálogo `lupabin-xor-cribs-v3`, cadena de referencia y su desplazamiento en caracteres dentro del texto. |
| `provenance.evidence_ids` | Base64/hex: exactamente la cadena fuente. XOR: vacío si la propia ancla verificó la clave; o la única decodificación XOR, verificada por sí misma, que estableció esa misma clave en otro punto de la muestra. |
| `data` | Mismas reglas de fidelidad que `string`: `text`, `raw_hex` del texto resultante, `characters`, `complete`. |

### Reutilización de clave

Una ancla demasiado corta no puede verificar sola una clave larga. Si otra decodificación XOR de la misma muestra ya verificó esa clave con su propia ancla, la aparición se acepta cuando reproduce la ancla completa con una clave idéntica salvo la fase, y cita en `provenance` la decodificación que estableció la clave. El modelo rechaza una clave reutilizada que no cite una decodificación XOR autoverificada con la misma clave.

El modelo rechaza también XOR sin ancla o con más de una cita, Base64/hex con clave o ancla, una cita que no sea la cadena ubicada en los mismos bytes, una ancla que no aparece en su desplazamiento, claves nulas o no canónicas, regiones fuera de la muestra y cuotas superadas por componente.

**Reverificación en el host.** El launcher vuelve a derivar cada `decoded_string` desde el buffer original: Base64/hex desde los bytes de la cadena citada; XOR aplicando la clave a la región y comprobando que la ancla pertenece al catálogo, que su ventana no era ya texto, que la ancla puede verificar ese periodo de clave (o, si la clave es reutilizada, que la decodificación citada tiene la misma clave y se reproduce a su vez) y que un texto declarado completo no continúa más allá de sus límites. Una evidencia que no se reproduce invalida toda la respuesta (`invalid_worker_output`).

| Componente | Revisa | Limitaciones propias |
| --- | --- | --- |
| `decode_strings` | Todas las cadenas extraídas y completas | `decode_strings_limit` (2.000 resultados) |
| `decode_xor` | Todas las apariciones de los patrones del catálogo en los bytes | `decode_xor_limit` (256 resultados), `decode_xor_examined_limit` (200.000 apariciones examinadas), `decoded_length_limit` (texto recortado a 1.024 caracteres), `decode_time_limit` (el análisis lleva 10 s, o un tercio de `timeout_seconds`) |

Los límites efectivos aparecen en `analysis.limits.decode`. Cero decodificaciones con cobertura completa es el caso habitual y no significa nada sobre la muestra.

## Llamadas (`api_call`)

`api_call` es `observed`: afirma que en esos bytes hay una instrucción, alcanzada por el recorrido del código, que llama a la casilla de ese import. No afirma que se ejecute. Campos:

| Campo | Contenido |
| --- | --- |
| `component` | `api_calls`. |
| `location` | La instrucción de llamada: `offset`, `rva`, `length` y `section`, que debe ser la única sección ejecutable que contiene esos bytes en disco. |
| `data.via` | `direct` (`call [casilla]`), `thunk` (`call rel32` a un `jmp [casilla]`), `register` (`mov reg, [casilla]` inmediatamente antes de `call reg`) o `tail` (`jmp [casilla]` que termina un tramo: una llamada en cola). |
| `data.raw_hex` | Los bytes de la instrucción de llamada. |
| `data.helper` | Solo `thunk` y `register`: el `jmp` del thunk o la carga del registro, con `offset`, `rva` y `raw_hex`. |
| `provenance.evidence_ids` | Exactamente el `import` al que llama. |

Una llamada en cola solo admite argumentos de registro y solo en x64: en el salto, la dirección de retorno de quien llamó ya está en la pila.

**Verificación en el propio informe.** Sin la muestra, el modelo vuelve a derivar la casilla desde los bytes citados con las formas canónicas de `src/lupabin/evidence/call_forms.py` y exige que sea el `iat_rva` del import citado. En x86 la dirección es absoluta (menos la base de imagen de la cabecera); en x64, relativa a la instrucción siguiente. En un thunk, el destino del `call` debe ser el `jmp` citado; en la vía por registro, la carga debe terminar justo donde empieza la llamada y usar el mismo registro. También comprueba que cada `offset` corresponde a su `rva` según la tabla de secciones.

**Verificación en el host.** El launcher y `lupabin explain --sample` comparan los bytes de cada instrucción citada con los de la muestra. El host no lleva desensamblador: una prueba comprueba que ni la CLI ni el runner cargan capstone. Lo que ninguna comprobación puede demostrar es que el recorrido llegó a esa instrucción (y no a unos bytes que solo lo parecen). Eso es una regla del worker, probada con casos negativos y medida en binarios benignos.

## Argumentos (`call_argument`)

`call_argument` es `inferred`: afirma que una instrucción del mismo tramo lineal que la llamada, anterior a ella, fija ese argumento a una constante, y que el recorrido no vio nada que lo cambie antes de la llamada. Solo se publica para las funciones del catálogo `lupabin-api-semantics-v4` (`src/lupabin/evidence/api_catalog.py`: 72 entradas de registro, servicios, procesos, bibliotecas, archivos, red, sincronización, memoria y criptografía, importadas de una DLL que su página de Microsoft Learn declara como exportadora) y solo si el valor es del tipo del parámetro. Campos:

| Campo | Contenido |
| --- | --- |
| `component` | `call_arguments`. |
| `location` | La instrucción que fija el argumento, en la misma sección ejecutable que la llamada y antes de ella. |
| `data.catalog`, `data.method` | `lupabin-api-semantics-v4`. Método `block-constant-v1` (registro o `push`) o `stack-slot-v1` (ranura de la pila en x64, del quinto argumento en adelante). |
| `data.position`, `data.name`, `data.type` | Posición (desde 0), nombre y tipo del parámetro según el catálogo: `hkey`, `string` o `integer`. |
| `data.value` | `hkey`: el valor tal como se fija (en x64, extendido con signo: `0xffffffff80000001`). `integer`: módulo el ancho del parámetro (32 bits para `REGSAM`). `string`: el puntero tal como se fija (dirección absoluta en x86, RVA de un `lea` relativo a rip en x64). |
| `data.raw_hex` | Los bytes de la instrucción que lo fija: `lea r64, [rip+disp32]`, `mov r32, imm32`, `mov r64, simm32` o `xor r32, r32` en x64; `push imm32` o `push imm8` en x86 (`src/lupabin/evidence/argument_forms.py`). Con `stack-slot-v1`, la escritura en la ranura `[rsp+8·i]`: `mov dword/qword ptr [rsp+d], imm32`, `and dword/qword ptr [rsp+d], 0` o `mov [rsp+d], r32/r64`. |
| `data.constant` | Solo `hkey`: el nombre de la clave predefinida. Se aceptan las cinco que Learn lista para `hKey` (`HKEY_CLASSES_ROOT`, `HKEY_CURRENT_USER`, `HKEY_LOCAL_MACHINE`, `HKEY_USERS`, `HKEY_CURRENT_CONFIG`). |
| `data.source` | Solo con `stack-slot-v1` y cuando se copia un registro: la instrucción (forma canónica, sobre cualquiera de los 16 registros) que fijó ese registro antes de la escritura, con `offset`, `rva` y `raw_hex`. Un puntero exige escribir los 8 bytes de la ranura; un entero de 32 bits admite 4 u 8. |
| `data.string` | Solo `string`: `offset`, `rva`, `raw_hex` (texto más su terminador NUL) y `text` imprimible ASCII, en una sección que no se puede escribir: el programa podría cambiar una cadena escribible antes de la llamada. |
| `provenance.evidence_ids` | Exactamente el `api_call` al que pertenece. |

**Verificación.** El modelo vuelve a derivar el valor desde `raw_hex` con las formas canónicas, exige que en x64 el registro fijado sea el del parámetro, que la clave sea una de las aceptadas, que el entero coincida, que el puntero lleve exactamente a la cadena citada y que la cadena decodifique sus bytes con su terminador. También exige que la función llamada y el parámetro estén en el catálogo, y que no haya dos valores para el mismo argumento de una llamada. El host compara además con la muestra los bytes de la instrucción y de la cadena. Lo que no puede comprobar sin desensamblar es que ninguna instrucción intermedia cambie el valor, ni que otro camino no entre en medio. Por eso el hecho es `inferred`, y el método es una regla del worker probada con casos negativos (`tests/test_code_args.py`).

## Rangos de función (`code_function`)

`code_function` es `observed`: afirma que la tabla `.pdata` de un PE32+ declara, en esos 12 bytes, una entrada `RUNTIME_FUNCTION` con ese inicio, fin e información de desenrollado. Sirve para que una explicación pueda decir que dos llamadas están en el mismo rango de función sin volver a la muestra. No afirma que el rango sea una función completa: una función partida tiene varias entradas. Se publica, sin repetir, la entrada que contiene cada llamada publicada a una función del catálogo de argumentos; si dos entradas de la tabla se solapan, la tabla está malformada y no se publica ninguna. En x86 no hay `.pdata`. Campos:

| Campo | Contenido |
| --- | --- |
| `component` | `api_calls` (la cuota es la de llamadas: como mucho una entrada por llamada). |
| `location` | La entrada: `offset`, `rva`, `length` 12 y `section`. |
| `data.begin`, `data.end`, `data.unwind` | Las tres RVA de la entrada, con `begin < end`. |
| `data.raw_hex` | Los 12 bytes de la entrada. |
| `provenance.evidence_ids` | Vacío. |

**Verificación.** El modelo exige que los bytes codifiquen los tres valores, que la cabecera sea PE32+, que el desplazamiento corresponda a su RVA según la tabla de secciones, que el rango contenga al menos una llamada publicada y que cada inicio aparezca una sola vez. El informe no lleva los directorios de datos, así que no puede demostrar que la entrada esté dentro del directorio de excepciones; el host compara sus bytes con la muestra, igual que los de las llamadas.

## Componentes y límites del código

| Componente | Revisa | Limitaciones propias |
| --- | --- | --- |
| `disassembly` | Instrucciones decodificadas por descenso recursivo en secciones ejecutables (`examined`) | `code_instruction_limit` (8.000.000), `call_site_limit` (1.048.576 llamadas examinadas), `code_entry_limit` (262.144 puntos de partida), `code_time_limit` (el análisis lleva 15 s, o la mitad de `timeout_seconds`) |
| `api_calls` | Instrucciones `call` examinadas (`examined`) | Las del recorrido, más `api_call_limit` (4.096 publicadas) y `dependency_omitted` si la tabla de imports no se leyó completa |
| `call_arguments` | Llamadas publicadas a funciones del catálogo cuyo tramo se examinó (`examined`) | `argument_instruction_limit` (65.536 instrucciones en modo detallado, en total), `code_time_limit` (la misma marca que el recorrido), `call_argument_limit` (4.096 publicados) y `dependency_omitted` si `api_calls` no es completo |

Los puntos de partida del recorrido son el punto de entrada, los exports y tablas que escribe el compilador o el enlazador: callbacks TLS, `.pdata` (x64), la tabla de funciones de Control Flow Guard y los manejadores SafeSEH (x86). Ninguno se adivina.

**Límites de tiempo.** La búsqueda XOR y el recorrido del código se detienen al llegar a su marca de tiempo, contada desde el inicio del análisis (`analysis.limits.decode.seconds` y `analysis.limits.code.seconds`), y lo declaran con su código. Así una máquina lenta o una entrada diseñada contra ellos deja el informe parcial en vez de agotar el tiempo del worker y perderlo entero.

`api_calls` solo puede ser completo si también lo son `disassembly` y los dos componentes de imports, y `call_arguments` solo si lo es `api_calls`. Un argumento ausente con cobertura completa significa que ninguna instrucción del tramo lo fija con una forma canónica, no que no tenga valor. Con la cuota agotada, se publica primero la primera llamada de cada import y después las repetidas, para cubrir el máximo de funciones distintas. Arquitecturas distintas de x86/x64 bloquean la fuente (`unsupported_architecture`), igual que las correspondencias ambiguas entre memoria y archivo (`unsafe_mapping`) y las entradas que no son PE. Cero llamadas con cobertura completa no demuestra que el programa no llame a nada: el código al que solo se llega por saltos indirectos no se recorre.

## Versiones del contrato

| Versión | Añade | Esquema |
| --- | --- | --- |
| 0.1.0 | Hashes, tipo validado e imports normales y retardados | `docs/schemas/0.1.0.json` |
| 0.2.0 | Cabecera PE, secciones, entropía, exports, cadenas y anomalías; cobertura por componente y `limitations` | `docs/schemas/0.2.0.json` |
| 0.3.0 | Fuente `yara` y `yara_match` | `docs/schemas/0.3.0.json` |
| 0.4.0 | Fuente `decode` y `decoded_string` | `docs/schemas/0.4.0.json` |
| 0.5.0 | Fuente `code`: `api_call`, `call_argument` e `iat_rva` en los imports | `docs/schemas/0.5.0.json` |
| 0.6.0 | `code_function` (rangos de `.pdata` en x64) | `docs/schemas/0.6.0.json` |
| 0.7.0 | La vía `tail` de `api_call` (saltos en cola a una función importada) | `docs/evidence-schema.json` (activo) |

Los consumidores rechazan versiones de esquema no soportadas. La CLI no transforma informes antiguos.
