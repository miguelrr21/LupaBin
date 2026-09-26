# LupaBin: contrato de evidencias

El informe de hechos que produce `lupabin analyze --json` sigue el contrato **0.11.0**. Su JSON Schema se genera desde los modelos (`docs/evidence-schema.json`) y los esquemas de versiones anteriores se conservan en `docs/schemas/`. Cómo se obtiene cada hecho y qué se midió para fijar sus umbrales está en [Cómo trabaja LupaBin](metodo.md).

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
| `schema_version` | Literal `0.11.0`; versiones distintas se rechazan. |
| `sample` | SHA-256, MD5, tamaño y tipo reconocido (`PE32`, `PE32+`, `unknown`), sin ruta local. MD5 se incluye solo por interoperabilidad. |
| `analysis` | Versión, timestamps del análisis, límites efectivos y estado global. |
| `evidence` | Unión discriminada por `kind`: `import`, `pe_header`, `section`, `entropy`, `export`, `string`, `header_anomaly`, `toolchain_marker`, `yara_match`, `decoded_string`, `api_call`, `call_argument`, `code_function`, `local_link`, `main_call`, `code_reach` y `string_reference`. |
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

## Marcas de compilador (`toolchain_marker`)

Bytes que un compilador, un enlazador o un empaquetador deja en el archivo, con la forma exacta del catálogo `lupabin-toolchains-v1` (componente `toolchain` de la fuente `pe`). `data` lleva `catalog`, `marker`, `raw_hex` (los bytes de la marca tal como están en el archivo) y `text` (lo que esos bytes dicen, si dicen algo). `confidence` es `observed`: los bytes están ahí; lo que significa cada marca lo dice su explicación, con lo que no demuestra.

| `marker` | Bytes publicados | `text` | Dónde debe estar |
| --- | --- | --- | --- |
| `rich_header` | De «DanS» cifrado hasta «Rich» y su clave | nulo | Entre la cabecera MS-DOS y la cabecera PE, con el checksum del enlazador de Microsoft correcto |
| `gcc_ident` | «GCC: (» y texto imprimible hasta su NUL, incluido | El texto | Dentro de los datos de una sección; cada texto distinto una vez, hasta 8 |
| `mingw_w64_runtime` | «Mingw-w64 runtime failure:» | nulo | Dentro de los datos de una sección |
| `go_buildinfo` | La cabecera de 16 bytes o, si guarda la versión en línea, hasta el final de la versión | La versión, o nulo | En una sección, con RVA múltiplo de 16 e indicadores que Go define |
| `clr_header` | Los 8 primeros bytes de la cabecera CLI (tamaño 72 y versión del formato) | La versión del formato | Donde apunta el directorio 14 (`CLR Runtime Header`), con tamaño de al menos 72 |
| `pyinstaller_cookie` | Los 88 bytes de la cookie | La biblioteca de Python | Después de los datos de todas las secciones, con su archivo también detrás de ellos |

El modelo comprueba la forma de los bytes; el informe, dónde está cada marca respecto a las secciones y que cada una aparezca una vez (la de GCC, una vez por texto); y el host, con la muestra, que los bytes son los suyos, que el checksum de la cabecera Rich se cumple sobre los bytes anteriores y que el directorio CLR apunta a la cabecera publicada. Solo `go_buildinfo` y `clr_header` llevan RVA y sección. Una candidata que falla cualquier comprobación no se publica. Con más de 8 textos distintos de GCC, el componente queda parcial (`toolchain_limit`). Una correspondencia ambigua entre memoria y archivo bloquea el componente (`unsafe_mapping`).

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

## Variables locales entre llamadas (`local_link`)

`local_link` es `inferred`: afirma que una llamada recibe la dirección de una variable local en el parámetro con el que devuelve un identificador (`phkResult` de `RegOpenKeyEx` y `RegCreateKeyEx`), y que una llamada posterior pasa el valor de esa misma variable como clave (`hKey` de una función del catálogo). Campos:

| Campo | Contenido |
| --- | --- |
| `component` | `call_arguments`. |
| `location` | La instrucción que pasa el valor a la segunda llamada: `push dword ptr [ebp+d]` en x86; `mov r64, qword ptr [rsp/rbp+d]` en x64, al registro del parámetro. |
| `data.method` | `frame-slot-v1`. |
| `data.slot` | La variable: registro de marco (`ebp`, `rsp` o `rbp`) y desplazamiento con signo. |
| `data.writer_position`, `data.writer_name` | El parámetro que recibe la dirección (`phkResult`, posición 4 o 7). |
| `data.reader_position`, `data.reader_name` | El parámetro que recibe el valor (`hKey`). |
| `data.raw_hex` | Los bytes de `location`. |
| `data.address` | El `lea` que toma la dirección de la variable, con `offset`, `rva` y `raw_hex`. |
| `data.passes` | La instrucción que pasa esa dirección a la primera llamada: `push r32` en x86; `mov qword ptr [rsp+8·i], r64` en x64. |
| `provenance.evidence_ids` | Las dos llamadas: la que escribe y la que lee. |

**Verificación.** El modelo exige que las dos llamadas lleguen por nombre a funciones que escriben y leen una clave en esos parámetros, que las tres instrucciones nombren la misma variable con las formas canónicas de `src/lupabin/evidence/local_forms.py` (en x64, además, que la dirección se guarde en la ranura de `phkResult` y el valor llegue al registro de `hKey`), que todo esté en una sección ejecutable y en orden, que la lectura esté a menos de 4.096 bytes de la primera llamada y que la variable no esté en las cuatro primeras ranuras de la pila en x64, que pertenecen a la función llamada. El host compara los bytes con la muestra. Lo que no se puede comprobar sin desensamblar es el camino entre las dos llamadas: esa es la regla del worker y la razón de que el hecho sea `inferred`.

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

## La función main (`main_call`) y el alcance (`code_reach`)

Componente `main_function` de la fuente `code`. Los dos hechos son `inferred`: descansan en las reglas del recorrido.

- **`main_call`**: la llamada directa con la que el código de arranque entra en `main` (método `getmainargs-v1`). `location` es la instrucción `call rel32` (5 bytes); `data.target` es la RVA de `main`; `data.setters` son las tres instrucciones que pasan `&argc`, `&argv` y `&envp` a `__getmainargs` o `__wgetmainargs` de `msvcrt.dll` (`lea` relativa a RIP en x64, `push imm32` en x86), y `data.loads` las tres que cargan esos valores para `main` (`mov` desde `[rip+disp32]` a rcx/rdx/r8 en x64, `push dword ptr [addr]` en x86). Cita la `api_call` a `__getmainargs`. El informe comprueba que la llamada citada va a esa función de `msvcrt.dll`, que el destino es lo que dicen los bytes de la llamada y está en una sección ejecutable, que cada carga lee la misma dirección que su instrucción pasó (en x64, en el mismo registro de argumento), que las tres direcciones son distintas y que cada instrucción está antes de su llamada; el host, que todos los bytes son los de la muestra. Se publica como mucho una, y solo si en todo el código recorrido hay exactamente una llamada que cumple la regla.
- **`code_reach`**: las `api_call` que el recorrido alcanza desde una raíz siguiendo solo llamadas y saltos con destino constante (método `direct-reach-v1`). `root` es `main` (desde el destino de `main_call`) o `startup` (desde el punto de entrada y las funciones TLS, sin entrar en `main` y sin las que también alcanza `main`). `data.calls` son sus IDs, en el orden del informe. Cita la `main_call`. El informe comprueba que son `api_call` publicadas, sin repetir y sin llamadas en las dos raíces.

Si el recorrido del código no está completo, no se publica nada (`dependency_omitted`): el código no recorrido podría tener un segundo candidato. Si lo está pero la lista de llamadas publicadas no (por ejemplo, porque hay más de las que caben), se publica `main_call` sin alcances, porque sus cifras engañarían, y el componente queda parcial (`dependency_omitted`). Si un recorrido de alcance se detiene por un límite, tampoco se publican alcances, con el código de ese límite.

## Textos que usa el código (`string_reference`)

Componente `string_references` de la fuente `code`, `observed`. `location` es una instrucción que el recorrido decodificó y `data.raw_hex` sus bytes: `lea r64, [rip+disp32]` en x64, `push imm32` o `mov r32, imm32` en x86. Cita la cadena (`string`) donde apunta. El informe comprueba que la dirección que dan los bytes es exactamente el inicio de esa cadena y que la sección que la contiene no se puede escribir; el host, los bytes. Se publica la primera instrucción de cada cadena. `code_reach.data.strings` lista las referencias cuyas instrucciones decodificó el recorrido de esa raíz, sin repetir entre raíces. Sin recorrido completo o con cadenas sin publicar, el componente queda parcial (`dependency_omitted`).

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
| 0.7.0 | La vía `tail` de `api_call` (saltos en cola a una función importada) | `docs/schemas/0.7.0.json` |
| 0.8.0 | `local_link` (un identificador que pasa de una llamada a otra por una variable local) | `docs/schemas/0.8.0.json` |
| 0.9.0 | Componente `toolchain` y `toolchain_marker` (marcas de compilador) | `docs/schemas/0.9.0.json` |
| 0.10.0 | Componente `main_function`, `main_call` y `code_reach` (la función main y el alcance) | `docs/schemas/0.10.0.json` |
| 0.11.0 | Componente `string_references`, `string_reference` y los textos de `code_reach` (textos que usa el código) | `docs/evidence-schema.json` (activo) |

Los consumidores rechazan versiones de esquema no soportadas. La CLI no transforma informes antiguos.
