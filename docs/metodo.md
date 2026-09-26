# Cómo trabaja LupaBin: método y límites medidos

Este documento explica cómo obtiene LupaBin cada hecho y cada frase, por qué se eligió cada método y qué se midió antes de adoptarlo. El formato exacto de los hechos está en el [contrato de evidencias](evidence-schema.md).

**Cómo se mide.** Todas las cifras de este documento se tomaron sobre binarios benignos de Windows: System32, SysWOW64, drivers, .NET, Program Files y Program Files (x86), según la medición. Se leyeron como datos en el host; nunca se ejecutaron ni se añadieron al repositorio. Sobre ellos, un resultado que no se reproduce o una frase que no describe lo que dicen los bytes cuenta como error. Cada caso señalado se revisó a mano. Una variante que subía la cobertura pero añadía errores se descartó, y aquí se dice cuáles. Las mediciones se repiten con las herramientas de [Repetir las mediciones](#repetir-las-mediciones).

## Principios

- **La muestra nunca se ejecuta ni se emula.** Se leen sus bytes dentro de un contenedor sin red, sin privilegios y con límites de memoria, CPU y tiempo.
- **Hechos observados e inferencias, separados.** Un hecho `observed` está escrito en el archivo (una entrada de la tabla de imports, una instrucción de llamada). Uno `inferred` sale de aplicar un método a los bytes (un texto decodificado, el valor constante de un argumento).
- **Abstenerse antes que inventar.** Lo que no se puede determinar se dice. Un resultado vacío no demuestra que algo falte.
- **Sin puntuaciones ni veredictos.** LupaBin no dice si un archivo es malicioso.
- **Cada frase cita sus hechos y se regenera al validar.** Una explicación manipulada, con una cita de menos o con un caso oculto no se muestra.
- **El host no confía en el worker.** Vuelve a comprobar contra la muestra los bytes de las decodificaciones, llamadas, argumentos y rangos de función.

## Hechos del archivo PE

**Cabecera y secciones.** Se conservan los enteros declarados. El tipo PE32 o PE32+ solo se asigna tras validar las firmas y el bloque de cabeceras; si no se puede, queda `unknown` y no se fabrican hechos con bytes parciales. El timestamp de la cabecera es un entero declarado: los valores 0 y 0xFFFFFFFF no significan nada según la especificación PE, y ningún otro valor demuestra una fecha de compilación. Los nombres de sección conservan sus ocho bytes originales, y los permisos de lectura, escritura y ejecución son la traducción de los bits declarados, no permisos efectivos durante una ejecución.

**Imports.** Las tablas normales y retardadas se recorren directamente sobre el buffer original, en regiones acotadas. Los ordinales se conservan como ordinales, los nombres como bytes y el texto solo cuando decodifica estrictamente como ASCII. No se usan los nombres que pefile sustituye o completa por su cuenta, porque no siempre están en la muestra. Un error de tabla conserva solo las entradas anteriores validadas y deja la cobertura parcial.

**Exports.** Cada entrada describe un símbolo exportado, no necesariamente una función. Se validan límites, contadores, índices y terminadores antes de asociar nombres. Los forwarders se conservan como texto, sin cargar la DLL de destino. Si las tablas de nombres están corruptas, se conservan las entradas válidas con `names_status=incomplete`, nunca "sin nombre".

### Entropía de bytes

Se calcula `H = -Σ p_i · log2(p_i)` sobre exactamente los bytes en disco de cada sección, incluido el relleno dentro de `SizeOfRawData`, sin relleno virtual (método `shannon-byte-v1`, redondeado a seis decimales). Una sección vacía no produce medida: falta de datos no es entropía cero. Un rango parcialmente fuera del archivo tampoco se mide sobre su prefijo.

No hay umbral que afirme "empaquetado", "cifrado" o "malicioso". La explicación de entropía alta (≥ 7,2 bits por byte, solo en secciones de 4 KiB o más, porque con pocos bytes la estimación se acerca a 8) da como contexto su frecuencia en software legítimo: en 55.313 binarios benignos, 475 de 139.057 secciones de 4 KiB o más (0,34 %) llegan a 7,2. Por nombre: `.rsrc` 0,6–0,8 %, `.rdata` 0,2–0,3 %, `.text` 0,1–0,2 %.

### Cadenas literales

Secuencias de al menos cuatro caracteres ASCII imprimibles (U+0020–U+007E), en ASCII y en UTF-16LE con ambos alineamientos. Cada aparición es un hecho distinto, con su desplazamiento real y sus bytes; el modelo comprueba que los bytes decodifican exactamente al texto. Una secuencia de más de 1.024 caracteres conserva un prefijo marcado `complete=false`. No se promete recuperar todo Unicode, cadenas cifradas ni cadenas construidas en la pila, y no se interpreta el texto: una URL no es una conexión ni una ruta un archivo creado.

### Anomalías estructurales

Comprobaciones de campos declarados, no una reproducción del cargador de Windows:
- rango de datos de una sección fuera del archivo;
- solapamiento de rangos físicos entre secciones;
- solapamiento de rangos virtuales entre secciones (con `max(VirtualSize, SizeOfRawData)`);
- extensión virtual mayor que `SizeOfImage`;
- punto de entrada no nulo fuera de `SizeOfImage`.

Cada anomalía cita las cabeceras y secciones que la sustentan, y el modelo comprueba que el predicado se cumple sobre sus valores. Los intervalos vacíos no son solapamientos. Un warning genérico de pefile no se convierte en una anomalía concreta: se conserva como limitación y deja la cobertura parcial.

## Cobertura, estados y abstención

Cada extractor declara la cobertura de cada componente: `complete`, `partial` o `blocked`, con contadores y motivos. Un directorio de imports ausente puede tener cobertura completa con cero hallazgos; una tabla que no se pudo leer, nunca. Detectar una anomalía no significa que el análisis fallara: puede haberse comprobado bien una inconsistencia.

El estado global se calcula por cobertura, no por el número de hallazgos: `completed` si todas las fuentes completan, `failed` si todas quedan bloqueadas y `partial` en los demás casos. Un fallo de un componente no borra los hechos válidos de otro. Un timeout o un agotamiento de memoria que termine el worker produce un error explícito, no un informe parcial inventado. Los errores y limitaciones identifican siempre su fuente y componente, sin rutas locales ni mensajes del parser.

## Reglas YARA

LupaBin evalúa solo su propio catálogo de cuatro reglas (`src/lupabin/rules/yara/`), con patrones literales y condiciones simples, sin módulos, includes, expresiones regulares ni reglas aportadas por el usuario. Cada regla y el manifiesto van fijados por digest. La afirmación permitida es "el motor YARA evaluó como verdadera esta regla sobre estos bytes", no que el archivo sea malware ni que use una técnica.

| Regla | Qué encuentra | Qué no demuestra |
| --- | --- | --- |
| `lupabin_dos_stub_text` | El texto `This program cannot be run in DOS mode` | El tipo PE |
| `lupabin_process_memory_api_names` | Los nombres `VirtualAllocEx`, `WriteProcessMemory` y `CreateRemoteThread` juntos | Imports ni inyección |
| `lupabin_debug_marker_pair` | Los marcadores `RSDS` y `.pdb` | Una ruta PDB ni un directorio de depuración válido |
| `lupabin_training_marker` | El marcador de práctica `LUPABIN PRACTICE` | Una familia |

YARA corre en un subproceso dentro del contenedor. Si falla o se interrumpe, no publica coincidencias y los demás hechos se conservan.

## Decodificación

Tres transformaciones deterministas, sin dependencias nuevas. La afirmación permitida es "estos bytes, transformados con este algoritmo y estos parámetros exactos, producen este texto". Todo resultado es `inferred`, y el host lo reproduce desde el buffer original.

### Base64 estricto

`base64-strict-v1`, sobre cadenas ya extraídas y completas:
- longitud múltiplo de 4, y al menos 12 caracteres si termina en `=` o 16 si no lleva relleno (los identificadores de código nunca llevan `=`);
- solo el alfabeto estándar, con como mucho dos `=` finales;
- se decodifica con validación estricta y **se vuelve a codificar exactamente al mismo texto**, lo que rechaza bits de relleno no canónicos (`"aGVsbG9="`);
- el resultado es ASCII imprimible con al menos 4 caracteres distintos.

### Hexadecimal estricto

`hex-strict-v1`: longitud par de al menos 8, solo `0-9a-fA-F`, no formada solo por dígitos decimales (`2147483647` es hexadecimal válido, pero es un número), y resultado ASCII imprimible con al menos 4 bytes y 4 caracteres distintos.

Los mínimos de Base64 y hexadecimal salen de dos rondas de medición. En la primera, todo el ruido eran identificadores de 8 letras (`fileType`) y relleno repetitivo (`44444444444444` → `DDDDDDD`). En la segunda quedaban un identificador de 12 letras sin relleno (`SystemEventW`) y ocho números decimales, que motivan las dos reglas finales.

### XOR anclado por diferenciales

`xor-repeating-v1`: XOR con claves repetidas de 1 a 8 bytes sobre los bytes crudos de la muestra, en ASCII y UTF-16LE.

**Invariante.** Si `c[i] = p[i] ⊕ k[i mod L]`, entonces `c[i] ⊕ c[i+L] = p[i] ⊕ p[i+L]`: el diferencial con retardo `L` del texto cifrado no depende de la clave. Buscar el diferencial de una cadena de referencia (una *crib*) en el diferencial del archivo la encuentra **bajo cualquier clave de periodo `L` en una sola pasada**, sin enumerar claves.

Para cada crib y cada retardo:
1. El patrón de la crib solo se usa si tiene **al menos 5 bytes no nulos**: un cero del diferencial coincide con cualquier racha de bytes repetidos.
2. Se **rechaza la aparición si la ventana del archivo ya es texto**. Es la regla que elimina los falsos positivos texto⊕texto.
3. La clave se deriva de los bytes (`K[j] = datos[i+j] ⊕ crib[j]`), se reduce a su periodo mínimo y se rechaza si es nula (sería la crib en claro, ya visible como cadena). Se reverifica byte a byte.
4. El texto descifrado se extiende a los dos lados mientras siga siendo imprimible, hasta 1.024 caracteres.

La clave no se elige entre candidatas por parecer texto: se deriva de los bytes. Cada resultado es exacto y cualquiera puede reproducirlo con la región, la clave y la crib publicadas.

**Reutilización de clave.** Una crib de *n* bytes solo verifica sola claves de hasta unos *n*−5 bytes. Tras la primera pasada, cada clave que alguna crib verificó por sí sola se busca en el resto de la muestra, para cribs más cortas. Se acepta una aparición solo si reproduce la crib completa bajo la misma clave, y el hecho cita la decodificación que la estableció. Es el caso habitual en malware: las tablas de cadenas cifradas suelen compartir una clave.

**Catálogo de anclas `lupabin-xor-cribs-v3`** (62 cribs, fijado por digest): cadenas neutrales frecuentes en binarios Windows, elegidas por longitud y no por significado. Por ejemplo `http://`, `kernel32.dll`, `GetProcAddress`, `This program cannot be run in DOS mode`, `User-Agent: ` y fragmentos de rutas y registro (`\Microsoft\`, `\CurrentControlSet\`, `SOFTWARE\`…). Los fragmentos de rutas se eligieron sobre cadenas reales de binarios benignos, con una mitad para elegir y otra reservada para medir. Encontrar una crib no demuestra ninguna capacidad.

**Qué no se encuentra.** Un texto cifrado sin ninguna crib del catálogo. Un XOR que deja el texto cifrado todavía legible (claves pequeñas por debajo de 0x80), porque sin puntuar la plausibilidad es indistinguible de un artefacto texto⊕texto; esos bytes siguen visibles como cadena. Tampoco Base32, ROT, compresión, RC4 ni XOR rodante.

### Mediciones de la decodificación

**Falsos positivos.** 0 en XOR y 0 en Base64/hexadecimal sobre más de 30.000 archivos benignos (unos 13 GB). Variantes medidas y descartadas por añadir errores:

| Variante | Resultado |
| --- | --- |
| XOR sobre las cadenas ya extraídas, aceptando claves cuyo resultado es imprimible | Ruido estructural: una cadena imprimible admite de media 24–37 claves "válidas", y una URL cifrada con un byte no es imprimible en el 83 % de las claves, así que nunca se extrae como cadena |
| 4 bytes verificados contando ceros, sin reglas de rechazo | 167 falsos positivos en 400 archivos |
| 5 bytes no nulos, sin la regla de ventana ya-texto | 46 falsos positivos en 4.092 archivos |
| Patrones débiles (3–4 bytes) confirmados por una racha descifrada de 16 caracteres | 402 falsos positivos en 4.092 archivos |
| Nivel débil de 2–4 bytes con clave con un byte ≥ 0x80 | Entre 61 y 52.119 falsos positivos en 1.500 archivos |

**Cobertura XOR** (43 textos realistas por categoría escritos sin mirar el catálogo, 10 de ellos sin ninguna crib; cada uno cifrado y plantado en una DLL real, 150 pruebas por celda). "Compartida" significa que otra cadena usa la misma clave:

| Clave | ASCII, sola | ASCII, compartida | UTF-16LE, sola | UTF-16LE, compartida |
| --- | --- | --- | --- | --- |
| 1 byte, uniforme 1–255 | 71,3 % | 67,3 % | 77,3 % | 79,3 % |
| 1 byte, ≥ 0x80 | 87,3 % | 88,7 % | 86,7 % | 85,3 % |
| 2 bytes | 76,0 % | 71,3 % | 82,7 % | 82,7 % |
| 4 bytes | 63,3 % | 84,7 % | 87,3 % | 85,3 % |
| 8 bytes | 36,7 % | 92,0 % | 62,0 % | 87,3 % |

Sobre 16.193 rutas y claves de registro reales, reservadas y no usadas para elegir las anclas, se recupera un 41–53 % con claves de 1 a 4 bytes. Una ruta aislada en ASCII con clave de 8 bytes casi nunca (6 %): las anclas de rutas miden menos de 13 caracteres.

**Ofuscación real encontrada en software benigno**, que muestra que el método funciona fuera de los tests: una DLL completa embebida y cifrada con `0xCC` en MATLAB, rutas de registro cifradas con una clave de 3 bytes en su gestor de licencias, URLs negadas bit a bit (`0xFF`) en una DLL de Epson, recursos con el bit alto activado (`0x80`) en Office, una ruta de registro en UTF-16LE bajo la clave `7f520e51` en `ci.dll` y `PEAuth.sys`, y en Base64 una cabecera JWT y texto en inglés. Ninguna prueba intención maliciosa: son transformaciones reproducibles de los bytes.

**Coste.** La primera pasada sobre 20 MiB tarda unos 3 s. El peor caso con la reutilización de ocho claves termina en unos 10 s dentro del contenedor, lejos del límite de 30 s. La búsqueda se detiene a los 10 s de análisis y lo declara (`decode_time_limit`).

## Llamadas a funciones importadas

LupaBin recorre el código máquina x86 y x64 dentro del worker, con capstone, que solo traduce bytes a instrucciones. No hay estado de ejecución, memoria simulada ni saltos tomados. Se descartó capa porque su motor por defecto emula instrucciones.

**Recorrido.** Descenso recursivo por las secciones ejecutables desde puntos de partida que escribe el compilador o el enlazador: el punto de entrada, los exports, los callbacks TLS, `.pdata` (x64), la tabla de funciones de Control Flow Guard y los manejadores SafeSEH (x86). Se siguen los destinos directos de `call`, `jmp` y saltos condicionales. De los saltos indirectos solo se siguen las tablas de `switch` que se pueden comprobar (abajo); no se adivinan tablas de salto ni inicios de función.

**Cuatro formas de llamada**, cada una comprobable con aritmética sin desensamblador: `direct` (`call [casilla]`), `thunk` (`call rel32` a un `jmp [casilla]`), `register` (`mov reg, [casilla]` justo antes de `call reg`) y `tail` (un `jmp [casilla]` que termina un tramo de código: una llamada en cola, en la que la función importada vuelve a quien llamó al código que salta). Un `jmp [casilla]` que empieza su tramo es un thunk y no se cuenta dos veces. El propio informe rehace la aritmética, y el host compara los bytes con la muestra.

**Tablas de `switch`.** Un salto indirecto solo se sigue cuando las instrucciones justo anteriores tienen la forma que emite MSVC para una tabla acotada: la comparación con la cota (`cmp índice, N; ja`), la lectura de la tabla y el salto, con como mucho 1.024 entradas. Cada entrada tiene que superar una comprobación que da el propio archivo:
- en x86 la tabla guarda direcciones absolutas, así que el enlazador marca cada entrada con una reubicación; una entrada sin ella no es un puntero a código y la tabla no se sigue (un ejecutable sin reubicaciones no tiene tablas);
- en x64 cada destino tiene que estar dentro de la misma función de `.pdata` que el salto.

**Campos reubicados.** Una instrucción real nunca empieza dentro de un campo que el enlazador reubica ni lo parte. Si el recorrido decodifica una así, ha salido del código (por ejemplo, tras una llamada que no vuelve, hacia los datos de una tabla) y ese tramo se detiene. Se encontró al medir las tablas: en `urlmon.dll` una tabla correcta llevaba a un `case` que termina en una llamada que no vuelve, y el recorrido seguía hasta decodificar los datos de la tabla como código.

**Medición** (1.363 binarios de System32 y 520 de SysWOW64): 0 informes inválidos y 0 fallos de verificación. El 92,5 % de los imports por nombre en x64 y el 92,6 % en x86 tienen alguna llamada localizada. En x86, añadir la tabla de Control Flow Guard como punto de partida lo subió del 43,8 % al 91,1 %, y las llamadas en cola y las tablas, al 92,6 %. En x64 las llamadas en cola y las tablas lo subieron del 90,4 % al 92,5 %.
- Llamadas en cola: 18.114 en System32 y 1.134 en SysWOW64. En x64 aparecen fuera de `.pdata`, porque una función hoja que termina con un salto no reserva pila ni llama a nada, y Microsoft no le da entrada; se revisaron a mano ejemplos, todos auténticos. Las demás formas siguen con 0 llamadas fuera de `.pdata` (las 3 de `edit.exe` son auténticas).
- Tablas de `switch`, en una muestra de 66 binarios de SysWOW64: 444 tablas y un 2,1 % más de código recorrido, con 0 instrucciones solapadas. En 69 de System32: 25 tablas.
- Instrucciones solapadas (un inicio que cae dentro de otra instrucción), el indicador de un recorrido que se sale del código: 0 en la muestra x86. En la de x64 quedan 18 en un solo binario, un flujo desalineado anterior a estos cambios, sin ninguna llamada a una función importada.
- En una llamada en cola solo se leen argumentos de registro en x64: la dirección de retorno ya está en la pila, así que las ranuras de la pila están 8 bytes más allá que en una llamada, y en x86 los `push` anteriores no son argumentos de la función. Revisión manual de 30 argumentos de llamadas en cola, desensamblando cada tramo: 30 correctos.

**Límite principal.** El código al que solo se llega por saltos o llamadas indirectos que no son una tabla de `switch` comprobable (vtables, callbacks, tablas de otros compiladores) no se recorre si ninguna tabla del compilador lo declara. Un binario empaquetado solo muestra su desempaquetador.

## Argumentos constantes

Para las 72 entradas del catálogo `lupabin-api-semantics-v4` (registro, servicios, procesos, bibliotecas, archivos, red, sincronización, memoria y criptografía; firmas, anchos y DLL comprobados en Microsoft Learn y en las cabeceras del Windows SDK), LupaBin lee con qué constantes se llama a la función.

**Método.**
- Un valor se recupera solo si una instrucción del mismo tramo lineal, anterior a la llamada, lo fija con una forma canónica y nada lo cambia después. Una llamada intermedia reinicia el seguimiento, porque los registros de argumentos son volátiles, y cualquier entrada de otro camino en medio también.
- x86: `push imm32` y `push imm8`. x64: `lea r64, [rip+disp32]`, `mov` de un inmediato y `xor r32, r32`. Del quinto argumento en adelante, en x64, la escritura canónica en la ranura `[rsp+8·i]`, directa o copiando un registro fijado en el tramo.
- Solo se confía en capstone para una lista revisada de instrucciones. Cualquier otra olvida todo. Las escrituras en memoria se deciden por la semántica de x86, porque capstone marca como lectura el destino de `movups` y `movq`. Una escritura en memoria con una base que no sea `rsp` ni `rip` olvida todas las ranuras de la pila.
- No se propagan valores entre registros (`mov rcx, r15`).
- Tipos: una clave `HKEY` solo si es una de las cinco predefinidas que Learn lista; un entero módulo el ancho del parámetro; una cadena solo si es ASCII imprimible, no vacía, terminada en NUL y en una sección que no se puede escribir.

**Medición** (mismos 1.883 binarios): 72.358 argumentos publicados, 0 informes inválidos y 0 fallos de bytes. Indicadores de error revisados sobre todos los casos, no sobre una muestra:
- ninguna clave `HKEY` recuperada era errónea;
- ningún entero con valores documentados sale de su conjunto por un error de seguimiento (el único valor fuera, `dwProvType = 0` en certreq.exe, es auténtico);
- ningún puntero rechazado señala algo que no sea el argumento: son `NULL`, ordinales de `GetProcAddress`, cadenas vacías, búferes sin inicializar o cadenas en secciones escribibles.

Las revisiones manuales, desensamblando cada tramo, dieron 213 correctos de 213: 60 de `RegOpenKeyEx` y `RegCreateKeyEx`, 30 nombres de `GetProcAddress`, 30 argumentos de la pila en x64 y 93 del resto del catálogo.

**Límite conocido.** La línea de órdenes de `CreateProcessW` nunca se lee: Learn exige que esté en memoria escribible, y una cadena escribible puede cambiar antes de la llamada.

### Misma variable local

`RegOpenKeyEx(…, &clave)` deja la clave que abre en una variable local cuya dirección recibe (`phkResult`), y `RegSetValueEx(clave, …)` la usa después. Cuando las dos llamadas nombran la misma variable (un desplazamiento del registro de marco: `[ebp-0x8]` en x86, `[rsp+0x30]` o `[rbp-0x10]` en x64), LupaBin publica un enlace entre ellas (`local_link`), pero solo si el camino entre ambas la conserva:
- la instrucción que lee la variable solo se alcanza desde la primera llamada, sin otro camino que entre en medio;
- ninguna instrucción intermedia cambia el registro de marco, escribe en la variable, vuelve a tomar su dirección ni salta de forma incondicional; se admiten otras llamadas;
- una escritura a través del otro registro de la pila (`esp` para una variable de `ebp`; `rbp` o `rsp` en x64) cuenta como escritura en la variable, porque los dos apuntan al mismo marco a una distancia que el código no dice;
- en x64 no se admite una variable de las cuatro primeras ranuras de la pila, que según Microsoft pertenecen a la función llamada, y la lectura tiene que estar a menos de 4.096 bytes.

**Medición.** En una muestra de 1 de cada 6 binarios de SysWOW64, el 73 % de las llamadas que abren una clave pasan la dirección de una variable reconocible, y de 1.673 parejas candidatas el camino conserva la variable en 635. Casi todas las rechazadas (892) lo son porque otro camino entra entre las dos llamadas. En 1 de cada 20 binarios de System32 salen 122 enlaces. Revisión manual, desensamblando el tramo entre las dos llamadas: 30 de 30 correctos en x86 y 30 de 30 en x64, incluidos casos con varias llamadas intermedias y con escrituras en variables vecinas.

**Coste.** Cada llamada que lee una clave busca por bisección la última llamada anterior que escribió en esa variable. El peor caso sintético, 4.096 llamadas publicadas en las que cada una lee la variable que escribió la anterior y la vuelve a escribir, tarda 6,5 s en el contenedor y 14,4 s en total, con las explicaciones. Llena el cupo de hechos del informe, y el informe lo declara (`evidence_budget`).

### Nota de cobertura del recorrido

Cuando el recorrido decodifica pocas instrucciones para el tamaño del código, una explicación lo pone en contexto (`code.walk_density@1`). Solo se aplica con al menos 64 KiB de código nativo, recorrido completo y un binario que no sea .NET. Umbral: 20 instrucciones por KiB, por debajo del cual se queda el 0,28 % de los binarios benignos medidos. Con un mínimo de solo 4 KiB, incluso un umbral de 5 por KiB saltaba en uno de cada quince binarios benignos (distribuciones de teclado, DLL de recursos), y se descartó. No demuestra empaquetado.

## Explicaciones y glosario

Las explicaciones se generan en el host a partir de un informe ya validado, nunca en el worker. Cada frase es una regla pura de sus citas: sus valores salen solo de los campos de los hechos citados, lleva su texto de límite (qué no demuestra) y remite al glosario. Al validar, cada frase se regenera desde sus citas y se exige igualdad exacta. Una frase hereda el nivel más débil de lo que cita.

El glosario es conocimiento general, nunca una afirmación sobre la muestra. Cada entrada tiene al menos una fuente editorial (Microsoft Learn, RFC, MITRE ATT&CK, la documentación de YARA) comprobada, y el catálogo va fijado por digest.

**Familias de APIs.** Nueve listas curadas de nombres exactos (`lupabin-api-families-v1`), cada una con sus páginas de Learn. La explicación dice qué imports aparecen en la lista, nunca que la muestra haga algo, y da su frecuencia en 55.035 binarios benignos:

| Familia | Binarios benignos que la importan |
| --- | --- |
| Carga dinámica de bibliotecas | 34,8 % |
| Comprobación de depuradores | 32,2 % (sobre todo `IsDebuggerPresent`, del runtime de C de Microsoft) |
| Registro de Windows | 10,6 % |
| Creación de procesos | 4,8 % |
| Memoria de otros procesos | 3,7 % |
| Criptografía | 3,0 % |
| Sockets de red | 2,1 % (los imports por ordinal de ws2_32 no se cuentan) |
| Servicios de Windows | 1,7 % |
| HTTP y descargas | 1,0 % |

**Texto de la muestra.** Todo texto que procede de la muestra o de VirusTotal se neutraliza antes de mostrarse: caracteres de control, secuencias de escape de terminal y caracteres de dirección (bidi) se sustituyen por marcas visibles. En Markdown, las cadenas van en bloques de código que no pueden inyectar enlaces ni HTML.

## Capacidades

### Qué se puede afirmar y qué no

Una capacidad es una frase sobre lo que el código **contiene**, construida a partir de llamadas y argumentos constantes ya verificados. Por ejemplo: "el código contiene una llamada que crea el servicio «X», con arranque automático, cuyo binario es «C:\…»". No afirma que el programa lo haga: eso depende de condiciones y entradas que el análisis estático no resuelve. Tampoco afirma intención: una clave `Run` o memoria ejecutable y escribible aparecen en programas legítimos, y cada capacidad da su frecuencia en binarios benignos.

### Explicaciones, no hechos nuevos

Las capacidades son reglas de explicación del host, no un tipo de hecho. Salen de hechos que el informe ya valida, se regeneran al validar y son `inferred`, porque los argumentos lo son. Cada regla cita **todos** los casos del informe que cumplen su condición, con todos sus argumentos: no puede ocultar llamadas que no encajan con la frase. Una condición que necesita un argumento no publicado no se cumple, y lo que no se sabe (la raíz de una clave, el proceso de destino) se dice.

### Catálogo de capacidades

Catálogo `lupabin-capabilities-v3` (`src/lupabin/explain/capabilities.py`), fijado por digest. Las constantes de Windows se copian de las cabeceras del Windows SDK 10.0.26100.0. La frecuencia es el porcentaje de binarios con algún caso sobre 3.087 PE benignos (System32, SysWOW64 y Program Files).

| Capacidad | Condición | ATT&CK | Binarios benignos |
| --- | --- | --- | --- |
| Escribir un valor en una clave `Run` | `RegSetKeyValue` sobre `…\CurrentVersion\Run`, `RunOnce`, `RunServices`, `RunServicesOnce`, `…\Policies\Explorer\Run` o `RunOnceEx` (solo bajo `HKEY_LOCAL_MACHINE`, con sus subclaves) | T1547.001 | 0 |
| Abrir una clave `Run` para escribir | `RegOpenKeyEx`/`RegCreateKeyEx` con un permiso que incluya `KEY_SET_VALUE`, `GENERIC_WRITE` o `GENERIC_ALL` | — | 9 (0,29 %) |
| Abrir una clave `Run` y escribir un valor en el mismo rango de función | Las dos llamadas anteriores dentro de un mismo rango de `.pdata` (x64) | T1547.001 | 5 (0,16 %) |
| Escribir un valor en `Winlogon` | `RegSetKeyValue` sobre `…\Windows NT\CurrentVersion\Winlogon` | T1547.004 solo para `Shell`, `Userinit` o la subclave `Notify` | 0 |
| Abrir `Winlogon` para escribir | Como la clave `Run` | — | 1 (0,03 %) |
| Abrir `Winlogon` y escribir en el mismo rango de función | Como la clave `Run` | T1547.004 solo para `Shell` o `Userinit` | 0 |
| Crear un servicio | `CreateService` con nombre o binario conocidos | T1543.003 | 2 (0,06 %) |
| Ejecutar un programa u orden, o pedir al shell que abra algo | `WinExec`, `CreateProcess` o `ShellExecute` con el programa, la orden o el destino conocidos | T1059.003 (`cmd`) o T1059.001 (`powershell`, `pwsh`) | 26 (0,84 %) |
| Descargar una URL a un archivo | `URLDownloadToFile` con la URL o el archivo conocidos | T1105 | 0 |
| Servidor o URL de destino | `InternetConnect`, `WinHttpConnect` o `InternetOpenUrl` | — | 3 (0,10 %) |
| Agente de usuario | `InternetOpen` o `WinHttpOpen` con agente | — | 39 (1,26 %) |
| Memoria ejecutable y escribible | `VirtualAlloc(Ex)` o `VirtualProtect(Ex)` con `PAGE_EXECUTE_READWRITE` o `PAGE_EXECUTE_WRITECOPY`; se aceptan los modificadores documentados y se abstiene con cualquier otro bit | — | 72 (2,33 %) |
| Abrir un proceso con derechos sobre su memoria | `OpenProcess` con `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION` o `PROCESS_ALL_ACCESS` | — | 22 (0,71 %) |
| Mover o borrar un archivo al reiniciar | `MoveFileEx` con `MOVEFILE_DELAY_UNTIL_REBOOT` | — | 9 (0,29 %) |
| Mutex con nombre | `CreateMutex`/`OpenMutexW` con nombre | — | 105 (3,40 %) |
| Algoritmo o proveedor criptográfico | `BCryptOpenAlgorithmProvider` con algoritmo o `CryptAcquireContext` con proveedor | — | 152 (4,92 %) |

Reglas comunes del registro:
- La raíz de la clave solo se nombra si `hKey` se recuperó. Si no, la frase dice que está bajo una clave que no se pudo determinar.
- `MAXIMUM_ALLOWED` no cuenta como permiso de escritura: puede no concederla.
- `RegOpenKey` y `RegCreateKey` no cuentan, porque no reciben un permiso.
- `RegCreateKeyEx` necesita el mismo permiso de escritura que `RegOpenKeyEx`: la clave `Run` existe siempre, así que crearla para leer equivale a abrirla para leer.

Se descartó "carga la biblioteca X" como capacidad: aparece en el 53 % de los binarios benignos, así que no distingue nada.

### MITRE ATT&CK

Una técnica solo se asocia cuando el mecanismo del caso coincide con su definición, nunca por parecido:
- escribir un valor en una clave `Run` es T1547.001; abrirla para escribir, sin ver la escritura, no;
- memoria ejecutable y escribible no es, por sí sola, inyección de procesos;
- ejecutar `rundll32`, `regsvr32` o `mshta` no es T1218.x, que describe su abuso para ejecutar código encubierto; Windows y muchos programas los invocan legítimamente;
- `wscript` y `cscript` quedan sin técnica, porque la llamada no dice si ejecutan VBScript (T1059.005) o JScript (T1059.007).

Coincidir con una técnica no demuestra intención: muchos programas legítimos usan el mismo mecanismo. Cada técnica tiene su entrada de glosario con su página de attack.mitre.org.

### Mismo rango de función

Abrir una clave y escribir en ella son dos llamadas. Para decir que están en la misma función sin adivinar límites, LupaBin usa la tabla `.pdata` de x64, que escribe el compilador: cada entrada declara el inicio y el fin de un tramo contiguo de una función, y el host comprueba sus 12 bytes contra la muestra. Se descartaron la distancia entre llamadas (adivina límites), la región alcanzable desde un inicio de función (el host no la puede comprobar sin desensamblador) y la tabla de Control Flow Guard (da inicios, no finales).

La frase dice "en el rango 0x…–0x… que declara `.pdata`", porque un archivo puede declarar una tabla falsa, y añade que no se sabe si la escritura usa la clave abierta, porque no se sigue el identificador entre llamadas. En los 5 casos del corpus benigno, revisados por desensamblado, las 6 escrituras usan la clave que la otra llamada abrió. Solo x64: en x86 no hay `.pdata` y esta capacidad nunca se reconoce.

### Revisión de los casos

Los 821 casos que dan las capacidades en los 3.087 binarios benignos se revisaron uno a uno: **ninguna frase describe algo que sus argumentos no digan**. Abstenciones contadas, que cuestan cobertura y no errores: 190 llamadas a `CreateProcessW` sin nombre de aplicación, cuya línea de órdenes no se lee (el resumen del informe lo avisa), y una clave `Run` cuyo permiso no se recuperó.

El informe abre con un resumen, "qué contiene el código", que agrupa las capacidades por táctica y termina con los avisos que lo limitan: no se reconoció ninguna (y eso no demuestra nada), el recorrido es incompleto o poco denso, o hay líneas de órdenes que no se leen.

## VirusTotal

VirusTotal aporta lo que LupaBin no obtiene sin ejecutar la muestra: veredictos de motores antivirus y comportamiento observado en sus sandboxes. Nada de eso lo verifica LupaBin, así que va en un documento aparte (`VirusTotalReport`), se muestra en su propia sección como fuente externa y siempre atribuido ("N motores lo marcan", "en los sandboxes de VirusTotal se observó"). "VirusTotal no conoce este archivo" no significa nada sobre su peligrosidad.

- La consulta se hace desde el host, nunca desde el worker, y solo a `https://www.virustotal.com/api/v3/`, con TLS, sin seguir redirecciones y con tiempo y tamaño de respuesta acotados.
- Primero se consulta por SHA-256. Si VirusTotal no conoce el archivo, se sube con un aviso: su contenido puede compartirse con los clientes de pago de VirusTotal. La subida se desactiva con `--no-upload-to-virustotal` o `LUPABIN_VIRUSTOTAL_UPLOAD=off`, y la consulta entera con `--no-virustotal` o `LUPABIN_VIRUSTOTAL=off`.
- El archivo sube con el nombre genérico `sample`. La clave se lee de `VT_API_KEY` o de un `.env` que ni git, ni el paquete ni la imagen incluyen, y nunca aparece en la salida.
- La respuesta es un dato no fiable: solo se extraen los campos esperados, con tipos comprobados y listas acotadas, y todo texto se neutraliza.

## Interfaz web

La web es otra forma de usar `lupabin analyze`: cada archivo se analiza en un contenedor nuevo, igual que en la CLI, y se muestra el mismo informe. No guarda ni la muestra ni el informe, no pone cookies, no carga nada de terceros y no registra accesos. Todo texto de la muestra o de VirusTotal se neutraliza en el servidor y el navegador lo inserta solo como texto, con una política de seguridad de contenido sin código en línea.

El servicio escucha solo en `127.0.0.1`, detrás de Caddy, y systemd lo aísla. Su usuario pertenece al grupo `docker`, que en la práctica equivale a administrador en esa máquina: por eso debe desplegarse en un servidor dedicado ([guía de despliegue](deploy.md)). Límites por defecto: 20 MiB por archivo, 6 análisis por IP cada 10 minutos, entre uno y tres análisis a la vez según la memoria y las CPU del servidor, y una cuota de VirusTotal compartida por todo el servidor (4 peticiones por minuto y 500 al día con la API pública).

## Límites conocidos

- **Código.** Solo x86 y x64. De los saltos indirectos solo se siguen las tablas de `switch` de MSVC comprobables; vtables y callbacks no. Tras una llamada que no vuelve, el recorrido sigue en línea recta: en x86 los campos reubicados lo detienen, pero en x64 puede decodificar bytes que no son código. Un binario empaquetado muestra poco más que su desempaquetador.
- **Argumentos.** No se propagan valores entre registros. Un identificador solo se sigue entre dos llamadas a través de una variable local y en un camino recto (sección «Misma variable local»). La línea de órdenes de `CreateProcessW` no se lee.
- **Decodificación.** Sin una crib del catálogo no hay resultado. Una cadena aislada con clave de 8 bytes se recupera en el 37 % de los casos en ASCII y el 62 % en UTF-16LE.
- **Familias de APIs.** Solo reconocen imports por nombre exacto, no por ordinal.
- **Idioma.** Las explicaciones y el glosario están en español.
- **Fuentes externas.** Las páginas que cita el glosario pueden moverse: `tests/check_glossary_sources.py` lo comprueba con red, fuera de la CI.
- **Tiempo.** En una máquina lenta, los binarios más grandes pueden quedar parciales en XOR o en código, y lo declaran con su código.

## Repetir las mediciones

Las herramientas están en `tests/` y no forman parte del paquete ni de la CI. Reciben un directorio de binarios benignos que aporte quien evalúa, y los leen como datos:

- `uv run python -m tests.decode_eval false-positives <dir>` y `recall <dir>`: falsos positivos y cobertura de la decodificación.
- `uv run python -m tests.code_eval corpus <dir>`: llamadas, argumentos, verificación de bytes y tiempos; `worst` mide los peores casos sintéticos: los de 20 MiB y uno con tantas llamadas enlazadas por una variable local como se pueden publicar.
- `uv run python -m tests.capability_eval corpus <dir>`: frecuencia de cada capacidad; `review` lista cada caso para revisarlo.

Cambiar un umbral, una condición, un catálogo o una redacción exige una nueva versión fijada por digest, repetir la medición y revisar los casos a mano.
