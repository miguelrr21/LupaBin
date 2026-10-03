# Cómo trabaja LupaBin: método y límites medidos

Este documento explica cómo obtiene LupaBin cada hecho y cada frase, por qué se eligió cada método y qué se midió antes de adoptarlo. El formato exacto de los hechos está en el [contrato de evidencias](evidence-schema.md).

**Cómo se mide.** Todas las cifras de este documento se tomaron sobre binarios benignos de Windows: System32, SysWOW64, drivers, .NET, Program Files y Program Files (x86), según la medición. Se leyeron como datos en el host; nunca se ejecutaron ni se añadieron al repositorio. Sobre ellos, un resultado que no se reproduce o una frase que no describe lo que dicen los bytes cuenta como error. Cada caso señalado se revisó a mano. Una variante que subía la cobertura pero añadía errores se descartó, y aquí se dice cuáles. Las mediciones se repiten con las herramientas de [Repetir las mediciones](#repetir-las-mediciones).

## Principios

- **La muestra nunca se ejecuta ni se emula.** Se leen sus bytes dentro de un contenedor sin red, sin privilegios y con límites de memoria, CPU y tiempo.
- **Hechos observados e inferencias, separados.** Un hecho `observed` está escrito en el archivo (una entrada de la tabla de imports, una instrucción de llamada). Uno `inferred` sale de aplicar un método a los bytes (un texto decodificado, el valor constante de un argumento).
- **Abstenerse antes que inventar.** Lo que no se puede determinar se dice. Un resultado vacío no demuestra que algo falte.
- **Sin puntuaciones de riesgo ni veredictos.** LupaBin no dice si un archivo es malicioso. La corrección de ejercicios puntúa únicamente las respuestas del estudiante.
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

El host compara también los bytes conservados de cada cadena con el intervalo original, tanto al recibir al worker como al contrastar un informe guardado mediante `--sample`. Modificar texto y hexadecimal en un informe manteniendo sus hashes no evita esta comprobación. Se verifica el fragmento publicado, no la maximalidad de la cadena, su longitud total no capturada ni que el extractor haya publicado todas las cadenas.

### Anomalías estructurales

Comprobaciones de campos declarados, no una reproducción del cargador de Windows:
- rango de datos de una sección fuera del archivo;
- solapamiento de rangos físicos entre secciones;
- solapamiento de rangos virtuales entre secciones (con `max(VirtualSize, SizeOfRawData)`);
- extensión virtual mayor que `SizeOfImage`;
- punto de entrada no nulo fuera de `SizeOfImage`.

Cada anomalía cita las cabeceras y secciones que la sustentan, y el modelo comprueba que el predicado se cumple sobre sus valores. Los intervalos vacíos no son solapamientos. Un warning genérico de pefile no se convierte en una anomalía concreta: se conserva como limitación y deja la cobertura parcial.

### Marcas de compilador

Bytes que una herramienta deja en todo lo que produce (catálogo `lupabin-toolchains-v1`). Sirven para leer el resto del informe: parte del código y de las funciones importadas la añade el compilador, no el autor. Solo se publica una marca con la forma exacta del catálogo y en el sitio donde su herramienta la pone; una candidata que falla cualquier comprobación se descarta, sin puntuarla:

- **Cabecera Rich** (enlazador de Microsoft): entre la cabecera MS-DOS y la cabecera PE, de «DanS» a «Rich». Se recalcula su checksum, que el enlazador obtiene de los bytes anteriores (sin `e_lfanew`) y de cada entrada, y solo se publica si coincide.
- **Marca de GCC**: el texto «GCC: (…» que GCC añade a cada archivo que compila, dentro de los datos de una sección. Cada texto distinto se publica una vez, hasta ocho.
- **Arranque de MinGW-w64**: el mensaje «Mingw-w64 runtime failure:», dentro de los datos de una sección. Ese código de arranque usa `VirtualQuery` y `VirtualProtect` para aplicar las pseudo-relocations: por eso un programa de MinGW-w64 las importa aunque su autor no las use.
- **Información de compilación de Go**: la cabecera «\xff Go buildinf:», con RVA múltiplo de 16 e indicadores que Go define, y la versión si la guarda en línea (Go 1.18 o posterior).
- **Cabecera CLR (.NET)**: la que señala el directorio 14 de la cabecera PE, que empieza por su tamaño, 72. El análisis de código de LupaBin no ve el IL de .NET, y la explicación lo dice.
- **Cookie de PyInstaller**: los 88 bytes que cierran el archivo que PyInstaller añade al ejecutable, después de todas las secciones y con una estructura coherente (tabla de contenidos dentro del archivo, nombre de la biblioteca de Python imprimible).

Todas son `observed`: los bytes están ahí. Ninguna dice quién hizo el programa ni qué hace, y cualquiera puede copiarse, quitarse o fabricarse; que no aparezca ninguna no significa nada.

**Mediciones** (2026-09-26, binarios benignos de Windows). La búsqueda de las seis firmas recorrió 54.899 PE de System32, SysWOW64 y Program Files; la cadena completa (informe validado, comprobación de los bytes en el host y regeneración de cada explicación) se ejecutó sobre 19.046 de ellos sin ningún fallo. Se revisaron uno a uno los casos de Go y de PyInstaller y las combinaciones inesperadas:

- **Rich**: el checksum coincide en 24.021 de las 24.073 cabeceras encontradas. Las 52 restantes (51 binarios de VirtualBox y `tcblaunch.exe`) no se publican.
- **Go**: la firma aparece en 53 binarios de Program Files. En 30 está alineada, con indicadores válidos y una versión legible, y los 30 son programas de Go (Docker, Tailscale, git-lfs y herramientas de JetBrains y MATLAB). En los otros 23 está desalineada y con indicadores inválidos: son programas de Git para Windows escritos en C (y su copia dentro de Visual Studio), y se descartan. Esta es la razón de exigir la alineación.
- **PyInstaller**: 12 binarios con cookie, todos hechos con PyInstaller. En 7 de ellos la firma también está dentro del propio cargador, como constante para buscarla; solo cuenta la cookie de después de las secciones.
- **GCC y Rich a la vez**: 2 DLL de JNA enlazadas con el enlazador de Microsoft que incluyen un objeto compilado con GCC. Las dos marcas son ciertas.

## Cobertura, estados y abstención

Cada extractor declara la cobertura de cada componente: `complete`, `partial` o `blocked`, con contadores y motivos. Un directorio de imports ausente puede tener cobertura completa con cero hallazgos; una tabla que no se pudo leer, nunca. Detectar una anomalía no significa que el análisis fallara: puede haberse comprobado bien una inconsistencia.

El estado global se calcula por cobertura, no por el número de hallazgos: `completed` si todas las fuentes completan, `failed` si todas quedan bloqueadas y `partial` en los demás casos. Un fallo de un componente no borra los hechos válidos de otro. Un timeout o un agotamiento de memoria que termine el worker produce un error explícito, no un informe parcial inventado. Los errores y limitaciones identifican siempre su fuente y componente, sin rutas locales ni mensajes del parser.

## Retos autocorregibles

El módulo del host `lupabin.challenge` transforma un informe validado en preguntas tipo test, sin extraer nuevos hechos, sin LLM y sin red. Banco `lupabin-challenges-v1`, con textos fijados por digest y tipos propios 0.1.0, separados del contrato de hechos. La puntuación es un recuento de respuestas correctas, incorrectas y sin responder: no evalúa la muestra.

Se selecciona la primera evidencia aplicable de cada tipo en el orden del informe, como máximo una pregunta por regla (siete en total): `pe_header.number_of_sections`, significado de `section.raw_size`, qué acredita `import`, qué añade `api_call`, clasificación de `string`, clasificación de `decoded_string` y cómo interpretar un componente con cobertura `partial` o `blocked`. La pregunta identifica la evidencia concreta; no pregunta por un único valor global cuando hay varias secciones o cadenas. La regla de cobertura cita fuente, componente y estado mediante rutas de campos del informe y se marca como conocimiento `general`; las demás conservan `observed` o `inferred`. Sin una evidencia aplicable no se fabrica la pregunta, y un reto vacío no recibe nota. No se pregunta por malware, intención ni ejecución.

Cada pregunta ofrece tres alternativas distintas y una única respuesta aceptada. Los distractores son alternativas del ejercicio, nunca se agregan como hechos al informe. En la pregunta de `NumberOfSections` las alternativas son valores cercanos, y el valor declarado es el menor, el central o el mayor de los tres con la misma frecuencia (elegido de forma determinista), para que su posición no delate la respuesta. La corrección publica explicación, límite y citas con valores neutralizados por `render.safe`. El motor vuelve a validar el informe y regenera preguntas, opciones, respuesta y explicación: ni un `correct=true` editable ni el texto de una pregunta importada son autoridad. `validate` exige igualdad con el reto regenerado; `grade` solo acepta identificadores de preguntas y opciones del reto actual, rechaza duplicados y comprueba el vínculo al informe.

El identificador del reto deriva del banco (versión y digest), de un digest canónico del informe completo salvo los timestamps de inicio y fin y del contenido regenerado de preguntas y soluciones. Así, un cambio efectivo de selección o corrección invalida las respuestas anteriores incluso si no cambia el texto del banco. También se publica SHA-256 de la muestra y versión del contrato; la proyección web vincula el reto al digest del informe mostrado. Los IDs de pregunta son locales al reto, y el orden de las opciones es determinista. Una modificación de hechos, cobertura o límites cambia el vínculo aunque conserve el mismo hash de muestra. Cambiar los textos o la lógica de selección/corrección exige revisar las pruebas y versionar el banco; no hay migración automática de respuestas entre bancos o informes distintos.

**Límites de confianza y portabilidad.** La CLI puede exportar preguntas y plantilla de respuestas en JSON; solo importa el objeto de respuestas para corregirlo frente al informe original. No importa bancos ni solucionarios arbitrarios. Un informe guardado validado estructuralmente puede haber sido editado; la CLI conserva el aviso de origen y permite `--sample` para las comprobaciones de contraste disponibles, sin prometer autenticidad criptográfica. Los hashes vinculan documentos, no son firmas. La web no importa ni exporta sesiones de reto: calcula sus soluciones en el host junto con el informe y las manda al navegador para corregir localmente. Es posible inspeccionar las respuestas y alterar la nota local; no es un examen protegido. No hay almacenamiento persistente de respuestas, llamadas de red adicionales, certificados ni clasificación de estudiantes. Cambiar de informe o repetir reinicia la práctica; el JSON y Markdown del análisis permanecen intactos.

**Medición con la exportación a Ghidra (2026-09-30).** `tests/learning_eval.py` analizó con el worker Docker, de uno en uno, 398 ejecutables benignos (la misma selección por variedad que la medición de VirusTotal: System32, SysWOW64, Program Files y los dos programas de práctica; dos ya no existían). Para cada uno comprueba que el valor de cada cita de cada pregunta coincide con el campo del informe, que ninguna pregunta repite una opción, que la corrección da todas las respuestas por buenas con las soluciones y ninguna con las otras opciones, que exportar no altera el informe, que cada anotación cita un hecho existente y, cuando tiene ubicación, que el SHA-256 de su intervalo coincide con los bytes del archivo, que ninguna anotación contiene `{@` y que ningún hecho queda sin exportar. Resultado: 281 informes completos y 117 parciales, 1.223.622 anotaciones y 2.066 preguntas (398 de cabecera, 398 de sección, 387 de importación, 368 de llamada, 398 de cadena y 117 de cobertura); 0 errores. Con 398 archivos sin fallos, la tasa de error por archivo es menor del 0,75 % con un 95 % de confianza (regla de 3/n). Mide la coherencia del reto y de la exportación, no su valor pedagógico.

Las pruebas focalizadas `tests/test_challenge.py` y `tests/test_web_challenge.cjs` usan fixtures sintéticos y DOM simulado: comprueban campos citados, reglas, estados completos/parciales/fallidos, abstención, determinismo, alteraciones de identidad y opciones, texto hostil, corrección y conservación del informe. No son una medición de eficacia pedagógica ni una certificación de ausencia de errores.

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

Con el enlace, "abre la clave `Run` y escribe en ella" ya no depende de `.pdata` y funciona también en x86: la frase dice qué clave abre, qué valor escribe y por qué variable pasa el identificador, sin la advertencia de que no se sabe si la escritura usa la clave abierta. En el corpus de capacidades (3.090 binarios benignos) salen 7 casos, 4 en x64 y 3 en x86, todos en `RunOnce`: los 7 se revisaron por desensamblado y en todos la escritura usa la clave que abre la otra llamada. De los 5 pares que antes solo se reconocían por `.pdata`, 4 pasan a tener enlace.

### Nota de cobertura del recorrido

Cuando el recorrido decodifica pocas instrucciones para el tamaño del código, una explicación lo pone en contexto (`code.walk_density@1`). Solo se aplica con al menos 64 KiB de código nativo, recorrido completo y un binario que no sea .NET. Umbral: 20 instrucciones por KiB, por debajo del cual se queda el 0,28 % de los binarios benignos medidos. Con un mínimo de solo 4 KiB, incluso un umbral de 5 por KiB saltaba en uno de cada quince binarios benignos (distribuciones de teclado, DLL de recursos), y se descartó. No demuestra empaquetado.

## La función main

Un programa no empieza en su `main`: el punto de entrada es código de arranque que añade el compilador. Con la biblioteca `msvcrt.dll`, el arranque llama a `__getmainargs` (o a `__wgetmainargs`) con las direcciones de tres variables, y según Microsoft esa función «copia los argumentos para `main()` a través de los punteros que recibe». Después llama a `main` con los valores de esas tres variables: argc, argv y envp.

**Regla (`getmainargs-v1`).** Por cada llamada a esas funciones de `msvcrt.dll`, las formas canónicas de sus tres primeros argumentos (una `lea` relativa a RIP en x64, un `push imm32` en x86) dan tres direcciones. `main` es el destino de la **única** llamada directa (`call rel32`) de todo el código recorrido cuyos tres primeros argumentos se cargan de exactamente esas tres direcciones (`mov` desde `[rip+disp32]` a rcx, rdx y r8 en x64; `push dword ptr [dirección]` en x86), en el tramo lineal de la llamada y sin que nada los cambie antes de ella, con las mismas reglas de seguimiento que los argumentos constantes. Si ninguna llamada cumple la regla, o si la cumple más de una, LupaBin no dice nada. El host comprueba con los bytes que las direcciones coinciden y que el destino es el de la llamada.

**Alcance.** Con `main` encontrado, el código se recorre dos veces más, siguiendo solo llamadas y saltos con destino constante: desde `main` y desde el punto de entrada y las funciones TLS sin entrar en `main`. Lo que alcanza el primer recorrido forma parte del programa, aunque no lo haya escrito el autor (bibliotecas enlazadas, comprobaciones del compilador). Lo que solo alcanza el segundo es código de arranque del compilador: en un programa de MinGW-w64, por ejemplo, `VirtualProtect` y `VirtualQuery` (sus pseudo-relocations), `SetUnhandledExceptionFilter` o `_initterm`. Una llamada que no aparece en ninguno solo se alcanza por otros caminos, como las funciones de `.pdata`.

**Familias.** Con el alcance desde `main`, el informe dice de cuáles de las nueve familias de funciones de la lista curada (red, registro, procesos, servicios, criptografía…) hay llamadas alcanzables desde `main`, y de cuáles no se ve ninguna. Que no se vea ninguna no demuestra que el programa no haga eso: puede usar funciones que no están en la lista, cargarlas al ejecutarse o llegar a ellas por caminos que el recorrido no ve. En un programa de referencia que abre una clave del registro desde `main`, sale el registro; en los retos, ninguna.

**Abstenciones.** No se reconocen otros arranques: Visual Studio con la UCRT (`_get_initial_narrow_environment`), MinGW-w64 con la UCRT (su `__getmainargs` va dentro del programa) y el MinGW-w64 reciente de 32 bits, que llama a `__getmainargs` a través de una función propia y escribe los argumentos con `mov [esp+n]`. Tampoco los programas de ventanas (`WinMain`) ni los servicios, que llaman a `__wgetmainargs` pero entran en funciones con otros argumentos.

**Mediciones** (2026-09-26):

- **Programas de referencia**: 90 compilaciones propias e inofensivas con GCC 16 de MSYS2 (cinco programas, entre ellos uno con `wmain`; `-O0`, `-O2` y `-Os`; con y sin símbolos), cuyo `main` se conoce por la tabla de símbolos. Las 30 de x64 con `msvcrt.dll`: 30 aciertos. Las 30 de 32 bits y las 30 con la UCRT: abstención. Ningún `main` equivocado.
- **Ejecutables de Windows** (uno de cada cuatro de System32 y uno de cada tres de SysWOW64): de 259 ejecutables, 149 llaman a `__getmainargs` o `__wgetmainargs`; en 74 se encuentra `main` y en 75 LupaBin se abstiene (programas de ventanas y servicios, sobre todo). Ningún informe, comprobación ni explicación falló. Se revisaron a mano 20 de los encontrados (12 de 64 bits y 8 de 32), desensamblando el principio de la función: en 12 se ve cómo lee argc o argv en sus primeras instrucciones, y en los otros 8 no los usa al principio, algo que un `main` puede hacer. Ninguno contradice la regla. En ejecutables con más llamadas de las que caben en el informe (`git.exe`, `sppsvc.exe`), se publica `main` sin el alcance.
- **Los dos retos** (`reto_final.exe`, `reto_prueba.exe`, MinGW-w64 x64): `main` en `0x1528`, la función que compara la contraseña. Solo del arranque: 21 llamadas, entre ellas `VirtualProtect`, `VirtualQuery` y `SetUnhandledExceptionFilter`.
- **Coste**: en los ocho ejecutables más grandes que usan `__getmainargs` (de 2,5 a 4,8 MB), encontrar `main` y los dos recorridos de alcance añaden entre 0 y 0,5 s. Los recorridos comparten el plazo del recorrido principal: si no les da tiempo, el alcance no se publica y se dice por qué.

## Textos que usa el código

El barrido de cadenas publica todo lo que parece texto (476 cadenas en uno de los retos de prueba). Para saber cuáles usa el programa, LupaBin busca entre las instrucciones que decodificó el recorrido las que toman una dirección con una forma canónica (`lea` relativa a RIP en x64; `push imm32` o `mov r32, imm32` en x86) y publica, por cada cadena, la primera cuya dirección es **exactamente** el inicio de esa cadena publicada, en una sección que no se puede escribir (`string_reference`). El informe comprueba la dirección con los bytes de la instrucción y la sección de la cadena; el host, los bytes. Con `main` encontrado, cada alcance lista también las referencias cuyas instrucciones decodificó su recorrido.

En los dos retos de prueba, el código alcanzable desde `main` usa exactamente sus seis mensajes («Introduce la flag para ganar :)», «FELICIDADES, LLAMAME PARA RECLAMAR TU PREMIO!!!», «Acceso denegado, no es la flag correcta»…), y el arranque, los mensajes de error de MinGW-w64. Un puntero a la mitad de una cadena (el sondeo previo encontró «inity», dentro de «Infinity») no se publica, porque no es el inicio de ninguna cadena publicada.

No aparecen los textos que el código construye en la pila o descifra al ejecutarse, los que solo usa por caminos que el recorrido no ve, ni los de secciones que se pueden escribir, que pueden cambiar antes de usarse.

## UPX

UPX guarda casi todo el programa en un bloque comprimido y le añade un cargador que lo descomprime en memoria al arrancar. LupaBin descomprime ese bloque en estático, sin ejecutar nada, y publica lo que el propio bloque declara del programa original: sus secciones, su punto de entrada, su base y la lista de funciones que el cargador resuelve (`upx_image` y `upx_import`, componente `upx` de la fuente `pe`). Todavía no analiza el código descomprimido: las llamadas, los argumentos y las capacidades del informe siguen siendo los del cargador.

**Cómo se dedujo el formato.** Sin leer el código fuente de UPX ni el de UCL, cuya licencia es GPL. Se empaquetaron copias de programas benignos con `upx` 5.2.1, con los cuatro métodos que usa en Windows (NRV2B, NRV2D, NRV2E y LZMA), y se compararon byte a byte con los originales. Los descompresores de LupaBin están escritos a partir de esas observaciones; LZMA usa la biblioteca estándar de Python.

**Qué se exige.** La cabecera de 32 bytes que empieza por `UPX!` solo se acepta con la versión de UPX 5 (13), un formato `win32/pe` o `win64/pe`, uno de esos cuatro métodos y un tamaño descomprimido de hasta 32 MiB. El bloque comprimido se busca justo detrás de la cabecera o al principio de los datos de una sección, y solo vale la posición donde se cumple el Adler-32 que declara la cabecera. Al descomprimirlo, el flujo debe terminar exactamente al final del bloque, dar exactamente el tamaño declarado y cumplir el segundo Adler-32. Si algo falla, no se publica nada. Se prueban como mucho 8 cabeceras bien formadas, para que muchas copias de `UPX!` no encarezcan el análisis; más allá, LupaBin se abstiene.

**El final del bloque.** Tras la imagen, UPX guarda la lista de importaciones, las reubicaciones, una copia de la cabecera PE y de la tabla de secciones originales y, al final, las posiciones de esas partes. Se midieron dos formas: con reubicaciones, la lista de importaciones debe terminar justo donde empiezan; sin ellas, justo donde empieza la copia de la cabecera. Cualquier otra forma deja publicado el bloque sin lo que declara su final (`upx_layout_unrecognized`). Los nombres de las DLL se leen de la pequeña tabla de importaciones que conserva el archivo empaquetado; si uno no se puede leer, tampoco se publica la lista.

**Las cadenas del programa original.** Antes de comprimir, UPX transforma la imagen de dos maneras, que LupaBin deshace. Los saltos: tras cada `E8` o `E9` (y, en x64, tras `0F 80`-`0F 8F`), si el byte siguiente es el parámetro del filtro, los cuatro bytes guardan en big-endian ese parámetro desplazado más la posición del destino; el filtro solo llega al final de la última sección de código, y deshacerlo más allá alteraba datos. Las direcciones absolutas: cada campo reubicado se guarda en big-endian relativo a la imagen, y sus posiciones van en un flujo propio (incrementos de un byte, o de 16 a 20 bits tras un byte `F0`-`FF`) que debe terminar justo donde empieza la copia de la cabecera. Con otro filtro, o un flujo que no tenga esa forma, no se reconstruye nada (`upx_rebuild_unrecognized`). En la imagen reconstruida se buscan las cadenas con el mismo método que en el archivo (`upx_string`), salvo en las zonas que UPX cambia o mueve: los directorios de importaciones, recursos, reubicaciones, depuración, configuración de carga e IAT, según la copia de la cabecera original, y toda la sección de recursos.

**El host lo repite todo.** Con la muestra y la tabla de secciones del informe, el host vuelve a descomprimir el bloque y a leer su final, y rechaza la respuesta del worker si un solo campo difiere.

**Medición (2026-10-01).** Se empaquetaron con `upx` 5.2.1, con los cuatro métodos, copias de 466 programas benignos: 365 ejecutables (la misma selección por variedad que la medición de VirusTotal) y 101 DLL de System32, SysWOW64 y Program Files. De los 528 programas elegidos, UPX no empaquetó 62 (.NET, programas que no comprimen, drivers y ARM de 32 bits), y algunos solo con parte de los métodos. `tests/upx_eval.py` comparó cada una de las 1.845 copias con su original leído por pefile: en 1.797 copias de 454 programas coinciden exactamente el punto de entrada, la base, la tabla de secciones y las 271.278 importaciones (DLL, nombre u ordinal y casilla); ninguna copia dio un valor distinto. Con 1.797 copias sin errores, la tasa de error por copia es menor del 0,17 % con un 95 % de confianza (regla de 3/n; por programa, del 0,66 %). En 28 copias de 7 programas sin ninguna importación se publicó solo el bloque, porque su final tiene otra forma. Las 20 restantes no se reconocieron, como se pretende: 12 de 3 programas ARM64 y 8 de 2 programas que descomprimidos superan 32 MiB. Para comparar se elevó el límite de pefile, que corta los nombres de importación a 512 bytes: los nombres decorados de C++ de dos programas medían 652 y 1.173 bytes, y LupaBin los da completos. Cadenas: sobre una copia por programa, 2.457.677 cadenas de 453 programas reconstruidos, y cada una es exactamente la cadena que empieza en la misma RVA del programa original (o su comienzo, si se recorta); ninguna difiere. La primera versión dio 8 cadenas que no estaban en el original: 3 por deshacer el filtro en toda la imagen, en vez de solo en el código, y 5 en recursos y datos de depuración que UPX borra o mueve; por eso el filtro se limita al código y esas zonas se excluyen. Tras reconstruirla, la imagen solo difiere del original en esas zonas, en relleno que UPX pone a cero y en 4 bytes de un programa Delphi. Falsos positivos: en 59.022 binarios sin empaquetar de System32, SysWOW64 y Program Files no se reconoció ningún bloque. Dos DLL de una aplicación instalada están empaquetadas con UPX 1.24 (cabecera versión 12, no medida) y LupaBin se abstiene. Coste: el descompresor NRV en Python tarda unos 0,4 µs por byte descomprimido; el peor caso de la muestra, 11,4 s. Un programa de 5,8 MB descomprimidos tarda 15 s de principio a fin con el worker en Docker.

**Límites.** Solo UPX 5 en x86 y x64: ni ARM64, ni versiones anteriores de UPX, ni otros empaquetadores. Basta con borrar o alterar la cabecera `UPX!`, algo habitual en programas maliciosos, para que LupaBin no lo reconozca; no reconocerlo no significa que el archivo no esté empaquetado. Los programas sin ninguna importación tienen un final de bloque distinto, que no se publica. El código descomprimido aún no se recorre: sus llamadas y capacidades no aparecen en el informe.

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

Catálogo `lupabin-capabilities-v4` (`src/lupabin/explain/capabilities.py`), fijado por digest. Las constantes de Windows se copian de las cabeceras del Windows SDK 10.0.26100.0. La frecuencia es el porcentaje de binarios con algún caso sobre 3.090 PE benignos (System32, SysWOW64 y Program Files).

| Capacidad | Condición | ATT&CK | Binarios benignos |
| --- | --- | --- | --- |
| Escribir un valor en una clave `Run` | `RegSetKeyValue` sobre `…\CurrentVersion\Run`, `RunOnce`, `RunServices`, `RunServicesOnce`, `…\Policies\Explorer\Run` o `RunOnceEx` (solo bajo `HKEY_LOCAL_MACHINE`, con sus subclaves) | T1547.001 | 0 |
| Abrir una clave `Run` para escribir | `RegOpenKeyEx`/`RegCreateKeyEx` con un permiso que incluya `KEY_SET_VALUE`, `GENERIC_WRITE` o `GENERIC_ALL` | — | 9 (0,29 %) |
| Escribir un valor en una clave `Run` que el mismo código abre | `RegSetValueEx` sobre la clave que la llamada anterior dejó en una variable local (sección «Misma variable local») | T1547.001 | 7 (0,23 %) |
| Abrir una clave `Run` y escribir un valor en el mismo rango de función | Las dos llamadas anteriores dentro de un mismo rango de `.pdata` (x64), si la escritura no tiene enlace | T1547.001 | 1 (0,03 %) |
| Escribir un valor en `Winlogon` | `RegSetKeyValue` sobre `…\Windows NT\CurrentVersion\Winlogon` | T1547.004 solo para `Shell`, `Userinit` o la subclave `Notify` | 0 |
| Abrir `Winlogon` para escribir | Como la clave `Run` | — | 1 (0,03 %) |
| Escribir un valor en `Winlogon` que el mismo código abre | Como la clave `Run` | T1547.004 solo para `Shell` o `Userinit` | 0 |
| Abrir `Winlogon` y escribir en el mismo rango de función | Como la clave `Run` | T1547.004 solo para `Shell` o `Userinit` | 0 |
| Crear un servicio | `CreateService` con nombre o binario conocidos | T1543.003 | 3 (0,10 %) |
| Ejecutar un programa u orden, o pedir al shell que abra algo | `WinExec`, `CreateProcess` o `ShellExecute` con el programa, la orden o el destino conocidos | T1059.003 (`cmd`) o T1059.001 (`powershell`, `pwsh`) | 25 (0,81 %) |
| Descargar una URL a un archivo | `URLDownloadToFile` con la URL o el archivo conocidos | T1105 | 0 |
| Servidor o URL de destino | `InternetConnect`, `WinHttpConnect` o `InternetOpenUrl` | — | 3 (0,10 %) |
| Agente de usuario | `InternetOpen` o `WinHttpOpen` con agente | — | 40 (1,29 %) |
| Memoria ejecutable y escribible | `VirtualAlloc(Ex)` o `VirtualProtect(Ex)` con `PAGE_EXECUTE_READWRITE` o `PAGE_EXECUTE_WRITECOPY`; se aceptan los modificadores documentados y se abstiene con cualquier otro bit | — | 73 (2,36 %) |
| Abrir un proceso con derechos sobre su memoria | `OpenProcess` con `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION` o `PROCESS_ALL_ACCESS` | — | 23 (0,74 %) |
| Mover o borrar un archivo al reiniciar | `MoveFileEx` con `MOVEFILE_DELAY_UNTIL_REBOOT` | — | 9 (0,29 %) |
| Mutex con nombre | `CreateMutex`/`OpenMutexW` con nombre | — | 105 (3,40 %) |
| Algoritmo o proveedor criptográfico | `BCryptOpenAlgorithmProvider` con algoritmo o `CryptAcquireContext` con proveedor | — | 149 (4,82 %) |

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

La frase dice "en el rango 0x…–0x… que declara `.pdata`", porque un archivo puede declarar una tabla falsa, y añade que no se sabe si la escritura usa la clave abierta, porque el identificador no se pudo seguir entre las dos llamadas. Una escritura que tiene enlace de variable local no entra aquí: la describe la capacidad de escritura en la clave abierta. En el corpus benigno queda un caso (`setupapi.dll`, x64, dos escrituras): revisado por desensamblado, las dos usan la clave abierta, pero el enlace se rechaza porque otros caminos entran entre las llamadas. Solo x64: en x86 no hay `.pdata` y esta capacidad nunca se reconoce.

### Revisión de los casos

Los 831 casos que dan las capacidades en los 3.090 binarios benignos se revisaron uno a uno: **ninguna frase describe algo que sus argumentos no digan**. Abstenciones contadas, que cuestan cobertura y no errores: 200 llamadas a `CreateProcessW` sin nombre de aplicación, cuya línea de órdenes no se lee (el resumen del informe lo avisa), y una clave `Run` cuyo permiso no se recuperó.

El informe abre con un resumen, "qué contiene el código", que agrupa las capacidades por táctica y termina con los avisos que lo limitan: no se reconoció ninguna (y eso no demuestra nada), el recorrido es incompleto o poco denso, o hay líneas de órdenes que no se leen.

## VirusTotal

VirusTotal aporta lo que LupaBin no obtiene sin ejecutar la muestra: veredictos de motores antivirus y comportamiento observado en sus sandboxes. Nada de eso lo verifica LupaBin, así que va en un documento aparte (`VirusTotalReport`), se muestra en su propia sección como fuente externa y siempre atribuido ("N motores lo marcan", "en los sandboxes de VirusTotal se observó"). "VirusTotal no conoce este archivo" no significa nada sobre su peligrosidad.

- La consulta se hace desde el host, nunca desde el worker, y solo a `https://www.virustotal.com/api/v3/`, con TLS, sin seguir redirecciones y con tiempo y tamaño de respuesta acotados.
- Primero se consulta por SHA-256. Si VirusTotal no conoce el archivo, se sube con un aviso: su contenido puede compartirse con los clientes de pago de VirusTotal. La subida se desactiva con `--no-upload-to-virustotal` o `LUPABIN_VIRUSTOTAL_UPLOAD=off`, y la consulta entera con `--no-virustotal` o `LUPABIN_VIRUSTOTAL=off`.
- El archivo sube con el nombre genérico `sample`. La clave se lee de `VT_API_KEY` o de un `.env` que ni git, ni el paquete ni la imagen incluyen, y nunca aparece en la salida.
- La respuesta es un dato no fiable: solo se extraen los campos esperados, con tipos comprobados y listas acotadas, y todo texto se neutraliza. El objeto debe ser de tipo `file` y su `data.id` debe coincidir con el SHA-256 solicitado, como establece el [contrato de archivos de VirusTotal](https://docs.virustotal.com/reference/files). Si incluye `attributes.sha256`, también debe coincidir; de lo contrario se rechaza la respuesta, sin consultar el comportamiento ni intentar una subida como alternativa.
- Los contadores ausentes o inválidos no se sustituyen por cero. Solo se calcula el total cuando están las ocho categorías de estadísticas admitidas, todas con enteros no negativos; una categoría desconocida invalida el grupo de estadísticas. Con datos incompletos se conservan los contadores válidos y las etiquetas, pero el total figura como no disponible y la web no muestra una proporción. Un cero explícito sí se conserva.

### Significado documentado de las etiquetas

El catálogo `lupabin-vt-labels-v1` (`virustotal/labels.py`, fijado por digest) aplica reglas al **par exacto motor–etiqueta**, sin consultas adicionales ni generación de texto libre. Cada explicación incluye fuente y límite. No se extiende la nomenclatura de un fabricante a otro, y un texto que puede haberse recortado no se interpreta.

- **Microsoft:** [Learn](https://learn.microsoft.com/en-us/defender-xdr/malware-naming) documenta los sufijos `!…` como indicadores internos, no una traducción general de cada sufijo. Solo los patrones `Behavior:Win32/...!ml` enumerados en el [artículo del equipo de investigación](https://www.microsoft.com/en-us/security/blog/2019/10/08/in-hot-pursuit-of-elusive-threats-ai-driven-behavior-based-blocking-stops-attacks-in-their-tracks/) se explican como nomenclatura de detecciones de aprendizaje automático basadas en comportamiento. No se generaliza esa explicación a cualquier `!ml`, ni se atribuye a la muestra una familia o un motivo concreto.
- **F-Secure:** se reconocen únicamente las formas recogidas en el catálogo y documentadas en [Generic Detection](https://www.f-secure.com/v-descs/other-w32-generic) y [Heuristic](https://www.f-secure.com/v-descs/heuristic). Se explica la clase de nombre, no qué instrucciones o características activaron el motor.
- **Resto, incluido `ti!`:** se conserva la etiqueta y se indica que no hay una interpretación documentada en el catálogo. Eso no afirma que nunca exista documentación, ni que la detección sea correcta o un falso positivo.

### Contraste de técnicas, no explicación causal del antivirus

`exact-technique-id-v1` compara los identificadores conservados de `mitre_attack_techniques` con los casos del catálogo local de capacidades. Según [VirusTotal](https://docs.virustotal.com/reference/file-behaviour-summary), son datos agregados de comportamiento y pueden incluir acciones de procesos hijos: **no son necesariamente el motivo de las etiquetas antivirus**.

Se exige el mismo SHA-256. Solo se comparan identificadores exactos entre las seis técnicas actualmente asociadas por el catálogo local; no se equiparan técnicas padre y subtécnicas. Un caso local cita las llamadas y argumentos concretos que lo sustentan, no meramente los imports. Si no hay caso, se distingue entre recorrido incompleto, técnica fuera del catálogo y caso no observado dentro del alcance; ninguna de estas situaciones refuta el resultado externo. Sin informe local solo se explica la nomenclatura.

El contraste se genera de nuevo desde el informe de hechos, sin añadirle evidencias ni modificar sus condiciones de capacidades. La web recibe la proyección local ya calculada por el host y combina por igualdad de identificador los datos de su consulta asíncrona de VirusTotal, comprobando también los hashes; no conserva informes en el servidor ni solicita nuevos endpoints. El JSON de hechos y el JSON original de VirusTotal siguen separados. Las explicaciones y el contraste se muestran en consola, en el Markdown de la CLI y en la web; la descarga de la web conserva el documento estático generado antes de la consulta externa.

**Medición del contraste (2026-09-27).** Se analizaron 400 ejecutables benignos con el worker Docker, secuencialmente: 100 de System32, 60 de SysWOW64, 238 de Program Files y dos programas de referencia inofensivos. Los identificadores externos fueron **simulados**, no resultados consultados a VirusTotal: seis técnicas admitidas, una técnica padre no admitida y un identificador inválido por archivo. En 3.200 comparaciones no se detectaron errores de correspondencia entre el identificador, los casos del catálogo y sus citas. Hubo dos asociaciones locales, 2.218 casos no observados dentro del alcance, 180 comparaciones con extracción incompleta, 400 identificadores fuera del catálogo y 400 inválidos.

Se revisaron ambos casos con asociación y se repitieron para verificar la conservación de sus detalles: el código de `unregmp2.exe` contiene una llamada a `RegOpenKeyExW` con una ruta que termina en `Run` y otra a `RegSetValueExW` en el mismo rango `.pdata`, **sin conocer la raíz ni saber si ambas usan la misma clave**; el de `uhssvc.exe` contiene una llamada a `CreateServiceW` con el nombre «Update Health Service». El contraste conserva esas restricciones, muestra hasta veinte detalles por técnica y declara los restantes; las citas abarcan todos los casos. Esto no es una medición de falsos positivos antivirus ni valida las observaciones de un sandbox. La regla aproximada `3/n` daría `3/400 = 0,75 %` con cero errores bajo muestreo independiente y representativo; esta selección determinista no permite afirmar esa cota para todos los ejecutables.

Para repetir la muestra en Windows: `uv run python -m tests.vt_context_eval --jobs 1 --output <archivo-nuevo.jsonl> --reference <programa-benigno-1> <programa-benigno-2>`. `--files <rutas...>` mide una selección explícita, y `--review <resultados.jsonl>` lista los casos para revisión. Nunca usar malware real como corpus de estas pruebas.

## Interfaz web

La web es otra forma de usar `lupabin analyze`: cada archivo se analiza en un contenedor nuevo, igual que en la CLI, y se muestra el mismo informe. La página agrupa las frases del informe por la pregunta que responden (qué es el archivo, qué contiene su código, qué textos y datos lleva) y, dentro de cada una, por tema; cada frase conserva su texto, sus citas, su límite y su nivel (hecho o inferencia), que se muestra como etiqueta. El buscador y el filtro por nivel solo ocultan frases en el navegador: no cambian el informe ni lo que se descarga. No guarda ni la muestra ni el informe, no pone cookies, no carga nada de terceros y no registra accesos. Todo texto de la muestra o de VirusTotal se neutraliza en el servidor y el navegador lo inserta solo como texto, con una política de seguridad de contenido sin código en línea.

El servicio escucha solo en `127.0.0.1`, detrás de Caddy, y systemd lo aísla. Su usuario pertenece al grupo `docker`, que en la práctica equivale a administrador en esa máquina: por eso debe desplegarse en un servidor dedicado (`deploy/server/`). Límites por defecto: 20 MiB por archivo, 6 análisis por IP cada 10 minutos, entre uno y tres análisis a la vez según la memoria y las CPU del servidor, y una cuota de VirusTotal compartida por todo el servidor (4 peticiones por minuto y 500 al día con la API pública).

## Exportación a Ghidra

`export-ghidra` transforma un `Report` validado y contrastado con sus bytes originales en un ZIP con un JSON de datos y un script Java fijo. No añade hechos ni incorpora resultados de VirusTotal. La descarga web parte del mismo informe validado y del buffer ya leído: no guarda archivos en el servidor ni lanza otro análisis. Si la exportación falla, el informe web sigue disponible y el botón declara que no pudo generarse el paquete.

El documento tipado 1.0.0 contiene `report` íntegro, `notice` y `annotations`. Cada anotación conserva `evidence_id`, `kind`, `confidence`, `offset`, `length`, `rva` si estaba publicada, un SHA-256 del intervalo original y una clave `E<id>:<instancia>`. Las instancias YARA se exportan por separado con su longitud coincidente, no solo el prefijo capturado. Sin offset o longitud verificables, `reason=location_unavailable`; no se inventan coordenadas. Las decodificaciones mantienen el intervalo codificado. El texto mostrado se neutraliza y las llaves se representan de forma visible para impedir enlaces especiales de comentarios de Ghidra (`{@...}`). Puede abreviarse a 4.096 caracteres con aviso: el payload íntegro permanece en el informe adjunto. El importador regenera su texto a partir de `report.evidence`, no usa `annotations.text` como una afirmación independiente. La serialización compacta de Java puede diferir visualmente del texto del exportador.

El importador exige la igualdad del SHA-256 declarado por el programa y el recalculado sobre el único `FileBytes` original completo, de hasta 20 MiB. Rechaza programas sin esos datos y archivos importados como fragmentos de otro contenedor. Resuelve cada intervalo usando un único origen directo de un bloque inicializado: no equipara offset y RVA, no adivina direcciones de destinos declarados y se abstiene ante solapamientos, cruces entre orígenes, overlays o mapeos indirectos. Para una RVA explícita exige además `dirección = base actual + RVA`, sin desbordamiento. Compara el hash del intervalo original y los bytes actuales de memoria: un parche o una relocalización que altere esos bytes impide anotar ese intervalo, aunque el archivo original sí coincida.

La revisión previa se guarda con creación exclusiva antes de pedir confirmación; enumera preparadas, ya presentes, conflictos y abstenciones con sus motivos, además de la cobertura y los límites originales. No es un registro de aplicación. Las categorías incluyen el SHA-256 del JSON completo y la clave local: repetir ese documento es idempotente; otro informe se distingue aunque reutilice IDs o numere de otra forma los mismos hechos. No se deduplican hechos entre documentos: incluso cambiar el formato del JSON cambia este espacio de nombres. Los comentarios se añaden conservando exactamente el texto previo, y un marcador con contenido diferente no se sustituye. Una transacción vuelve a comprobar identidad, mapa, bytes y anotaciones antes de escribir y revierte en caso de error o cancelación. El script desactiva el análisis automático para sus cambios; no llama a analizadores, desensambladores, emuladores ni procesos externos.

Los presupuestos propios de importación son 32 MiB de JSON, 40.000 anotaciones, profundidad JSON 64 y 128 MiB de intervalos contrastados por revisión. Superar el presupuesto de bytes produce `verification_budget` para cada intervalo que no cabe; no un resultado inventado. Los comentarios combinados se acotan a 65.536 caracteres por dirección y 16.777.216 caracteres acumulados en el plan; `annotation_budget` declara las anotaciones que no caben sin borrar texto previo. Los textos regenerados se limitan a 16.777.216 caracteres tanto por conjunto de hechos como por conjunto de anotaciones; excederlos cancela la importación antes de escribir. El exportador cuenta incrementalmente los bytes JSON y las anotaciones antes de acumularlos, reutiliza el texto de cada hecho para sus instancias YARA y limita a 128 MiB los intervalos únicos que hashea. Si excede un presupuesto, no genera un ZIP parcial. La web mantiene la construcción del ZIP, las explicaciones, su validación, los retos y la serialización de la respuesta dentro del mismo cupo de concurrencia del análisis, fuera del bucle de atención de peticiones. Cancelar una petición no libera ese cupo mientras su trabajo del host siga en curso. Estos límites son de transporte y anotación, no umbrales de extracción; el cupo no impone al trabajo del host los límites de memoria y CPU del contenedor.

Verificar bytes no autentica el informe ni demuestra el significado de sus afirmaciones; el JSON no está firmado. Java comprueba la correspondencia entre ubicaciones y anotaciones, no reproduce todos los validadores semánticos del contrato Python ni reextrae los hechos. Alterar el payload de un hecho conservando sus coordenadas y hashes puede no detectarse: importa únicamente exportaciones de procedencia confiable y conserva la revisión. La neutralización de texto impide sintaxis activa en los comentarios, no transforma afirmaciones manipuladas en evidencias válidas.

Las APIs se contrastaron con la documentación y el código primarios de Ghidra: [FileBytes](https://ghidra.re/ghidra_docs/api/ghidra/program/database/mem/FileBytes.html), [MemoryBlockSourceInfo](https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/MemoryBlockSourceInfo.html), [Listing](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Listing.html), [BookmarkManager](https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/BookmarkManager.html) y [GhidraScript](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html). Las pruebas con dobles del programa cubren hashes distintos, offsets frente a RVA, rebase, cambios de memoria, repetición, conservación de anotaciones y reversión. La compilación se comprobó contra las bibliotecas instaladas de Ghidra 12.1.3 con Java 21; también se ejecutó el arnés con su Gson real, incluyendo claves duplicadas y profundidad excesiva. Además, `tests/check_ghidra_integration.py` ejecuta el importador en Ghidra 12.1.3 real, en modo headless, sin análisis automático y con un programa sintético que añade un overlay: rechaza un SHA-256 erróneo, desplaza la base de la imagen y comprueba que cada anotación se mueve con ella y que las RVA coinciden, que el overlay queda sin mapear, que una cancelación inyectada tras escribir revierte todos los cambios, que se conservan los comentarios y marcadores humanos previos, que repetir la importación no añade nada y que las anotaciones persisten al reabrir el proyecto. Con `--mutate-rollback`, la misma prueba confirma que detecta un importador que confirmara la transacción cancelada. El script de verificación hereda del importador y solo se ejecuta en esa prueba; la exigencia de revisión interactiva del importador no se relaja.

## Límites conocidos

- **Código.** Solo x86 y x64. De los saltos indirectos solo se siguen las tablas de `switch` de MSVC comprobables; vtables y callbacks no. Tras una llamada que no vuelve, el recorrido sigue en línea recta: en x86 los campos reubicados lo detienen, pero en x64 puede decodificar bytes que no son código. Un binario empaquetado muestra poco más que su desempaquetador; en los empaquetados con UPX 5 se descomprime el bloque y se publica lo que declara (sección «UPX»), pero su código no se recorre.
- **Argumentos.** No se propagan valores entre registros. Un identificador solo se sigue entre dos llamadas a través de una variable local y en un camino recto (sección «Misma variable local»). La línea de órdenes de `CreateProcessW` no se lee.
- **Decodificación.** Sin una crib del catálogo no hay resultado. Una cadena aislada con clave de 8 bytes se recupera en el 37 % de los casos en ASCII y el 62 % en UTF-16LE.
- **Familias de APIs.** Solo reconocen imports por nombre exacto, no por ordinal.
- **La función main.** Solo con el arranque que usa `__getmainargs` de `msvcrt.dll`, en x64 y en x86 con `push`; el alcance sigue solo llamadas y saltos directos.
- **Marcas de compilador.** Solo seis herramientas: otras (Delphi, Rust, Nuitka, AutoIt…) no se reconocen, y la versión de Visual Studio no se deduce de las entradas de la cabecera Rich, porque Microsoft no documenta su significado.
- **Idioma.** Las explicaciones y el glosario están en español.
- **Fuentes externas.** Las páginas que cita el glosario pueden moverse: `tests/check_glossary_sources.py` lo comprueba con red, fuera de la CI.
- **Tiempo.** En una máquina lenta, los binarios más grandes pueden quedar parciales en XOR o en código, y lo declaran con su código.

## Repetir las mediciones

Las herramientas están en `tests/` y no forman parte del paquete ni de la CI. Reciben un directorio de binarios benignos que aporte quien evalúa, y los leen como datos:

- `uv run python -m tests.decode_eval false-positives <dir>` y `recall <dir>`: falsos positivos y cobertura de la decodificación.
- `uv run python -m tests.code_eval corpus <dir>`: llamadas, argumentos, verificación de bytes y tiempos; `worst` mide los peores casos sintéticos: los de 20 MiB y uno con tantas llamadas enlazadas por una variable local como se pueden publicar.
- `uv run python -m tests.capability_eval corpus <dir>`: frecuencia de cada capacidad; `review` lista cada caso para revisarlo.
- `uv run python -m tests.main_eval corpus <dir>`: `main` encontrado o abstención por ejecutable, reparto de las llamadas y tiempos; `--out` lista cada caso para revisarlo.
- `uv run python -m tests.toolchain_eval corpus <dir>`: marcas de compilador por binario y combinación, comprobación de los bytes y regeneración de las explicaciones; `--out` las lista para revisarlas.
- `uv run python -m tests.upx_eval pairs <empaquetados> <originales> --output <nuevo.jsonl>`: copias benignas empaquetadas por quien evalúa frente a sus originales (punto de entrada, base, secciones e importaciones); `false-positives <dir>...` busca bloques UPX en binarios sin empaquetar.
- `uv run python -m tests.learning_eval --manifest <lista.jsonl> --output <nuevo.jsonl> --jobs 1`: coherencia de retos y exportación a Ghidra por archivo; la lista tiene una ruta por línea (`{"path": ...}`).
- `uv run python -m tests.check_ghidra_integration --ghidra <carpeta de Ghidra> --root <carpeta nueva>`: el importador en un Ghidra real, en modo headless, con Java en el PATH; `--mutate-rollback` comprueba que la prueba detecta una reversión rota.

Cambiar un umbral, una condición, un catálogo o una redacción exige una nueva versión fijada por digest, repetir la medición y revisar los casos a mano.
