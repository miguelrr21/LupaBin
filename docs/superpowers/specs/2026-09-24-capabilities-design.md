# Fase 5: capacidades a partir de llamadas y argumentos

Estado: revisión 2 (2026-09-24), implementada en las entregas 5.1, 5.2, 5.3 y 5.5 (sección 9). Petición del usuario: que Dissect diga "exactamente lo que hace" el programa. Con permiso para avanzar por secciones (5.0 a 5.7), confirmado por el usuario el 2026-09-24.

Revisión 2, aprobada por el usuario el 2026-09-24 tras revisar la revisión 1:
- T1547.001 solo se asocia a una escritura real en la clave `Run` hecha con una sola llamada (`RegSetKeyValue`). Abrir la clave para escribir se describe sin técnica hasta la entrega 5.4.
- Sin técnicas T1218.x en la entrega 5.1. Ejecutar `rundll32`, `regsvr32` o `mshta` no encaja por sí solo con su definición, que es un abuso para ejecutar código encubierto.
- Se corrigen condiciones que podían dar frases falsas: claves abiertas para leer, `MAXIMUM_ALLOWED`, protecciones ejecutables no escribibles, claves sin raíz conocida y procesos que no se identifican.
- Se dejan escritos el denominador de la medición, la dependencia del catálogo de APIs y los límites de cobertura de la ejecución de órdenes.

## 1. Qué se puede afirmar y qué no

Una capacidad es una frase sobre lo que el código **contiene**, construida a partir de llamadas (`api_call`) y argumentos constantes (`call_argument`) ya verificados. Por ejemplo: "el código contiene una llamada que crea el servicio «X», con arranque automático, cuyo binario es «C:\…»".

No afirma que el programa lo haga. Que se ejecute depende de condiciones y entradas que el análisis estático no resuelve. Tampoco afirma intención: una clave `Run` o memoria ejecutable y escribible aparecen en programas legítimos, y la medición de la sección 5 lo cuantifica. Siguen valiendo los límites de la Fase 4: un binario empaquetado solo muestra su desempaquetador, y el código al que solo se llega por saltos indirectos no se recorre.

## 2. Decisión: explicaciones, no hechos nuevos

Las capacidades son **reglas de explicación** del host, como las de la Fase 3. No son un tipo de hecho del informe.
- **No cambia el contrato de hechos 0.5.0 ni el worker.** Todo sale de hechos que el informe ya valida: la llamada, su import y sus argumentos.
- **Cada ítem se regenera desde sus citas**, porque `validate` vuelve a aplicar la regla y exige la misma frase.
- **El nivel es `inferred`**, porque los argumentos lo son.
- **Cada regla cita todos los casos del informe**, en su orden. No puede ocultar llamadas que no encajan con la frase.

Alternativa descartada: un tipo de hecho `capability` producido en el worker. Duplicaría en el contrato lo que ya se deriva de él, y obligaría a validar dos veces lo mismo.

## 3. Catálogo `dissect-capabilities-v1`

Un módulo propio (`src/dissect/explain/capabilities.py`) define cada capacidad como datos:
- identificador;
- táctica, para agrupar en el resumen;
- funciones y condición sobre los argumentos;
- plantilla;
- técnica de MITRE ATT&CK, si la hay, con su entrada de glosario;
- cifra de prevalencia benigna medida;
- límite.

El catálogo lleva digest, fijado por un test. Además, declara la versión del catálogo de APIs de la que depende (`dissect-api-semantics-v4`). Un test falla si esa versión cambia sin revisar el catálogo de capacidades, porque una condición sobre un parámetro puede dejar de tener sentido.

Los nombres de las constantes (tipos de inicio de servicio, protecciones `PAGE_*`, derechos de acceso) salen de las cabeceras del Windows SDK 10.0.26100.0, como en la Fase 4. Las tablas de valores documentados que usó la medición del catálogo v4 (`coherence.py`) no están en el repositorio. La entrega 5.1 las añade como módulo propio, con pruebas, en lugar de copiarlas de la medición.

**Capacidades de una sola llamada** (entrega 5.1), elegidas con el ensayo sobre el volcado de la medición del catálogo v4 (sección 5):

| Capacidad | Condición | ATT&CK |
| --- | --- | --- |
| Escritura de un valor en una clave `Run` | `RegSetKeyValue` con `lpSubKey` terminada en `\CurrentVersion\Run`, `RunOnce`, `RunServices`, `RunServicesOnce` o `\Policies\Explorer\Run` | T1547.001 |
| Clave `Run` abierta para escribir | `RegOpenKeyEx`/`RegCreateKeyEx` con la misma `lpSubKey` y un `samDesired` que contenga `KEY_SET_VALUE` (sola o dentro de `KEY_WRITE` o `KEY_ALL_ACCESS`), `GENERIC_WRITE` o `GENERIC_ALL` | — (hasta la entrega 5.4) |
| Clave `Winlogon` abierta para escribir | la condición anterior con `\CurrentVersion\Winlogon` | — (hasta la entrega 5.4) |
| Creación de un servicio | `CreateService` con nombre o ruta del binario conocidos; también el tipo y el inicio | T1543.003 |
| Ejecución de una orden | `WinExec`, `CreateProcess` o `ShellExecute` con el programa o la orden conocidos. La técnica solo se asocia si el programa es un intérprete de órdenes (`cmd`, `powershell`, `pwsh`). `wscript` y `cscript` quedan sin técnica: ejecutan VBScript (T1059.005) o JScript (T1059.007), y la llamada no dice cuál (sección 9.1) | T1059.003, T1059.001 |
| Descarga a un archivo | `URLDownloadToFile` con la URL o el archivo conocidos | T1105 |
| Destino de red | `InternetConnect`/`WinHttpConnect` con servidor (y puerto), o `InternetOpenUrl` con URL | — |
| Agente de usuario | `InternetOpen`/`WinHttpOpen` con agente | — |
| Memoria ejecutable y escribible | `VirtualAlloc(Ex)` con `PAGE_EXECUTE_READWRITE`, o `VirtualProtect(Ex)` a `PAGE_EXECUTE_READWRITE` o `PAGE_EXECUTE_WRITECOPY`. Se compara la protección base; los modificadores (`PAGE_GUARD`, `PAGE_NOCACHE`, `PAGE_WRITECOMBINE`) no cambian la frase. Con las variantes `Ex`, la frase dice que la función admite otro proceso, sin afirmar cuál: `hProcess` no se interpreta y puede ser el propio proceso (`GetCurrentProcess()`) | — |
| Apertura de un proceso con derechos sobre su memoria | `OpenProcess` con `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION` o `PROCESS_ALL_ACCESS`. La frase no dice qué proceso: `dwProcessId` no se interpreta | — |
| Mover o renombrar al reiniciar | `MoveFileEx` con `MOVEFILE_DELAY_UNTIL_REBOOT` | — |
| Mutex con nombre | `CreateMutex`/`OpenMutexW` con nombre | — |
| Algoritmos criptográficos | `BCryptOpenAlgorithmProvider` con algoritmo, o `CryptAcquireContext` con proveedor | — |

Se descarta **"carga la biblioteca X"** como capacidad: en el ensayo aparece en el 53 % de los binarios benignos, así que no distingue nada. Las llamadas a `LoadLibrary` siguen explicadas una a una por `code.arguments@1`.

**Reglas comunes de las capacidades del registro:**
- **Raíz de la clave.** La frase nombra la raíz (`HKEY_CURRENT_USER`, `HKEY_LOCAL_MACHINE`…) solo si `hKey` se recuperó como argumento. Si no, dice "una subclave terminada en …, bajo una clave que no se pudo determinar". El identificador puede venir de otra llamada, y la subclave es relativa a él.
- **`MAXIMUM_ALLOWED` no cuenta como permiso de escritura.** Pide el máximo acceso que se conceda, que puede no incluir escritura. Con ese permiso la llamada sigue explicada por `code.arguments@1`, pero no produce ninguna capacidad de escritura.
- **Se excluyen `RegOpenKey` y `RegCreateKey`.** No reciben un permiso, así que su argumento no dice si la clave se abre para leer o para escribir.
- **`RegCreateKeyEx` necesita el mismo permiso de escritura que `RegOpenKeyEx`.** La clave `Run` existe siempre, así que crearla con `KEY_READ` equivale a abrirla para leer.

**Límite de cobertura de "ejecución de una orden":** `CreateProcessW.lpCommandLine` nunca se publica (sección 10.6 de la Fase 4: Learn exige memoria escribible, y la regla de cadenas solo admite secciones no escribibles). En `CreateProcessW` solo queda `lpApplicationName`, que suele ser `NULL`. No reconocer esta capacidad no demuestra que el código no lance procesos, y la sección de resumen lo recuerda.

Las técnicas de ATT&CK se asocian solo cuando la condición coincide con la definición de la técnica. No se asocian por parecido:
- Escribir un valor en una clave `Run` es T1547.001. Abrirla para escribir no escribe nada: la técnica espera a la entrega 5.4, que puede ver la escritura en la llamada siguiente.
- Memoria ejecutable y escribible no es, por sí sola, inyección de procesos.
- Ejecutar `rundll32`, `regsvr32` o `mshta` no es, por sí solo, T1218.x, que describe su abuso para ejecutar código de forma encubierta. Windows y muchos programas los invocan legítimamente. La frase dice qué programa se ejecuta, sin técnica.

## 4. MITRE ATT&CK y glosario (entrega 5.2)

Cada técnica tiene una entrada de glosario con su página de `attack.mitre.org` como fuente, comprobada con `tests/check_glossary_sources.py`. El límite común: "coincidir con una técnica no demuestra intención; muchos programas legítimos usan el mismo mecanismo".

## 5. Medición en binarios benignos (entrega 5.3)

- Cada capacidad se mide sobre el corpus de la Fase 4 (System32 `--stride 3`, SysWOW64 `--stride 5`), ampliado con una muestra de Program Files. Solo con binarios de Windows la cifra no representaría el software de terceros.
- La cifra es el porcentaje de binarios con al menos un caso, **sobre todos los binarios PE analizados del corpus** (no solo los que tienen argumentos publicados). El informe de medición da además el número de binarios que importan alguna función de la capacidad. La frase la da como contexto: "en binarios benignos medidos, el X % contiene esta capacidad".
- Una capacidad cuya condición produzca falsos positivos, es decir, frases que no describen lo que dice la llamada, se corrige o se descarta. Cada caso se revisa a mano.

Ensayo previo sobre el volcado de argumentos de la medición del catálogo v4, con las condiciones de la revisión 1. No es la medición final: el denominador son los 1.465 binarios con algún argumento publicado, no los 1.883 del corpus. Las condiciones de la revisión 2 son más estrictas, así que las cifras del registro deberían bajar:

| Capacidad | Binarios |
| --- | --- |
| Clave `Run` abierta para escribir | 9 (0,61 %) |
| Clave `Winlogon` | 16 (1,09 %), casi todos de lectura |
| Creación de un servicio | 10 (0,68 %) |
| Ejecución de una orden | 24 (1,64 %) |
| Memoria ejecutable y escribible | 42 (2,87 %) |
| Mutex con nombre | 101 (6,89 %) |
| Algoritmos criptográficos | 97 (6,62 %) |
| Carga de bibliotecas por nombre | 775 (52,9 %): **descartada** |

## 6. Resumen "Qué hace el código" (entrega 5.5)

El informe didáctico abre con una sección nueva que agrupa las capacidades por táctica:
- persistencia;
- ejecución;
- comunicaciones;
- manipulación de memoria y procesos;
- archivos;
- sincronización y criptografía.

Cada ítem lleva sus citas y su límite. Después aparecen los avisos que la afecten: cobertura baja (`code.walk_density@1`), llamadas o argumentos parciales, módulos no revisados y, si el código llama a `CreateProcessW`, que su línea de órdenes no se lee (sección 3). Sin capacidades, la sección dice que no se reconoció ninguna, y que eso no demuestra que no las haya.

## 7. Capacidades de varias llamadas (entrega 5.4, pendiente de elegir camino)

Algunas capacidades encadenan llamadas. Por ejemplo, abrir una clave con `RegCreateKeyEx`, que devuelve el identificador en memoria, y escribir un valor con `RegSetValueEx`. Caben dos caminos, que el usuario elegirá cuando se llegue:
- **a) Coincidencia en la misma función**, con una frase prudente.
- **b) Seguimiento del identificador** a través de la variable local donde se guarda. Requiere un análisis nuevo con su propia medición.

Solo esta entrega podrá asociar T1547.001 a abrir una clave `Run` y escribir en ella con `RegSetValueEx`. Con el camino a), la técnica solo se asociaría si la frase deja claro que no se sabe si la escritura usa la clave abierta.

## 8. Plan

1. Este diseño (5.0).
2. Motor de capacidades, catálogo v1 y tablas de constantes del SDK en el repositorio, con fixtures sintéticos y pruebas negativas (5.1). Entre las negativas: clave `Run` abierta para leer o con `MAXIMUM_ALLOWED`, `RegOpenKey`/`RegCreateKey`, `PAGE_EXECUTE_READ`, `hKey` desconocida y `rundll32` sin técnica.
3. Entradas de glosario de ATT&CK con fuentes (5.2).
4. `tests/capability_eval.py`: prevalencia benigna y revisión de cada caso (5.3).
5. Sección de resumen en texto y Markdown (5.5).
6. Demostración, documentación y PR (5.7). La entrega 5.4 (capacidades de varias llamadas) y la 5.6 (más cobertura) quedan para después.

## 9. Implementación y mediciones (2026-09-24)

### 9.1 Qué se implementó y qué cambió respecto a las secciones anteriores

- **5.1.** `src/dissect/explain/capabilities.py` (catálogo `dissect-capabilities-v1`, fijado por digest) y `src/dissect/explain/winapi.py` (constantes copiadas de `winnt.h` y `WinBase.h` del SDK 10.0.26100.0; un test comprueba las máscaras compuestas). Cada capacidad declara qué parámetros del catálogo de APIs lee, y un test comprueba que existen en `dissect-api-semantics-v4`. Una capacidad es una regla `capability.<id>@1` que cita todas las llamadas del informe que cumplen su condición, cada una con todos sus argumentos publicados. El motor la regenera al validar, así que una cita de menos, un caso oculto o una frase alterada no se muestran.
- **5.2.** Siete entradas de glosario (revisión 1.3.0): `capability.static`, `attack.technique` y una por técnica, con sus páginas de attack.mitre.org y de Microsoft Learn comprobadas el 2026-09-24. El caso con técnica la muestra entre paréntesis y el ítem enumera las técnicas. Diferencia con la sección 3: **`wscript` y `cscript` quedan sin técnica**, porque ejecutan VBScript (T1059.005) o JScript (T1059.007) y la llamada no dice cuál. El programa se identifica por el nombre de archivo, sin ruta ni `.exe`: el de `lpApplicationName`, el primer elemento de la línea de órdenes (entre comillas si las hay) o `lpFile` de `ShellExecute`. Una ruta con espacios sin comillas (`C:\Program Files\cmd.exe`) se parte donde la parte Windows y no da técnica.
- **Protección con bits que Dissect no nombra.** Learn permite combinar `PAGE_TARGETS_INVALID`/`PAGE_TARGETS_NO_UPDATE` (0x40000000) con una protección ejecutable. Dissect solo acepta los modificadores `PAGE_GUARD`, `PAGE_NOCACHE` y `PAGE_WRITECOMBINE` y se abstiene con cualquier otro bit. Coste medido (sección 9.2): 13 llamadas en todo el corpus.
- **Redacción corregida al revisar los casos.** El destino de `ShellExecute` no siempre es un archivo o un programa: puede ser una URL (`https://aka.ms/msdtretire` en msdt.exe), un esquema (`ms-settings:fonts`) o un elemento del shell (`::{26EE0668-…}` en devmgr.dll). Ahora el caso dice «destino» y la capacidad, "pedir al shell de Windows que abra algo".
- **5.5.** El informe abre con "Resumen: qué contiene el código", sin número para no renumerar las secciones 1 a 5. Agrupa las capacidades por táctica, con sus técnicas, y termina con los avisos: no se reconoció ninguna (y eso no demuestra nada), el código no se pudo recorrer, la densidad del recorrido es baja, las llamadas o los argumentos están incompletos, hay llamadas a `CreateProcessW` cuya línea de órdenes no se lee, y aún no se reconocen capacidades de varias llamadas.

### 9.2 Medición (`uv run python -m tests.capability_eval corpus … --jobs 8 --out …`)

Corpus: System32 (`--stride 3`, 1.363 PE), SysWOW64 (`--stride 5`, 521) y Program Files con Program Files (x86) (`--recursive --stride 40`, 1.203). En total, 3.087 PE: 0 informes inválidos, 0 fallos de verificación de bytes y 0 errores al generar y validar las explicaciones.

| Capacidad | Binarios con algún caso | % de 3.087 | Casos | Binarios que llaman a alguna de sus funciones |
| --- | --- | --- | --- | --- |
| Escribir un valor en una clave `Run` | 0 | 0 % | 0 | 111 |
| Abrir una clave `Run` para escribir | 9 | 0,29 % | 11 | 1.058 |
| Abrir `Winlogon` para escribir | 1 | 0,03 % | 1 | 1.058 |
| Crear un servicio | 2 | 0,06 % | 2 | 12 |
| Ejecutar un programa u orden, o abrir algo con el shell | 26 | 0,84 % | 55 | 214 |
| Descargar una URL a un archivo | 0 | 0 % | 0 | 2 |
| Servidor o URL de destino | 3 | 0,10 % | 3 | 71 |
| Agente de usuario | 39 | 1,26 % | 45 | 75 |
| Memoria ejecutable y escribible | 69 | 2,24 % | 105 | 342 |
| Proceso abierto con derechos sobre su memoria | 22 | 0,71 % | 27 | 312 |
| Mover o borrar al reiniciar | 9 | 0,29 % | 11 | 89 |
| Mutex con nombre | 105 | 3,40 % | 200 | 205 |
| Algoritmo o proveedor criptográfico | 152 | 4,92 % | 343 | 230 |

**Revisión manual de los 803 casos**, uno a uno (los de mutex y criptografía, además, contrastando por programa que el texto cita exactamente el argumento): **ninguno describe algo que sus argumentos no digan.** Ejemplos: las 11 claves `Run` abiertas para escribir son `RunOnce` o `Run` con `KEY_SET_VALUE` directo o incluido (`0x2`, `0x3`, `0x20006`, `0x2001f`); `profsvc.dll` abre `Winlogon` con `KEY_ALL_ACCESS` desde una clave que no es predefinida, y la frase lo dice; los 27 `OpenProcess` piden `PROCESS_ALL_ACCESS` o incluyen `PROCESS_VM_OPERATION`/`PROCESS_VM_WRITE`. Ningún caso de ejecución lanzó `cmd` ni PowerShell, así que en el corpus solo aparece la técnica T1543.003 (dos servicios de controlador).

**Abstenciones contadas** (coste en cobertura, no en error):
- 190 llamadas a `CreateProcessW` sin nombre de aplicación: su línea de órdenes nunca se lee (sección 3), y el resumen lo avisa.
- 13 protecciones ejecutables y escribibles con bits que Dissect no nombra (sección 9.1).
- 1 clave `Run` cuyo permiso no se recuperó.

**Coste.** Calcular las 13 capacidades en shell32.dll (7.936 hechos) tarda 0,10 s. Generar y validar todas sus explicaciones tarda 14,41 s con capacidades y 14,46 s sin ellas, así que las capacidades no añaden coste medible. Los 14 s ya existían, y parecen deberse a reglas que recorren el informe entero por cada uno de sus ~2.860 ítems (sin comprobar); queda como mejora pendiente en la hoja de ruta.

Cambiar una condición, una redacción o una cifra exige una nueva versión del catálogo y repetir esta medición.

## 10. Entrega 5.6: más cobertura, catálogo `dissect-capabilities-v2` (2026-09-24)

Petición del usuario tras el merge del PR #8: seguir con la 5.4 (camino a) y la 5.6. Tres ampliaciones, cada una comprobada contra su fuente y medida antes de adoptarla con el mismo corpus y la misma revisión manual de la sección 9:

1. **Modificador de Control Flow Guard.** Learn permite `PAGE_TARGETS_INVALID` (0x40000000) con `VirtualAlloc(Ex)` y `PAGE_TARGETS_NO_UPDATE` (el mismo valor) con `VirtualProtect(Ex)`, "only valid when the protection changes to an executable type". No cambian si la memoria es escribible, así que pasan a ser modificadores aceptados, con el nombre que corresponde a cada función. Hasta ahora Dissect se abstenía en 13 llamadas del corpus.
2. **`RunOnceEx`.** ATT&CK (T1547.001) cita `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`, con su ejemplo de una subclave `0001\Depend` que carga una DLL. Se acepta esa clave y cualquier subclave suya, solo bajo `HKEY_LOCAL_MACHINE` (también a través de `Wow6432Node`), que es donde la sitúa la fuente. Bajo una clave que no se pudo determinar no se acepta: no se sabría si es la de la máquina.
3. **Escribir un valor en `Winlogon`** (`RegSetKeyValue`, capacidad nueva). T1547.004 (Winlogon Helper DLL) nombra los valores `Shell` y `Userinit` y la subclave `Notify`, en `HKLM\Software[\Wow6432Node\]\Microsoft\Windows NT\CurrentVersion\Winlogon` y en la de HKCU. La técnica solo se asocia si el nombre del valor es `Shell` o `Userinit` o la subclave es `Notify` o una suya; otros valores de `Winlogon` se describen sin técnica.

Abrir `Winlogon` para escribir sigue sin técnica, por la misma razón que la clave `Run` (sección 4). Un cambio de condición exige una nueva versión del catálogo: `dissect-capabilities-v2`.

### 10.1 Medición y adopción

Mismo corpus y herramienta que la sección 9.2 (3.087 PE). Resultado: 0 informes inválidos, 0 fallos de verificación y 0 errores de explicación. Se compararon, caso por caso, las mediciones con los catálogos v1 y v2:
- **13 casos nuevos**, todos de memoria ejecutable y escribible con `0x40000040`: 3 en System32 y 10 en SysWOW64 (RMActivate, msmpeg2ac3dec, msmpeg2adec, CPFilters y mshtml). Los 13 son correctos y cada uno nombra el bit como lo documenta su función (`PAGE_TARGETS_INVALID` con `VirtualAlloc`, `PAGE_TARGETS_NO_UPDATE` con `VirtualProtect`). Los binarios con algún caso pasan de 69 a 72 (2,33 %).
- **Ningún caso de v1 desaparece ni cambia**, salvo por la redacción.
- `RunOnceEx` y la escritura de valores en `Winlogon` no aparecen en el corpus benigno: 0 binarios. Solo las ejercitan los fixtures sintéticos, con sus pruebas positivas y negativas.

**Adoptado** como `dissect-capabilities-v2`. Glosario 1.4.0 con la entrada `attack.t1547_004`.

## 11. Entrega 5.4, camino a): abrir y escribir en la misma función (diseño, 2026-09-24)

El usuario eligió el camino a) de la sección 7. Esta sección concreta qué exige.

### 11.1 Por qué hace falta un hecho nuevo

Las capacidades se derivan solo del informe, para que `validate` pueda regenerarlas sin la muestra. El contrato 0.5.0 no publica ningún límite de función: una llamada solo lleva su instrucción. "Misma función" tiene que venir de un dato que el informe cite y que el host pueda comprobar:
- **Tabla `.pdata` (x64): adoptada.** Cada entrada `RUNTIME_FUNCTION` declara el inicio, el fin y la información de desenrollado de un tramo contiguo de una función, escritos por el compilador. Dos llamadas dentro del mismo rango están en el mismo tramo de la misma función. El host comprueba los 12 bytes de la entrada contra la muestra, sin parsear nada.
- **Descartado: distancia entre llamadas.** Adivina límites.
- **Descartado: región alcanzable desde un inicio de función sin seguir llamadas.** Es un dato del recorrido, y el host no puede comprobarlo sin un desensamblador (el host no importa capstone).
- **Descartado: tabla de Control Flow Guard.** Da inicios de función, pero no finales.

**Límite aceptado: solo x64.** En x86 no hay `.pdata`, y la capacidad nunca se reconoce. Un binario puede declarar una `.pdata` falsa: la frase dice "el rango que declara la tabla `.pdata`", no "la función".

### 11.2 Contrato 0.6.0

- Hecho nuevo `code_function` (`observed`, fuente `code`, componente `api_calls`). Datos: `begin`, `end` y `unwind` (RVA), y los 12 bytes de la entrada; `location` es su desplazamiento en el archivo. El modelo comprueba que los bytes codifican esos tres valores y que `begin < end`. El host compara los bytes con la muestra, igual que con las llamadas.
- Publicación: la entrada de `.pdata` que contiene cada llamada publicada a una función del catálogo de argumentos, sin repetir. Su número está acotado por el de esas llamadas.
- El 0.5.0 se conserva en `docs/schemas/`, y la imagen pasa a `dissect-worker:0.6.0`.
- Una regla nueva, `code.functions@1`, explica todas las funciones publicadas en un solo ítem, porque todo hecho tiene que estar explicado.

### 11.3 Capacidades nuevas

- **`run_key_open_and_set`**: en el mismo rango de `.pdata` hay una llamada que abre una clave `Run` para escribir (la condición de `run_key_open_write`) y una llamada a `RegSetValueExA/W`. Esa llamada no puede tener como `hKey` una clave predefinida publicada, porque entonces escribiría en otra clave. El caso cita el rango, las dos llamadas y sus argumentos. Frase: "en el rango 0x…–0x… que declara `.pdata`, el código abre «…» para escribir y llama a RegSetValueEx (valor «…»); no se sabe si esa escritura usa la clave abierta".
- **`winlogon_open_and_set`**: lo mismo con `Winlogon`.
- **Técnicas:** T1547.001 para `Run`; T1547.004 para `Winlogon` solo si el valor es `Shell` o `Userinit`. Así lo permite la sección 7, siempre que la frase diga que no se sabe si la escritura usa la clave abierta.

### 11.4 Criterio de adopción

Mismo corpus que la sección 9, más una **revisión por desensamblado de cada caso**: comprobar si el `hKey` de `RegSetValueEx` es el identificador que devolvió la llamada que abre la clave. La capacidad solo se adopta si la frase es cierta en todos los casos. La técnica, además, solo si en todos los casos revisados la escritura usa la clave abierta; si no, la capacidad se queda sin técnica. También se miden el tamaño que añade al informe y el coste en tiempo.
