# Fase 5: capacidades a partir de llamadas y argumentos

Estado: revisión 2 (2026-09-24). Petición del usuario: que Dissect diga "exactamente lo que hace" el programa. Con permiso para avanzar por secciones (5.0 a 5.7).

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
| Ejecución de una orden | `WinExec`, `CreateProcess` o `ShellExecute` con el programa o la orden conocidos. La técnica solo se asocia si el programa es un intérprete de órdenes o de scripts (`cmd`, `powershell`, `wscript`/`cscript`) | T1059.003, T1059.001, T1059.005 |
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
