# Fase 4: qué hace el código, en estático (llamadas a API y sus argumentos)

Estado: revisión 2 (2026-09-23). La primera entrega, la versión reducida (sección 9), está implementada en la rama `feat/static-api-calls`: qué funciones importadas llama el código y desde dónde, sin leer argumentos. Los argumentos (secciones 3.4 y 4) siguen solo diseñados. Responde a la petición del usuario: que Dissect "analice en estático el binario y diga exactamente lo que hace". El alcance y sus límites se registraron en `docs/roadmap.md`.

## 1. Qué se puede afirmar y qué no

El análisis estático lee el código máquina sin ejecutarlo. Puede afirmar, con los bytes como prueba:

- "La instrucción de `0x14000285d` llama a `RegOpenKeyExW` a través de su entrada en la tabla de imports" (observado).
- "Justo antes, en el mismo bloque, el código carga en el registro del segundo argumento la dirección de la cadena «Software\Microsoft\…\Policies\System»" (inferido: lectura de constantes, sin ejecutar nada).

No puede afirmar que esa llamada llegue a ejecutarse. Depende de condiciones, entradas y del entorno, y un binario empaquetado solo muestra su desempaquetador. Cada explicación lo dirá: "el código contiene esta llamada", nunca "el programa hace esto".

## 2. Alternativas y decisión

| Opción | Resultado |
| --- | --- |
| capa 9.4.0 (reglas de capacidades de Mandiant) | **Descartada.** Su motor por defecto, vivisect, **emula instrucciones** durante el análisis: el módulo `vivisect.analysis.generic.emucode` y los pases `i386/amd64 emulation`, comprobado en el código instalado. `AGENTS.md` prohíbe emular la muestra. Desactivar esos pases a mano sería frágil, y además vivisect es lento para el límite de 30 s del worker. |
| Motor propio sobre capstone 5.0.9 (BSD, wheels para Linux x86-64 y Windows) | **Elegida.** capstone solo decodifica: traduce bytes a instrucciones y operandos. Dissect recorre el código por descenso recursivo y lee operandos constantes. No hay ningún estado de ejecución, memoria simulada ni saltos tomados. |

Prototipo medido el 2026-09-23 sobre 205 binarios de System32:
- Se encontraron 233.816 llamadas a funciones importadas y 14.915 argumentos que son cadenas.
- De 646 primeros argumentos recuperados de `RegOpenKeyEx`/`RegCreateKeyEx`, los 646 eran constantes `HKEY` válidas y ninguno otra cosa.
- Velocidad: capstone decodifica en modo ligero a 0,83 µs por instrucción (1,8 millones de instrucciones de `shell32.dll` en 1,5 s). En modo detalle cuesta 4,8 µs y, instrucción a instrucción, ~17 µs. De ahí el diseño de dos pasadas (sección 3.2).

## 3. Método

### 3.1 Qué código se recorre

Descenso recursivo por las secciones con bytes en disco marcadas como ejecutables, desde puntos de entrada conocidos:
- el punto de entrada de la cabecera;
- los exports que apuntan a código;
- los callbacks TLS;
- en x64, el inicio de cada función de la tabla de excepciones (`.pdata`), que el compilador escribe para cada función.

Se siguen los destinos directos de `call`, `jmp` y saltos condicionales, y la instrucción siguiente salvo tras `ret`, `jmp`, `int3`, `hlt` o `ud2`. Los saltos indirectos no se resuelven: no se adivinan tablas de salto.

### 3.2 Dos pasadas

1. **Pasada ligera** (`disasm_lite`): recorre el código, registra el inicio de cada bloque (destinos de salto y de llamada) y localiza las llamadas a funciones importadas.
2. **Pasada detallada**, solo sobre los bloques que contienen una llamada a una API del catálogo: decodifica con operandos y registros leídos y escritos (`regs_access`, que incluye las escrituras implícitas) para recuperar los argumentos.

### 3.3 Llamadas a funciones importadas

Solo tres formas, cada una con codificaciones canónicas que el host puede comprobar con aritmética (sección 5):

| Vía | x86 | x64 |
| --- | --- | --- |
| `direct` | `FF 15 abs32` (call [IAT]) | `FF 15 disp32` o `48 FF 15 disp32` (call [rip+disp]) |
| `thunk` | `E8 rel32` hacia un `FF 25 abs32` | `E8 rel32` hacia un `FF 25 disp32` / `48 FF 25 disp32` |
| `register` | `8B /r abs32` o `A1 abs32` (mov reg, [IAT]) y después `FF D0+r` (call reg) | `48/4C 8B /r disp32` (mov reg, [rip+disp]) y después `FF D0+r` / `41 FF D0+r` |

En la vía `register`, entre la carga y la llamada no puede haber ninguna escritura del registro ni el inicio de otro bloque. Solo se publican llamadas a APIs del catálogo (sección 4).

### 3.4 Argumentos (constantes en el mismo bloque)

El valor de un argumento se recupera solo si una instrucción del mismo bloque, anterior a la llamada, lo fija con una forma canónica, y nada lo sobrescribe después. Si otro camino puede entrar en medio del bloque, el seguimiento se reinicia en ese punto.

- **x86** (stdcall: argumentos en la pila, en orden inverso): los `push` desde el inicio del bloque o desde la última alteración de la pila. Solo `68 imm32` y `6A imm8` dan un valor; cualquier otro `push` cuenta como argumento desconocido. Cualquier otra modificación de `esp` (sub, add, pop, llamada) reinicia la lista. Con la aridad del catálogo, el argumento *i* es el *i*-ésimo `push` contando hacia atrás desde la llamada.
- **x64** (rcx, rdx, r8, r9): `lea r64, [rip+disp32]` (dirección), `mov r32, imm32`, `mov r64, imm32` con signo extendido y `xor r32, r32` (cero). Una escritura del registro o de cualquier subregistro, explícita o implícita, lo invalida. Del quinto argumento en adelante (pila) no se recupera nada.

Un argumento se publica solo si su tipo coincide con el que declara el catálogo para ese parámetro:
- **cadena**: la dirección apunta dentro de la imagen a una cadena terminada en NUL, imprimible, en la codificación del parámetro (A → ASCII, W → UTF-16LE);
- **HKEY**: una de las constantes predefinidas `0x80000000`–`0x80000006`;
- **entero**: por ejemplo, permisos de memoria o de acceso.

Si no coincide, Dissect se abstiene, y se mide cuántas veces pasa (sección 7).

### 3.5 Límites

Hay presupuestos declarados para instrucciones decodificadas, llamadas publicadas y argumentos publicados. Alcanzarlos deja el componente como parcial y lo dice con un código propio. Una arquitectura que no sea x86 ni x64 bloquea el componente (`unsupported_architecture`).

## 4. Catálogo `dissect-api-semantics-v1`

Lista revisada y versionada, con digest fijado por un test como las cribs y las familias. Cada API tiene su aridad (necesaria para leer la pila en x86), su familia de la Fase 3 y los parámetros que se interpretan, con nombre y tipo:

- **Registro**: `RegOpenKeyEx`, `RegCreateKeyEx`, `RegSetValueEx`, `RegQueryValueEx`, `RegDeleteValue`, `RegDeleteKey`, `RegGetValue`, `RegSetKeyValue`, `RegOpenKey`, `RegCreateKey`.
- **Servicios**: `CreateService` (nombre, nombre visible y ruta del binario) y `OpenService`.
- **Procesos**: `CreateProcess`, `WinExec`, `ShellExecute`, `OpenProcess` (derechos de acceso).
- **Bibliotecas**: `LoadLibrary`, `LoadLibraryEx`, `GetModuleHandle` y `GetProcAddress`. El nombre que recibe `GetProcAddress` revela funciones resueltas en tiempo de ejecución, que no aparecen en la tabla de imports.
- **Archivos**: `CreateFile`, `DeleteFile`, `CopyFile`, `MoveFile`, `MoveFileEx`, `CreateDirectory`.
- **Red**: `InternetOpen`, `InternetOpenUrl`, `InternetConnect`, `HttpOpenRequest`, `URLDownloadToFile`, `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`.
- **Sincronización**: `CreateMutex` y `OpenMutex`.
- **Memoria**: `VirtualAlloc`, `VirtualAllocEx`, `VirtualProtect`, `VirtualProtectEx` (protección de páginas, p. ej. `0x40` = ejecutable y escribible).
- **Criptografía**: `CryptAcquireContext` y `BCryptOpenAlgorithmProvider` (nombre del algoritmo).

Se incluyen las variantes A y W. Cada aridad y cada nombre de parámetro se comprueban contra la firma publicada en Microsoft Learn antes de fijar el catálogo.

## 5. Contrato 0.5.0 y verificación en el host

Cambios respecto a 0.4.0 (el esquema 0.4.0 se conserva en `docs/schemas/`):

- `import` gana `iat_rva`: la dirección de su casilla en la tabla de direcciones de import, que es a donde apuntan las llamadas.
- Nueva fuente `code` (`dissect-code-v1`), con los componentes `disassembly`, `api_calls` y `call_arguments`, y límites en `analysis.limits.code`.
- **`api_call`** (`observed`): la instrucción de llamada (desplazamiento, RVA, bytes), la vía, las instrucciones auxiliares (thunk o carga del registro) con sus bytes, el nombre de la API y la DLL. Cita el `import` correspondiente.
- **`call_argument`** (`inferred`): índice y nombre del parámetro, tipo, valor, instrucción que lo fija (con sus bytes) y, si es una cadena, sus bytes y su ubicación. Cita su `api_call`. Método: `block-constant-v1`.

El host no lleva desensamblador: un parser de código no fiable fuera del worker aislado contradiría la arquitectura. Comprueba cada evidencia así:
1. Los bytes citados coinciden con los de la muestra en sus desplazamientos.
2. La codificación es una de las formas canónicas de las secciones 3.3 y 3.4.
3. La aritmética del operando lleva exactamente a la casilla `iat_rva` del import citado (o al thunk, y de este a la casilla), usando las secciones del informe para pasar de RVA a desplazamiento.
4. En un argumento, el valor se deriva de los bytes de su instrucción; si es una cadena, sus bytes están en la ubicación declarada y la decodifican exactamente.

Lo que el host no puede comprobar sin desensamblar es que ninguna instrucción intermedia sobrescriba el valor. Por eso los argumentos son `inferred`, y el método es una regla del worker probada con casos negativos.

## 6. Explicaciones

- **Resumen por familia** (lo que responde a "qué hace"): "El código contiene 4 llamadas a funciones de registro de Windows y 2 de servicios…", citando todas las llamadas.
- **Una explicación por llamada con argumentos**. Por ejemplo: "En 0x14000285d el código llama a RegOpenKeyExW con hKey = HKEY_CURRENT_USER y lpSubKey = «Software\…\Policies\System»". Cita la llamada y sus argumentos, y hereda el nivel `inferred`.
- **Funciones resueltas por nombre**: "El código pasa a GetProcAddress estos nombres: …", que son funciones que no aparecen en la tabla de imports.
- **Límite obligatorio**: "el código contiene esta llamada; no demuestra que se ejecute".
- **Cobertura**: instrucciones recorridas. Si el recorrido es muy corto frente al tamaño del código, se recuerda que un binario empaquetado solo muestra su desempaquetador.

## 7. Medición antes de adoptar

Sobre el corpus benigno de las fases anteriores:
- **Tiempo**: distribución por archivo y peor caso a 20 MiB, dentro del límite de 30 s del worker.
- **Coherencia de tipos por parámetro**: HKEY, cadena o entero. Es el indicador de precisión de la recuperación de argumentos; toda incoherencia se examina y se corrige antes de adoptar.
- **Revisión manual** de 30 argumentos elegidos al azar, desensamblando a mano su bloque.
- **0 fallos en la verificación del host** sobre todo el corpus: un fallo invalidaría el informe entero.

## 8. Plan de implementación

1. Este diseño y la hoja de ruta.
2. Dependencia capstone 5.0.9 fijada; contrato 0.5.0 con `iat_rva` en imports y esquema 0.4.0 archivado.
3. Motor de desensamblado (pasada ligera, bloques y presupuesto), con fixtures sintéticos x86/x64 construidos byte a byte.
4. Llamadas a imports (tres vías) y argumentos (pasada detallada), con casos negativos de sobrescritura, bloques partidos y aridad.
5. Catálogo `dissect-api-semantics-v1`, verificado contra Microsoft Learn.
6. Integración: evidencias, colector, límites, extractor `code`, verificación aritmética en el host e imagen `dissect-worker:0.5.0`.
7. Mediciones de la sección 7 y ajustes.
8. Explicaciones, glosario, renderizado, documentación, demostración con fixture sintético y PR.

## 9. Entrega 1: versión reducida (implementada)

Responde a "qué funciones importadas llama el código y desde dónde", sin argumentos ni catálogo semántico. Cubre los pasos 2, 3, 4 (sin argumentos), 6, 7 y 8 del plan de la sección 8. Los argumentos y el catálogo `dissect-api-semantics-v1` quedan para la entrega 2.

### 9.1 Diferencias con las secciones anteriores

- **Todas las funciones importadas, no solo las del catálogo.** Sin argumentos, el catálogo no aporta nada que no dé ya la tabla de imports: se publica toda llamada cuya casilla es la `iat_rva` de un `import` publicado, por nombre u ordinal.
- **Vía `register`, más estricta que en la sección 3.3.** La carga `mov reg, [casilla]` debe ser la instrucción inmediatamente anterior a `call reg`, sin nada en medio. Así el propio informe comprueba la adyacencia con aritmética, y no hace falta el modo detallado de capstone para saber qué registros se escriben entre las dos. El coste medido es de cobertura, no de error: 9 llamadas por registro en 92 DLL de SysWOW64 y ninguna en 88 de System32 (x64), donde el compilador llama casi siempre con `call [rip+disp]`.
- **Verificación también en el modelo.** Como el hecho lleva los bytes de sus instrucciones, `Report` rehace la aritmética de la sección 5 sin la muestra; el host y `explain --sample` solo comparan esos bytes con los de la muestra.
- **Sin pasada detallada.** Solo hay una pasada, que lee de cada instrucción su identificador numérico y su longitud, y el texto del operando solo en saltos y llamadas.

### 9.2 Presupuestos y orden de publicación

| Límite | Valor | Motivo medido |
| --- | --- | --- |
| Instrucciones decodificadas | 4.000.000 (8.000.000 desde la sección 9.5) | Peor caso sintético de 20 MiB dentro del tiempo del worker (sección 9.4) |
| Llamadas examinadas | 262.144 (1.048.576 desde la sección 9.5) | Clasificar una llamada cuesta varias veces más que decodificar una instrucción; sin este límite, 20 MiB de llamadas tardaban 29–38 s |
| Puntos de partida | 262.144 | Acota la lista de `.pdata`, que un archivo manipulado puede declarar enorme |
| Llamadas publicadas | 4.096 | Cabe en el presupuesto de bytes del informe (unos 330 bytes por hecho) |

Con la cuota agotada se publica primero la primera llamada de cada import y después las repetidas, en el orden del recorrido, para que las llamadas publicadas cubran el máximo de funciones distintas. En memoria solo se guarda una llamada por casilla más la cuota de repetidas, y las instrucciones visitadas se marcan en un `bytearray` por sección: el peor caso medido no pasa de 133 MiB de pico con 101 MiB de base.

### 9.3 Explicaciones y glosario

- `code.calls@1`: una por función importada llamada, citando el import y todas sus llamadas publicadas, con hasta 20 direcciones y su vía. Por ejemplo: "El código contiene 3 llamadas a la función importada «ExitProcess» de «kernel32.dll»", con los sitios `0x00002000 (directa)`, etc.
- `code.family@1`: una por familia curada de la Fase 3 con llamadas. La cifra de prevalencia de la Fase 3 se midió sobre imports, no sobre llamadas, así que no se repite aquí.
- Límite en ambas: "Que el código contenga la llamada no demuestra que se ejecute…".
- Nueva entrada de glosario `code.import_call` (revisión del glosario 1.1.0), con tres fuentes de Microsoft Learn comprobadas el 2026-09-23: el thunk `jmp DWORD PTR __imp_func1` de `__declspec(dllimport)`, la IAT del formato PE y `.pdata` en x64. Matiz de la fuente: `.pdata` solo lista las funciones que reservan pila o llaman a otras, así que las funciones hoja pueden no estar.

### 9.4 Mediciones (2026-09-23, `uv run python -m tests.code_eval`)

**Corpus benigno** (solo PE y código; muestreo `--stride 3` en System32 y `--stride 5` en SysWOW64):

| Conjunto | Archivos | Llamadas publicadas | Informes inválidos | Fallos de verificación de bytes | Llamadas x64 fuera de `.pdata` | Imports por nombre con alguna llamada | Tiempo p50 / p99 / máx. |
| --- | --- | --- | --- | --- | --- | --- | --- |
| System32 | 1.363 | 1.230.382 (84 % directas, 16 % thunk) | 0 | 0 | 0 de 1.230.245 | 90,4 % (198.466 de 219.628) | 0,23 / 3,77 / 14,15 s |
| SysWOW64 | 520 (+1 bloqueado) | 145.084 (88 % directas, 12 % thunk, 14 por registro) | 0 | 0 | 3 de 2.369 | 43,8 % (34.291 de 78.372) | 0,09 / 1,63 / 8,83 s |

- Las 3 llamadas fuera de `.pdata` (`edit.exe`, x64) se revisaron desensamblando a mano: son auténticas. Forman una función real (`push rsi; sub rsp, 0x30` tras relleno `int3`) que llama a `AddVectoredExceptionHandler`, `SetThreadStackGuarantee` y `GetCurrentThread`, pero no tiene entrada en `.pdata`. El indicador señala código fuera de funciones declaradas, no errores; cada caso se revisa.
- El mayor binario benigno medido tiene 2,3 millones de instrucciones recorridas (`Windows.UI.Xaml.dll`, 14,15 s, medido con otra carga en la máquina), por debajo del presupuesto de 4 millones. 66 archivos alcanzaron la cuota de 4.096 llamadas publicadas y 2 el máximo de 262.144 llamadas examinadas.
- **Cobertura x86, el límite principal.** Sin `.pdata`, el recorrido en x86 solo parte del punto de entrada, los exports y los callbacks TLS; el código al que se llega por punteros (vtables COM, callbacks) no se recorre. Por eso solo el 43,8 % de los imports por nombre tiene alguna llamada, frente al 90,4 % en x64. Candidato siguiente, que hay que medir: la tabla de funciones de Control Flow Guard (`GuardCFFunctionTable` del directorio de configuración de carga). La escribe el compilador, igual que `.pdata`, y lista los destinos válidos de llamadas indirectas. No se adoptará un barrido heurístico de prólogos: adivina inicios de función.

**Peores casos sintéticos de 20 MiB** (en el host, cada caso en su proceso):

| Caso | Tiempo | Pico de memoria | Resultado |
| --- | --- | --- | --- |
| `nop` continuo | 7,0 s | 103 MiB | `disassembly` parcial en 4.000.000 instrucciones |
| `jz` a la siguiente instrucción | 14,2 s | 103 MiB | parcial en 4.000.000 |
| `call rel32` continuo | 3,9 s | 103 MiB | parcial en 262.144 llamadas examinadas |
| `call [casilla]` continuo | 4,2 s | 104 MiB | parcial; 4.096 publicadas |

La base del proceso (intérprete y entrada de 20 MiB) ocupa 101 MiB. Variantes medidas y descartadas:
- `disasm_lite` de capstone convierte a texto cada mnemónico y operando: 10,5 s en el caso `nop`, frente a 7,0 s con `cs_disasm` e identificadores numéricos.
- Guardar cada sitio de llamada como objeto y clasificarlos después: unos 500 MiB previstos con 4 millones de llamadas. Un array compacto seguía necesitando 29–38 s de clasificación. Se sustituyó por la clasificación en línea con memoria acotada y el máximo de llamadas examinadas.
- Parsear el operando con `int()` y capturar la excepción: 3,5 µs por llamada; sin excepciones es casi gratis.
- `tracemalloc` para medir memoria ralentizaba el recorrido más de 10 veces: se mide el pico real del proceso.

**En el contenedor** (`dissect-worker:0.5.0`, 1 CPU, 512 MiB; las cinco fuentes y el arranque del contenedor; 11 pruebas `-m docker` en verde):

| Entrada | Tiempo total | Código |
| --- | --- | --- |
| `jz` continuo, 20 MiB | 17,2 s de 30 | parcial en 4.000.000 instrucciones |
| `nop` continuo, 20 MiB | 14,1 s | parcial en 4.000.000 instrucciones |
| `call [casilla]` continuo, 20 MiB | 11,6 s | parcial en 262.144 llamadas examinadas |
| `Windows.UI.Xaml.dll` (benigno, System32) | 12,2 s | parcial en 262.144 llamadas examinadas (2,3 millones de instrucciones) |

Pendiente de decidir con medición:
- Un binario benigno real agota el máximo de llamadas examinadas. Subirlo a 524.288 costaría unos 2 s más en el peor caso de llamadas (≈ 7 µs por llamada), que seguiría por debajo del caso `jz`. Exige cambiar el contrato y repetir estas mediciones.
- Falta medir un peor caso combinado (mitad del archivo diseñada contra la decodificación de la Fase 2 y mitad contra el recorrido).

### 9.5 Revisión: más puntos de partida y límites de tiempo (2026-09-23)

**Tablas del compilador como puntos de partida.** El recorrido parte además de la tabla de funciones de Control Flow Guard (`GuardCFFunctionTable`, x86 y x64) y de los manejadores SafeSEH (x86). Validación en x64, donde `.pdata` sirve de referencia (System32, `--stride 20`, 205 archivos):

| Puntos de partida | Imports por nombre con alguna llamada | Llamadas | Fuera de `.pdata` |
| --- | --- | --- | --- |
| Entrada, exports y TLS | 36,4 % | 50.909 | 0 |
| + `.pdata` | 89,6 % | 197.809 | 0 |
| + Control Flow Guard, **sin** `.pdata` | 87,7 % | 190.103 | 0 |
| Todas | 89,6 % | 197.809 | 0 |

Solo desde la tabla de Control Flow Guard se alcanza el 96 % de las llamadas que alcanza `.pdata`, y ninguna fuera de una función declarada. De 15.586 destinos de esa tabla en 60 DLL, 9.241 son inicios de `.pdata` y ninguno cae dentro del cuerpo de otra función. Los 6.345 restantes quedan fuera de todos los rangos; una muestra desensamblada a mano mostró funciones hoja (`mov eax, 0x40; ret`) y *adjustor thunks* de C++ (`sub rcx, 0x10; jmp …`), que no llevan entrada en `.pdata`.

En x86 (SysWOW64, `--stride 10`, 260 archivos), los imports por nombre con alguna llamada pasan del **44,5 % al 90,9 %** (18.174 → 37.173) y las llamadas, de 81.521 a 215.544. SafeSEH aporta poco (23 imports más) pero no cuesta nada. Precio: el p99 de PE+código en el host pasa de 2,2 s a 10,4 s.

**Bucle del recorrido.** Cada lote de capstone se copia una vez y solo se desempaquetan el identificador y el tamaño (`Windows.UI.Xaml.dll`: 17,5 → 14,8 s). Se midió un lote adaptativo (empezar con 4, 8 o 16 instrucciones y duplicar): sin ganancia fuera del ruido, descartado.

**Límites de tiempo.** Con el portátil en batería, la máquina virtual de Docker iba unas 2,5 veces más lenta: `Windows.UI.Xaml.dll` pasó de 12,2 s a más de 30 s y el análisis terminó en `timeout`, sin informe. Ahora el recorrido se detiene cuando el análisis lleva `code.seconds` (15 s, o la mitad de `timeout_seconds`), y la búsqueda XOR de la Fase 2 a los 10 s. Cada uno lo declara con su código. En el contenedor, en batería:

| Entrada | Total | Límites alcanzados |
| --- | --- | --- |
| `nop` continuo, 20 MiB | 21,9 s | `decode_time_limit` (el código completa sus 4.000.000 instrucciones) |
| `jz` continuo, 20 MiB | 20,0 s | `decode_time_limit`, `code_time_limit` |
| `call [casilla]` continuo, 20 MiB | 18,3 s | `decode_time_limit` |
| `Windows.UI.Xaml.dll` | 21,6 s | `decode_time_limit`, `code_time_limit` |
| `mshtml.dll` (x86) | 21,6 s | `decode_time_limit`, `code_time_limit` |
| `shell32.dll` | 20,7 s | ninguno (código completo; llamadas publicadas en su cuota) |

Ningún caso agota ya los 30 s. El coste es que, en una máquina lenta, los DLL benignos más grandes quedan parciales en XOR y código; en la misma máquina conectada a la corriente se completaban. Se prefirió este reparto conservador: un timeout pierde el informe entero.

**Topes por recuento, revisados.** Con el tiempo acotado por los dos límites anteriores, los topes por recuento ya no protegen del timeout: son solo topes de cordura. Se subieron a 8.000.000 instrucciones y 1.048.576 llamadas examinadas, porque con los anteriores quedaban partidos DLL benignos. Completar `Windows.UI.Xaml.dll` exige 3.266.335 instrucciones y 379.675 llamadas; `mshtml.dll` (x86), 4.246.274 instrucciones. Medido en el contenedor, con el portátil conectado a la corriente (11 pruebas `-m docker` en verde):

| Entrada | Total | Código | Límites |
| --- | --- | --- | --- |
| `nop` continuo, 20 MiB | 16,6 s | parcial en 8.000.000 | `code_instruction_limit`, `decode_time_limit` |
| `jz` continuo, 20 MiB | 17,7 s | parcial en 4.038.656 | `code_time_limit`, `decode_time_limit` |
| `call rel32` continuo, 20 MiB | 12,5 s | parcial en 1.048.576 llamadas | `call_site_limit` |
| `call [casilla]` continuo, 20 MiB | 15,0 s | parcial en 1.048.576 llamadas | `call_site_limit`, `api_call_limit` |
| `Windows.UI.Xaml.dll` | 15,1 s | **recorrido completo** | `api_call_limit` |
| `mshtml.dll` (x86) | 14,8 s | **recorrido completo** | `api_call_limit` |
| `shell32.dll` | 9,0 s | recorrido completo | `api_call_limit` |

El caso `nop` es también el peor combinado: agota a la vez el tiempo de la búsqueda XOR y el tope del recorrido. Por construcción, ninguna combinación pasa de la marca de 15 s del código más el arranque y la serialización.

**Corpus completo con los puntos de partida nuevos** (mismas muestras que la sección 9.4):

| Conjunto | Archivos | Llamadas | Inválidos | Fallos de verificación | Fuera de `.pdata` | Imports por nombre con alguna llamada |
| --- | --- | --- | --- | --- | --- | --- |
| System32 | 1.363 | 1.230.385 | 0 | 0 | 0 de 1.230.245 | 90,4 % (sin cambio: ya tenía `.pdata`) |
| SysWOW64 | 520 | 412.834 (antes 145.084) | 0 | 0 | 3 de 2.369 (los de `edit.exe`, auténticos) | **90,7 %** (antes 43,8 %) |

## 10. Entrega 2: argumentos constantes (implementada para `RegOpenKeyExA/W` y `RegCreateKeyExA/W`)

Responde a "con qué constantes llama el código a una función del catálogo". Publica `call_argument` (`inferred`, componente `call_arguments`) dentro del contrato 0.5.0, que no se había publicado. El catálogo `dissect-api-semantics-v1` empieza con `RegOpenKeyExA/W`; el resto de la sección 4 se añadirá en cambios separados, comprobando cada firma.

### 10.1 Diferencias con la sección 3.4

- **Tramo lineal, no bloque básico.** El recorrido pasa a cada llamada el inicio de su tramo: el inicio de la ejecución lineal o la instrucción siguiente a la llamada anterior del mismo tramo. Una llamada reinicia el seguimiento porque, según la convención x64 de Microsoft Learn, `RCX`, `RDX`, `R8` y `R9` son volátiles ("consider volatile registers destroyed on function calls"). En x86, la llamada mueve la pila. Los saltos condicionales no cortan el tramo: la entrada de otro camino está en su destino.
- **Marcas de entrada.** Un `bytearray` por sección marca los puntos de partida, los destinos constantes de saltos y llamadas (también los que un límite dejó pendientes) y los puntos donde una ejecución alcanza código ya decodificado por otra. Esto último cubre la entrada por un flujo de instrucciones desalineado. El coste no se pudo medir: shell32 2,67 → 2,69 s, mshtml 7,26 → 7,18 s.
- **Se decodifica solo desde la última entrada.** El modo detallado empieza en la última marca anterior a la llamada, o en el inicio del tramo si no hay ninguna. Si la decodificación no cae exactamente en la llamada, Dissect no publica nada: la llamada está en otro flujo de instrucciones. Si hay una marca en la propia llamada, tampoco se publica nada.
- **Solo instrucciones revisadas.** capstone 5.0.9 no declara todas las escrituras implícitas: `syscall` no incluye `RCX`, `rdpkru` no incluye `EDX` y `rdsspq rcx` no incluye `RCX` (comprobado al escribir el módulo). Por eso solo se confía en su lista de registros escritos para las instrucciones de `_TRUSTED` (`mov`, `lea`, aritmética y lógica, `push`/`pop`, `setcc`/`cmovcc`, copias SSE y saltos condicionales), cada una comprobada en `tests/test_code_args.py`. Cualquier otra olvida todo lo seguido.
- **x86.** Solo `push` de 32 bits. Cualquier otra escritura de `esp` (incluido `push` de 16 bits) o cualquier escritura en memoria direccionada desde `esp` olvida la lista. Límite aceptado: una escritura en la pila a través de otro registro que apunte a ella no se detecta.
- **Tipos, más estrictos:**
  - `hkey`: solo las cinco claves que Learn lista para `hKey`, con su valor de `winreg.h` (`((HKEY)(ULONG_PTR)((LONG)0x80000001))`). En x64 se acepta solo la extensión con signo; `mov ecx, 0x80000001` (extensión con ceros) es otro puntero y se descarta.
  - `integer`: módulo el ancho del parámetro (32 bits para `REGSAM`). Learn: "the callee can ignore the upper bits of the register".
  - `string`: cadena ASCII imprimible no vacía, terminada en NUL, en una sección que no se puede escribir.
  - Además, la función importada tiene que venir de una DLL que su página de Learn declare como exportadora (`api_location`).

### 10.2 Mediciones (2026-09-24, `uv run python -m tests.code_eval corpus … --review 15`)

Mismas muestras que la sección 9.4. Todo lo publicado es coherente con su tipo por construcción. El indicador de error es la constante que el tramo **recupera** y el tipo **rechaza**; cada caso se examina.

| Conjunto | Llamadas del catálogo examinadas | Argumentos publicados | Informes inválidos | Fallos de bytes |
| --- | --- | --- | --- | --- |
| System32 (x64) | 5.309 | 9.510 | 0 | 0 |
| SysWOW64 (x86; 3 en x64) | 1.839 | 3.514 | 0 | 0 |

| Parámetro | x64: recuperados / aceptados | x86: recuperados / aceptados | Rechazos examinados |
| --- | --- | --- | --- |
| `hKey` | 2.986 / 2.986 (+3 / 3 en SysWOW64) | 1.070 / 1.069 | El único es `push 0x80000007` en winmsipc.dll: `HKEY_CURRENT_USER_LOCAL_SETTINGS`, un valor auténtico que Learn no lista para `hKey`. **Ninguna clave recuperada era errónea.** |
| `lpSubKey` | 2.498 / 2.370 | 961 / 934 | 77 son `NULL` (`xor edx, edx` o `push 0`), válido según Learn pero no es una cadena. 69 están en una sección escribible. 5 apuntan a búferes sin bytes en disco. 4 no son una cadena imprimible no vacía; las dos revisadas (combase.dll y NetSetupEngine.dll) son cadenas vacías. |
| `samDesired` | 4.154 / 4.154 (+3 / 3) | 1.505 / 1.505 | — |

**Revisión manual de 30 argumentos al azar** (15 x64, semilla 64; 15 x86, semilla 32), desensamblando cada tramo: **30 correctos**. Ninguna instrucción entre la que fija el valor y la llamada escribe ese registro ni mueve la pila. En modemui.dll, un `jne` entra en el tramo antes de la instrucción que fija el valor: el seguimiento se reinicia ahí y el valor sigue siendo válido. Las abstenciones vistas en esas muestras eran correctas:
- `mov r9d, r12d` en mapi32: no se propagan valores entre registros;
- `lea r9d, [rdi+2]` en dxdiagn: no es una forma canónica;
- `xor edx, edx` en GameManager64: es `NULL`.

**Coste.**
- El paso de argumentos usó 56.687 instrucciones en modo detallado en todo System32 (2,07 s) y 19.533 en SysWOW64 (0,89 s). Ningún archivo se acercó al presupuesto.
- Un tramo diseñado para agotarlo (`argument-stretches`: 63 `nop` antes de cada llamada) mide unos 11,8 µs por instrucción detallada: 262.144 instrucciones costaban 3,05 s. Por eso el valor por defecto de `argument_instructions` es **65.536** (máximo del contrato, 262.144). El peor caso baja a 0,76 s y lo declara con `argument_instruction_limit`. Por la medición, ningún binario benigno pierde cobertura: el corpus entero de System32 usó menos que eso.
- El paso comparte además la marca de tiempo del recorrido (`code_time_limit`).

**Peores casos de 20 MiB en el host** (`uv run python -m tests.code_eval worst`, cada caso en su proceso, presupuesto de 262.144):

| Caso | Tiempo total | Pico | Resultado |
| --- | --- | --- | --- |
| `argument-stretches` | 8,14 s (paso de argumentos: 3,05 s; con 65.536: 0,76 s) | 125 MiB | `call_arguments` examina 4.096 llamadas y no publica nada: no hay constantes |
| `argument-values` (cuatro `push` constantes por llamada) | 7,38 s (paso: 0,44 s) | 135 MiB | 4.096 argumentos publicados, `call_argument_limit` |
| `nop`, `jz`, `call rel32`, `call [casilla]` | 4,3 / 10,1 / 3,4 / 4,2 s | 124–125 MiB | Sin cambio respecto a la sección 9.5 en lo que declaran |

**En el contenedor** (`dissect-worker:0.5.0` reconstruida con esta entrega, 1 CPU y 512 MiB, con las cinco fuentes y el arranque; portátil conectado a la corriente; valores por defecto, incluido el presupuesto de 65.536):

| Entrada | Total | Código |
| --- | --- | --- |
| `argument-stretches` | 17,4 s de 30 | `call_arguments` parcial en 1.040 llamadas: `argument_instruction_limit` |
| `argument-values` | 16,4 s | 4.096 argumentos publicados, `call_argument_limit` |
| `jz` continuo | 17,5 s (17,7 s en la sección 9.5) | `code_time_limit` |
| `nop` continuo | 16,1 s | `code_instruction_limit` |

El paso de argumentos no mueve el peor caso: el más lento sigue siendo el recorrido del caso `jz`.

### 10.3 Explicación y glosario

- `code.arguments@1`: una por llamada con argumentos. Cita la llamada y todos sus argumentos, en orden del informe, y hereda `inferred`. Por ejemplo: "En 0x00002017 el código llama a «RegOpenKeyExW» con hKey = HKEY_CURRENT_USER, lpSubKey = «Software\Dissect\Training», samDesired = 0x20019". Las cadenas de más de 200 caracteres se recortan indicando su longitud.
- Nueva entrada `code.call_argument` (glosario 1.2.0), con cinco fuentes de Learn comprobadas el 2026-09-24. Su límite recoge además que `RegOverridePredefKey` puede redirigir una clave predefinida: `hKey = HKEY_CURRENT_USER` no demuestra qué clave se abre.
- El título de la sección 3 del informe pasa a "resultados de aplicar un método a los bytes": un argumento no es una transformación.

### 10.4 Catálogo v2: `RegCreateKeyExA/W` (2026-09-24)

Firma comprobada en Microsoft Learn el 2026-09-24: 9 parámetros (`hKey`, `lpSubKey`, `Reserved`, `lpClass`, `dwOptions`, `samDesired`, `lpSecurityAttributes`, `phkResult`, `lpdwDisposition`). Las mismas cinco claves para `hKey` y las mismas DLL exportadoras que `RegOpenKeyEx`, salvo que la página ANSI no lista `kernel32.dll`. Se interpretan `hKey`, `lpSubKey`, `dwOptions` y `samDesired`. En x64, `dwOptions` y `samDesired` son el 5.º y el 6.º argumento y van en la pila, que Dissect no lee: solo se recuperan en x86. El catálogo pasa a `dissect-api-semantics-v2`, con su digest fijado.

Mismo corpus y método que la sección 10.2:

| Conjunto | Llamadas del catálogo examinadas | Argumentos publicados | Informes inválidos | Fallos de bytes | `argument_instruction_limit` |
| --- | --- | --- | --- | --- | --- |
| System32 | 6.938 (antes 5.309) | 10.822 (antes 9.510) | 0 | 0 | 0 archivos (79.147 instrucciones detalladas en total, 2,07 s) |
| SysWOW64 | 2.472 (antes 1.839) | 4.700 (antes 3.514) | 0 | 0 | 0 archivos (28.442 en total, 0,96 s) |

| `RegCreateKeyEx`, parámetro | x64: recuperados / aceptados | x86: recuperados / aceptados |
| --- | --- | --- |
| `hKey` | 715 / 715 (A 37, W 677, más 1 en SysWOW64) | 303 / 303 |
| `lpSubKey` | 617 / 598 | 296 / 288 |
| `dwOptions` | no se recupera (pila) | 82 / 82 |
| `samDesired` | no se recupera (pila) | 512 / 512 |

- **Ninguna clave recuperada era errónea.**
- **`dwOptions`** solo toma valores documentados: 33 × 0 (`REG_OPTION_NON_VOLATILE`), 47 × 1 (`REG_OPTION_VOLATILE`) y 2 × 4 (`REG_OPTION_BACKUP_RESTORE`).
- **`samDesired`**: el tipo entero acepta cualquier valor, así que aquí la coherencia de tipos no prueba nada. Lo que respalda estos valores es la revisión manual. Los más frecuentes son 0x2001f (164), 0x20006 (`KEY_WRITE`, 75), 0x2 (63), 0xf003f (`KEY_ALL_ACCESS`, 61) y 0x2000000 (`MAXIMUM_ALLOWED`, 30).
- **Los 27 `lpSubKey` rechazados:**
  - 22 están en una sección escribible;
  - 4 son una cadena vacía en `.rdata` de schedsvc.dll, que Learn permite pero Dissect no publica;
  - 1 apunta a un búfer sin bytes en disco.
  - Ninguno es `NULL`, coherente con Learn: "This parameter cannot be NULL".

**Revisión manual de 30 argumentos de `RegCreateKeyEx`** (15 x64, semilla 64; 15 x86, semilla 32; `--review-match RegCreateKeyEx`): **30 correctos**.
- En x86, `samDesired` es el 6.º `push` hacia atrás. En stobject.dll, un `mov [esp+0x10], 0x1f` entre los `push` reinicia la lista, y aun así las posiciones 0 a 7 que quedan son las correctas.
- Abstenciones vistas en las muestras: hKey copiada entre registros (`mov rcx, r15` en rtutils.dll) y valores desde registros o memoria (`push edi`, `push [ebp+8]`).

Con la suma de las dos funciones, el corpus de System32 usó en total más instrucciones detalladas (79.147) que el presupuesto por archivo (65.536). Pero el presupuesto se aplica a cada archivo, y ninguno lo alcanzó.
