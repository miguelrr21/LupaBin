# Fase 4: qué hace el código, en estático (llamadas a API y sus argumentos)

Estado: revisión 1 (2026-09-23), diseño antes de implementar. Responde a la petición del usuario: que Dissect "analice en estático el binario y diga exactamente lo que hace". El alcance y sus límites se registraron en `docs/roadmap.md`.

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
