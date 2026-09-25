# Fase 2: decodificación estática acotada (Base64/hex/XOR)

Estado: revisión 2 (2026-09-22), implementada; segunda ronda de optimización medida el 2026-09-23 (catálogo v3). La revisión 1 proponía aplicar XOR sobre las cadenas ya extraídas y filtrar con un umbral de ambigüedad `K`; al ejecutarla sobre datos reales resultó estructuralmente errónea (sección 2.2). Esta revisión corrige el enfoque XOR con un método medido sobre 4.092 binarios reales (sección 8). El usuario pidió corregir el problema y continuar la implementación. El contrato ejecutable es 0.4.0 (sección 11).

## 1. Propósito y límites del producto

LupaBin ya conserva cadenas literales (`string`, Fase 1A) y coincidencias de reglas (`yara_match`, Fase 1B). Esta fase añade hechos derivados: bytes que, al aplicarles una transformación determinista y documentada, producen texto legible.

La afirmación permitida es "estos bytes, transformados con este algoritmo y estos parámetros exactos, producen este texto". No equivale a decir que el programa realiza esa transformación, que el texto sea el pretendido por su autor ni que tenga un significado (URL, comando, ruta). Todo resultado es `confidence="inferred"`. Sigue prohibido ejecutar o emular la muestra.

Retoma lo que ya anticipaba el contrato 0.1.0 ("Desofuscación en una etapa posterior"): decodificación estricta de Base64/hexadecimal y candidatos XOR sencillos, donde "una transformación reproducible demuestra el resultado de esa operación, no que el programa la efectúe".

## 2. Alcance y alternativas

### 2.1 Alcance

- **Base64 y hexadecimal estrictos** sobre cadenas ya extraídas (`string`, ASCII o UTF-16LE). Son codificaciones imprimibles por construcción, así que su forma codificada siempre es visible como `string`.
- **XOR de clave repetida de 1 a 8 bytes** sobre los **bytes crudos** de la muestra, anclado en un catálogo versionado de cadenas de referencia ("cribs"), en ASCII y UTF-16LE.

Todo es cómputo en memoria con la biblioteca estándar, sin dependencias nuevas.

### 2.2 Enfoque descartado tras medirlo: XOR sobre cadenas extraídas

La revisión 1 aplicaba XOR a las cadenas ya extraídas y aceptaba claves cuyo resultado fuese imprimible. Medido sobre una muestra sintética real y sobre cadenas aleatorias imprimibles:

- **El ruido es estructural, no casual.** XOR con una clave `< 0x20` nunca saca un byte de su bloque de 32 valores, así que texto imprimible sigue siendo imprimible. Una cadena imprimible admite de media 37, 28 y 24 claves "válidas" con 6, 12 y 24 caracteres: la longitud no lo corrige. Con ello el umbral `K=4` de la revisión 1 se abstendría siempre.
- **Buscaba en el lugar equivocado.** Para una URL real cifrada con XOR de un byte, en 211 de 255 claves (83 %) el texto cifrado no es imprimible, y en ninguna clave `>= 0x80` lo es. `strings` nunca lo extrae, así que XOR sobre `strings` solo "descifra" texto que ya estaba en claro.

### 2.3 Otras alternativas descartadas

- **Fuerza bruta de claves con puntuación de "parecido a texto"** (enfoque de xortool/bbcrack): exige una puntuación de plausibilidad, que el contrato prohíbe ("no se asignarán probabilidades... sin un método definido").
- **Confirmar coincidencias débiles con una racha descifrada larga**: medido (sección 8), produce 402 falsos positivos en binarios benignos, porque las claves espurias son texto⊕texto y descifrar texto vecino con ellas sigue dando texto imprimible.
- **Nivel "débil" con menos bytes verificados** (2–4 bytes no nulos), incluso exigiendo que la clave derivada tenga un byte ≥ 0x80 y que el texto descifrado se extienda: medido en 1.500 archivos (sección 8), entre 52 y 52.119 falsos positivos según la variante. Recurren claves idénticas en decenas de DLL distintas: son estructuras del formato (tablas de nombres), no azar. Un solo byte alto en la clave no basta, porque basta un byte extraño en la ventana.
- **Modificador `xor` de YARA**: solo admite claves de un byte y acoplaría la decodificación al subproceso YARA.
- **Encadenar transformaciones** (Base64 sobre un resultado XOR, etc.): ambigüedad combinatoria. Cada `decoded_string` deriva de exactamente una transformación.
- **FLOSS/emulación**: descartados desde el contrato 0.1.0.

Quedan fuera: Base32, ROT/Caesar, compresión, RC4 u otros cifrados con clave, XOR rodante o incremental, claves de más de 8 bytes, capa, web, LLM y cualquier puntuación.

## 3. Enfoque técnico

El extractor `decode` se ejecuta después de `strings` (`pe` → `strings` → `yara` → `decode`). Base64/hex leen las evidencias `string` del colector; XOR recorre el buffer original.

### 3.1 Base64 estricto (`base64-strict-v1`)

Se admite una cadena fuente con `complete=true` cuyo texto: tiene longitud múltiplo de 4 y **≥ 12 caracteres si termina en `=`, o ≥ 16 si no lleva relleno** (los identificadores de código nunca llevan `=`); usa solo el alfabeto estándar con como máximo dos `=` finales; se decodifica con validación estricta; y **se vuelve a codificar exactamente al mismo texto** (rechaza bits de relleno no canónicos, que `base64.b64decode(validate=True)` de Python acepta, p. ej. `"aGVsbG9="`). El resultado debe ser ASCII imprimible con **≥ 4 caracteres distintos**.

### 3.2 Hexadecimal estricto (`hex-strict-v1`)

Longitud par **≥ 8**, solo `0-9a-fA-F`, **y no formada solo por dígitos decimales** (un número como `2147483647` es hexadecimal válido); resultado ASCII imprimible con **≥ 4 bytes** y **≥ 4 caracteres distintos**.

Los mínimos de 3.1 y 3.2 provienen de dos rondas de medición (sección 8). En la primera (1.500 binarios) todos los falsos positivos Base64 tenían 8 caracteres (identificadores como `fileType`) y todos los hexadecimales eran relleno repetitivo (`44444444444444` → `DDDDDDD`). En la segunda, con el corpus completo, quedaban un identificador de 12 letras sin relleno (`SystemEventW`) y ocho números decimales (`2147483647` → `!GH6G`), que motivan las dos reglas finales.

### 3.3 XOR anclado por diferenciales (`xor-repeating-v1`)

**Invariante.** Si `c[i] = p[i] ⊕ k[i mod L]`, entonces `c[i] ⊕ c[i+L] = p[i] ⊕ p[i+L]`: el diferencial con retardo `L` del texto cifrado no depende de la clave. Buscar el diferencial de una crib en el diferencial del archivo encuentra esa crib **bajo cualquier clave de periodo `L` en una sola pasada**, sin enumerar claves.

Procedimiento para cada crib (codificada en ASCII y en UTF-16LE) y cada retardo `L` planificado:

1. `D_L = datos[0:n-L] ⊕ datos[L:n]`, calculado como XOR de enteros grandes (tiempo lineal, en C).
2. Patrón de la crib `P_L[i] = crib[i] ⊕ crib[i+L]`. Solo se usa si tiene **≥ 5 bytes no nulos**: un cero del diferencial coincide con cualquier racha de bytes repetidos (relleno, alineación), así que no verifica nada.
3. Para cada aparición de `P_L` en `D_L` en la posición `i`:
   - **Rechazar si la ventana del archivo `datos[i:i+len(crib)]` ya es texto** (todos sus bytes en ASCII imprimible ∪ {0x00, \t, \n, \r}). Es la regla que elimina los falsos positivos texto⊕texto (sección 8).
   - Derivar la clave `K[j] = datos[i+j] ⊕ crib[j]`, `j < L`, y reducirla a su **periodo mínimo**. Rechazar la clave nula (sería la crib en claro, ya visible como `string`).
   - Reverificar byte a byte que `datos[i+j] ⊕ K[j mod |K|] = crib[j]` en toda la crib (defensa en profundidad).
   - Extender el texto descifrado a izquierda y derecha mientras siga siendo imprimible (ASCII) o pares (imprimible, 0x00) alineados con la crib (UTF-16LE), con un presupuesto total de 1.024 caracteres repartido de forma equilibrada. `complete=true` solo si ambos extremos son límites naturales.
4. La clave publicada se rota para alinearse con el inicio de la región: `texto[j] = datos[inicio+j] ⊕ clave[j mod |clave|]`.

**Planificación de retardos.** Una clave de periodo `p` también es invariante para todo retardo múltiplo de `p`. Para cada crib se eligen, de mayor a menor, los retardos `L ≤ 8` con patrón válido que cubren algún periodo aún no cubierto. Un periodo sin retardo válido no se busca con esa crib: es el límite de cobertura documentado en la sección 8, no un fallo.

**Por qué no hay umbral de ambigüedad.** La clave no se elige entre candidatas: se deriva de los bytes. Cada resultado es exacto y cualquiera puede reproducirlo con la región, la clave y la crib publicadas. El parámetro `K` de la revisión 1 desaparece.

**Reutilización de clave.** Tras la primera pasada, cada clave de periodo ≥ 2 que alguna crib verificó por sí sola se busca en el resto de la muestra, para las cribs que *no* pueden verificar ese periodo solas (p. ej. `http://`, de 7 bytes, con una clave de 8). Se acepta una aparición solo si reproduce la crib completa bajo una clave **idéntica** (salvo la fase) a una ya verificada: una coincidencia casual exige alinear *n* bytes al azar (≤ 256⁻⁷ por posición para la crib más corta). Para no inundar la búsqueda, el diferencial con retardo *p* se usa solo si tiene ≥ 3 bytes no nulos; si no, se busca directamente el texto cifrado de la crib bajo cada rotación de la clave. Se reutilizan como máximo 8 claves distintas. La evidencia resultante **cita en `provenance` la decodificación que estableció la clave**, y el informe y el host comprueban que ambas claves son idénticas. Es el caso habitual en malware: las tablas de cadenas cifradas suelen compartir una sola clave.

### 3.4 Catálogo de anclas `lupabin-xor-cribs-v3`

Cadenas neutrales frecuentes en texto de binarios Windows, elegidas por longitud (una crib de *n* bytes solo verifica claves de hasta ~*n*−5 bytes) y no por significado. Encontrarlas **no demuestra ninguna capacidad ni intención**, igual que la regla YARA de nombres de API no demuestra imports ni inyección.

`http://`, `https://`, `This program cannot be run in DOS mode`, `kernel32.dll`, `ntdll.dll`, `advapi32.dll`, `user32.dll`, `ws2_32.dll`, `wininet.dll`, `Software\Microsoft\Windows\CurrentVersion`, `cmd.exe`, `powershell`, `LoadLibrary`, `GetProcAddress`, `VirtualAlloc`, `CreateProcess`, `CreateRemoteThread`, `WriteProcessMemory`, `URLDownloadToFile`, `InternetOpen`, `HttpSendRequest`, `ShellExecute`, `Mozilla/`, `Mozilla/5.0 (Windows NT `, `User-Agent: `, `\AppData\Roaming\`, `SeDebugPrivilege`, `-----BEGIN `.

La versión 2 añade veinte anclas largas para que una cadena aislada pueda verificar claves de hasta 8 bytes: `GetModuleHandle`, `VirtualProtect`, `IsDebuggerPresent`, `CreateToolhelp32Snapshot`, `NtUnmapViewOfSection`, `InternetReadFile`, `HttpOpenRequest`, `RegSetValueEx`, `Content-Type: `, `Content-Length: `, `Accept-Language: `, `HTTP/1.1`, `powershell.exe`, `rundll32.exe`, `cmd.exe /c `, `schtasks /create`, `http://www.`, `https://www.`, `\Microsoft\Windows\` y `C:\Windows\System32`.

La versión 3 añade catorce fragmentos de rutas y registro, porque la v2 solo cubría el 11 % de las rutas reales: `\Microsoft\`, `\windows\`, `\Windows\`, `\CurrentControlSet\`, `\system32\`, `\System32\`, `\Device\`, `SOFTWARE\`, `Software\`, `\Users\`, `\Registry\Machine\`, `\ProgramData\`, `%APPDATA%\` y `\Temp\`. Los doce primeros se eligieron por cobertura sobre cadenas de rutas reales, extraídas en claro de binarios benignos y separadas en una mitad de entrenamiento (para elegir) y otra reservada (para medir). Los dos últimos son ubicaciones de persistencia habituales que los binarios benignos apenas contienen. Se descartaron fragmentos frecuentes pero propios de rutas de compilación (`C:\__w\1\s\`, `D:\a\_work\1\s\`), que no aportan nada frente a malware. Mediciones en la sección 8.

El catálogo es código revisado. Un test fija su digest SHA-256 junto a su identificador de versión: cambiar una crib sin cambiar la versión hace fallar la suite. Un test verifica además que cada crib es ASCII imprimible y tiene al menos un retardo con patrón válido en ambas codificaciones.

### 3.5 UTF-16LE

- Base64/hex operan sobre `StringData.text`, que ya elimina el ancho UTF-16: ambas codificaciones de origen convergen al mismo texto.
- XOR busca cada crib también codificada en UTF-16LE. La forma UTF-16 duplica la longitud en bytes, lo que amplía los retardos verificables (sección 8).

## 4. Contrato 0.4.0 y el tipo `decoded_string`

Se versionan contrato, paquete e imagen como 0.4.0, conservando 0.1.0–0.3.0 en `docs/schemas/`. El launcher exigirá las fuentes `pe`, `strings`, `yara`, `decode`.

`decoded_string` es un modelo propio, no una subclase de `Fact`, para no ampliar `confidence` ni `Provenance` de las evidencias existentes (lo que alteraría el esquema 0.3.0). Conserva:

- `location`: dónde están **los bytes codificados** en el archivo. Para Base64/hex coincide con la cadena fuente; para XOR es la región cifrada.
- `transform`: `name` y, solo para XOR, `key_hex` (1–8 bytes, periodo mínimo, no nula, alineada con el inicio de la región).
- `anchor` (solo XOR): catálogo, crib y desplazamiento en caracteres de la crib dentro del texto.
- `provenance.evidence_ids`: exactamente la cadena fuente para Base64/hex. Para XOR, vacío si la propia ancla verificó la clave; o bien la única decodificación XOR, verificada por sí misma, que estableció esa misma clave (reutilización).
- `component`: `decode_strings` (Base64/hex) o `decode_xor`.
- `data`: mismos campos y reglas de fidelidad que `StringData` sobre el texto resultante.

El modelo rechaza combinaciones incoherentes (XOR sin ancla o con más de una cita, Base64 con clave, crib que no aparece en el texto en su desplazamiento, longitud de región distinta del resultado XOR, clave no canónica). El informe completo comprueba además que una clave reutilizada cita una decodificación XOR que no cita a su vez nada y cuya clave es idéntica salvo la fase.

**Reverificación en el host.** Como con las instancias YARA, el host no confía en el worker: vuelve a leer los bytes de cada `decoded_string` en el buffer original y comprueba que la transformación publicada produce exactamente el texto publicado. Para una clave reutilizada verifica también la decodificación citada. Una evidencia que no se reproduce invalida la respuesta.

## 5. Reglas de publicación y abstención

- Una cadena que no cumple la sintaxis estricta de Base64/hex no es candidata. No es un error ni una limitación.
- Una aparición XOR rechazada por ventana ya-texto, clave nula o patrón no informativo es abstención por diseño.
- Un XOR cuyo texto cifrado sigue siendo texto (típicamente claves `< 0x80` pequeñas) **no se publica**: sin puntuar plausibilidad es indistinguible de un artefacto texto⊕texto. Esos bytes siguen visibles como `string`.
- Un XOR sin ninguna crib del catálogo **no se encuentra**. Es el precio de no puntuar y se declara en la documentación, no se presenta como ausencia.
- Las evidencias `decoded_string` no se correlacionan entre sí ni con otras fuentes, no cambian el tipo de muestra y no alteran otros extractores.

## 6. Cobertura y estados

La fuente `decode` tiene dos componentes: `decode_strings` (Base64/hex) y `decode_xor`. Cada uno es `complete` si revisó todo su alcance dentro de los límites, `partial` si un presupuesto recortó resultados o candidatos, y `blocked` si no pudo ejecutarse. Cero resultados con cobertura completa es lo habitual y no significa nada sobre la muestra.

El estado global considera cuatro fuentes con la regla ya existente: `completed` si todas completan, `failed` si todas quedan bloqueadas, `partial` en el resto.

## 7. Límites y robustez frente a entradas adversarias

Se mantienen los límites exteriores del worker (20 MiB, 30 s, 512 MiB, 1 CPU, 64 procesos, 8 MiB de salida). Parámetros del método (fijados por la versión del algoritmo, no configurables): longitud máxima de clave 8, 5 bytes no nulos verificados, mínimos de Base64/hex de la sección 3.

Presupuestos del informe:

| Límite | Valor |
| --- | --- |
| Evidencias `decode_strings` | 2.000 |
| Evidencias `decode_xor` | 256 |
| Apariciones de patrón XOR examinadas (ambas pasadas) | 200.000 |
| Claves distintas reutilizadas | 8 |
| Caracteres por texto descifrado | 1.024 (el límite de cadenas existente) |

Una muestra hostil puede contener millones de apariciones de un patrón para agotar la CPU. El tope de apariciones examinadas convierte ese caso en `decode_xor=partial` con su motivo, en vez de agotar el timeout. Los resultados se ordenan por `(offset, longitud, codificación, clave)` antes de aplicar el tope de evidencias, así que el subconjunto conservado es determinista.

Coste medido con el catálogo v2: los 8 diferenciales sobre 20 MiB tardan 0,6 s con un pico de 84 MiB; la primera pasada completa sobre 20 MiB cuesta 2,7 s. La reutilización solo se ejecuta si hay claves verificadas (ninguna en los 4.516 archivos benignos, medido con el catálogo v2): con 20 MiB, 3,6 s en total con una clave y 5,7 s con ocho claves de periodos 2 a 8, examinando 7–37 apariciones. Una primera versión usaba el diferencial para todas las cribs y agotaba las 200.000 apariciones en datos aleatorios; de ahí el umbral de 3 bytes no nulos de 3.3.

Con el catálogo v3 (62 cribs, 453 planes frente a 361), la primera pasada sobre 20 MiB cuesta 3,3 s. La reutilización con ocho claves pasa de 6,4 s a 9,0 s en total, porque las anclas cortas nuevas se buscan bajo cada rotación de cada clave (335 búsquedas por juego de claves frente a 166). El análisis completo de ese peor caso dentro del contenedor, con 1 CPU y 20 MiB, terminó en 10,3 s, con `decode` completo y las 96 decodificaciones reverificadas en el host, lejos del timeout de 30 s. Estas cifras se tomaron con otras mediciones en paralelo, así que son cotas superiores.

Optimización medida (O2, 2026-09-23). El perfil sobre `shell32.dll` (7,6 MiB) muestra que el 78 % del tiempo está en `bytes.find`: una pasada completa por plan, a unos 3 GB/s, y cada plan tarda lo mismo (2–5 ms). El coste es proporcional al número de planes, que ya es el mínimo por crib (los retardos 8, 7, 6 y 5 son imprescindibles para cubrir los periodos 1–8). Adoptado: derivar los ocho diferenciales de una sola conversión a entero, con resultados idénticos campo a campo en 408 entradas (649 aciertos por reutilización) y la primera pasada de 3,18 s a 2,76 s con 20 MiB, con el mismo pico de memoria. Descartado tras medirlo: búsqueda por bloques que quepan en caché (sin ganancia: no está limitada por memoria), una sola expresión regular por retardo (10 veces más lenta), una única búsqueda sobre `datos ⊕ clave` para la reutilización (incorrecta: una clave reutilizada puede aparecer con cualquier fase y el comparador detectó 72 entradas distintas) y resolver patrones contenidos en otros (solo el 6 % de los planes, a cambio de complicar código crítico). La siguiente mejora grande exigiría un buscador multipatrón nativo, es decir, una dependencia compilada dentro del worker, y no se adopta sin un diseño propio.

### 7.1 Límite de tiempo (contrato 0.5.0, 2026-09-23)

La búsqueda XOR se detiene, antes de cada búsqueda sobre todo el buffer, cuando el análisis lleva `decode.seconds` (10 s, o un tercio de `timeout_seconds`), y declara `decode_time_limit`. Motivo medido: con el portátil en batería, la máquina virtual de Docker iba unas 2,5 veces más lenta. Sobre 20 MiB de un byte repetido (`0x90`), `bytes.find` bajó a 0,6 GB/s, porque los patrones que contienen ese byte apenas permiten saltar, y la búsqueda XOR tardó 16,4 s en el host. Con la Fase 4 detrás, el worker superaba los 30 s y se perdía el informe. No cambia ningún umbral ni resultado cuando hay tiempo: en los binarios benignos medidos termina muy por debajo. Solo convierte un timeout en un resultado parcial declarado.

## 8. Evidencia empírica

Medido el 2026-09-22 sobre los binarios de `C:\Windows\System32` (4.092 `.dll`/`.exe` ≤ 20 MiB, 1,9 GB). Son archivos benignos del sistema: cualquier resultado sobre ellos se trata como falso positivo. Se leyeron como datos en el host; no se ejecutaron ni se añadieron al repositorio.

**Falsos positivos XOR** (búsqueda anclada; catálogo inicial de 17 cribs salvo la última fila):

| Configuración | Archivos | Falsos positivos |
| --- | --- | --- |
| 4 bytes verificados (contando ceros), sin reglas de rechazo | 400 | 167 |
| 5 bytes (contando ceros) + ventana ya-texto | 400 | 7 |
| 5 bytes (contando ceros) + ventana ya-texto + fragmento de la crib en claro | 4.092 | 38 |
| 5 bytes **no nulos**, sin reglas | 4.092 | 46 |
| 5 bytes no nulos + fragmento en claro | 4.092 | 33 |
| 5 bytes no nulos + ventana ya-texto | 4.092 | **0** |
| Ídem + patrones débiles (3–4 bytes) confirmados por racha descifrada ≥ 16 | 4.092 | 402 (descartado) |
| 5 bytes no nulos + ventana ya-texto, catálogo final de 28 cribs | 4.092 | **0** |
| Motor definitivo (primera versión, 28 cribs) | 4.516 (todos los archivos) | **0** |
| Nivel débil: 4 / 3 / 2 bytes no nulos + clave con byte ≥ 0x80 | 1.500 | 61 / 486 / 52.119 (descartado) |
| Nivel débil + extensión del texto (3 bytes y +4 car. / 2 bytes y +8 car.) | 1.500 | 104 / 4.929 (descartado) |
| Catálogo v2 (48 cribs) + reutilización de clave, motor definitivo | 4.516 (todos los archivos) | **0** |
| Solo las 22 anclas de rutas candidatas a v3 (primera pasada) | 17.388 de System32, SysWOW64 y .NET (5,6 GB) | **0** (2 auténticas, abajo) |
| Catálogo v3 (62 cribs) + reutilización | 4.516 de System32 (1,98 GB) | **0** (1 auténtica) |

La regla de "fragmento de la crib en claro dentro de la ventana" resultó redundante con la de ventana ya-texto y no se incorpora.

**Cobertura XOR** con el motor definitivo (catálogo v3 + reutilización, entre paréntesis la v2; `tests/decode_eval.py recall`, semilla `lupabin-decode-eval`, 150 pruebas por celda). Los textos son 43 cadenas realistas por categoría escritas sin mirar el catálogo; 10 de ellas (23 %) no contienen ninguna crib y se incluyen a propósito. Cada texto se cifra y se planta en una DLL real, solo o con una segunda cadena bajo la misma clave ("compartida", como en las tablas de cadenas reales). Cuenta como recuperada una región solapada con la clave exacta:

| Clave | ASCII, sola | ASCII, compartida | UTF-16LE, sola | UTF-16LE, compartida |
| --- | --- | --- | --- | --- |
| 1 byte, uniforme 1–255 | 71,3 % (62,0) | 67,3 % (63,3) | 77,3 % (67,3) | 79,3 % (74,0) |
| 1 byte, ≥ 0x80 | 87,3 % (77,3) | 88,7 % (78,7) | 86,7 % (75,3) | 85,3 % (76,7) |
| 2 bytes aleatorios | 76,0 % (68,7) | 71,3 % (62,0) | 82,7 % (72,0) | 82,7 % (73,3) |
| 4 bytes | 63,3 % (56,0) | 84,7 % (76,0) | 87,3 % (78,0) | 85,3 % (75,3) |
| 8 bytes | 36,7 % (33,3) | 92,0 % (80,7) | 62,0 % (57,3) | 87,3 % (80,0) |
| 4 bytes ASCII (tipo contraseña) | 56,0 % (49,3) | 82,0 % (74,0) | 69,3 % (63,3) | 80,7 % (70,7) |
| 8 bytes ASCII | 36,7 % (34,0) | 80,0 % (68,0) | 60,0 % (52,7) | 82,7 % (71,3) |

Por categoría, clave de 8 bytes y texto ASCII (el techo es la fracción de textos que contiene alguna crib; n = casos muestreados):

| Categoría | Techo | Sola | Compartida |
| --- | --- | --- | --- |
| URL | 100 % | 0,0 % (n=31) | 100 % (n=31) |
| HTTP | 100 % | 81,2 % (n=16) | 100 % (n=16) |
| API | 100 % | 71,0 % (n=31) | 100 % (n=37) |
| DLL | 100 % | 0,0 % (n=13) | 100 % (n=11) |
| Comando | 67 % | 25,0 % (n=12) | 82,4 % (n=17) |
| Ruta/registro | 100 % (v2: 43 %) | 44,7 % (v2: 31,6 %) (n=38) | 100 % (v2: 41,4 %) (n=29) |
| Sin ancla | 0 % | 0,0 % (n=9) | 0,0 % (n=9) |

La fila de rutas está sesgada a favor de v3: tres de las anclas nuevas (`\Users\`, `\ProgramData\`, `%APPDATA%\`) aparecen en rutas de este conjunto de evaluación. La medida sin ese sesgo es la de rutas reales reservadas, en la tabla siguiente. Con v3, 37 de los 43 textos (86 %) contienen alguna crib, frente a 33 (77 %) con v2.

**Rutas reales reservadas** (catálogo v2 → v3). Son 16.193 cadenas de rutas y registro extraídas en claro de la mitad de prueba de System32 y SysWOW64, que no se usó para elegir las anclas. Se muestrearon 400 textos, 150 pruebas por celda, sobre DLL reales. Techo (cadenas que contienen alguna crib): 10,6 % → 50,5 %.

| Clave | ASCII, sola | ASCII, compartida | UTF-16LE, sola | UTF-16LE, compartida |
| --- | --- | --- | --- | --- |
| 1 byte | 7,3 → 46,7 % | 8,0 → 42,7 % | 8,7 → 41,3 % | 11,3 → 43,3 % |
| 2 bytes | 9,3 → 53,3 % | 11,3 → 42,0 % | 12,0 → 47,3 % | 12,7 → 44,0 % |
| 4 bytes | 10,7 → 50,0 % | 12,7 → 48,7 % | 13,3 → 49,3 % | 15,3 → 46,0 % |
| 8 bytes | 5,3 → 6,0 % | 10,7 → 48,7 % | 10,0 → 52,7 % | 15,3 → 48,7 % |

Una ruta aislada en ASCII con clave de 8 bytes sigue casi sin cubrir: las anclas de rutas miden menos de 13 caracteres y no verifican solas una clave de 8. Con la clave establecida por otra cadena (compartida) sí se recuperan.

Con clave compartida la cobertura queda en el techo alcanzable (86 % de los textos contiene alguna crib con v3). Con una cadena aislada, una crib de *n* bytes solo verifica claves de hasta ~*n*−5 bytes: `http://` no puede verificar sola una clave de 8, de ahí el 0 % de las URL aisladas. La pérdida con claves de un byte corresponde a los textos sin crib y a las claves que dejan el texto cifrado todavía legible (sección 5). Un texto cifrado sin crib no se encuentra. Estas cifras no son comparables con la tabla de la revisión anterior, que solo usaba textos con crib; las diferencias entre celdas vecinas de menos de ~5 puntos están dentro del ruido de muestreo.

**Base64/hex.** Una decodificación en un binario benigno no es necesariamente un error: los binarios legítimos también contienen texto codificado. Cada resultado se clasificó a mano:

| Ronda | Corpus | Ruido | Decodificaciones auténticas |
| --- | --- | --- | --- |
| Reglas de la revisión 1 | 1.500 archivos, 1,1 M de cadenas | 23 (identificadores de 8 letras, relleno repetitivo) | 0 |
| Mínimos 12/8 y diversidad ≥ 4 | 4.516 archivos, 1,98 GB | 9: `SystemEventW` y ocho números decimales | 4: XML en hexadecimal dentro de `license.rtf` (2), Base64 doble de texto inglés en `globinputhost.dll`, Base64 de un patrón de relleno en `ntoskrnl.exe` |
| Reglas finales (3.1/3.2), medido | ídem | **0** | las mismas 4 |

**Corpus ampliado (2026-09-23).** Medido con `false-positives --recursive --ext .exe,.dll,.sys,.ocx,.cpl,.scr,.efi,.mui`. En Program Files se usó `--stride 2` para XOR y `--stride 12` para Base64/hex. Como antes, cada resultado se clasificó a mano:

| Corpus | Archivos | XOR | Base64/hex |
| --- | --- | --- | --- |
| SysWOW64, `System32\drivers`, `Microsoft.NET` (v2) | 6.398 (1,75 GB) | 0 | — |
| SysWOW64 y `Microsoft.NET` (1 de cada 2) | 2.851 (0,79 GB) | — | 3 auténticas, 0 ruido |
| Program Files y Program Files (x86), 1 de cada 2 (v2) | 24.588 (9,9 GB) | 65 auténticas, 0 ruido | — |
| Ídem, 1 de cada 12 | 4.099 (1,6 GB) | — | 0 |
| Program Files, 1 de cada 2 (v3) | 24.588 | 96 auténticas (las 65 de v2 y 31 rutas de registro nuevas en las mismas regiones), 0 ruido | — |

Las decodificaciones auténticas muestran que el método encuentra ofuscación real en software comercial benigno:
- DLL de MATLAB con otra DLL completa embebida y cifrada con XOR `0xCC`: cabecera `This program cannot be run in DOS mode` e imports `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`.
- El gestor de licencias de MATLAB, con rutas de registro `Software\Microsoft\Windows\CurrentVersion\…` cifradas con una clave de 3 bytes.
- DLL de Epson con URLs de espacios de nombres SOAP negadas bit a bit (clave `0xFF`).
- Recursos localizados de Office Click-to-Run con el bit alto activado (clave `0x80`).
- `ci.dll` y el driver DRM `PEAuth.sys` con `\Registry\Machine\System\CurrentControlSet\Services\PEAuth` en UTF-16LE bajo la clave `7f520e51`. Esta la encontraron las anclas v3, y la reproduce un test sintético.
- En Base64: una cabecera JWT, el texto `Base 64 Stream` y un Base64 doble de texto inglés.

Ninguna prueba intención maliciosa (sección 1): son transformaciones reproducibles de los bytes.

El repositorio incluye `tests/decode_eval.py` (`uv run python -m tests.decode_eval`) para repetir estas mediciones sobre cualquier directorio de binarios benignos que aporte quien evalúa; no forma parte del paquete ni de la CI.

## 9. Pruebas y criterios de aceptación

| Área | Prueba | Afirmación que debe impedir |
| --- | --- | --- |
| Base64 | Válido con/sin relleno, relleno no canónico, alfabeto, longitud < 12, salida binaria, salida poco diversa | Publicar identificadores o relleno como secretos |
| Hex | Longitud impar, dígitos inválidos, relleno numérico repetitivo | Ídem |
| XOR 1–8 bytes | Clave plantada recuperada exacta (ASCII y UTF-16LE), rotación alineada al inicio, periodo mínimo | Publicar una clave no derivada de los bytes |
| Abstención XOR | Crib en claro (clave nula), ventana ya-texto, patrón con ceros, crib ausente | Convertir texto en claro o coincidencias estructurales en hallazgos |
| Extensión | Límite natural, presupuesto de 1.024 caracteres y `complete=false` | Inventar la longitud total o truncar sin declararlo |
| Presupuestos | Apariciones examinadas y evidencias en su tope, orden determinista | Colgar el worker o elegir el subconjunto al azar |
| Catálogo | Digest fijado a la versión; cada crib con retardo válido | Cambiar el catálogo sin versionarlo |
| Modelo | Combinaciones incoherentes rechazadas; `inferred` obligatorio | Mezclar inferencias con observaciones |
| Reverificación | Evidencia manipulada rechazada frente al buffer original | Confiar en el worker sin comprobar |
| Regresión | Suite 0.1.0–0.3.0 completa y pruebas Docker reales | Perder garantías previas |

La demostración final mostrará, con la CLI aislada y fixtures sintéticos: Base64, hexadecimal, XOR de un byte, XOR multibyte, una fuente UTF-16LE y un caso sin resultados. Ningún JSON escrito a mano.

## 10. Fundamento

La propagación de restricciones de la revisión 1 y el diferencial de esta revisión comparten el objetivo de no elegir claves por plausibilidad, pero solo el diferencial lo consigue: la revisión 1 derivaba restricciones de "el resultado es imprimible", una propiedad que el propio texto imprimible satisface con decenas de claves. Aquí la restricción es igualdad exacta con una crib, y las dos reglas de rechazo se justifican con mediciones, no por intuición.

No introduce capa, FLOSS, web, LLM ni puntuaciones. El motor de glosario sigue pendiente.

## 11. Plan de implementación

Bloques pequeños, cada uno cerrado con `ruff`, `mypy`, suite completa y `schema --check` antes del siguiente, con commit propio:

1. **Hecho**: tipos `Transform` y `DecodedStringEvidence` aislados del contrato 0.3.0.
2. **Hecho**: Base64/hex sobre cadenas, con los mínimos y la diversidad de la sección 3 fijados por medición.
3. **Hecho**: motor XOR de la sección 3.3 (claves de 1–8 bytes, catálogo, presupuestos, reverificación), que sustituye al XOR de un byte sobre cadenas de la revisión 1.
4. **Hecho**: herramienta `tests/decode_eval.py` y mediciones de la sección 8 repetidas con el motor definitivo.
5. **Hecho**: integración 0.4.0 — fuente `decode` en el registro, colector y límites (`analysis.limits.decode`), validación en el informe, reverificación en el launcher, esquema 0.3.0 preservado, imagen `lupabin-worker:0.4.0`, CI, documentación, fixture `decode-demo` y pruebas en contenedor real (recorrido completo y una muestra hostil de un millón de patrones que termina en limitación declarada).
6. **Hecho**: optimización medida — niveles de verificación más débiles probados y descartados por falsos positivos; reutilización de clave con cita a la decodificación que la estableció; catálogo v2 con 20 anclas largas; reglas finales de Base64/hex. Resultado en el corpus completo: 0 falsos positivos XOR, 0 decodificaciones Base64/hex espurias, y cobertura de claves de 8 bytes del 81 % con clave compartida.
7. **Hecho**: optimización medida, segunda ronda (2026-09-23). Corpus benigno ampliado a más de 30.000 archivos sin ruido. Diferenciales a partir de un único entero, con resultado idéntico. Catálogo v3 con 14 anclas de rutas elegidas sobre datos reales con separación entrenamiento/reserva: las rutas reales recuperadas pasan del ~10 % al ~45–50 %, y la clave compartida de 8 bytes del 81 % al 92 %, sin falsos positivos.
