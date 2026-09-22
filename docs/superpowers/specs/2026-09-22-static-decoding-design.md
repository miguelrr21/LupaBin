# Fase 2: decodificación estática acotada (Base64/hex/XOR)

Estado: revisión 2 (2026-09-22). La revisión 1 proponía aplicar XOR sobre las cadenas ya extraídas y filtrar con un umbral de ambigüedad `K`; al ejecutarla sobre datos reales resultó estructuralmente errónea (sección 2.2). Esta revisión corrige el enfoque XOR con un método medido sobre 4.092 binarios reales (sección 8). El usuario pidió corregir el problema y continuar la implementación. El contrato ejecutable continúa en 0.3.0 hasta el bloque de integración (sección 11).

## 1. Propósito y límites del producto

Dissect ya conserva cadenas literales (`string`, Fase 1A) y coincidencias de reglas (`yara_match`, Fase 1B). Esta fase añade hechos derivados: bytes que, al aplicarles una transformación determinista y documentada, producen texto legible.

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
- **Modificador `xor` de YARA**: solo admite claves de un byte y acoplaría la decodificación al subproceso YARA.
- **Encadenar transformaciones** (Base64 sobre un resultado XOR, etc.): ambigüedad combinatoria. Cada `decoded_string` deriva de exactamente una transformación.
- **FLOSS/emulación**: descartados desde el contrato 0.1.0.

Quedan fuera: Base32, ROT/Caesar, compresión, RC4 u otros cifrados con clave, XOR rodante o incremental, claves de más de 8 bytes, capa, web, LLM y cualquier puntuación.

## 3. Enfoque técnico

El extractor `decode` se ejecuta después de `strings` (`pe` → `strings` → `yara` → `decode`). Base64/hex leen las evidencias `string` del colector; XOR recorre el buffer original.

### 3.1 Base64 estricto (`base64-strict-v1`)

Se admite una cadena fuente con `complete=true` cuyo texto: tiene longitud múltiplo de 4 y **≥ 12 caracteres**; usa solo el alfabeto estándar con como máximo dos `=` finales; se decodifica con validación estricta; y **se vuelve a codificar exactamente al mismo texto** (rechaza bits de relleno no canónicos, que `base64.b64decode(validate=True)` de Python acepta, p. ej. `"aGVsbG9="`). El resultado debe ser ASCII imprimible con **≥ 4 caracteres distintos**.

### 3.2 Hexadecimal estricto (`hex-strict-v1`)

Longitud par **≥ 8**, solo `0-9a-fA-F`; resultado ASCII imprimible con **≥ 4 bytes** y **≥ 4 caracteres distintos**.

Los mínimos de 3.1 y 3.2 provienen de la medición de la sección 8: en 1.500 binarios benignos todos los falsos positivos Base64 tenían exactamente 8 caracteres (identificadores como `fileType`) y todos los hexadecimales eran relleno numérico repetitivo con salidas de ≤ 2 caracteres distintos (`44444444444444` → `DDDDDDD`).

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

### 3.4 Catálogo de anclas `dissect-xor-cribs-v1`

Cadenas neutrales frecuentes en texto de binarios Windows, elegidas por longitud (una crib de *n* bytes solo verifica claves de hasta ~*n*−5 bytes) y no por significado. Encontrarlas **no demuestra ninguna capacidad ni intención**, igual que la regla YARA de nombres de API no demuestra imports ni inyección.

`http://`, `https://`, `This program cannot be run in DOS mode`, `kernel32.dll`, `ntdll.dll`, `advapi32.dll`, `user32.dll`, `ws2_32.dll`, `wininet.dll`, `Software\Microsoft\Windows\CurrentVersion`, `cmd.exe`, `powershell`, `LoadLibrary`, `GetProcAddress`, `VirtualAlloc`, `CreateProcess`, `CreateRemoteThread`, `WriteProcessMemory`, `URLDownloadToFile`, `InternetOpen`, `HttpSendRequest`, `ShellExecute`, `Mozilla/`, `Mozilla/5.0 (Windows NT `, `User-Agent: `, `\AppData\Roaming\`, `SeDebugPrivilege`, `-----BEGIN `.

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
- `provenance.evidence_ids`: exactamente la cadena fuente para Base64/hex; vacío para XOR (los bytes y la región bastan, igual que una `string`).
- `component`: `decode_strings` (Base64/hex) o `decode_xor`.
- `data`: mismos campos y reglas de fidelidad que `StringData` sobre el texto resultante.

El modelo rechaza combinaciones incoherentes (XOR sin ancla o con procedencia, Base64 con clave, crib que no aparece en el texto en su desplazamiento, longitud de región distinta del resultado XOR, clave no canónica).

**Reverificación en el host.** Como con las instancias YARA, el host no confía en el worker: vuelve a leer los bytes de cada `decoded_string` en el buffer original y comprueba que la transformación publicada produce exactamente el texto publicado. Una evidencia que no se reproduce invalida la respuesta.

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
| Apariciones de patrón XOR examinadas | 200.000 |
| Caracteres por texto descifrado | 1.024 (el límite de cadenas existente) |

Una muestra hostil puede contener millones de apariciones de un patrón para agotar la CPU. El tope de apariciones examinadas convierte ese caso en `decode_xor=partial` con su motivo, en vez de agotar el timeout. Los resultados se ordenan por `(offset, longitud, codificación, clave)` antes de aplicar el tope de evidencias, así que el subconjunto conservado es determinista.

Coste medido: los 8 diferenciales sobre 20 MiB tardan 0,6 s con un pico de 84 MiB; la búsqueda completa cuesta ~0,11 s/MiB (~2,3 s en el peor caso de entrada).

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

La regla de "fragmento de la crib en claro dentro de la ventana" resultó redundante con la de ventana ya-texto y no se incorpora.

**Cobertura XOR** con el catálogo final: cadenas que contienen alguna crib, cifradas con claves aleatorias y plantadas en posiciones aleatorias de 60 DLL reales, 300 pruebas por celda:

| Clave | ASCII | UTF-16LE |
| --- | --- | --- |
| 1 byte, uniforme 1–255 | 79 % | 89 % |
| 1 byte, ≥ 0x80 (medido con el catálogo inicial de 17 cribs) | 100 % | 100 % |
| 2 bytes aleatorios | 90 % | 93 % |
| 3 bytes | 85 % | 99 % |
| 4 bytes | 81 % | 92 % |
| 8 bytes | 50 % | 83 % |

La pérdida con claves de un byte coincide con los casos en que el texto cifrado sigue siendo texto (sección 5). La pérdida con claves largas proviene de cribs cortas (`http://`, `cmd.exe`) que no pueden verificar tantos bytes de clave. Estas cifras describen cadenas que contienen alguna crib; un texto cifrado sin crib no se encuentra.

**Base64/hex** en 1.500 archivos (1,1 M de cadenas examinadas con la revisión 1): 23 decodificaciones, todas ruido, que motivaron los mínimos de 3.1/3.2.

El repositorio incluye `tools/decode_eval.py` para repetir estas mediciones sobre cualquier directorio de binarios benignos que aporte quien evalúa; no forma parte del paquete ni de la CI.

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
2. **Hecho, a endurecer**: Base64/hex sobre cadenas → mínimos y diversidad de la sección 3.
3. **Sustituido**: XOR de un byte sobre cadenas (revisión 1) → reemplazado por el motor de la sección 3.3 con claves de 1–8 bytes, catálogo, presupuestos y reverificación; modelo actualizado (ancla, reglas por transformación, componente `decode_xor`).
4. **Herramienta de evaluación** `tools/decode_eval.py` y repetición de las mediciones de la sección 8 con el motor definitivo.
5. **Integración 0.4.0**: registro de la fuente, colector, límites, esquema, reverificación en el launcher, imagen, CI, documentación y demostración real.
