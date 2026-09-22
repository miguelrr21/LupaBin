# Fase 2: decodificación estática acotada (Base64/hex/XOR)

Estado: borrador para revisión del usuario. Ninguna sección de este documento está aprobada todavía; no se ha escrito ni modificado código de producto para esta fase. El contrato ejecutable continúa en 0.3.0.

## 1. Propósito y límites del producto

Dissect ya conserva cadenas literales (`string`, Fase 1A) y coincidencias de reglas (`yara_match`, Fase 1B). Esta fase añade una tercera capa: transformar de forma determinista el contenido de una cadena ya extraída cuando existe un candidato de codificación reconocible, y publicar el resultado como un hecho derivado, explícitamente marcado como inferencia.

La afirmación permitida es "estos bytes, interpretados como Base64/hexadecimal/XOR de clave repetida, producen este otro texto". No equivale a decir que el programa realiza esa decodificación, que el resultado es el texto "real" pretendido por el autor, ni que el texto decodificado tiene algún significado (URL, comando, ruta). Sigue prohibido ejecutar o emular la muestra; ninguna transformación interpreta ni corre instrucciones.

Esto retoma directamente lo que ya anticipaba el contrato 0.1.0 ("Desofuscación en una etapa posterior"): "la primera ampliación propuesta es extracción de cadenas y decodificación estricta de Base64/hexadecimal, más candidatos XOR sencillos. Una transformación reproducible demuestra el resultado de esa operación, no que el programa la efectúe ni use el texto resultante."

## 2. Alcance y alternativas

Se añade un tipo de evidencia nuevo, `decoded_string`, y un cuarto extractor de registro cerrado, `decode`, que consume las cadenas ASCII **y UTF-16LE** ya extraídas por `strings` — no vuelve a recorrer el buffer completo del archivo.

Tres transformaciones, todas de biblioteca estándar, sin dependencias nuevas:

- **Base64 estricto**: alfabeto estándar, padding correcto, sin caracteres fuera de alfabeto.
- **Hexadecimal estricto**: secuencia de dígitos hexadecimales de longitud par.
- **XOR de clave repetida (1 a 8 bytes)**: no por fuerza bruta sobre el espacio de claves, sino por **propagación de restricciones** determinista (sección 3.3) — es lo que hace viable incluir multibyte sin convertirlo en una heurística de puntuación.

Alternativas descartadas para esta fase:

- **XOR con clave de longitud no acotada, o búsqueda de longitud por análisis de coincidencias (Kasiski)**: requeriría una función de puntuación de "qué tan parecido a texto plausible" es un resultado — el propio contrato prohíbe justamente eso ("no se asignarán probabilidades, puntuaciones de riesgo... sin un método definido"). Se descarta cualquier técnica que dependa de comparar candidatos entre sí; el método de la sección 3.3 solo publica una clave cuando está **completamente determinada** por el propio texto candidato, no por comparación.
- **Encadenar transformaciones** (p. ej. Base64 sobre un resultado XOR): añade ambigüedad combinatoria y complica la procedencia. Cada `decoded_string` de esta fase deriva de exactamente una evidencia `string` original, nunca de otro `decoded_string`.
- **FLOSS o motores de desofuscación de terceros**: ya descartados en el contrato 0.1.0 mientras no puedan garantizar la ausencia de rutas de emulación.
- **Decodificar directamente sobre el buffer crudo del archivo** en vez de sobre cadenas ya extraídas: dispararía el mismo barrido O(n) que `strings` una segunda vez y produciría candidatos sin una cadena imprimible de origen que los justifique. Se descarta: toda decodificación parte de una evidencia `string` existente.

Quedan fuera de esta fase: Base32, ROT13/Caesar, compresión (zlib/gzip), cifrado con clave conocida o derivada, capa, web, LLM y cualquier puntuación de "plausibilidad" del texto decodificado.

## 3. Enfoque técnico

El extractor `decode` se ejecuta después de `strings` en el registro (`pe` → `strings` → `yara` → `decode`), leyendo las evidencias `string` ya presentes en el colector — no repite el barrido de bytes.

Solo se consideran cadenas fuente que cumplan `data.complete == True`. Una cadena truncada por el límite de 1.024 caracteres no es un candidato válido: decodificar un prefijo conocido-incompleto simularía tener más información de la que realmente se conservó.

Se admiten ambas codificaciones de origen (`ascii` y `utf-16-le`), pero cada transformación decide sobre qué representación de la cadena opera (sección 3.4) — no se trata a las dos por igual internamente.

Para cada cadena fuente admitida se intentan, en este orden fijo, las tres transformaciones. Cada una que produzca un resultado válido genera una evidencia `decoded_string` independiente; una cadena puede producir cero, una o varias.

### 3.1 Base64 estricto

Candidato válido: longitud múltiplo de 4, ≥ 8 caracteres (decodifica a ≥ 4 bytes), únicamente caracteres del alfabeto estándar (`A-Za-z0-9+/`) y como máximo dos `=` de padding solo al final. Se decodifica con validación estricta (se rechaza si el decodificador acepta el texto pero no es información canónica, p. ej. bits de padding no nulos). No se prueba el alfabeto URL-safe en esta fase; es una decisión de alcance, no una imposibilidad técnica.

### 3.2 Hexadecimal estricto

Candidato válido: longitud par ≥ 8 caracteres, únicamente dígitos `0-9a-fA-F`. Se decodifica directamente a bytes. No se aplica a cadenas que ya son íntegramente el `raw_hex` interno de otra evidencia (eso sería decodificar la propia representación de depuración de Dissect, no un dato de la muestra).

### 3.3 XOR de clave repetida — propagación de restricciones, no fuerza bruta

El objetivo es eficiente por construcción: en vez de probar claves y puntuar cuál "parece más texto" (lo que el proyecto prohíbe), se calcula qué claves son **compatibles de forma exacta** con la exigencia de que todo el resultado sea texto imprimible.

Para una longitud de clave `L` (de 1 a 8, sección 7 fija el máximo), se opera sobre los bytes originales en disco de la cadena fuente (`raw_hex`, no el texto ya interpretado):

1. Los bytes se agrupan por clase de residuo `i mod L` (`L` grupos).
2. Para cada grupo, se calcula el conjunto de valores de byte de clave (de un universo de 256) que, aplicados por XOR a **todos** los bytes de ese grupo, producen únicamente bytes válidos de salida (ver criterio de validez en 3.4, que depende de si la cadena fuente es ASCII o UTF-16LE). Esto es una intersección de conjuntos, no una búsqueda: se recorre el grupo una vez y se descartan candidatos de clave incompatibles con cada byte visto.
3. Si algún grupo queda con el conjunto vacío, esa longitud `L` no tiene solución y se descarta sin publicar nada.
4. Si todos los grupos quedan con **como máximo `K` candidatos** (sección 7), se combinan (producto cartesiano acotado por `K^L`, con `K` y `L` pequeños por diseño) y cada combinación resultante es una clave completamente verificable: aplicarla produce, por construcción, texto imprimible completo. Se publican como evidencias independientes, en orden ascendente de `(L, clave como entero)`.
5. Si algún grupo supera `K` candidatos, esa longitud `L` se descarta para esa cadena: no está lo bastante determinada por los datos como para publicarse sin elegir arbitrariamente. No es un error, es abstención.

Esto es determinista, no heurístico, y de coste `O(n × L_max)` sobre la longitud de la cadena — nada de branching exponencial ni de comparar candidatos entre sí para elegir "el mejor". Reutiliza exactamente el mismo criterio de "texto imprimible" que ya implementan `ascii_runs`/`utf16_runs` en `src/dissect/extractors/strings.py`, en vez de definir un segundo criterio paralelo.

### 3.4 Cadenas fuente UTF-16LE

Base64 y hexadecimal son alfabetos puramente ASCII: para una cadena fuente `utf-16-le`, estas dos transformaciones operan sobre su **texto ya decodificado** (`StringData.text`, que ya eliminó el padding de ancho), exactamente igual que para una fuente ASCII. Ambas codificaciones de origen convergen a la misma entrada antes de que Base64/hex actúen.

XOR, en cambio, opera siempre sobre los bytes crudos en disco, que para una cadena UTF-16LE incluyen los bytes de relleno intercalados. El criterio de "salida válida" en el paso 2 de la sección 3.3 reutiliza directamente `ascii_runs`/`utf16_runs` de `strings.py` sobre el buffer ya des-XORado: se exige que **todo** el intervalo decodificado forme una única racha completa reconocida por esas mismas funciones (ASCII o UTF-16LE en cualquiera de sus dos alineamientos), no una coincidencia parcial. Así no se inventa un segundo criterio de "parece texto": es literalmente la misma pasada de detección que ya usa `StringsExtractor`, aplicada al resultado en vez de al archivo original.

## 4. Contrato 0.4.0 y el tipo `decoded_string`

Se versiona contrato, paquete e imagen como 0.4.0. Se conservan 0.1.0, 0.2.0 y 0.3.0 en `docs/schemas/`. El launcher exigirá las cuatro fuentes `pe`, `strings`, `yara`, `decode`.

Esta fase requiere dos cambios de tipado que hoy no existen en el código:

- `Fact.confidence` está fijo a `Literal["observed"]` (`src/dissect/evidence/facts.py`). Debe ampliarse para admitir `"inferred"` en las variantes que lo necesiten, sin cambiar el valor por defecto de las evidencias 0.1.0–0.3.0, que siguen siendo `observed`.
- `Provenance` (`src/dissect/evidence/primitives.py`) hoy solo tiene `evidence_ids`. Se añade una transformación tipada: nombre y versión del algoritmo (`base64-strict-v1`, `hex-strict-v1`, `xor-repeating-v1`), y parámetros propios de cada uno (ninguno para Base64/hex; longitud de clave y la propia clave en hexadecimal para XOR). Esto es exactamente lo que el contrato 0.1.0 ya anticipaba textualmente ("nombre y versión de la transformación, parámetros tipados") sin implementarlo.

`decoded_string` conserva:

- `provenance.evidence_ids`: exactamente un elemento, el ID de la evidencia `string` de origen.
- `provenance.transform`: nombre/versión de la transformación y sus parámetros tipados (para XOR: `key_hex`, `key_length`).
- `data.encoding`, `data.text`, `data.raw_hex`, `data.characters`, `data.complete`: mismos campos y mismas reglas de fidelidad que `StringData` — el texto publicado debe decodificar exactamente a partir de `raw_hex`.
- `confidence = "inferred"` siempre; nunca `observed`.
- `location`: el offset y longitud de la cadena fuente en el archivo original (no una ubicación nueva; el dato decodificado no tiene bytes propios en el archivo).

Una evidencia `decoded_string` nunca se presenta sin su cadena de origen también presente en el informe: si la fuente se descarta por presupuesto, su(s) evidencia(s) derivadas se descartan con ella. No se decodifica "en abstracto" sin conservar el hecho `string` que lo justifica.

## 5. Reglas de publicación y abstención

- Un resultado Base64/hex sintácticamente inválido (padding incorrecto, longitud impar, caracteres fuera de alfabeto) no se publica ni se registra como error: simplemente esa cadena no es un candidato para esa transformación. No es una limitación del análisis.
- Una longitud de clave XOR sin solución, o con un grupo de residuo por encima del umbral `K` de ambigüedad, no se publica ni se registra como error: es abstención por diseño (sección 3.3, paso 5), no un fallo del extractor.
- Igual que con las reglas YARA, el nombre de la transformación y sus parámetros son metadatos técnicos, no una afirmación sobre la intención del autor del binario. Estas evidencias no se correlacionan entre sí en esta fase.
- Ninguna evidencia `decoded_string` cambia el `type` de la muestra (`PE32`/`PE32+`/`unknown`) ni el resultado de otros extractores. Es aditiva.

## 6. Cobertura y estados

Nuevo componente único: `decode_strings`, bajo la fuente `decode`. Sigue las mismas reglas de estado que el resto: `complete` si se revisaron todas las cadenas completas (ASCII o UTF-16LE) disponibles dentro de los límites; `partial` si el presupuesto de evidencias truncó candidatos calificados; `blocked` solo si un fallo de la propia extracción (no esperado, dado que son operaciones de biblioteca estándar sin E/S) impide continuar.

Cero evidencias `decoded_string` con `decode_strings=complete` es un resultado válido y común. No se interpreta como fallo ni como señal de nada.

El estado global pasa a considerar cuatro fuentes: `completed` si las cuatro completan, `failed` si las cuatro quedan bloqueadas, `partial` en el resto — misma regla ya usada al pasar de dos a tres fuentes en la Fase 1B.

## 7. Límites y presupuestos

Se mantienen los límites exteriores del worker sin cambios (20 MiB de entrada, 30 s, 512 MiB, 1 CPU, 64 procesos, 8 MiB de salida): esta fase no ejecuta subprocesos ni necesita aislamiento adicional, es cómputo puro en memoria sobre datos ya extraídos.

Límites internos propuestos (provisionales, a validar con datos reales de la implementación, igual que se hizo con los de YARA):

| Límite | Valor propuesto |
| --- | --- |
| Cadenas fuente consideradas (ya acotadas por el límite `strings` existente) | 5.000 (sin cambio) |
| Longitud máxima de clave XOR probada (`L_max`) | 8 |
| Candidatos de clave admitidos por grupo de residuo antes de abstenerse (`K`) | 4 |
| Combinaciones de clave publicadas por `(cadena, L)` | `K^L` en el peor caso teórico, pero acotadas además a 8 evidencias publicadas por `(cadena, L)`; superado ese tope, se trata igual que el paso 5 de la sección 3.3 (abstención, no publicación parcial arbitraria) |
| Total de evidencias `decoded_string` en el informe | 2.000 |

El total de 2.000 es deliberadamente menor que el límite de `strings` (5.000): cada cadena fuente puede producir resultados de Base64, hex y hasta 8 longitudes de clave XOR. Al alcanzar el límite se marca `decode_strings=partial` con el motivo correspondiente; no se sigue decodificando silenciosamente un subconjunto sin avisarlo.

## 8. Pruebas y criterios de aceptación

| Área | Prueba verificable | Afirmación que debe impedir |
| --- | --- | --- |
| Base64 | Válido con/sin padding, inválido (longitud, alfabeto, padding incorrecto), decodifica a binario no imprimible | Publicar un resultado de una entrada sintácticamente inválida |
| Hex | Longitud par/impar, mayúsculas/minúsculas, caracteres fuera de rango | Publicar sobre longitud impar o caracteres inválidos |
| XOR de una clave (`L=1`) | Clave conocida que produce texto plano; 0x00 excluido por no cambiar el texto; ninguna clave califica | Elegir "la" clave correcta sin que esté completamente determinada |
| XOR multibyte | Clave de 2–8 bytes conocida, reconstruida exactamente por el algoritmo de la sección 3.3; caso con grupo de residuo ambiguo (> `K` candidatos) que se abstiene | Publicar una clave parcialmente determinada, o probar claves por fuerza bruta con puntuación |
| Fuente truncada | Cadena con `complete=false` nunca es candidata | Decodificar un prefijo como si fuera el dato completo |
| Fuente UTF-16LE | Base64/hex sobre el texto decodificado; XOR sobre bytes crudos reutilizando `ascii_runs`/`utf16_runs` | Tratar UTF-16LE igual que ASCII a nivel de bytes, o inventar un segundo criterio de "texto" |
| Procedencia | Cada `decoded_string` referencia exactamente su cadena de origen y sus parámetros de transformación; se descarta si la fuente se descarta | Evidencia derivada huérfana, sin parámetros, o con más de un origen |
| Confidence | Todo `decoded_string` es `inferred`; ninguna evidencia 0.1.0–0.3.0 cambia a `inferred` por accidente | Confundir observación con inferencia en cualquier evidencia existente |
| Presupuestos | Cadena que produce el máximo de variantes XOR; total de evidencias en el límite de 2.000 | Superar el presupuesto de salida o perder evidencias sin declarar la limitación |
| Independencia | Un `decoded_string` inválido en su propia validación cruzada no descarta otras evidencias del informe | Que un fallo de decodificación tire hechos ya observados |
| Regresión | Suite completa 0.1.0–0.3.0 (PE, strings, YARA, presupuestos, aislamiento) sigue en verde | Perder garantías de fases anteriores |

La demostración de aceptación mostrará al menos: una cadena Base64 real decodificando a texto legible, una cadena hexadecimal decodificando a texto legible, una cadena XOR de clave multibyte reconstruida exactamente, una cadena fuente UTF-16LE decodificada, y un caso donde ninguna transformación califica. Ninguna salida se presentará como JSON escrito a mano.

## 9. Fundamento y siguiente paso

Esta fase ejecuta literalmente lo que el contrato 0.1.0 dejó anotado como primer paso de desofuscación, y cierra dos huecos de tipado (`confidence` e inferencia con procedencia de transformación) que ya estaban previstos en el diseño original pero nunca implementados por no haber sido necesarios hasta ahora.

La elección de propagación de restricciones en vez de fuerza bruta con puntuación no es solo una optimización de rendimiento: es la única forma de admitir XOR multibyte sin violar la regla del propio proyecto contra inventar niveles de certeza. Una clave publicada por este método es exacta y reproducible por cualquiera que la verifique a mano, no "la más probable".

No introduce todavía `capa`, FLOSS, web, LLM ni ninguna forma de puntuación o veredicto. El motor de glosario/capacidades (mencionado en `CONTRIBUTING.md` como pendiente) seguirá sin ruta funcional después de esta fase: aquí solo se añade el dato crudo decodificado, no su explicación pedagógica.

Como en las fases anteriores, los valores numéricos de la sección 7 son decisiones de producto de Dissect, no propiedades universales de Base64/hex/XOR.

## 10. Cómo se implementará: en bloques pequeños, no de una vez

Dado que Devin no está disponible varios días y esto lo ejecuto yo directamente, el plan de implementación (cuando el diseño de arriba se apruebe) se trabajará en bloques independientes y verificables, cada uno cerrado con su propia verificación antes de pasar al siguiente — igual que los bloques A–H de 1A/1B, pero ejecutados uno por sesión/turno, no todos seguidos:

1. **Tipado base**: `confidence="inferred"` y `Provenance.transform` en los modelos, sin extractor todavía. Solo tests de modelos + `mypy`.
2. **Base64 y hex**: el extractor `decode` con esas dos transformaciones únicamente, sin XOR. Integrado y probado de forma aislada.
3. **XOR de una clave**: caso `L=1` del algoritmo de propagación de restricciones.
4. **XOR multibyte**: generalización a `L=2..8` con el umbral de ambigüedad `K`.
5. **Integración 0.4.0**: registro de cuatro fuentes, esquema, CI, Docker, documentación y demostración real — el equivalente al bloque H de las fases anteriores.

Cada bloque termina con su propia tanda de `ruff`/`mypy`/`pytest` en verde antes de tocar el siguiente, y un commit propio. No se avanza al bloque siguiente dentro del mismo turno si eso implica dejar el anterior a medias sin verificar.

---

**Pendiente de tu aprobación antes de empezar el bloque 1**: el diseño de las secciones 1–9, en particular el umbral de ambigüedad `K=4` y la longitud máxima de clave `L_max=8` de la sección 7 — son los dos números que más afectan a cuánto ruido/cuánta cobertura tendrá el resultado final.
