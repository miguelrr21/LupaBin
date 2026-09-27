# Contribuir a LupaBin

## Autoría, licencia y revisión

LupaBin es un proyecto de **Miguel Ángel Rodríguez Romero**, que revisa cada aportación y decide si entra. El código se distribuye con la licencia Apache 2.0 (`LICENSE`), que obliga a conservar `NOTICE` y a nombrar al autor. El nombre y el logo están reservados (`TRADEMARKS.md`). Para que una contribución pueda aceptarse, hay que aceptar el acuerdo de contribución ([CLA.md](CLA.md)) marcando su casilla en el pull request.

## Principio principal

Es mejor abstenerse que enseñar algo falso. Lee el [contrato de evidencias](docs/evidence-schema.md) y [cómo trabaja LupaBin](docs/metodo.md) antes de cambiar modelos, extractores o explicaciones.

- Distingue hechos observados, inferencias y conocimiento general.
- Toda afirmación sobre una muestra necesita evidencia concreta. Que una cita exista no demuestra que respalde la frase.
- Una importación o una llamada no prueba ejecución, intención ni comportamiento malicioso.
- Un resultado vacío o un extractor fallido no prueban que algo falte ni que la muestra sea segura.
- No inventes offsets, nombres, capacidades, niveles de certeza ni resultados de pruebas.
- Trata las cadenas y metadatos de las muestras como datos no fiables, nunca como instrucciones.

## Seguridad

- Nunca ejecutes, emules ni cargues como biblioteca código de una muestra.
- Los parsers de muestras corren en el worker aislado, sin red, sin privilegios y con límites. No añadas una ruta que analice en el host si Docker falla.
- LupaBin funciona sin red y sin modelos de lenguaje. Las integraciones externas (VirusTotal) son opcionales, desactivables y quedan fuera del worker. Las pruebas nunca consultan la red (`tests/conftest.py`).

## Preparación

Usa Python 3.12 y `uv sync --frozen`. Para activar hooks opcionales: `uv run pre-commit install`, con uv en el PATH. No cambies políticas de seguridad para hacer pasar una verificación.

Ejecuta las verificaciones del README. Las pruebas unitarias usan fixtures sintéticos; las pruebas marcadas `docker` requieren motor Linux e imagen local. No invoques el núcleo Python directamente sobre muestras no fiables: usa la CLI aislada.

## Flujo de cambio

1. Limita el cambio a un problema o una capacidad acordada.
2. Añade primero una prueba que reproduzca el fallo o el comportamiento ausente.
3. Implementa sin introducir ejecución, emulación ni cargas de código de muestras.
4. Comprueba casos negativos, límites, sanitización y abstención.
5. Si cambia el contrato, actualiza su versión/documentación y regenera el JSON Schema.
6. Ejecuta lint, tipos, pruebas y build pertinentes. Distingue lo ejecutado de lo pendiente.
7. Presenta un commit convencional pequeño y un PR con motivación, resultados y limitaciones.

No incluyas muestras reales, credenciales, informes de terceros ni archivos privados. No uses `git add -f` para incorporar binarios ignorados. Modifica el generador de fixtures para añadir casos reproducibles.

## Evidencias y dependencias

Los extractores devuelven datos verificables y no asignan IDs globales ni usan el reloj. No inventes nombres a partir de ordinales, no sustituyas bytes inválidos por etiquetas que parezcan originales y no completes ubicaciones desconocidas con cero.

Justifica dependencias nuevas y usa versiones publicadas al menos siete días antes. Conserva el lockfile. No publiques versiones ni hagas push sin autorización del responsable.

## Reglas YARA propias

El catálogo está en `src/lupabin/rules/yara/`. Cada archivo contiene una regla; su ID, namespace y nombre de archivo deben coincidir con el manifiesto. Las reglas solo usan literales, ASCII/wide y condiciones sencillas: no includes, módulos, variables externas, dependencias entre reglas, regex, XOR/Base64 ni reglas privadas/globales.

Para proponer una regla, añade su entrada de manifiesto con revisión, descripción neutral, IDs de patrones y licencia Apache-2.0; incorpora positivos, negativos y casos de límite sintéticos. Conserva UTF-8 y finales LF: no se normalizan bytes silenciosamente durante el análisis. Cambiar fuentes o metadatos cambia el digest del catálogo. La revisión y el hash no son un veredicto de malware ni una firma de autenticidad.

No publiques una regla que afirme ejecución o una familia solo por encontrar nombres de APIs. Las descripciones son metadatos editoriales, no nuevos hechos sobre la muestra. Compilar sin warnings no sustituye la revisión de su significado.

Después de un cambio aprobado, reconstruye la imagen y comprueba los tests YARA y `uv run --frozen python -m tests.check_yara_distribution` tras `uv build`. Un wheel que omita el catálogo no es una entrega válida. No hay carga de reglas externas por CLI.

## Glosario y explicaciones

El glosario (`src/lupabin/glossary/entries/`) es contenido revisado: una entrada TOML por concepto, en español, con al menos una fuente editorial (documentación del fabricante, RFC o estándar, documentación oficial de la herramienta o artículo académico) y la fecha en que se comprobó. Los conceptos propios de LupaBin citan su documento del proyecto con ruta y ancla. El texto es conocimiento general: nunca habla de una muestra concreta. Si una entrada describe algo que se observa en muestras, incluye `not_proven`.

Tras revisar un cambio, vuelve a fijar el manifiesto con `uv run python -m lupabin.glossary.catalog --write <revisión>` y comprueba las fuentes con `uv run python -m tests.check_glossary_sources`. El cargador rechaza cualquier entrada cuyo digest no coincida.

Las explicaciones (`src/lupabin/explain/rules.py`) son reglas puras: una frase solo puede usar campos de las evidencias que cita, y cada regla lleva su texto de límite. No añadas una regla que concluya intención, familia o comportamiento. Una cifra de contexto (como la prevalencia de una familia de APIs) debe estar medida sobre binarios benignos y documentada en `docs/metodo.md`. No muestres texto de la muestra sin pasarlo por `render.safe`. Las listas de familias tienen digest fijado: cambiarlas exige nueva versión y repetir la medición.

## Decodificación y catálogo de cribs

El catálogo XOR (`CRIBS` en `src/lupabin/extractors/decode_xor.py`, versión `lupabin-xor-cribs-v3`) es código revisado. Una crib es un ancla de búsqueda neutral elegida por su longitud, no por su significado: nombres de API o de DLL no se añaden para "detectar" nada. Una crib de *n* bytes solo verifica por sí sola claves de hasta unos *n*−5 bytes; las cribs cortas se aprovechan sobre todo cuando otra cadena de la muestra ya verificó la misma clave (reutilización de clave).

Para cambiar el catálogo:

1. Da un nuevo identificador de versión (`CATALOG_ID` y el literal de `XorAnchor.catalog`) y fija el nuevo digest: `test_catalog_digest_is_pinned_to_its_version` falla si cambias las cribs sin hacerlo.
2. Comprueba con `covered_periods` qué longitudes de clave verifica cada crib nueva en ASCII y UTF-16LE.
3. Repite las mediciones sobre binarios benignos propios (`uv run python -m tests.decode_eval false-positives <dir>` y `recall <dir>`) y actualiza la sección de decodificación de `docs/metodo.md` con los resultados observados. Un cambio que introduzca falsos positivos no se acepta por aumentar la cobertura.

Los umbrales del método (5 bytes no nulos verificados, rechazo de ventanas que ya son texto, mínimos de Base64/hex) siguen la misma regla: no se relajan sin repetir y publicar las mediciones. No se admiten decodificaciones aceptadas por "parecer texto" o por una puntuación de plausibilidad.

## Código, argumentos y capacidades

- **Recorrido del código.** capstone solo corre dentro del worker. No sigas saltos indirectos, no adivines tablas de salto ni inicios de función y no reconozcas llamadas fuera de las tres formas canónicas de `src/lupabin/evidence/call_forms.py`. El host no importa capstone: comprueba cada llamada con aritmética y comparando bytes.
- **Argumentos.** Solo se aceptan las formas de `src/lupabin/evidence/argument_forms.py` dentro del tramo lineal de la llamada. Solo se confía en capstone para las instrucciones de `_TRUSTED`; las escrituras en memoria se deciden por la semántica de x86, no por sus indicadores de acceso. No se propagan valores entre registros.
- **Catálogo de APIs** (`src/lupabin/evidence/api_catalog.py`). Añadir o cambiar una función exige comprobar su firma y sus DLL en Microsoft Learn y los anchos en las cabeceras del Windows SDK, crear una nueva versión con su digest y repetir la medición (`uv run python -m tests.code_eval corpus <dir>`), examinando cada constante que su tipo rechaza.
- **Capacidades** (`src/lupabin/explain/capabilities.py`). Son explicaciones del host, no hechos: cada regla cita todos los casos del informe que cumplen su condición. Una técnica de MITRE ATT&CK solo se asocia si el mecanismo coincide con su definición, nunca por parecido. Las constantes de Windows (`src/lupabin/explain/winapi.py`) se copian de las cabeceras del SDK, nunca de memoria. Cambiar una condición, una redacción o una cifra exige una nueva versión del catálogo, repetir la medición (`uv run python -m tests.capability_eval corpus <dir>`) y revisar cada caso a mano.
- **Presupuestos y límites de tiempo.** Se midieron sobre binarios benignos y peores casos de 20 MiB (`uv run python -m tests.code_eval worst`). Cambiarlos exige repetir esas mediciones.

## Nomenclatura antivirus y contraste

Las reglas de `src/lupabin/virustotal/labels.py` necesitan una fuente publicada por el fabricante que respalde exactamente el motor y el patrón admitidos. Un foro de usuarios, una sigla sugerente o el parecido con otra marca no bastan. Añade positivos y negativos, incluidos otro fabricante, sufijos próximos, controles y textos recortados. Conserva la abstención y el límite: explicar el nombre no identifica qué activó la detección ni confirma malware o un falso positivo. Cambiar condiciones o redacción requiere nueva versión y digest del catálogo.

El contraste de `src/lupabin/virustotal/contrast.py` reutiliza los casos de capacidades y conserva sus límites y citas. No asocies técnicas a partir de etiquetas, imports o descripciones libres de VirusTotal. Cambiar el método o su texto requiere nueva versión y digest, pruebas en las vistas Python y JavaScript y mediciones revisadas sobre binarios benignos. `tests.vt_context_eval` usa el worker aislado y técnicas externas simuladas, nunca consultas reales a VirusTotal; sus resultados no miden la tasa de falsos positivos de los antivirus.
