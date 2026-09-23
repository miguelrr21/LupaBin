# Contribuir a Dissect

## Principio principal

Es mejor abstenerse que enseñar algo falso. Lee `AGENTS.md` y `docs/evidence-schema.md` antes de cambiar modelos, extractores o explicaciones. Distingue hechos, hipótesis y conocimiento general. No conviertas un fallo del parser en ausencia de comportamiento.

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

El catálogo está en `src/dissect/rules/yara/`. Cada archivo contiene una regla; su ID, namespace y nombre de archivo deben coincidir con el manifiesto. Las reglas de esta fase solo usan literales, ASCII/wide y condiciones sencillas: no includes, módulos, variables externas, dependencias entre reglas, regex, XOR/Base64 ni reglas privadas/globales.

Para proponer una regla, añade su entrada de manifiesto con revisión, descripción neutral, IDs de patrones y licencia Apache-2.0; incorpora positivos, negativos y casos de límite sintéticos. Conserva UTF-8 y finales LF: no se normalizan bytes silenciosamente durante el análisis. Cambiar fuentes o metadatos cambia el digest del catálogo. La revisión y el hash no son un veredicto de malware ni una firma de autenticidad.

No publiques una regla que afirme ejecución o una familia solo por encontrar nombres de APIs. Las descripciones son metadatos editoriales, no nuevos hechos sobre la muestra. Compilar sin warnings no sustituye la revisión de su significado.

Después de un cambio aprobado, reconstruye la imagen y comprueba los tests YARA y `uv run --frozen python -m tests.check_yara_distribution` tras `uv build`. Un wheel que omita el catálogo no es una entrega válida. No hay carga de reglas externas por CLI en esta fase.

## Glosario y explicaciones

El glosario (`src/dissect/glossary/entries/`) es contenido revisado: una entrada TOML por concepto, en español, con al menos una fuente editorial (documentación del fabricante, RFC o estándar, documentación oficial de la herramienta o artículo académico) y la fecha en que se comprobó. Los conceptos propios de Dissect citan su documento del proyecto con ruta y ancla. El texto es conocimiento general: nunca habla de una muestra concreta. Si una entrada describe algo que se observa en muestras, incluye `not_proven`.

Tras revisar un cambio, vuelve a fijar el manifiesto con `uv run python -m dissect.glossary.catalog --write <revisión>` y comprueba las fuentes con `uv run python -m tests.check_glossary_sources`. El cargador rechaza cualquier entrada cuyo digest no coincida.

Las explicaciones (`src/dissect/explain/rules.py`) son reglas puras: una frase solo puede usar campos de las evidencias que cita, y cada regla lleva su texto de límite. No añadas una regla que concluya intención, familia o comportamiento. Una cifra de contexto (como la prevalencia de una familia de APIs) debe estar medida sobre binarios benignos y documentada en el diseño de la Fase 3. Las listas de familias tienen digest fijado: cambiarlas exige nueva versión y repetir la medición.

## Decodificación y catálogo de cribs

El catálogo XOR (`CRIBS` en `src/dissect/extractors/decode_xor.py`, versión `dissect-xor-cribs-v3`) es código revisado. Una crib es un ancla de búsqueda neutral elegida por su longitud, no por su significado: nombres de API o de DLL no se añaden para "detectar" nada. Una crib de *n* bytes solo verifica por sí sola claves de hasta unos *n*−5 bytes; las cribs cortas se aprovechan sobre todo cuando otra cadena de la muestra ya verificó la misma clave (reutilización de clave).

Para cambiar el catálogo:

1. Da un nuevo identificador de versión (`CATALOG_ID` y el literal de `XorAnchor.catalog`) y fija el nuevo digest: `test_catalog_digest_is_pinned_to_its_version` falla si cambias las cribs sin hacerlo.
2. Comprueba con `covered_periods` qué longitudes de clave verifica cada crib nueva en ASCII y UTF-16LE.
3. Repite las mediciones sobre binarios benignos propios (`uv run python -m tests.decode_eval false-positives <dir>` y `recall <dir>`) y actualiza la sección 8 del diseño de la Fase 2 con los resultados observados. Un cambio que introduzca falsos positivos no se acepta por aumentar la cobertura.

Los umbrales del método (5 bytes no nulos verificados, rechazo de ventanas que ya son texto, mínimos de Base64/hex) siguen la misma regla: no se relajan sin repetir y publicar las mediciones. No se admiten decodificaciones aceptadas por "parecer texto" o por una puntuación de plausibilidad.

## Contenido educativo

El motor de glosario y capacidades pertenece a una fase posterior. Todavía no existe una ruta funcional para añadir capacidades mediante YAML; no se promete que un archivo de contenido aislado vaya a aparecer en el informe. Cuando se implemente, las contribuciones deberán incluir fuentes verificables, niveles de explicación y una separación explícita entre teoría y hechos de la muestra.
