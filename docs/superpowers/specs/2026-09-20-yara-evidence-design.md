# Fase 1B: coincidencias YARA trazables

Estado: alcance aceptado; diseño escrito pendiente de revisión. No se han instalado dependencias ni implementado YARA. El contrato ejecutable continúa en 0.2.0.

## 1. Propósito y límites del producto

Dissect añadirá coincidencias de reglas a los hechos PE y a las cadenas que ya obtiene. El objetivo educativo es poder contestar: qué regla coincidió, qué versión se usó y qué bytes asociados pueden comprobarse.

La afirmación permitida es "el motor YARA evaluó como verdadera esta regla sobre estos bytes". No equivale a identificar malware, demostrar una técnica ATT&CK, probar una conexión ni reconstruir una ejecución. Los nombres, descripciones y tags de reglas tampoco se convierten en hechos sobre la muestra.

La interfaz seguirá siendo `dissect analyze <archivo> --json`. Se conserva funcionamiento sin LLM, sin red durante el análisis y sin ejecución/emulación de instrucciones de la muestra. Evaluar reglas de análisis confiables no significa ejecutar código del binario analizado.

Quedan fuera: reglas proporcionadas por argumentos de CLI o subidas por usuarios, feeds descargables, reglas compiladas externas, capa, FLOSS, desofuscación, correlación ATT&CK/MBC, puntuaciones, antivirus, LLM e interfaz web.

## 2. Enfoque y dependencia

Se elige `yara-python` frente a un ejecutable YARA externo: ofrece metadatos, identificadores de patrones, offsets, longitudes y callbacks sin interpretar una salida textual de consola.

La versión candidata es 4.5.4, publicada el 27 de mayo de 2025 según PyPI. Se han identificado wheels para Python 3.12 en Windows y Linux; no se ha verificado aún su instalación en este proyecto. La implementación fijará la versión y el lockfile con uv, sin modificar la política de antigüedad de dependencias. No se instalarán paquetes durante un análisis.

El binding declara Apache-2.0 y el motor YARA BSD-3-Clause, compatibles con la distribución Apache-2.0 del proyecto conservando los avisos correspondientes. No se importarán conjuntos de reglas de terceros en esta entrega.

Alternativas descartadas para esta fase: integrar YARA y capa simultáneamente, cargar reglas arbitrarias o ejecutar la biblioteca nativa en el mismo proceso que reúne todas las evidencias. La primera mezcla alcances; la segunda amplía la superficie de ataque y licencias; la tercera no contiene un fallo nativo del motor.

## 3. Catálogo propio y reproducible

La única fuente de reglas será `src/dissect/rules/yara/`, con archivos `.yar` y un manifiesto JSON. Situarlas como recursos del paquete permite usar el mismo catálogo en la instalación editable, el wheel y la imagen Docker, sin duplicar reglas ni buscar archivos según el directorio de trabajo. Esta decisión ajusta la ubicación propuesta inicialmente en el brief, no el principio de contenido como código.

Cada archivo contendrá una regla identificada de forma única. El manifiesto incluirá un ID de catálogo, revisión, identificadores de regla, namespace, nombre de archivo, revisión de la regla, IDs de sus patrones, descripción neutral y licencia. Los IDs y nombres de archivo estarán restringidos; no se aceptarán rutas absolutas, traversal, enlaces fuera del paquete, duplicados ni reglas no enumeradas en el manifiesto.

Cada fuente será una entrada independiente del argumento `sources` de YARA. En este primer catálogo su namespace será igual al ID de regla y deberá ser único; no se usarán claves repetidas que pudieran sustituir silenciosamente una fuente por otra. Compartir un namespace entre varios archivos queda fuera de esta política inicial.

El catálogo inicial tendrá cuatro reglas propias:

| ID | Condición prevista | Afirmación permitida |
| --- | --- | --- |
| `dissect_dos_stub_text` | Presencia literal de `This program cannot be run in DOS mode` | Se encontró ese texto; no demuestra por sí solo el tipo PE. |
| `dissect_process_memory_api_names` | Presencia conjunta de `VirtualAllocEx`, `WriteProcessMemory` y `CreateRemoteThread` | Aparecen esos tres nombres; no demuestra imports ni inyección. |
| `dissect_debug_marker_pair` | Presencia de los patrones `RSDS` y `.pdb` | Coinciden esos marcadores; no acredita una ruta PDB ni un directorio de depuración válido. |
| `dissect_training_marker` | Presencia de `DISSECT PRACTICE` en ASCII o con el modificador `wide` | Se encontró el marcador de práctica; no identifica una familia. |

Se usarán patrones literales y condiciones simples, sin módulos importados, includes, variables externas, referencias entre reglas, reglas privadas/globales, modificadores XOR/Base64, regex ni condiciones sin patrones positivos. Ampliar ese subconjunto requerirá revisar los tests y el diseño de procedencia. No se construirá un intérprete YARA alternativo.

La fuente original de cada regla tendrá SHA-256 calculado sobre los bytes UTF-8 que se compilan. Un archivo incluirá una sola regla para que ese hash identifique su fuente sin ambigüedad. La compilación no añadirá ni reescribirá texto silenciosamente. Las reglas y el manifiesto tendrán finales LF fijados mediante atributos del repositorio y comprobados en CI.

El digest del conjunto será SHA-256 de una representación JSON canónica, UTF-8, con claves ordenadas y separadores compactos: versión del formato de catálogo, hash del manifiesto y lista ordenada por `(namespace, rule_id)` de las revisiones y hashes de fuente. Cambiar una regla o sus metadatos producirá un digest diferente. Una revisión textual no sustituye al digest ni demuestra autenticidad criptográfica del distribuidor.

## 4. Flujo y aislamiento

Orden de ejecución: PE -> strings -> YARA. Se conserva primero el trabajo actual y se asignan IDs en un orden determinista. Si los hechos anteriores agotan el presupuesto de evidencias, se comunica que YARA no pudo publicar resultados; no se devuelve una lista vacía como si todo estuviera revisado.

YARA será un tercer extractor del registro cerrado. El proceso principal del worker gestionará el catálogo y un subproceso interno de YARA, iniciado con el intérprete del propio entorno y argumentos fijos, sin shell. Solo ese subproceso importará el binding nativo durante el análisis público.

El subproceso permanece dentro del contenedor existente: usuario no root, sin red, raíz de solo lectura, capacidades eliminadas, sin montajes del host ni socket Docker. Recibe el buffer original por stdin; no recibe una ruta de muestra, PID, módulo a importar ni reglas indicadas por el usuario. Solo utiliza `rules.match(data=...)`, nunca escanea procesos ni carga el binario.

La comunicación tendrá entrada/salida acotadas y un protocolo JSON interno tipado. El padre verificará tamaño/hash de muestra, digest de catálogo, IDs de reglas, posiciones y bytes conservados antes de incorporar los resultados. No aceptará texto arbitrario del subproceso como diagnóstico público.

Un fallo nativo o timeout del hijo provoca su terminación y recogida; el padre conserva PE y strings cuando sigue operativo. No se garantiza recuperación ante OOM, fallo del daemon o terminación del contenedor completo: en esos casos puede no haber informe y se comunica el fallo sin inventar resultados parciales.

## 5. Compilación y política de reglas

El catálogo revisado se compila desde sus textos empaquetados con `includes=False` y `error_on_warning=True`. No se usa `yara.load` sobre bytecode externo ni se escribe una caché de reglas en disco.

Las restricciones de autoría se verifican sobre el catálogo entregado mediante revisión y tests. No se afirmará que una expresión regular valida de forma segura cualquier programa YARA. No existe una interfaz de reglas arbitrarias en esta fase.

Como defensa adicional, cualquier callback de módulo importado o de consola se trata como incumplimiento de política: se aborta o invalida esa ejecución y no se publican coincidencias YARA. La salida de consola se intercepta para no contaminar stdout del informe. Las pruebas confirmarán estas rutas con reglas sintéticas controladas; no se confiará solo en que el catálogo actual no las use.

Los warnings de compilación impiden activar el conjunto; los warnings de ejecución, incluidos demasiados matches, impiden declarar un escaneo completo. Se usa `fast=False`: un modo rápido no debe omitir apariciones mientras se promete enumerarlas.

## 6. Contrato 0.3.0

Se versionarán contrato, paquete e imagen como 0.3.0. El esquema 0.2.0 se conservará junto al 0.1.0. No se sobrescribirán las imágenes anteriores ni se convertirán informes silenciosamente. El launcher exigirá el protocolo esperado y las fuentes `pe`, `strings`, `yara`.

El nuevo tipo `yara_match` conservará:

- `rule_id`, `namespace`, revisión, licencia y descripción neutral del manifiesto, con longitudes acotadas.
- `rule_source_sha256` y `ruleset_sha256`, enlazados con el catálogo de esta ejecución.
- Versiones realmente observadas del paquete y del módulo YARA; no se rellenan con la versión esperada si el motor no llega a iniciarse.
- `instances`, lista tipada de apariciones de patrones.
- `instances_status` (`complete` o `partial`) y `omitted_instances`, entero únicamente cuando la cantidad se conoce; de lo contrario, nulo.

Cada instancia incluye `string_id`, `offset`, `matched_length`, `captured_length`, `raw_hex` y `complete`. Su ID de patrón debe pertenecer a la regla del catálogo y su intervalo total debe caber en la muestra. Los bytes conservados deben coincidir con el prefijo exacto de ese intervalo. Si se devuelven menos bytes que la longitud del match, `complete=false`; no se añade texto ni se confunde longitud capturada con longitud coincidente.

Una evidencia publicada debe conservar al menos una instancia validada. Un match inesperado sin patrones positivos se rechaza como respuesta incompatible con la política del catálogo; no recibe un offset cero ni una prueba inventada. `instances_status=partial` se utiliza si se omiten instancias o se recortan sus bytes, aunque el motor haya terminado el escaneo.

Una regla combinada puede depender de varios offsets. Por ello, la ubicación de la evidencia de regla será explícitamente nula; las ubicaciones verificadas están en `instances`. Esta excepción corresponde solo a `yara_match`, no relaja las ubicaciones exigidas para las evidencias 0.2.0.

`confidence="observed"` significa coincidencia observada del motor, no veracidad de una etiqueta de malware. `provenance.evidence_ids` queda vacío: los bytes y el catálogo respaldan el match sin fingir dependencia de una cadena previamente extraída. Los hashes de reglas aportan procedencia externa al grafo de evidencias de la muestra.

El informe incluirá `yara_context`, un contexto tipado con ID/revisión/digest del catálogo, inventario de reglas y versiones observadas disponibles. El inventario se conserva incluso cuando hay cero matches, para identificar qué conjunto se intentó revisar. Si un campo no se pudo obtener, se mantiene nulo con su motivo; no se inventa la versión del motor.

Se validarán unicidad de `(namespace, rule_id)`, pertenencia al catálogo, coincidencia de hashes, tipos, cuotas, intervalos y equivalencia del hexadecimal con los bytes originales en la frontera de integración. Una respuesta inconsistente se rechaza; no se corrige adivinando. El host no importa libyara para verificarla ni vuelve a ejecutar reglas.

## 7. Cobertura, resultados incompletos y contadores

Los componentes de YARA serán `yara_rules`, `yara_scan` y `yara_evidence`:

- `yara_rules`: validar el catálogo y compilarlo correctamente.
- `yara_scan`: obtener una evaluación completa del conjunto sobre el buffer.
- `yara_evidence`: conservar y validar las coincidencias dentro de las cuotas de salida.

La versión del extractor identifica al adaptador de Dissect; las versiones del paquete/módulo nativo van en el contexto, distinguiendo versión esperada de versión observada. `examined` expresa reglas compiladas o evaluadas cuando ese total está confirmado. Se permitirá valor nulo para ese contador en los componentes YARA cuando una interrupción impida conocerlo; no se usará cero como sustituto de "desconocido". Los contadores actuales de PE/strings mantienen su semántica.

Un escaneo normal con cero matches es cobertura completa de ese catálogo, no ausencia de malware. Una instalación sin el binding, un catálogo ausente, una compilación fallida o un proceso hijo sin respuesta válida produce componentes bloqueados y un error identificable, no un éxito silencioso.

Ante timeout nativo, warning de demasiadas coincidencias, incumplimiento de política, fallo del hijo o respuesta inválida, se descartan las coincidencias YARA de esa ejecución. Es una decisión conservadora: no se presupone que una parte devuelta tras una interrupción sea una evaluación completa y fiable. Se mantienen las evidencias de los otros extractores.

Si el escaneo sí termina normalmente pero la representación excede cuotas de instancias, bytes o reglas publicadas, se conserva un subconjunto explícitamente parcial. El orden es `(namespace, rule_id)` y, dentro de cada regla, `(string_id, offset, matched_length)`. Se prioriza una aparición de cada patrón coincidente antes de añadir repeticiones, sin atribuir a esa selección una explicación completa de la condición.

Los resultados descartados no consumen IDs ni dejan referencias colgantes. El estado global sigue la regla existente aplicada a tres fuentes: completo si todas completan, fallido si todas quedan bloqueadas, parcial en el resto de casos. Los fallos de infraestructura pueden impedir emitir un informe.

## 8. Presupuestos y límites de memoria

Se mantienen los límites exteriores de 20 MiB de entrada, 30 segundos por worker, 512 MiB, 1 CPU, 64 procesos y 8 MiB de respuesta. El hijo comparte esos límites, no recibe recursos o privilegios adicionales.

Valores máximos iniciales de la integración:

| Límite | Valor |
| --- | --- |
| Reglas en el catálogo | 32; inicialmente se entregan 4 |
| Fuente por archivo | 16 KiB |
| Fuente total | 256 KiB |
| Manifiesto | 64 KiB |
| Patrones por regla | 8 |
| Longitud de identificadores | 128 caracteres |
| Texto descriptivo por regla | 320 caracteres |
| Tiempo nativo de matching | 5 segundos |
| Tiempo total del subproceso, incluyendo compilación | 10 segundos, sin ampliar el límite exterior |
| Matches de regla publicados | 32 |
| Instancias conservadas por regla | 16 |
| Bytes conservados por instancia | 256 |
| Salida JSON del subproceso | 1 MiB |
| Stderr del subproceso | 64 KiB; no se publica como explicación |

`yara.set_config` fijará explícitamente el máximo de patrones por regla y los bytes de datos de match devueltos. El límite de instancias conservadas no se presentará como un límite de memoria interno de libyara: el motor puede acumular más resultados antes del callback. Esa superficie queda bajo el timeout, tratamiento de warnings y límites del contenedor; debe probarse con entradas repetitivas sintéticas.

Los valores efectivos se registran en el informe. La cota global de evidencias pasa a admitir hasta 20.353 con los máximos predeterminados; el presupuesto de bytes del recolector sigue prevaleciendo y no se eleva a raíz de esta integración.

## 9. Reproducibilidad y empaquetado

El catálogo es único y se carga con recursos del paquete, no desde rutas de la muestra ni desde el cwd. Wheel, sdist, instalación editable e imagen deben contener las mismas fuentes y producir los mismos digests. La imagen se construye antes del análisis; la documentación usará un build con carga explícita cuando sea necesario y una inspección de la etiqueta en el mismo contexto Docker.

Se probará el contenido del paquete instalado, no solo la presencia de archivos en el checkout. Una discrepancia entre el catálogo empaquetado esperado y el usado por el worker debe ser visible y provocar rechazo de sus resultados, no una atribución a reglas diferentes.

El orden de reglas y resultados es canónico. Mismos bytes, catálogo, versiones, configuración y ejecuciones completas producen hechos e IDs reproducibles. No se promete el mismo resultado parcial frente a variaciones de tiempo, fallos nativos o agotamiento de memoria.

La discrepancia Docker observada entre sesiones permanece como asunto operativo sin causa confirmada. Añadir esta integración no la resuelve por sí solo; la entrega deberá distinguir la verificación realizada por el agente de la disponibilidad confirmada en la terminal del usuario.

## 10. Pruebas y criterios de aceptación

Todas las muestras y reglas de fallo serán sintéticas y controladas. Las pruebas no ejecutan binarios ni acceden a procesos reales.

| Área | Comprobación |
| --- | --- |
| Reglas iniciales | Positivo y negativo por regla; la combinación de APIs no coincide si falta una; ASCII/wide del marcador de práctica. |
| Semántica | No aparecen veredictos, familias, probabilidades ni afirmaciones de comportamiento derivadas del nombre de regla. |
| Catálogo | Hashes reproducibles; cambios de fuente/metadatos cambian digest; IDs duplicados, archivos ausentes, rutas inseguras y reglas extra rechazados. |
| Packaging | Catálogo idéntico desde checkout, wheel y worker, incluso ejecutando la CLI fuera del directorio del repo. |
| Compilación | Sintaxis inválida, warning e include causan fallo explícito; no se cargan bytecodes externos. |
| Módulos/consola | Reglas de prueba que intenten esos usos no publican resultados ni contaminan stdout. |
| Ubicaciones | Múltiples patrones en offsets distintos, datos binarios y coincidencias repetidas; ninguna ubicación global inventada. |
| Captura acotada | Longitud coincidente mayor que los bytes conservados, límite de instancias y omisiones conocidas/desconocidas. |
| Respuesta inválida | Hash de muestra, digest de reglas, IDs, bytes o rangos inconsistentes rechazados. |
| Interrupciones | Timeout, warning de demasiados matches, fallo nativo simulado y salida excesiva; se descarta YARA y se conservan PE/strings cuando el padre sigue operativo. |
| Independencia | YARA puede coincidir sobre bytes de tipo `unknown` sin afirmar que PE se revisó correctamente. |
| Cero resultados | Escaneo completo vacío se distingue de motor ausente, catálogo inválido y escaneo interrumpido. |
| Regresiones | Imports, exports, strings, entropía, anomalías, presupuestos y validaciones 0.2.0 continúan comprobados. |
| Aislamiento | Red, usuario, solo lectura, recursos, timeout y limpieza verificados en el contenedor real con el nuevo subproceso. |

La demostración final mostrará una coincidencia explicada a partir de sus bytes, un caso negativo y un caso incompleto con el motivo visible. No se usarán salidas JSON escritas a mano como prueba de funcionamiento.

## 11. Fundamento y siguiente paso

Referencias primarias consultadas: [API de yara-python](https://yara.readthedocs.io/en/stable/yarapython.html), [lenguaje de reglas YARA](https://yara.readthedocs.io/en/stable/writingrules.html) y metadatos de `yara-python` en PyPI. Se han contrastado también las licencias de los repositorios YARA y yara-python. Los límites numéricos, catálogo inicial y política conservadora de descarte son decisiones de producto propuestas aquí, no garantías aportadas automáticamente por la biblioteca.

Esta fase prepara el contenido didáctico sobre coincidencias y, más adelante, integraciones de capacidades que respeten la prohibición de emulación. No introduce todavía capa, FLOSS, LLM ni web.

Este documento requiere aprobación antes de preparar y autorizar el plan de implementación. La rama `feat/yara-evidence` parte de la Fase 1A local; no se hará push, merge ni publicación sin autorización explícita.
