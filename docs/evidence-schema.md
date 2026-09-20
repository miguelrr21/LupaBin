# Dissect: diseño inicial y contrato de evidencias

Estado: propuesta para revisión; no describe funcionalidad implementada.

## Objetivo y alcance

Dissect es un tutor defensivo de análisis estático de binarios. Su prioridad es enseñar con información verificable, no producir el mayor número de hallazgos. Está dirigido a estudiantes, docentes y analistas junior. El proyecto usará licencia Apache-2.0.

La primera entrega comprende el andamiaje, el esquema de evidencias y `dissect analyze <archivo> --json`: hashes SHA-256/MD5, tamaño, clasificación PE validada y evidencias de imports. Incluye documentación inicial, pruebas sintéticas, configuración de calidad, Docker endurecido y workflow de CI.

No incluye todavía web, LLM, VirusTotal, capa, YARA, FLOSS, decodificadores, desempaquetado ni informes didácticos completos. Preparar interfaces para estas funciones no significa implementarlas en esta entrega.

## Regla principal: no inventar datos

1. Ningún dato de análisis se publica sin una fuente identificable y trazable.
2. Un fallo, límite o formato no soportado se comunica como análisis incompleto o imposibilidad de determinar el dato. Nunca se sustituye por un valor plausible.
3. Una lista de hallazgos vacía no demuestra ausencia de comportamiento malicioso. Hay que mostrar el estado y la cobertura del extractor.
4. Las observaciones y las inferencias son categorías distintas. No se promoverá una hipótesis a hecho por su plausibilidad, por repetición o por una respuesta del LLM.
5. Una importación demuestra la presencia de una entrada en una tabla, no que una función se ejecute ni que se use con fines maliciosos.
6. Las citas existentes son una condición necesaria, no suficiente: una afirmación también debe estar respaldada por el contenido citado. Un verificador de IDs no garantiza veracidad semántica.
7. En futuras explicaciones, las afirmaciones sobre la muestra procederán de hechos estructurados y reglas deterministas verificables. La redacción libre del LLM no se considerará una fuente. Si no se puede validar una afirmación, se omitirá y se usará la explicación determinista o una abstención explícita.
8. El conocimiento general del glosario se distinguirá de los hechos de la muestra y tendrá fuentes editoriales. Las cadenas de la muestra son datos no fiables, nunca instrucciones para un LLM.
9. No se asignarán probabilidades, puntuaciones de riesgo ni etiquetas de malware sin un método definido y evidencia suficiente.

La abstención no es un error del producto: es un resultado válido y preferible a una afirmación falsa. No se promete una garantía matemática de ausencia de errores; se exige trazabilidad, validación, pruebas negativas y comunicación de límites.

## Arquitectura de la primera entrega

Flujo: CLI -> lectura acotada de bytes y hashes -> worker aislado -> clasificación y extracción PE -> validación y asignación de IDs -> JSON.

- `ingest`: lee una entrada regular con límite efectivo durante la lectura, calcula hashes sobre los mismos bytes que se analizan y rechaza entradas inválidas. No incluye rutas locales en el resultado.
- `extractors`: interfaz independiente; extractor PE basado en `pefile`, sin cargar ni ejecutar el binario. Los resultados del extractor no asignan IDs globales ni dependen del reloj.
- `evidence`: modelos Pydantic v2, payloads discriminados por `kind`, validaciones entre campos y exportación de JSON Schema.
- `runner`: controla aislamiento, límites y timeout; trata la salida del worker como entrada no fiable y la valida.
- `cli`: Typer; JSON en stdout y diagnósticos sanitizados en stderr. No mezcla mensajes de progreso con JSON.

Se usará Python 3.12 con uv y dependencias fijadas en lockfile. El núcleo tendrá mypy estricto. La extracción de imports no incorporará LIEF, FLOSS ni otras dependencias pesadas.

### Alternativas consideradas

- Parser en el proceso de la CLI: simple, pero no proporciona el aislamiento exigido para muestras no fiables. Descartado como ruta normal de análisis.
- Worker en contenedor con núcleo modular: recomendado; separa la superficie de ataque y permite probar el núcleo con fixtures sintéticos.
- API, cola y workers desde el inicio: añade complejidad fuera de esta entrega. Pospuesto.

## Aislamiento y límites

La ruta pública de análisis ejecutará el parser en un contenedor Linux, no directamente en el host. Si Docker o la imagen no están disponibles, se comunicará el problema; no habrá fallback silencioso a un parser sin aislamiento. Las pruebas unitarias podrán invocar el núcleo directamente sobre fixtures sintéticos.

El worker no tendrá red, capacidades Linux adicionales, privilegios de root, socket Docker ni montajes del host. Recibirá bytes por stdin y emitirá una respuesta acotada por stdout. El sistema de archivos raíz será de solo lectura; cualquier espacio temporal necesario será acotado. La imagen no contendrá muestras reales ni credenciales.

Límites iniciales propuestos: entrada de 20 MiB, 30 segundos de análisis, 512 MiB de memoria, 1 CPU, 64 procesos y respuesta de 8 MiB. El número de imports estará limitado a 10.000. Si se alcanza un límite, se registrará explícitamente que el resultado no está completo. El timeout debe detener y limpiar el contenedor, no solo el cliente Docker.

Los límites efectivos se incluirán en los metadatos. Estos controles reducen el riesgo; no convierten Docker ni los parsers en una garantía de seguridad absoluta.

El Dockerfile define la imagen; los límites de ejecución y la ausencia de red se aplican en el launcher y la configuración de Compose. El servicio web de `docker compose up` pertenece a una fase posterior; esta entrega proporciona el worker CLI y su configuración endurecida.

## Contrato del informe: versión 0.1.0

El esquema se generará desde los modelos, no se mantendrá una segunda definición manual. El archivo previsto es `docs/evidence-schema.json`.

### Campos principales

| Campo | Contenido |
| --- | --- |
| `schema_version` | Versión explícita del contrato, inicialmente `0.1.0`. |
| `analysis` | Versión de Dissect, inicio/fin UTC, estado global y límites efectivos. |
| `sample` | SHA-256, MD5, tamaño y tipo validado o `unknown`; nunca ruta local. |
| `evidence` | Evidencias tipadas con IDs únicos dentro del informe. |
| `extractor_runs` | Extractor, versión, configuración relevante, estado y cobertura. |
| `extractor_errors` | Errores sanitizados, estructurados y atribuibles a un extractor. |

SHA-256 identifica los bytes analizados. MD5 se incluye únicamente para interoperabilidad, no como garantía criptográfica de integridad.

Los estados globales son `completed`, `partial` y `failed`. `completed` significa que finalizaron las operaciones solicitadas, no que se haya demostrado seguridad ni comprendido todo el programa. Los estados de extractor son `completed`, `partial`, `failed` y `not_applicable`.

El análisis no requiere red; la imagen debe estar construida o provisionada de antemano y el launcher no intentará descargarla durante el análisis. La ausencia de Docker o de la imagen, y los fallos anteriores a la lectura completa, producen un diagnóstico estructurado y una salida no exitosa; no se fabrica un informe con hashes vacíos o datos parciales presentados como completos.

### Evidencia

| Campo | Regla |
| --- | --- |
| `id` | Patrón `E[1-9][0-9]*`, único en el informe. |
| `kind` | Discriminador de un payload tipado; inicialmente `import`. |
| `source` | Extractor que produjo la evidencia, enlazado con `extractor_runs`. |
| `data` | Payload correspondiente a `kind`; se rechazan campos extra. |
| `location` | Offset, RVA y sección cuando se conocen; no inventar equivalencias. |
| `confidence` | `observed` o `inferred`; no es una probabilidad. |
| `provenance` | Referencias a evidencias de origen y transformación cuando existan. |

Los offsets y RVA serán enteros no negativos. Una dirección virtual no se etiquetará como RVA; las conversiones deberán usar la base de imagen validada. Un offset publicado debe estar dentro de los bytes originales. No se rellenarán ubicaciones desconocidas con cero.

La procedencia derivada tendrá un modelo explícito: evidencias de origen, nombre y versión de la transformación, parámetros tipados y región de entrada. El modelo inicial admitirá esa relación, pero no aceptará transformaciones arbitrarias o plugins no implementados como si ya estuvieran soportados. Las referencias deberán existir, no podrán autorreferenciarse ni formar ciclos.

Los tipos futuros (`string`, `section`, `capability`, `yara_match`, `header_anomaly`) se introducirán con sus propios payloads y pruebas, no con un diccionario genérico de valores sin validar.

### Payload `import`

- Biblioteca declarada por el PE, preservando sus bytes originales.
- Nombre de función o ordinal; exactamente una de las dos formas.
- Tabla de origen: importación normal o retardada.
- Ubicación disponible de la entrada; sin confundir el thunk/IAT con el código de la función importada.

Las cadenas válidas tendrán representación textual y representación hexadecimal de los bytes originales. Si la codificación no puede interpretarse de forma estricta, se conserva la representación hexadecimal y el texto queda sin determinar; no se usan caracteres de sustitución que aparenten un nombre real.

El extractor deberá cubrir explícitamente tablas normales y retardadas, imports por nombre y por ordinal. Una tabla corrupta no debe confundirse con una tabla ausente. Los warnings relevantes del parser se evaluarán y reflejarán como limitaciones o errores, no se descartarán silenciosamente.

Los imports son `observed` respecto al contenido del archivo, nunca evidencia directa de ejecución o intención.

### Tipos de muestra y errores

La extensión y el prefijo `MZ` no bastan para afirmar que una entrada es PE32 o PE32+. Se validarán las cabeceras y sus límites. Si la clasificación no puede establecerse, el tipo será `unknown` y se comunicará el motivo.

Errores previstos: `invalid_pe`, `unsupported_format`, `timeout`, `resource_limit`, `output_limit` y `extractor_failure`. El extractor se identifica de forma estable; los mensajes públicos no incluyen rutas, tracebacks, secretos ni fragmentos binarios arbitrarios.

Los errores fatales de ingesta no son fallos de un extractor. Los fallos de un extractor no eliminan las evidencias válidas de otros extractores; si se conserva un resultado parcial, se explicita su cobertura.

### Determinismo y compatibilidad

Para los mismos bytes, versión de extractor, reglas y configuración, las extracciones que completan deben producir los mismos hechos y el mismo orden. Los IDs se asignarán tras ordenar canónicamente los resultados. Son referencias locales al informe, no identificadores estables entre versiones distintas.

Los timestamps y las duraciones no forman parte de los hechos deterministas. Los límites de tiempo pueden producir resultados incompletos según el entorno; esa diferencia debe ser visible, no ocultarse bajo la promesa de determinismo.

Los consumidores rechazarán versiones de esquema no soportadas. Los cambios incompatibles requerirán una nueva versión explícita y pruebas de compatibilidad.

## Desofuscación en una etapa posterior

Se mantiene la prohibición de ejecutar o emular instrucciones de la muestra. Se permite transformar datos mediante algoritmos propios auditados, con regiones, parámetros y recursos delimitados.

La primera ampliación propuesta es extracción de cadenas y decodificación estricta de Base64/hexadecimal, más candidatos XOR sencillos. Una transformación reproducible demuestra el resultado de esa operación, no que el programa la efectúe ni use el texto resultante. Las hipótesis sobre su significado serán `inferred` y no se mostrarán como hechos confirmados.

FLOSS solo podría integrarse con las rutas emulativas desactivadas, versión fijada y pruebas que intercepten cualquier intento de construir el workspace emulativo. Comprobar únicamente los tipos de salida no basta para garantizar que no hubo emulación. Binary Refinery queda como opción futura para transformaciones permitidas individualmente, no como motor indiscriminado.

No se promete desofuscación general de código, descifrado sin claves recuperables ni desempaquetado arbitrario. Cuando no sea posible, el informe lo dirá.

## Criterios de aceptación y pruebas

- Fixtures PE sintéticos generados por el proyecto; ninguna muestra maliciosa descargada, ejecutada o versionada.
- Pruebas de hashes conocidos, tamaños, entradas vacías, truncadas, sobredimensionadas y no regulares.
- Pruebas PE32/PE32+, imports normales/retardados, por nombre/ordinal, sin tabla y con tabla corrupta.
- Pruebas de nombres no decodificables, RVA/offsets fuera de límites y warnings del parser.
- Igualdad de hechos e IDs entre ejecuciones completas equivalentes; timestamps comprobados por separado.
- Validación de IDs únicos, referencias existentes, ausencia de ciclos, payloads tipados y rechazo de campos inesperados.
- Pruebas negativas: un fallo de parsing no se convierte en una lista de imports completa; un import no genera una afirmación de comportamiento; `unknown` no se sustituye por una conjetura.
- Contrato JSON coherente con el JSON Schema generado; CI detecta si el esquema versionado se queda desactualizado.
- Pruebas CLI de stdout JSON, stderr separado y códigos de salida para éxito, análisis incompleto y fallo.
- Pruebas de aislamiento efectivo: usuario no root, red deshabilitada, raíz de solo lectura, límites y finalización del worker al vencer el timeout.
- Ruff, mypy estricto en el núcleo, pytest, build de paquete y build/prueba de imagen en CI.

La documentación inicial incluirá README, CONTRIBUTING, SECURITY, licencia y procedencia de fixtures. AGENTS.md recogerá las reglas de veracidad, no ejecución y verificaciones para futuros cambios.

## Verificación y publicación

El informe de entrega distinguirá comprobaciones locales, comprobaciones en contenedor y resultados remotos de GitHub Actions. Tener un workflow escrito no significa tener CI en verde. No se declarará un test o build exitoso si no se ha ejecutado y observado su resultado.

El repositorio local existe en `C:\Users\migue\orca\projects\Dissect`. Crear un remoto o publicar requiere confirmar propietario y visibilidad. No se hará push sin autorización explícita.
