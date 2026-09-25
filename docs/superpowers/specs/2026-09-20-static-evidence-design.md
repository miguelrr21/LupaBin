# Fase 1A: evidencias estáticas básicas ampliadas

Estado del diseño (secciones 1–9): aprobado por el usuario. El plan de implementación de la sección 10 está aprobado y su ejecución secuencial está autorizada. La implementación de esta rama usa el contrato 0.2.0; las secciones siguientes conservan la especificación y el plan acordados, no sustituyen los resultados de verificación de cada entrega.

## 1. Propósito y resultado para el usuario

LupaBin debe enseñar a observar un binario antes de atribuirle comportamientos. Esta ampliación permitirá consultar secciones, medidas de entropía, cabeceras, exports y cadenas literales junto con los imports existentes. Cada dato tendrá una ubicación verificable y una descripción de lo que se pudo revisar.

Se mantiene la prioridad explícita del usuario: abstenerse antes que inventar datos. No se ejecuta ni emula la muestra; no se usa un LLM, red ni código de la muestra para producir hallazgos.

El resultado visible seguirá siendo JSON mediante `lupabin analyze <archivo> --json`. No habrá todavía web, informe narrativo ni clasificación de malware. Al terminar la implementación se mostrará una demostración real y un cierre que explique cada cambio, su fundamento y qué prepara para el futuro.

## 2. Alcance y alternativas

Se incluyen siete tipos de evidencia: `import` existente y nuevos `pe_header`, `section`, `entropy`, `export`, `string`, `header_anomaly`.

Alternativas consideradas:

- **Ampliación progresiva del núcleo actual, elegida:** pefile para cabeceras, lectura acotada de tablas y algoritmos pequeños de biblioteca estándar. Conserva la trazabilidad sin añadir dependencias.
- **Integrar primero YARA/capa/FLOSS:** aporta reglas y capacidades, pero añade dependencias, licencias, políticas de ejecución y nuevas interpretaciones antes de completar la observación básica. Queda para el siguiente bloque.
- **Construir primero la web sobre imports:** hace visible la interfaz, pero no amplía lo que LupaBin puede enseñar sobre la muestra. No es el orden acordado.

Quedan fuera de esta fase: YARA, capa, FLOSS, Base64/XOR, desempaquetado, análisis del flujo de instrucciones, ELF, interpretación de scripts, firmas Authenticode, VirusTotal, detección de familias, puntuaciones de riesgo, LLM y renderers didácticos. Extraer cadenas literales de bytes de tipo desconocido no equivale a soportar su formato ni su comportamiento.

## 3. Punto de partida y cambios de arquitectura

El código actual vincula `Finding.data` y `Evidence.data` a `ImportData`, cuenta toda evidencia contra el límite de imports, expresa cobertura mediante `normal`/`delay` y acepta solo el extractor `pe` en el launcher. Esos supuestos deben cambiar explícitamente, no parchearse mediante campos sin tipar.

Se conservan la ingesta, la separación CLI/worker, los hashes y los controles Docker. El worker ejecutará un registro cerrado de dos extractores: `pe` y `strings`. No habrá descubrimiento automático de plugins, imports de módulos indicados por la muestra ni configuración ejecutable aportada por el usuario.

Responsabilidades propuestas:

- **Modelos de evidencia:** unión discriminada por `kind`; cada variante valida su payload y su procedencia.
- **Lectura PE:** reconocimiento de cabeceras, lectura de descriptores y construcción de un mapa RVA/offset seguro como responsabilidades separadas. Se dividirá el módulo actual por esas responsabilidades para no acumular todo en un único archivo.
- **Extractor PE:** cabeceras, secciones, entropía, imports normales/retardados, exports y comprobaciones estructurales acotadas.
- **Extractor strings:** barrido de bytes independiente de la interpretación PE. No recibe ubicaciones supuestas de otros extractores.
- **Ensamblador:** límites de salida, orden canónico, IDs, referencias, estados y coherencia del conjunto.
- **Launcher:** verifica las fuentes esperadas, versión de protocolo, límites, hashes, tamaño y coherencia del resultado. No vuelve a parsear el PE en el host.

Los fallos recuperables de un componente no borran los hechos válidos de otro. Un timeout o agotamiento de memoria que termine el worker completo puede impedir recuperar cualquier resultado; en ese caso se devuelve un fallo explícito, no un informe parcial inventado.

## 4. Contrato 0.2.0 y compatibilidad

Esta ampliación cambia payloads y reglas de agregación; se usará `schema_version="0.2.0"`. La versión del paquete y de la nueva imagen será 0.2.0 para distinguirla de la entrega inicial. No se sobrescribirá ni eliminará la imagen 0.1.0 existente.

Se conservará el JSON Schema 0.1.0 como referencia histórica en `docs/schemas/0.1.0.json`. El esquema activo `docs/evidence-schema.json` se regenerará desde los modelos 0.2.0 durante la implementación. La regeneración forma parte de la implementación aprobada; el archivo histórico no se reescribe.

La CLI nueva emitirá únicamente 0.2.0 y rechazará un worker 0.1.0 con un error de incompatibilidad identificable. No transformará informes antiguos ni prometerá compatibilidad de lectura que no existe. Los IDs siguen siendo locales al informe; añadir nuevos hechos puede cambiar la numeración de imports entre versiones.

Se conservarán `sample`, `analysis`, `evidence`, `extractor_runs` y `extractor_errors`. Se añadirá una lista separada de limitaciones con códigos estables, fuente y componente: un límite intencionado no es lo mismo que una excepción del parser. Ningún detalle incluirá rutas locales, tracebacks ni texto arbitrario procedente del parser.

En esta fase todos los hechos publicados serán `observed`. Las medidas calculadas tendrán un método explícito; `observed` no significará que el número estuviera escrito en el archivo. No se habilitan hipótesis de comportamiento ni evidencias `inferred` todavía.

## 5. Hechos nuevos y condiciones para publicarlos

### 5.1 Cabecera PE

`pe_header` conserva los enteros declarados: `machine`, `number_of_sections`, `timestamp_raw`, `characteristics`, `optional_magic`, `image_base`, `entry_point_rva`, `section_alignment`, `file_alignment`, `size_of_image` y `size_of_headers`.

Su ubicación identifica los bytes de cabecera leídos. Los valores de máquina desconocidos permanecen como enteros, sin inventar nombres. `timestamp_raw` conserva los 32 bits originales: no se publica un campo `compiled_at` ni se convierte automáticamente a una fecha supuestamente real. Los valores 0 y 0xFFFFFFFF no representan timestamps significativos según la especificación PE; otros valores tampoco demuestran por sí mismos una fecha de compilación.

El tipo PE32/PE32+ solo se asigna al validar las firmas y el bloque de cabeceras requerido, incluyendo límites y tamaños. Que se reconozca el tipo no acredita la validez de todas las secciones o tablas. Si ese bloque está truncado o no puede validarse, el tipo queda `unknown` y no se fabrican evidencias PE a partir de bytes parciales.

### 5.2 Secciones

`section` conserva índice, los ocho bytes originales del nombre, RVA, tamaño virtual, offset y tamaño declarados de datos en disco, y flags originales. `name_raw_hex` preserva los ocho bytes; `name_text` elimina solo el padding NUL final y decodifica UTF-8 estrictamente, o queda nulo si no puede hacerlo. No se normalizan ni reparan los bytes. Las etiquetas de lectura/escritura/ejecución solo serán traducciones de bits definidos en la especificación, no prueba de permisos efectivos durante una ejecución.

La ubicación de la evidencia apunta al descriptor de sección, no al intervalo declarado de datos. Así puede describirse fielmente que un descriptor declara un rango fuera del archivo sin presentar ese rango como una ubicación válida. El payload distingue rango declarado y estado de validación.

Se conservan nombres duplicados usando el índice de sección; no se fusionan secciones por nombre. Un tamaño en disco cero con datos virtuales no se convierte automáticamente en anomalía. No se añaden ceros sintéticos para simular la imagen cargada.

### 5.3 Entropía de bytes

`entropy` es una medida separada por sección, con `method="shannon-byte-v1"`, `byte_count` y `bits_per_byte` finito entre 0 y 8. Cita mediante procedencia la evidencia `section` que define su intervalo.

Se calcula `H = -sum(p_i * log2(p_i))` para frecuencias no nulas de los 256 valores posibles, sobre exactamente los bytes en disco de la sección. Se incluye el padding que esté físicamente dentro de `SizeOfRawData`, nunca relleno virtual ni bytes fuera del intervalo. Se sumará en orden fijo por valor de byte y se redondeará a seis decimales; los tests verificarán el resultado numérico con tolerancia y su serialización en las plataformas soportadas.

Una sección vacía no produce una medida: no se confunde falta de datos con entropía cero. Un rango parcialmente fuera del archivo tampoco produce una medida sobre el prefijo como si cubriera toda la sección. Los intervalos solapados pueden medirse por separado si sus bytes están presentes, pero el solapamiento se comunica y cada lectura consume presupuesto.

No habrá umbral que afirme "empaquetado", "cifrado" o "malicioso". La futura explicación podrá contextualizar la medida, pero no convertirla en una conclusión demostrada.

### 5.4 Exports

`export` describe un símbolo exportado, no necesariamente una función. Conserva índice EAT, ordinal calculado como base más índice, nombres originales asociados y RVA declarada de destino, o el texto original de un forwarder. No resuelve el forwarder cargando otra DLL.

La evidencia apunta a la entrada de la tabla de direcciones de exportación. El destino se guarda aparte: que haya un RVA declarado no permite inventar un offset de código. Los nombres y la cadena de forwarder conservarán bytes originales y texto ASCII estricto opcional, como los imports.

Se comprobarán todos los límites, contadores, índices de la tabla de ordinales y terminadores antes de aceptar asociaciones. Se admiten varios nombres para una misma entrada y exports sin nombre; no se completan nombres mediante diccionarios externos. Una entrada EAT cero se trata como hueco, no como símbolo exportado en RVA cero. La suma ordinal debe caber en 32 bits; no se fuerza al límite de 16 bits de los imports.

La clasificación como forwarder depende de que su RVA esté dentro del intervalo del directorio de exportación. Su cadena debe terminar dentro de ese intervalo. Fuera de él se conserva el RVA como destino declarado, sin afirmar que apunte a código ejecutable o siquiera a bytes presentes en disco.

Si las tablas de nombres están corruptas, se pueden conservar entradas EAT válidas, pero `names_status` será `incomplete`, nunca "sin nombre" por defecto. La evidencia indica exactamente qué campos quedaron sin determinar y el componente queda parcial.

### 5.5 Cadenas literales

`string` conserva `encoding`, `text`, `raw_hex`, número de caracteres y si la secuencia se devolvió completa. Su ubicación es siempre el offset real y la longitud de los bytes retornados. El modelo valida que esos bytes decodifican exactamente al texto publicado.

La primera política reconoce secuencias de al menos cuatro caracteres del rango imprimible ASCII U+0020–U+007E, tanto en ASCII como en UTF-16LE. El modo UTF-16LE queda explícitamente limitado a ese repertorio: no se promete recuperar todo Unicode, texto de Go/Rust, cadenas cifradas o cadenas construidas en la pila.

Se buscan secuencias máximas sobre el buffer completo. UTF-16LE se revisa en ambos alineamientos de byte. Los resultados se intercalan por offset y codificación antes de aplicar límites; no se agota todo el presupuesto en ASCII para ignorar después UTF-16LE. Apariciones del mismo texto en offsets distintos son evidencias distintas.

Una secuencia mayor de 1.024 caracteres conserva únicamente un prefijo explícitamente marcado `complete=false`. Su ubicación abarca solo ese prefijo; la longitud total solo se publica si se ha recorrido y contado la secuencia entera. Se registra la limitación, sin añadir puntos suspensivos dentro del texto observado.

No se añade RVA ni sección a una cadena en esta fase: la relación con secciones requiere un mapa válido y se deja para una ampliación posterior. El offset basta para contrastar sus bytes. No se clasifican URLs como comunicaciones, rutas como archivos creados ni palabras como capacidades.

La extracción de cadenas puede completarse aunque falle el parsing PE. En ese caso solo se afirman bytes literales; el tipo puede seguir `unknown` y el resultado global no será completo porque el análisis PE solicitado falló.

### 5.6 Anomalías estructurales

`header_anomaly` conserva código de comprobación, versión de regla, campos involucrados y referencias a cabeceras/secciones observadas. No contiene una etiqueta de familia ni una puntuación de peligrosidad.

Comprobaciones iniciales: rango declarado de datos de sección fuera del archivo, solapamiento de rangos físicos entre secciones, solapamiento de rangos virtuales entre secciones, extensión virtual declarada mayor que `SizeOfImage` y entrada declarada no nula fuera de `SizeOfImage`. Los intervalos vacíos no se tratan como solapamientos.

El intervalo virtual de cada sección para esas comparaciones usa `max(VirtualSize, SizeOfRawData)` sin fingir que se haya cargado el archivo. Se explicita que es una comprobación conservadora de campos declarados, no una reproducción del loader de Windows. Cada par de secciones solapadas se publica una vez.

Un warning genérico de pefile no se convierte en una anomalía concreta: conserva su código de limitación y fuerza estado parcial. Para afirmar una anomalía concreta deben existir los campos suficientes y una comprobación propia reproducible.

Si un mapa RVA/offset resulta ambiguo, se bloquea su uso para imports y exports. Las cabeceras o descriptores válidos ya leídos pueden mantenerse; no se elige arbitrariamente una sección para continuar.

## 6. Cobertura, estados y abstención

Cada ejecución de extractor tendrá un modelo de cobertura tipado. Para `pe`: cabeceras, secciones, entropía, imports normales, imports retardados, exports y comprobaciones estructurales. Para `strings`: ASCII y UTF-16LE restringido. Cada componente distingue `complete`, `partial` y `blocked`; se registran contadores de evidencias conservadas y las limitaciones pertinentes.

Un directorio de imports/exports ausente puede tener cobertura completa con cero hallazgos. Una tabla que no se pudo leer nunca recibe ese estado. Una sección sin datos no requiere inventar una medida para completar el recorrido de entropía.

Estados por extractor:

- `completed`: todos sus componentes se revisaron conforme al alcance declarado, sin errores ni límites que reduzcan cobertura o resultados.
- `partial`: existe al menos un componente completo o parcialmente revisado, pero también componentes parciales/bloqueados, warnings o resultados omitidos por límites.
- `failed`: todos los componentes están bloqueados; ninguno aporta trabajo verificable.

Detectar una anomalía no implica por sí solo que fallara el análisis: puede haberse comprobado correctamente una inconsistencia. Los componentes quedan incompletos cuando esa condición impide revisar datos de forma segura, no simplemente porque el archivo tenga un hallazgo.

No se usará `not_applicable` en los dos extractores de esta fase: una entrada no PE produce un fallo explícito `unsupported_format` del análisis PE solicitado. Este estado podrá diseñarse para plugins opcionales futuros sin tratarlo ahora como éxito.

El estado global se calcula por cobertura, no por el número de evidencias: `completed` si ambos extractores completan; `failed` si ambos fallan; `partial` en los demás casos. Un extractor completado con cero hallazgos sigue siendo trabajo realizado. Esta regla sustituye explícitamente la heurística 0.1.0 basada en si la lista de evidencias estaba vacía.

Los errores o limitaciones siempre identifican fuente y componente. Los estados parciales/fallidos requieren al menos un motivo registrado; una fuente completa no puede coexistir con un motivo de cobertura incompleta. Se mantienen los códigos de salida 0 completo, 3 parcial, 1 fallo y 2 uso incorrecto.

## 7. Límites y determinismo

Se conservan los límites externos: 20 MiB de entrada, 30 segundos de worker, 512 MiB de memoria, 1 CPU, 64 procesos y 8 MiB de respuesta. No se amplían permisos ni red para acomodar el trabajo adicional.

Límites internos iniciales: 96 descriptores de sección; 10.000 imports; 5.000 entradas EAT examinadas; 10.000 asociaciones de nombres de exportación examinadas; 5.000 cadenas; 1.024 caracteres por cadena retornada; 128 anomalías; 20 MiB acumulados de bytes procesados para entropía. Todos se registran en los límites efectivos del informe. Los nombres de imports/exports conservan su máximo actual de 4.096 bytes.

Los límites de tablas controlan entradas examinadas, incluidos huecos o duplicados, no solo hallazgos emitidos. Se mantiene además un máximo de 4.096 descriptores de importación por tabla para que una sucesión de descriptores vacíos no eluda el límite de imports. Al alcanzar un máximo no se seguirá recorriendo sin límite para afirmar un total exacto. Se indica "no determinado" para cualquier total que no se haya contado completamente.

La cota global de evidencias deriva de esas cuotas: como máximo 20.321 con los valores predeterminados, no 10.000 hechos de cualquier clase contados como si fueran imports. Se acotan a 128 entradas las listas de errores y de limitaciones; los motivos repetidos por fuente, componente y código se agrupan sin inventar el número de casos no recorridos.

El ensamblador reserva al menos 1 MiB de la respuesta para metadatos y motivos. El presupuesto de evidencias es como máximo `min(6 MiB, output_bytes - 1 MiB)`. Si no cabe ni un informe mínimo dentro de un límite solicitado, se devuelve `output_limit` sin truncar JSON. El recuento se hace sobre UTF-8 serializado con un límite conservador para la longitud final de IDs y referencias.

Se procesan y admiten candidatos en orden fijo: cabeceras, secciones y sus medidas, imports, exports, anomalías y cadenas. Cada extractor produce candidatos en orden de ubicación/índice; la política evita acumular todas las cadenas o tablas antes de aplicar límites. Una medida o anomalía dependiente solo se conserva si también se conservan las evidencias que cita. Después se asignan los IDs locales y se validan todas las referencias. El límite final de 8 MiB sigue siendo obligatorio aunque una comprobación interna falle.

Este orden protege los hechos estructurales básicos frente a un archivo lleno de texto. No representa mayor certeza de una fuente sobre otra. Los mismos bytes, versiones, límites y ejecuciones completas deben producir los mismos hechos e IDs; los timestamps se comprueban por separado.

## 8. Pruebas y aceptación del diseño

Las pruebas se escribirán antes de cada bloque funcional. Solo se usarán fixtures sintéticos generados por el proyecto.

| Área | Prueba verificable | Afirmación que debe impedir |
| --- | --- | --- |
| Cabeceras | Campos y offsets conocidos; truncamientos; timestamp 0/0xFFFFFFFF | "Se compiló en esta fecha" a partir del campo |
| Secciones | Nombres repetidos, flags, tamaño físico/virtual diferente, sección vacía | Confundir declaración con permisos efectivos o rellenar datos ausentes |
| Entropía | Todos los bytes iguales: 0; dos valores equiprobables: 1; 256 valores equiprobables: 8 | Concluir empaquetado/cifrado por la cifra |
| Entropía incompleta | Rango truncado, vacío o presupuesto agotado | Medir un prefijo y atribuirlo a toda la sección |
| Exports | Nombre, ordinal, aliases, huecos EAT, forwarder, índices y cadenas corruptos | Inventar nombres o llamar función a cualquier símbolo |
| Cadenas | ASCII, UTF-16LE en ambos alineamientos, umbral, duplicados por offset, prefijo limitado | Presentar texto decodificado como comunicación o comportamiento |
| Anomalías | Solapamientos y rangos inválidos con referencias a descriptores válidos | Convertir un warning inespecífico en un hecho concreto |
| Independencia | PE fallido con cadenas válidas; fallo de strings con PE válido | Borrar datos respaldados o declarar éxito total |
| Estados | Cero hallazgos con cobertura completa; componente bloqueado; todos fallidos | Equiparar vacío, no revisado y seguro |
| Presupuestos | Un caso por límite, salida muy grande y dependencia descartada | Truncar JSON, perder referencias o ocultar omisiones |
| Versiones | Worker/schema 0.1.0 frente a CLI 0.2.0 | Aceptar silenciosamente un contrato distinto |
| Regresión | Imports por nombre/ordinal y retardados actuales; hashes, errores sanitizados | Perder garantías de la entrega inicial |
| Aislamiento | Build y tests reales Docker, incluyendo timeout y retirada del contenedor | Volver al parser en el host si Docker falla |

La demostración de aceptación mostrará un PE sintético con varios tipos de evidencia y otro caso incompleto que obligue a abstenerse. No se mostrará como salida real ningún JSON escrito a mano.

## 9. Fundamento y evolución posterior

Fundamentos: brief original, prioridad de veracidad indicada por el usuario, contrato 0.1.0, código actual y especificación oficial [PE Format de Microsoft](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). Las decisiones sobre secciones, RVA, tablas de exportación y significado limitado de timestamps se apoyan en esa especificación. Los límites de producto y de cadenas son decisiones conservadoras de LupaBin, no propiedades universales del formato.

La entropía usa una medida matemática de distribución de bytes; su utilidad educativa no autoriza inferencias de peligrosidad. Las cadenas son patrones literales definidos por una política explícita, no resultados de ejecución ni desofuscación.

Esta base prepara las integraciones YARA/capa, la decodificación estática acotada y las plantillas didácticas con citas. Después podrán llegar los renderers y la web. Ninguna de esas funciones se considera implementada por aprobar este diseño.

La implementación se realizará en la rama `feat/static-evidence`, con commits pequeños y PR de fase cuando se autorice publicar. El diseño de las secciones 1–9 está aprobado; no cambia el motor por sí mismo.

## 10. Plan de implementación para revisión

Estado: aprobado. Método acordado: ejecución secuencial en esta sesión, sin subagentes adicionales. No se añadirá ninguna dependencia ni se relajarán controles de seguridad. Los archivos nuevos descritos aquí son objetivos de implementación, no componentes ya existentes.

La skill `writing-plans` no está disponible en este entorno; este plan se ha redactado directamente a partir del diseño aprobado y del código revisado.

### A. Línea base y conservación del contrato anterior

Archivos afectados: esquema existente y nuevo archivo histórico `docs/schemas/0.1.0.json`; pruebas de esquema.

1. Confirmar estado Git y ejecutar los tests actuales antes de cambiar el motor.
2. Conservar una copia exacta del JSON Schema 0.1.0 antes de regenerar nada. Comprobar mediante un test que la copia histórica no se modifica al exportar el esquema activo.
3. Trabajar en la rama actual; no sobrescribir ni eliminar la imagen Docker 0.1.0.

Verificación: `uv run --frozen pytest -m "not docker"` y `uv run --frozen python -m lupabin.evidence.schema --check`. Las verificaciones Docker se ejecutarán cuando el motor esté disponible; su ausencia no se contabiliza como prueba superada.

### B. Modelos tipados, cobertura y validaciones cruzadas

Archivos: `src/lupabin/evidence/models.py`, nuevos módulos de payloads y cobertura bajo `src/lupabin/evidence/` si lo exige el tamaño, `src/lupabin/extractors/base.py`; `tests/test_evidence.py`, `tests/test_schema.py` y nuevos tests focalizados de payloads/cobertura.

1. Escribir primero tests fallidos para cada variante nueva y para combinaciones inválidas: `kind`/payload incompatibles, floats no finitos, texto distinto de los bytes originales, estados contradictorios y referencias a tipos o ubicaciones incorrectos.
2. Definir la unión discriminada de los siete tipos, sin sustituir la validación por `dict[str, Any]`.
3. Distinguir ubicaciones verificadas del archivo de direcciones y tamaños meramente declarados en campos PE. Validar referencias de entropía a su sección y de anomalías a los campos que las sustentan.
4. Introducir cobertura específica para PE y strings, contadores y motivos tipados. Separar errores de limitaciones, conservar su fuente/componente y rechazar estados completos con motivos de cobertura incompleta.
5. Añadir cuotas por tipo, cota global y restricciones de longitud. Probar específicamente que añadir strings no consume la cuota de imports.
6. Adaptar el contrato interno de hallazgos para identificar dependencias antes de asignar IDs públicos. No usar IDs inventados o provisionales en el JSON final.

Verificación focalizada: tests de modelos/esquema y `uv run --frozen mypy src`. No se regenerará el esquema 0.2.0 definitivo hasta integrar los consumidores; un cambio parcial del contrato no se declarará una entrega funcional.

### C. Cabeceras, secciones y conservación de imports

Archivos: `src/lupabin/extractors/pe.py`, nuevos módulos `pe_layout.py` y `pe_imports.py`; `tests/fixtures/pe_builder.py`, `tests/test_pe.py` y nuevos tests de cabeceras/secciones.

1. Extender el generador sintético para disponer de varias secciones y campos conocidos sin ejecutar ni descargar binarios.
2. Escribir tests de cabeceras válidas/truncadas, números de máquina desconocidos, timestamps originales y nombres de sección UTF-8 válidos o no decodificables.
3. Separar reconocimiento de cabeceras, lectura de descriptores y construcción del mapa seguro RVA/offset. Conservar campos comprobados aunque otro componente no pueda interpretarse.
4. Emitir cabeceras y descriptores con offsets de sus estructuras originales. No confundir `PointerToRawData` declarado con una ubicación comprobada dentro del archivo.
5. Reutilizar el lector de imports actual, trasladándolo a un módulo enfocado sin perder la preservación de ordinales, bytes originales, tablas retardadas y control de IAT truncada.
6. Mantener bloqueadas las lecturas dependientes de un mapa ambiguo. Actualizar los tests actuales que asumían que el único hallazgo era `E1`: comprobar contenido y procedencia, no perpetuar un ID que cambia legítimamente al añadir nuevos tipos.

Verificación: suite PE existente y nueva, determinismo con reloj fijo y comprobación de que un valor de timestamp nunca genera una supuesta fecha de compilación.

### D. Entropía y anomalías estructurales

Archivos: nuevos `src/lupabin/extractors/pe_sections.py` y `pe_checks.py`, integración en el extractor PE; nuevos `tests/test_entropy.py` y `tests/test_pe_checks.py`.

1. Escribir los vectores matemáticos conocidos: entropía 0, 1 y 8; incluir entradas vacías y rangos truncados antes de implementar el cálculo.
2. Calcular la medida únicamente sobre intervalos completos de bytes físicos. Redondear según el método aprobado, normalizar cero y rechazar resultados no finitos.
3. Controlar los bytes acumulados procesados, incluyendo lecturas repetidas de secciones solapadas. El agotamiento de presupuesto no permite medir un prefijo como si fuese la sección entera.
4. Escribir tests de cada predicado estructural aprobado y después implementarlo con referencias a evidencias originales. Un par solapado se emite una sola vez; los intervalos vacíos no se consideran solapamientos.
5. No interpretar warnings genéricos como anomalías concretas. Conservarlos como motivos de cobertura incompleta, sin copiar mensajes arbitrarios del parser.

Verificación: valores matemáticos, límites y referencias válidas; ausencia de campos o reglas que conviertan entropía/flags en un veredicto de malware.

### E. Exports fieles a las tablas

Archivos: nuevo `src/lupabin/extractors/pe_exports.py`, integración en `pe.py`; fixtures y nuevo `tests/test_exports.py`.

1. Crear fixtures de EAT y tablas de nombres/ordinales: símbolo con nombre, solo ordinal, aliases, hueco cero y forwarder.
2. Escribir pruebas fallidas de índices fuera de rango, suma ordinal fuera de 32 bits, contadores excesivos, terminadores ausentes y nombres corruptos.
3. Recorrer estructuras con límites de entradas examinadas, no solo de resultados encontrados. Conservar la ubicación de la entrada EAT y el destino declarado como datos diferentes.
4. Conservar todos los nombres originales que se hayan podido validar dentro de las cuotas. Si la asociación está incompleta, marcar `names_status=incomplete`, sin afirmar que no existe nombre.
5. Validar forwarders dentro del directorio; nunca cargar ni buscar la DLL de destino. Limitar también la memoria usada al acumular aliases y la representación serializada de una evidencia individual.

Verificación: cada salida se contrasta con los bytes del fixture; ninguna entrada EAT se etiqueta como función ejecutada ni se completa mediante diccionarios de ordinales.

### F. Strings estáticas independientes

Archivos: nuevo `src/lupabin/extractors/strings.py`, integración posterior del registro; nuevo `tests/test_strings.py`.

1. Escribir primero casos de ASCII y UTF-16LE restringido en ambos alineamientos, cuatro caracteres exactos, secuencias cortas, EOF, repeticiones y datos sin texto reconocido.
2. Implementar barridos acotados que no materialicen todas las coincidencias antes de aplicar cuotas. Intercalar candidatos por offset y codificación de forma determinista.
3. Probar y aplicar el límite de 1.024 caracteres con prefijo explícito, sin añadir caracteres al texto observado ni inventar la longitud total si no se ha contado.
4. Hacer verificable la equivalencia entre texto, bytes originales, codificación y longitud. No añadir RVA/sección ni interpretar semánticamente URLs/rutas.
5. Probar que un PE malformado puede conservar strings válidas como hechos literales sin cambiar el tipo desconocido por una conjetura.

Verificación: suite de strings, consumo de cuotas y conservación exacta de bytes. Quedan fuera decodificación Base64/XOR, Unicode completo y emulación.

### G. Ensamblado, presupuestos e integración 0.2.0

Archivos: `src/lupabin/analysis.py`, `extractors/base.py`, nuevo `evidence/collector.py`, `evidence/models.py`, `evidence/schema.py`, `runner.py`, `worker.py`, `errors.py`, `__init__.py`, `pyproject.toml` y `uv.lock`; tests de análisis, presupuestos, runner, worker y CLI.

1. Escribir pruebas de agregación independientes de la cantidad de hallazgos: completo vacío, parcial sin hallazgos, PE fallido con strings completas, y todas las fuentes bloqueadas.
2. Introducir el registro cerrado `pe`/`strings` y un recolector que admita hallazgos bajo presupuestos antes de acumular una salida demasiado grande. Mantener el orden acordado y reservar espacio para explicar omisiones.
3. Resolver dependencias internas a IDs finales solo para hechos conservados. Probar que descartar una sección por presupuesto nunca deje una entropía o anomalía citándola.
4. Aplicar cuotas globales/por tipo y límites de metadatos; comprobar tanto muchos hallazgos pequeños como una evidencia grande con aliases. Si no cabe el informe mínimo, emitir un error sin JSON truncado.
5. Integrar las nuevas coberturas y motivos, actualizar las expectativas de fuentes del launcher y verificar hashes, tamaño, límites, estado y código de salida del worker.
6. Añadir error identificable de protocolo incompatible y tests frente a 0.1.0. Cambiar coherentemente paquete, contrato e imagen esperada a 0.2.0, actualizando el lockfile con uv sin actualizar dependencias de forma incidental.
7. Regenerar el JSON Schema activo y verificarlo; conservar intacto el archivo histórico. Actualizar pruebas de CLI y paquete para el nuevo contrato, sin eliminar las garantías que ya verificaban.

Verificación: suite unitaria completa, mypy, Ruff y comprobación del esquema. No considerar terminada la integración mientras algún consumidor siga esperando solo imports o el esquema 0.1.0.

### H. Docker, CI, documentación y demostración

Archivos: `compose.yaml`, `docker/Dockerfile` si requiere adaptar empaquetado, `.github/workflows/ci.yml`, `tests/integration/test_docker.py`, fixtures, `README.md`, `docs/evidence-schema.md`, `samples/README.md` y `AGENTS.md`.

1. Apuntar build, launcher, Compose y CI a `lupabin-worker:0.2.0`; no modificar controles de red, privilegios, montajes ni recursos. No borrar la imagen anterior.
2. Ampliar el recorrido real CLI -> worker -> JSON con los tipos nuevos y un caso parcial; repetir las pruebas de aislamiento y timeout que ya existen.
3. Mantener comprobaciones de Windows/Linux en CI, pero no atribuir a esta rama los resultados verdes anteriores de `master`. El push y el PR requieren autorización explícita.
4. Actualizar documentación de contrato, códigos de salida y límites. Indicar que el comando sigue siendo de consola y que la web y las explicaciones narrativas aún no existen.
5. Generar dos entradas sintéticas nuevas, sin sobrescribir archivos: una demostración de hechos nuevos y otra de limitación/abstención. Ejecutar la CLI real aislada y mostrar exclusivamente los resultados obtenidos.
6. Revisar el diff final, mantener commits convencionales acotados y cerrar con explicación de producto: qué puede hacer ahora, motivo/fundamento de cada cambio, qué prepara después y qué sigue sin estar disponible.

Comprobaciones finales previstas:

```text
uv run --frozen ruff format --check .
uv run --frozen ruff check .
uv run --frozen mypy src
uv run --frozen mypy --platform linux src
uv run --frozen pytest -m "not docker"
uv run --frozen python -m lupabin.evidence.schema --check
uv build
docker compose config --quiet
docker build -f docker/Dockerfile -t lupabin-worker:0.2.0 .
uv run --frozen pytest -m docker
```

En el workspace Windows actual se usará `.bootstrap/Scripts/uv.exe` donde uv no esté en el PATH. Una comprobación no ejecutada se declarará pendiente, y cualquier fallo se investigará sin relajar las condiciones para aparentar éxito.

### Condición de cierre

La fase solo se considerará implementada cuando el nuevo contrato y todos sus consumidores estén integrados, pasen las verificaciones ejecutables disponibles y se haya demostrado el comportamiento real de éxito y abstención. La validación remota se informa por separado y solo tras observar su ejecución. Este plan no autoriza web, nuevas integraciones, publicación de paquetes, releases ni cambios en políticas de seguridad.
