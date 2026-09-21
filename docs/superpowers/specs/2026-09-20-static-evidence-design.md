# Fase 1A: evidencias estáticas básicas ampliadas

Estado: propuesta de diseño para revisión. El alcance ha sido aceptado; este documento todavía no autoriza la implementación. El motor actual sigue usando el contrato 0.1.0.

## 1. Propósito y resultado para el usuario

Dissect debe enseñar a observar un binario antes de atribuirle comportamientos. Esta ampliación permitirá consultar secciones, medidas de entropía, cabeceras, exports y cadenas literales junto con los imports existentes. Cada dato tendrá una ubicación verificable y una descripción de lo que se pudo revisar.

Se mantiene la prioridad explícita del usuario: abstenerse antes que inventar datos. No se ejecuta ni emula la muestra; no se usa un LLM, red ni código de la muestra para producir hallazgos.

El resultado visible seguirá siendo JSON mediante `dissect analyze <archivo> --json`. No habrá todavía web, informe narrativo ni clasificación de malware. Al terminar la implementación se mostrará una demostración real y un cierre que explique cada cambio, su fundamento y qué prepara para el futuro.

## 2. Alcance y alternativas

Se incluyen siete tipos de evidencia: `import` existente y nuevos `pe_header`, `section`, `entropy`, `export`, `string`, `header_anomaly`.

Alternativas consideradas:

- **Ampliación progresiva del núcleo actual, elegida:** pefile para cabeceras, lectura acotada de tablas y algoritmos pequeños de biblioteca estándar. Conserva la trazabilidad sin añadir dependencias.
- **Integrar primero YARA/capa/FLOSS:** aporta reglas y capacidades, pero añade dependencias, licencias, políticas de ejecución y nuevas interpretaciones antes de completar la observación básica. Queda para el siguiente bloque.
- **Construir primero la web sobre imports:** hace visible la interfaz, pero no amplía lo que Dissect puede enseñar sobre la muestra. No es el orden acordado.

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

Se conservará el JSON Schema 0.1.0 como referencia histórica en `docs/schemas/0.1.0.json`. El esquema activo `docs/evidence-schema.json` se regenerará desde los modelos 0.2.0 durante la implementación. No se modificarán ahora los modelos ni el esquema generado.

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

Fundamentos: brief original, prioridad de veracidad indicada por el usuario, contrato 0.1.0, código actual y especificación oficial [PE Format de Microsoft](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). Las decisiones sobre secciones, RVA, tablas de exportación y significado limitado de timestamps se apoyan en esa especificación. Los límites de producto y de cadenas son decisiones conservadoras de Dissect, no propiedades universales del formato.

La entropía usa una medida matemática de distribución de bytes; su utilidad educativa no autoriza inferencias de peligrosidad. Las cadenas son patrones literales definidos por una política explícita, no resultados de ejecución ni desofuscación.

Esta base prepara las integraciones YARA/capa, la decodificación estática acotada y las plantillas didácticas con citas. Después podrán llegar los renderers y la web. Ninguna de esas funciones se considera implementada por aprobar este diseño.

La implementación se realizará en la rama `feat/static-evidence`, con commits pequeños y PR de fase cuando se autorice publicar. Este documento requiere revisión del usuario antes de redactar y aprobar el plan de implementación; no cambia el motor por sí mismo.
