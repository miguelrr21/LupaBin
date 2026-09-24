# Hoja de ruta y trabajo pendiente

Actualizado: 2026-09-25 (Fase 5 completa: entregas 5.1 a 5.7).

## Objetivo que guía todo lo siguiente

El usuario quiere que Dissect sea **lo más optimizado posible y con la tasa de error más baja posible**. Esto se traduce en reglas de trabajo:

1. **Primero la tasa de error, después la cobertura.** Una mejora que sube la cobertura pero añade un solo falso positivo en el corpus benigno no se adopta. Así se descartaron en la Fase 2 cinco variantes que subían la cobertura (sección 8 del diseño de la Fase 2).
2. **Nada sin medir.** Cada cambio de umbral, catálogo o algoritmo se mide antes de adoptarlo con `uv run python -m tests.decode_eval` (falsos positivos, cobertura y tiempo) y se registra en el diseño de su fase, incluidas las variantes descartadas.
3. **Rendimiento con cifras.** Se mide el peor caso de entrada (20 MiB) y el caso adversario, no solo el caso típico.
4. **Trabajo en bloques pequeños** y verificados de uno en uno, cada uno con su commit, para no dejar nada a medias si se corta una sesión.

## Estado actual

- **Fase 2 (decodificación, contrato 0.4.0, catálogo de anclas v3)**: cerrada. Está publicada en `master` mediante el PR #2 (2026-09-23), con la CI remota en verde en Ubuntu, Windows y Docker. Ruido medido: 0 en XOR y 0 en Base64/hex sobre un corpus benigno ampliado (System32, SysWOW64, drivers, .NET y Program Files: más de 30.000 archivos, unos 13 GB). Todas las decodificaciones encontradas se revisaron a mano y son auténticas. Diseño y mediciones: [Fase 2](superpowers/specs/2026-09-22-static-decoding-design.md).
- **Fase 3 (explicaciones didácticas y glosario con fuentes)**: cerrada. Publicada en `master` mediante el PR #3 (2026-09-23), con la CI remota en verde en Ubuntu, Windows y Docker. Incluye un glosario de 38 entradas con 75 fuentes verificadas, reglas deterministas regenerables para todos los tipos de hecho, contrato `Explanation` 0.1.0, renderizado de texto y Markdown que neutraliza el texto de la muestra, `dissect analyze` legible por defecto y `dissect explain` con contraste opcional contra la muestra. Hay dos cifras de contexto medidas en 55.000 binarios benignos: la entropía alta y la prevalencia de nueve familias de APIs. 447 tests y 11 pruebas en Docker real en verde. Diseño y mediciones: [Fase 3](superpowers/specs/2026-09-23-didactic-glossary-design.md).
- **Fase 4 (qué hace el código, en estático)**: cerrada. Se publica en `master` mediante el PR #5 (2026-09-24), con la CI remota en verde en Ubuntu, Windows y Docker antes del merge.
- **Fase 4, entrega 1 (versión reducida)**: Qué funciones importadas llama el código x86/x64 y desde qué instrucción (`api_call`, contrato 0.5.0), verificado por el propio informe y por el host sin desensamblador. Medido en 1.883 binarios benignos: 0 informes inválidos, 0 fallos de verificación y ninguna llamada falsa entre las señaladas para revisión. Con las tablas de Control Flow Guard y SafeSEH como puntos de partida, el 90,9 % de los imports por nombre en x86 y el 89,6 % en x64 tienen alguna llamada localizada (antes, 44,5 % en x86). La búsqueda XOR y el recorrido tienen tiempo máximo, para que una máquina lenta dé un informe parcial y no un timeout. La imagen `dissect-worker:0.5.0`, las 11 pruebas `-m docker` y los peores casos en el contenedor están comprobados en local. Cifras: [Fase 4, sección 9.4](superpowers/specs/2026-09-23-static-api-calls-design.md).
- **Fase 4, entrega 2 (argumentos constantes)**: las 72 funciones de la sección 4 del diseño (catálogo v4). `call_argument` (`inferred`) dice con qué clave predefinida, subclave y permisos se llama, citando la instrucción que fija cada valor. El informe lo vuelve a derivar desde los bytes y el host compara esos bytes con la muestra. Con `RegCreateKeyExA/W` (catálogo v2), medido en los mismos 1.883 binarios: 15.522 argumentos publicados, 0 informes inválidos y 0 fallos de bytes. Ninguna de las 5.077 claves recuperadas era errónea, y las dos revisiones manuales (30 argumentos por función) dieron 60 correctos. En x64 también se leen los argumentos de la pila (sección 11: 1.895 argumentos nuevos, 30 de 30 correctos en la revisión manual). `GetProcAddress` (catálogo v3) añade 13.436 nombres de función resueltos en tiempo de ejecución, con 30 de 30 correctos en la revisión manual y todos los rechazos comprobados como ordinales; una explicación los resume. El catálogo v4 completa la sección 4: 72.358 argumentos en el corpus. Ningún valor entero sale de sus conjuntos documentados por un error de seguimiento, ningún puntero rechazado señala algo que no sea el argumento, y 93 de 93 son correctos en la revisión manual. Una nota de cobertura (`code.walk_density@1`) pone en contexto un recorrido con poco código para el tamaño de sus secciones ejecutables: solo el 0,28 % de los binarios nativos benignos medidos con al menos 64 KiB de código se queda por debajo del umbral. Peores casos en el contenedor: 17,4 s de 30 como máximo. Cifras: [Fase 4, sección 10](superpowers/specs/2026-09-23-static-api-calls-design.md).
- **VirusTotal**: integrada en `master` mediante los PR #4 y #6 (2026-09-24). La consulta por hash está activa por defecto (revisión 2 del diseño). Si VirusTotal no conoce el archivo, se sube automáticamente con un aviso (revisión 3). `--no-virustotal`, `--no-upload-to-virustotal`, `DISSECT_VIRUSTOTAL=off` y `DISSECT_VIRUSTOTAL_UPLOAD=off` lo desactivan. Los resultados se muestran como fuente externa. Ver [su diseño](superpowers/specs/2026-09-23-virustotal-design.md).
- **Fase 5 (capacidades)**: completa. Entregas 5.1, 5.2, 5.3 y 5.5 en `master` (PR #8); 5.6 en el PR #9 y 5.4 en el PR siguiente, que parte de él (los PR se fusionan en ese orden). Trece capacidades de una sola llamada (clave `Run` y `Winlogon`, servicios, ejecución, descargas, destinos de red, agentes, memoria ejecutable y escribible, derechos sobre procesos, mover al reiniciar, mutex y criptografía), construidas como explicaciones que citan llamadas y argumentos ya verificados, con técnicas de MITRE ATT&CK solo donde el mecanismo coincide con su definición (T1547.001, T1543.003, T1059.003, T1059.001, T1105), su prevalencia benigna y un resumen que abre el informe. Medido en 3.087 binarios benignos: 0 informes inválidos, 0 fallos de verificación, 803 casos revisados a mano sin ninguna frase falsa. Cifras: [Fase 5, sección 9](superpowers/specs/2026-09-24-capabilities-design.md).
- Mantenimiento: todas las ramas de funcionalidad se borraron tras sus merges (la última limpieza, el 2026-09-24, tras los PR #4, #5 y #6); en GitHub solo queda `master`. `agent/` son las skills locales de *context-mode*, ignoradas en git. La rama `fiddler` pertenece a un worktree de Orca (`orca/workspaces/Dissect/fiddler`) y no se toca.

## Pendiente de la Fase 3

- [ ] **Revisión de contenido**: el glosario y los textos de las reglas se escribieron y verificaron con fuentes, pero conviene una lectura humana del tono didáctico.

## Límites conocidos de las explicaciones

- Las explicaciones son en español; la estructura admite otros idiomas (`lang`), pero no hay traducciones.
- Las familias de APIs solo reconocen imports por nombre exacto: los imports por ordinal (frecuentes en `ws2_32.dll`) no se asignan a ninguna familia.
- La entrada de glosario de una función concreta solo existe para las familias curadas. El resto de imports se explica con la entrada genérica de la tabla de imports.
- Las fuentes externas pueden moverse: `tests/check_glossary_sources.py` lo detecta, pero no forma parte de la CI.

## Límites conocidos de la decodificación y líneas de mejora

Cifras de la sección 8 del diseño de la Fase 2: 43 textos realistas, 150 pruebas por celda.

| Límite | Cifra actual | Por qué | Línea de mejora a investigar (medir falsos positivos antes) |
| --- | --- | --- | --- |
| Cadena aislada con clave de 8 bytes | 37 % ASCII / 62 % UTF-16LE | Una crib de *n* bytes solo verifica claves de hasta ~*n*−5 | Más anclas largas y neutrales, elegidas con un conjunto de evaluación independiente para no sobreajustar |
| Cadena con clave compartida de 8 bytes | 92 % (techo del conjunto: 86 % + ruido) | Ya en el techo: el resto no tiene crib | Solo mejora si baja la fracción de textos sin ancla (fila siguiente) |
| Textos sin ninguna crib | 0 % | Por diseño: sin ancla habría que puntuar plausibilidad | Con una clave ya verificada, descifrar texto sin crib solo si hay evidencia estructural extra (tabla de cadenas contigua, terminadores NUL cifrados); es el candidato de mayor ganancia y mayor riesgo |
| Rutas y registro | Rutas reales reservadas: ~45–50 % (claves de 1–4 bytes u 8 compartida; antes ~10 %); 6 % aisladas en ASCII con clave de 8 | Hecho en v3 (14 anclas de rutas). El techo sobre rutas reales es 50 %: la otra mitad no contiene ningún fragmento común | Anclas más largas (≥ 13 caracteres) para verificar solas claves de 8 bytes; elegirlas con la misma separación entrenamiento/reserva |
| Claves pequeñas que dejan el texto cifrado legible | 62 % frente a 77 % con clave ≥ 0x80 (1 byte) | Indistinguible de texto⊕texto sin puntuar | Buscar evidencia estructural, no puntuaciones |
| Transformaciones fuera de alcance | — | Base32, ROT/ADD/ROL, XOR rodante o incremental, RC4 con clave presente, compresión, claves de más de 8 bytes | Cada una requiere su propio diseño y medición |
| Rendimiento | Primera pasada: 3,3 s con 20 MiB; reutilización: 9,0 s en el peor caso (8 claves); análisis completo del peor caso en el contenedor: 10,3 s de 30 | Perfilado: una pasada de `bytes.find` por plan (453), ya a ~3 GB/s en C | Solo queda un buscador multipatrón nativo (dependencia compilada en el worker): requiere diseño propio. Variantes en Python puro medidas y descartadas en la sección 7 del diseño |

## Mejorar la propia evaluación

- **Corpus benigno más variado**: hecho con SysWOW64, drivers, .NET y Program Files (`--recursive --ext --stride --only`). Quedan instaladores y binarios empaquetados.
- **Textos de evaluación independientes** del catálogo, escritos por alguien que no diseñó las anclas, para medir la cobertura sin sesgo.
- Solo datos sintéticos o benignos: no descargar ni versionar malware real (`AGENTS.md`).

## Fases siguientes

Ninguna está aprobada ni diseñada. Cada una requiere su documento de diseño antes de escribir código:

- Interfaz web (`docker compose up` todavía es solo un worker de consola).
- **Fase 5, entrega 5.4, camino a) (hecha, contrato 0.6.0)**: la tabla `.pdata` (x64) se publica como `code_function`, y dos capacidades nuevas dicen que en el mismo rango de función el código abre `Run` o `Winlogon` para escribir y llama a `RegSetValueEx`. 5 casos en 3.087 binarios benignos, todos revisados por desensamblado: todas las escrituras usan la clave abierta (sección 11.5 del diseño). El camino b), seguir el identificador entre llamadas, sigue disponible si se quiere cubrir x86.
- **Fase 5, entrega 5.6 (más cobertura)**: hecha en el catálogo `dissect-capabilities-v2`: modificador de CFG en la memoria ejecutable y escribible (+13 casos, todos correctos), `RunOnceEx` bajo HKLM y escritura de valores en `Winlogon` con T1547.004 solo para `Shell`, `Userinit` y `Notify` (sección 10 del diseño). Queda sin solución segura la línea de órdenes de `CreateProcessW`, que está en memoria escribible.
- **Rendimiento de las explicaciones (hecho, 2026-09-25)**: varias reglas recorrían el informe entero por cada ítem. Ahora un índice por informe (por identidad del objeto, liberado con él) agrupa imports, llamadas y argumentos una sola vez. shell32.dll pasa de 14,34 s a 0,58 s, y las explicaciones de seis binarios de System32 (shell32, setupapi, notepad, kernel32, advapi32 y ndfapi) son idénticas byte a byte antes y después.
- **Más cobertura de la Fase 4**, midiendo que no añada errores: copias entre registros (`mov rcx, r15`), argumentos colocados con `mov [esp+x], …` (compiladores MinGW/GCC en x86) y cadenas construidas en la pila byte a byte, lo que hace FLOSS pero sin emular.
- Sandbox propio para análisis dinámico: pospuesto. Solo en una máquina dedicada con virtualización completa (el equipo del usuario tiene Windows 11 Home, sin Hyper-V), nunca en el worker Docker.
- **LLM barato como segundo revisor en caso de duda** (petición del usuario, 2026-09-23). Solo en el host, opcional y desactivado por defecto. Emite un documento `Review` aparte, cuyas opiniones citan explicaciones existentes y nunca se convierten en hechos. La arquitectura ya lo prevé: sección 9 del diseño de la Fase 3.
