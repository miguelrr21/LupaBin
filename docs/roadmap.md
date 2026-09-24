# Hoja de ruta y trabajo pendiente

Actualizado: 2026-09-23.

## Objetivo que guía todo lo siguiente

El usuario quiere que Dissect sea **lo más optimizado posible y con la tasa de error más baja posible**. Esto se traduce en reglas de trabajo:

1. **Primero la tasa de error, después la cobertura.** Una mejora que sube la cobertura pero añade un solo falso positivo en el corpus benigno no se adopta. Así se descartaron en la Fase 2 cinco variantes que subían la cobertura (sección 8 del diseño de la Fase 2).
2. **Nada sin medir.** Cada cambio de umbral, catálogo o algoritmo se mide antes de adoptarlo con `uv run python -m tests.decode_eval` (falsos positivos, cobertura y tiempo) y se registra en el diseño de su fase, incluidas las variantes descartadas.
3. **Rendimiento con cifras.** Se mide el peor caso de entrada (20 MiB) y el caso adversario, no solo el caso típico.
4. **Trabajo en bloques pequeños** y verificados de uno en uno, cada uno con su commit, para no dejar nada a medias si se corta una sesión.

## Estado actual

- **Fase 2 (decodificación, contrato 0.4.0, catálogo de anclas v3)**: cerrada. Está publicada en `master` mediante el PR #2 (2026-09-23), con la CI remota en verde en Ubuntu, Windows y Docker. Ruido medido: 0 en XOR y 0 en Base64/hex sobre un corpus benigno ampliado (System32, SysWOW64, drivers, .NET y Program Files: más de 30.000 archivos, unos 13 GB). Todas las decodificaciones encontradas se revisaron a mano y son auténticas. Diseño y mediciones: [Fase 2](superpowers/specs/2026-09-22-static-decoding-design.md).
- **Fase 3 (explicaciones didácticas y glosario con fuentes)**: implementada y verificada en local en la rama `feat/didactic-glossary`, sin publicar todavía. Incluye un glosario de 38 entradas con 75 fuentes verificadas, reglas deterministas regenerables para todos los tipos de hecho, contrato `Explanation` 0.1.0, renderizado de texto y Markdown que neutraliza el texto de la muestra, `dissect analyze` legible por defecto y `dissect explain` con contraste opcional contra la muestra. Hay dos cifras de contexto medidas en 55.000 binarios benignos: la entropía alta y la prevalencia de nueve familias de APIs. 447 tests y 11 pruebas en Docker real en verde. Diseño y mediciones: [Fase 3](superpowers/specs/2026-09-23-didactic-glossary-design.md).
- **Fase 4, entrega 1 (versión reducida)**: implementada y verificada en local en la rama `feat/static-api-calls`, sin publicar. Qué funciones importadas llama el código x86/x64 y desde qué instrucción (`api_call`, contrato 0.5.0), verificado por el propio informe y por el host sin desensamblador. Medido en 1.883 binarios benignos: 0 informes inválidos, 0 fallos de verificación y ninguna llamada falsa entre las señaladas para revisión. Con las tablas de Control Flow Guard y SafeSEH como puntos de partida, el 90,9 % de los imports por nombre en x86 y el 89,6 % en x64 tienen alguna llamada localizada (antes, 44,5 % en x86). La búsqueda XOR y el recorrido tienen tiempo máximo, para que una máquina lenta dé un informe parcial y no un timeout. Pendiente: imagen `dissect-worker:0.5.0`, pruebas `-m docker`, peor caso en el contenedor y publicación con autorización. Cifras: [Fase 4, sección 9.4](superpowers/specs/2026-09-23-static-api-calls-design.md).
- **Fase 4, entrega 2 (argumentos constantes)**: implementada para `RegOpenKeyExA/W` y `RegCreateKeyExA/W` en la misma rama, sin publicar. `call_argument` (`inferred`) dice con qué clave predefinida, subclave y permisos se llama, citando la instrucción que fija cada valor. El informe lo vuelve a derivar desde los bytes y el host compara esos bytes con la muestra. Con `RegCreateKeyExA/W` (catálogo v2), medido en los mismos 1.883 binarios: 15.522 argumentos publicados, 0 informes inválidos y 0 fallos de bytes. Ninguna de las 5.077 claves recuperadas era errónea, y las dos revisiones manuales (30 argumentos por función) dieron 60 correctos. Pendiente: el resto del catálogo de la sección 4, una función por cambio y con su firma comprobada. Peores casos en el contenedor: 17,4 s de 30 como máximo. Cifras: [Fase 4, sección 10](superpowers/specs/2026-09-23-static-api-calls-design.md).
- Mantenimiento: las ramas `feat/static-evidence` y `feat/yara-evidence` se borraron tras sus merges. `agent/` son las skills locales de *context-mode*, ignoradas en git. La rama `fiddler` pertenece a un worktree de Orca (`orca/workspaces/Dissect/fiddler`) y no se toca.

## Pendiente para cerrar la Fase 3

- [ ] **Publicar**: subir `feat/didactic-glossary`, abrir el PR y comprobar la CI remota (requiere autorización del usuario).
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

## Fases siguientes (sin diseño todavía)

Ninguna está aprobada ni diseñada. Cada una requiere su documento de diseño antes de escribir código:

- Interfaz web (`docker compose up` todavía es solo un worker de consola).
- **Fase 4 (siguiente, petición del usuario del 2026-09-23): qué hace el programa, en estático.** El usuario quiere que Dissect "analice en estático el binario y diga exactamente lo que hace". Eso es análisis de capacidades a partir del código: desensamblar las funciones, seguir las llamadas a APIs y sus argumentos constantes, y reconocer patrones (por ejemplo, "crea un servicio con este nombre" o "escribe esta clave de registro"). Candidatos: capa (reglas de capacidades de Mandiant sobre desensamblado, verificando que no emula) y un desensamblador acotado dentro del worker. Límites que el diseño debe aceptar de partida:
  - Lo que se puede afirmar es "el código contiene una ruta que llama a X con estos argumentos", no "el programa lo hará". Si esa ruta se ejecuta depende de condiciones, entradas y entorno que el análisis estático no resuelve en general.
  - Un binario empaquetado o cifrado solo muestra su desempaquetador hasta desempaquetarlo, y eso exige emulación o ejecución, que están prohibidas. En ese caso Dissect debe decirlo y abstenerse, no adivinar.
  - Cada capacidad debe citar las direcciones y bytes de código que la respaldan, con la misma regla de "citar no basta" y una medición de falsos positivos sobre binarios benignos antes de adoptarla.
- FLOSS solo sin sus rutas de emulación (probablemente dentro de la Fase 4 o después).
- VirusTotal, como integración opcional y separada del worker sin red.
- **LLM barato como segundo revisor en caso de duda** (petición del usuario, 2026-09-23). Solo en el host, opcional y desactivado por defecto. Emite un documento `Review` aparte, cuyas opiniones citan explicaciones existentes y nunca se convierten en hechos. La arquitectura ya lo prevé: sección 9 del diseño de la Fase 3.
