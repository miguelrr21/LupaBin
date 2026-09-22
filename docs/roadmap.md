# Hoja de ruta y trabajo pendiente

Actualizado: 2026-09-22.

## Objetivo que guía todo lo siguiente

El usuario quiere que Dissect sea **lo más optimizado posible y con la tasa de error más baja posible**. Esto se traduce en reglas de trabajo:

1. **Primero la tasa de error, después la cobertura.** Una mejora que sube la cobertura pero añade un solo falso positivo en el corpus benigno no se adopta. Así se descartaron en la Fase 2 cinco variantes que subían la cobertura (sección 8 del diseño de la Fase 2).
2. **Nada sin medir.** Cada cambio de umbral, catálogo o algoritmo se mide antes de adoptarlo con `uv run python -m tests.decode_eval` (falsos positivos, cobertura y tiempo) y se registra en el diseño de su fase, incluidas las variantes descartadas.
3. **Rendimiento con cifras.** Se mide el peor caso de entrada (20 MiB) y el caso adversario, no solo el caso típico.
4. **Trabajo en bloques pequeños** y verificados de uno en uno, cada uno con su commit, para no dejar nada a medias si se corta una sesión.

## Estado actual

- **Fase 2 (decodificación, contrato 0.4.0)**: implementada y verificada en local. 360 tests y 10 pruebas en Docker real en verde; 0 falsos positivos XOR y 0 decodificaciones Base64/hex espurias en 4.516 archivos benignos de System32.
- Diseño y mediciones: [Fase 2](superpowers/specs/2026-09-22-static-decoding-design.md).

## Pendiente para cerrar la Fase 2

- [ ] **Publicar**: los commits de la Fase 2 están en `master` local, sin subir. Crear la rama `feat/static-decoding`, subirla y abrir el PR (mismo flujo que la Fase 1B). No hacer push directo a `master`.
- [ ] **CI remota**: comprobar que GitHub Actions pasa para esta fase. Hasta verlo, solo hay verificación local.
- [ ] **Limpieza**: borrar las ramas ya mergeadas `feat/static-evidence` y `feat/yara-evidence`, lo que requiere confirmación del usuario. Identificar qué es la carpeta sin versionar `agent/`, que no creó ninguna sesión de Claude.

## Límites conocidos de la decodificación y líneas de mejora

Cifras de la sección 8 del diseño de la Fase 2: 43 textos realistas, 150 pruebas por celda.

| Límite | Cifra actual | Por qué | Línea de mejora a investigar (medir falsos positivos antes) |
| --- | --- | --- | --- |
| Cadena aislada con clave de 8 bytes | 33 % ASCII / 57 % UTF-16LE | Una crib de *n* bytes solo verifica claves de hasta ~*n*−5 | Más anclas largas y neutrales, elegidas con un conjunto de evaluación independiente para no sobreajustar |
| Cadena con clave compartida de 8 bytes | 81 % (techo del conjunto: 77 % + ruido) | Ya en el techo: el resto no tiene crib | Solo mejora si baja la fracción de textos sin ancla (fila siguiente) |
| Textos sin ninguna crib | 0 % | Por diseño: sin ancla habría que puntuar plausibilidad | Con una clave ya verificada, descifrar texto sin crib solo si hay evidencia estructural extra (tabla de cadenas contigua, terminadores NUL cifrados); es el candidato de mayor ganancia y mayor riesgo |
| Rutas y registro | 41 % con clave compartida | La mayoría de rutas no contiene ninguna crib | Anclas de rutas comunes (`\Users\`, `%APPDATA%`, `\ProgramData\`), si pasan la medición |
| Claves pequeñas que dejan el texto cifrado legible | 62 % frente a 77 % con clave ≥ 0x80 (1 byte) | Indistinguible de texto⊕texto sin puntuar | Buscar evidencia estructural, no puntuaciones |
| Transformaciones fuera de alcance | — | Base32, ROT/ADD/ROL, XOR rodante o incremental, RC4 con clave presente, compresión, claves de más de 8 bytes | Cada una requiere su propio diseño y medición |
| Rendimiento | Primera pasada: 2,7 s con 20 MiB; reutilización: 5,7 s en el peor caso (8 claves) | Búsqueda de patrones en Python sobre diferenciales en C | Búsqueda multipatrón en una sola pasada; perfilar antes de optimizar |

## Mejorar la propia evaluación

- **Corpus benigno más variado** que System32: instaladores, binarios .NET, drivers, software de terceros. Un corpus más diverso da una cifra de falsos positivos más robusta.
- **Textos de evaluación independientes** del catálogo, escritos por alguien que no diseñó las anclas, para medir la cobertura sin sesgo.
- Solo datos sintéticos o benignos: no descargar ni versionar malware real (`AGENTS.md`).

## Fases siguientes (sin diseño todavía)

Ninguna está aprobada ni diseñada. Cada una requiere su documento de diseño antes de escribir código:

- Motor de glosario y capacidades didácticas (contenido con fuentes verificables).
- Interfaz web (`docker compose up` todavía es solo un worker de consola).
- capa, con verificación de que no emula; FLOSS solo sin sus rutas de emulación.
- VirusTotal, como integración opcional y separada del worker sin red.
- LLM, solo para redactar el glosario y nunca como fuente de hechos sobre la muestra.
