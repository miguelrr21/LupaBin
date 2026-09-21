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

## Contenido educativo

El motor de glosario y capacidades pertenece a una fase posterior. Todavía no existe una ruta funcional para añadir capacidades mediante YAML; no se promete que un archivo de contenido aislado vaya a aparecer en el informe. Cuando se implemente, las contribuciones deberán incluir fuentes verificables, niveles de explicación y una separación explícita entre teoría y hechos de la muestra.
