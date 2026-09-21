# Fixtures sintéticos

No hay malware real ni ejecutables versionados en este directorio.

El generador `tests/fixtures/pe_builder.py` construye bytes de cabeceras PE y tablas de importación con la biblioteca estándar de Python. Su código es original de Dissect y usa la licencia Apache-2.0 del proyecto. No copia ni descarga muestras externas.

Permite PE32/PE32+, tablas normales/retardadas, imports por nombre/ordinal y nombres arbitrarios para comprobar errores de decodificación. Los tests modifican copias en memoria para probar corrupción y límites. No hay una rutina de aplicación diseñada para ejecutarse; estos archivos solo son datos de prueba y no deben ejecutarse.

Desde la raíz del repositorio:

```text
uv run python -m tests.fixtures.pe_builder --output samples/practice.bin
```

El generador exige una ruta nueva y no sobrescribe archivos. Los archivos `.bin`, `.exe` y `.dll` están ignorados por Git. Para analizar el fixture, usa la CLI después de construir y verificar el worker Docker; no lo abras como programa.
