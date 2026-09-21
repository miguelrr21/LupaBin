# ADR 001: conservar los imports originales

Estado: adoptado en la primera entrega.

## Contexto

pefile 2024.8.26, en `parse_import_directory`, sustituye algunos nombres de DLL no válidos por `*invalid*` y puede resolver nombres de funciones mediante una tabla auxiliar de ordinales. Esos textos no necesariamente están presentes en la muestra. Además, ciertos errores se comunican mediante warnings o resultados parciales.

## Decisión

Usar pefile con `fast_load=True` para las cabeceras y validar sus límites. Recorrer las tablas normales y retardadas directamente sobre regiones acotadas del buffer original. Conservar ordinales como ordinales, nombres como bytes hexadecimales y texto solo cuando decodifica estrictamente como ASCII. Registrar la ubicación del thunk, no inventar una dirección de la función importada.

Toda advertencia del parsing de cabeceras impide marcar el análisis completo. Un error de tabla conserva únicamente las entradas anteriores validadas y comunica cobertura parcial. Los formatos o disposiciones ambiguos se rechazan antes de completar nombres o ubicaciones por heurística.

## Consecuencias

El extractor es deliberadamente conservador y puede abstenerse ante PE inusuales que otra herramienta acepte. Mantener un lector pequeño exige pruebas específicas de límites, ordinales, imports retardados y corrupción. No se usa el parsing de imports de pefile como fuente de nombres observados.
