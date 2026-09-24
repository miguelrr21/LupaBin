# Fixtures sintéticos

No hay malware real ni ejecutables versionados en este directorio.

El generador `tests/fixtures/pe_builder.py` construye bytes de cabeceras PE y tablas de importación con la biblioteca estándar de Python. Su código es original de Dissect y usa la licencia Apache-2.0 del proyecto. No copia ni descarga muestras externas.

Permite PE32/PE32+, tablas normales/retardadas, imports por nombre/ordinal y nombres arbitrarios para comprobar errores de decodificación. Los tests modifican copias en memoria para probar corrupción y límites. No hay una rutina de aplicación diseñada para ejecutarse; estos archivos solo son datos de prueba y no deben ejecutarse.

Desde la raíz del repositorio:

```text
uv run python -m tests.fixtures.pe_builder --output samples/practice.bin
```

La Fase 1A añade `--scenario demo`: dos secciones, un export, una URL literal del dominio reservado `.invalid` y una cadena UTF-16LE. Estos textos se han escrito deliberadamente como material de práctica; no provienen de malware ni acreditan actividad de red. `--scenario corrupt` recorta 64 bytes de ese mismo fixture para demostrar una sección incompleta y la abstención de lecturas que dependen de un mapa seguro.

```text
uv run python -m tests.fixtures.pe_builder --scenario demo --output samples/phase1a-complete.bin
uv run python -m tests.fixtures.pe_builder --scenario corrupt --output samples/phase1a-partial.bin
```

La Fase 1B incorpora `--scenario yara-limited`: parte del PE básico y añade veinte apariciones ASCII de `DISSECT PRACTICE` como datos. Con la cuota predeterminada de dieciséis instancias por regla, el informe indica cuatro omisiones. Para contrastar resultados YARA, `demo` contiene un marcador wide y `basic` no contiene los patrones suficientes para las cuatro reglas incluidas. Ninguno prueba capacidades maliciosas.

La Fase 2 incorpora `--scenario decode-demo`: el PE básico seguido de seis textos de práctica codificados con la biblioteca estándar: uno en Base64, uno en hexadecimal y cuatro cifrados con XOR (clave de 1 byte, clave de 4 bytes, una cadena UTF-16LE con clave de 2 bytes y una URL que reutiliza la clave de 4 bytes; su ancla `http://` es demasiado corta para verificar esa clave por sí sola, así que solo se recupera por reutilización de clave). Los textos usan el dominio reservado `.invalid` y contienen cadenas del catálogo de anclas solo para que el método pueda verificarlos; cifrarlos no los convierte en comportamiento ni imita malware. Las claves usan bytes `>= 0x80` y cada texto cifrado va entre terminadores NUL cifrados, para que el texto descifrado termine exactamente en sus límites.

```text
uv run python -m tests.fixtures.pe_builder --scenario decode-demo --output samples/decode-demo.bin
```

La Fase 5 incorpora `--scenario capability-demo` (solo x86): una única llamada a `RegSetKeyValueW` cuyos argumentos constantes son `HKEY_CURRENT_USER`, la subclave `Software\Microsoft\Windows\CurrentVersion\Run`, el nombre de valor inventado `DissectTraining` y `REG_SZ`. No hay datos del valor ni código que llegue a ejecutarse: sirve para ver cómo el informe reconoce la capacidad, le asocia T1547.001 y la sitúa en su contexto benigno.

```text
uv run python -m tests.fixtures.pe_builder --scenario capability-demo --output samples/capability-demo.bin
uv run --frozen dissect analyze samples/capability-demo.bin --no-virustotal
```

El generador exige una ruta nueva y no sobrescribe archivos. Los archivos `.bin`, `.exe` y `.dll` están ignorados por Git. Para analizar el fixture, usa la CLI después de construir y verificar el worker Docker; no lo abras como programa.
