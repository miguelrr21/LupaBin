# LupaBin

Tutor de análisis estático de ejecutables de Windows. LupaBin lee un archivo PE sin ejecutarlo nunca, dice qué contienen sus bytes y explica cada afirmación: qué evidencia la respalda, qué no demuestra y dónde leer más. No es un antivirus y no da veredictos.

Creado por [Miguel Ángel Rodríguez Romero](https://github.com/miguelrr21). *English overview: [README.en.md](README.en.md).*

**Si no hay evidencia suficiente, no se afirma.** Cada método se midió en binarios benignos antes de adoptarlo, incluidas las variantes que se descartaron, y las cifras están en [cómo trabaja LupaBin](docs/metodo.md).

## Qué hace

- **Hechos de los bytes**, obtenidos en un contenedor Docker sin red: hashes, cabeceras y secciones PE32/PE32+, entropía, importaciones y exportaciones, anomalías estructurales, marcas de compilador (Microsoft, GCC y MinGW-w64, Go, .NET, PyInstaller), cadenas, reglas YARA propias y decodificación acotada (Base64, hexadecimal y XOR anclado en texto conocido).
- **Qué llama el código.** Un recorrido del código x86/x64 encuentra qué funciones importadas se llaman, desde dónde y con qué argumentos constantes, en 72 funciones de Windows (claves de registro, servicios, líneas de órdenes, URL, permisos de memoria…). En los programas que arrancan con `__getmainargs`, como los de MinGW-w64, separa lo que se alcanza desde `main` de lo que solo hace el arranque del compilador.
- **Capacidades**: frases como «el código contiene 1 llamada que escribe en una clave de arranque automático (Run)», con la técnica de MITRE ATT&CK solo cuando el mecanismo coincide con su definición y con su frecuencia en 3.090 binarios benignos.
- **Programas empaquetados con UPX 5**: descomprime el bloque sin ejecutarlo y muestra las secciones, el punto de entrada y las funciones importadas que esconde.
- **VirusTotal**, como fuente externa separada de los hechos, con el significado documentado de algunas etiquetas y el contraste de sus técnicas con las capacidades observadas.
- **Para aprender**: explicaciones que citan cada evidencia, un glosario con fuentes, preguntas de práctica autocorregibles sobre el propio informe y exportación de las evidencias a Ghidra.

Ningún resultado se da por bueno porque lo diga el worker: el host vuelve a comprobar con los bytes de la muestra cada llamada, argumento, decodificación, marca, coincidencia YARA y bloque UPX, y cada frase del informe se regenera desde sus citas antes de mostrarse.

## Ejemplo

Fragmento del informe de un fixture sintético (`--scenario capability-demo`):

```text
Resumen: qué contiene el código
   Persistencia
   X10    El código contiene 1 llamada de este tipo: escribir un valor en una clave de arranque
          automático (Run). Ninguno de los 3.090 binarios benignos medidos contiene un caso.
          Técnicas de MITRE ATT&CK con el mismo mecanismo: T1547.001 (Boot or Logon Autostart
          Execution: Registry Run Keys / Startup Folder)
...
   X1   El archivo es PE32 (32 bits, máquina x86, 0x014c). Declara el punto de entrada en la RVA
        0x00002000 y un tamaño de imagen de 12.288 bytes.
        Límite: Son valores declarados por el archivo: no garantizan que Windows lo cargue así ni
          dicen nada de lo que hace el programa.
        Evidencia: E1 · Glosario: pe.format, pe.header
```

## Inicio rápido

Requisitos: Python 3.12, [uv](https://docs.astral.sh/uv/) y Docker con motor Linux (en Windows, Docker Desktop en modo Linux).

```text
uv sync --frozen
docker build --load -f docker/Dockerfile -t lupabin-worker:0.12.0 .
uv run --frozen lupabin analyze "ruta/al/archivo.exe"
```

Por defecto se muestra el informe didáctico; `--markdown` lo da en Markdown y `--json`, el informe de hechos validado ([contrato](docs/evidence-schema.md)). Un informe guardado se explica de nuevo con `lupabin explain informe.json --sample archivo.exe`, que vuelve a contrastarlo con la muestra. Códigos de salida: 0 completo, 3 parcial, 1 fallo, 2 uso incorrecto.

Para practicar sin aportar un binario, el generador crea archivos sintéticos e inofensivos (no los ejecutes):

```text
uv run python -m tests.fixtures.pe_builder --scenario capability-demo --output samples/demo.bin
uv run --frozen lupabin analyze samples/demo.bin --no-virustotal
```

Otros escenarios: `demo`, `decode-demo`, `toolchain-demo` y `upx-demo` ([procedencia de los fixtures](samples/README.md)).

## VirusTotal

Con una clave de API en `VT_API_KEY` (o en un archivo `.env`, ignorado por git), `analyze` añade los resultados de VirusTotal como fuente externa: detecciones, veredictos de sus sandboxes y el comportamiento que observaron. Todo ocurre en el host; el worker sigue sin red.

Si VirusTotal no conoce el archivo, **LupaBin lo sube** con el nombre genérico `sample`. Lo subido puede compartirse con los clientes de pago de VirusTotal: para archivos confidenciales usa `--no-upload-to-virustotal`, o `LUPABIN_VIRUSTOTAL_UPLOAD=off` para no subir nunca. `--no-virustotal` o `LUPABIN_VIRUSTOTAL=off` desactivan la consulta. Una etiqueta es la opinión de un motor, y que VirusTotal no conozca un archivo no dice nada de él. [Más detalle](docs/metodo.md#virustotal).

## Web, Ghidra y práctica

- **Web:** `uv sync --extra web` y `uv run lupabin-web` (en `http://127.0.0.1:8080`) sirven el mismo análisis aislado en el navegador, sin guardar muestras ni informes. Para un servidor dedicado: `deploy/server/` (systemd y Caddy).
- **Ghidra:** `lupabin export-ghidra informe.json --sample archivo.exe --output evidencias.zip` genera un JSON y un script que, en Ghidra, comprueba el SHA-256, muestra una revisión previa y añade las evidencias como comentarios sin tocar tus anotaciones. [Detalles](docs/metodo.md#exportación-a-ghidra).
- **Práctica:** `lupabin challenge informe.json --practice`, o *Practicar con este informe* en la web, plantea preguntas tipo test sobre el propio informe y las corrige citando las evidencias. [Detalles](docs/metodo.md#retos-autocorregibles).

## Seguridad

Las muestras nunca se ejecutan ni se emulan. Los parsers corren en un contenedor sin red, con raíz de solo lectura, sin privilegios y con límites de recursos; el host valida todo lo que recibe. En el repositorio solo hay fixtures sintéticos: no envíes malware real. Modelo de amenaza y cómo informar de vulnerabilidades: [SECURITY.md](SECURITY.md).

## Desarrollo

```text
uv run --frozen ruff format --check .
uv run --frozen ruff check .
uv run --frozen mypy src
uv run --frozen pytest -m "not docker"
uv run --frozen pytest -m docker
node --test tests/test_web_vt.cjs tests/test_web_challenge.cjs tests/test_web_ghidra.cjs
```

Las pruebas de la web necesitan Node.js 22 o posterior, sin paquetes npm. La CI ejecuta además las comprobaciones de los esquemas, el build y la distribución del catálogo YARA; tras cambiar los modelos, los esquemas se regeneran con `uv run python -m lupabin.evidence.schema` y `uv run python -m lupabin.explain.schema`. Las mediciones sobre binarios benignos se repiten con las herramientas `tests/*_eval.py` ([cómo](docs/metodo.md#repetir-las-mediciones)).

## Contribuir y licencia

Lee [CONTRIBUTING.md](CONTRIBUTING.md) y el [código de conducta](CODE_OF_CONDUCT.md). LupaBin se distribuye con la licencia [Apache-2.0](LICENSE): puedes usarlo, modificarlo y redistribuirlo conservando el archivo [NOTICE](NOTICE). El nombre y el logo están reservados ([TRADEMARKS.md](TRADEMARKS.md)) y las contribuciones requieren aceptar el [acuerdo de contribución](CLA.md).
