# Integración opcional con VirusTotal

Estado: revisión 1 (2026-09-23). Petición del usuario: "mandar a VirusTotal el binario mediante la API y que se encarguen ellos". Acordado ese mismo día: primero se consulta por hash, la subida es opcional y explícita, y los resultados se muestran como fuente externa. Un sandbox propio queda para más adelante.

## 1. Qué aporta y qué no

VirusTotal añade dos cosas que Dissect no puede obtener por sí mismo sin ejecutar la muestra:
- **Veredictos de motores antivirus**: cuántos marcan el archivo y con qué etiqueta.
- **Comportamiento observado en sus sandboxes**: procesos, comandos, archivos, registro, red, mutex, servicios y técnicas MITRE ATT&CK.

Nada de eso es un hecho verificado por Dissect. Una etiqueta es la opinión de un motor. El comportamiento se observó al ejecutar el archivo en máquinas de VirusTotal, en un entorno concreto y en un momento concreto. Por eso los resultados:
- van en un documento aparte (`VirusTotalReport`), nunca dentro del informe de hechos;
- se muestran en una sección propia, "Fuente externa: VirusTotal (no verificada por Dissect)";
- se presentan atribuidos ("N motores lo etiquetan…", "en los sandboxes de VirusTotal se observó…"), nunca como conclusiones de Dissect.

"VirusTotal no conoce este archivo" no significa nada sobre su peligrosidad.

## 2. Privacidad y condiciones

- **Por defecto solo se envía el SHA-256**, nunca el archivo. Si VirusTotal ya lo conoce, se obtiene todo sin subir nada.
- **Subir el archivo exige una opción explícita** (`--upload-to-virustotal`) y muestra un aviso. Según su documentación ("How it works"), el contenido de los archivos subidos puede compartirse con los clientes de pago de VirusTotal. Un documento o un binario interno no deben subirse.
- **No se envía la ruta ni el nombre local**: el archivo sube con el nombre genérico `sample`.
- **La clave de API se lee de la variable de entorno `VT_API_KEY`** o, si no existe, de un archivo `.env` en la carpeta de trabajo. Ese archivo está en `.gitignore`, el `.dockerignore` lo excluye de la imagen y el paquete no lo incluye; un test comprueba ambas reglas. La clave nunca aparece en la salida, en los errores ni en los informes.
- **API pública**: 500 peticiones al día y 4 por minuto, y no se puede usar en productos o servicios comerciales (documentación "Public vs Premium API"). Un error de cuota se comunica como tal.

## 3. Arquitectura

- Solo en el host. El worker sigue sin red: la integración no toca el análisis aislado.
- Cliente con la biblioteca estándar (`urllib`), sin dependencias nuevas:
  - solo `https://www.virustotal.com/api/v3/`, con verificación TLS;
  - sin seguir redirecciones;
  - con un tiempo máximo por petición y un tamaño máximo de respuesta.
- Peticiones:
  - `GET /files/{sha256}`;
  - `GET /files/{sha256}/behaviour_summary`;
  - con la opción de subida: `POST /files` (formulario, campo `file`, hasta 32 MB) y consultas a `GET /analyses/{id}` hasta que el análisis termine o venza una espera máxima. Entre consultas se espera lo suficiente para respetar el límite de 4 por minuto.
- La respuesta es un dato no fiable, igual que la muestra:
  - se extraen solo los campos esperados, con tipos comprobados y listas y textos acotados, y se declaran las omisiones;
  - todo texto pasa por la neutralización de la Fase 3 antes de mostrarse (un nombre de archivo en VirusTotal lo elige quien lo subió).

## 4. Documento `VirusTotalReport` 0.1.0

- **Identificación**: SHA-256 consultado, fecha de consulta y estado: `found`, `not_found`, `queued` (subido, análisis sin terminar) o `unavailable` (error, con motivo).
- **Estadísticas de motores** (`last_analysis_stats`) y los motores que marcan el archivo como malicioso o sospechoso, con su etiqueta. Se limitan a 100.
- **Metadatos**: nombre más significativo, nombres, tipo, fecha del primer envío y del último análisis, reputación, votos y etiquetas.
- **Veredictos de sandbox**: nombre, categoría, confianza y clasificación.
- **Comportamiento**: procesos creados, comandos, archivos escritos, borrados y soltados, claves de registro escritas, consultas DNS, tráfico IP, conversaciones HTTP, mutex, servicios creados y técnicas MITRE (id, descripción, gravedad). Cada lista se limita a 100 elementos y cada texto a 2.048 caracteres, y se declara lo omitido.
- **Enlace** a la ficha pública del archivo.

## 5. CLI

**Revisión 2 (2026-09-24), a petición del usuario: la consulta por hash es la opción por defecto.**
- `analyze` y `explain` consultan VirusTotal sin opciones.
- `--no-virustotal` lo desactiva para un análisis, y `DISSECT_VIRUSTOTAL=off` (también `0`, `no` o `false`) lo desactiva siempre.
- Con `--json` no se consulta: ese JSON es el informe de hechos.
- Sin clave no hay ninguna conexión: la sección explica cómo definirla o desactivar la consulta.
- La subida sigue exigiendo `--upload-to-virustotal` (cambiado en la revisión 3).
- Consecuencia para la privacidad: con una clave configurada, el SHA-256 de cada archivo analizado se envía a VirusTotal (el archivo no).
- Las pruebas fijan `DISSECT_VIRUSTOTAL=off` en `tests/conftest.py`, así que nunca llegan a la red aunque haya una clave en el equipo.

**Revisión 3 (2026-09-24), a petición del usuario: la subida también es automática.**
- Si VirusTotal no conoce el archivo, `analyze` y `dissect virustotal ARCHIVO` lo suben y esperan su análisis hasta 3 minutos.
- Antes se muestra un aviso en la salida de errores: lo subido puede compartirse con los clientes de pago de VirusTotal, y la subida se evita con `--no-upload-to-virustotal`.
- `DISSECT_VIRUSTOTAL_UPLOAD=off` la desactiva siempre, y `--no-virustotal` no consulta ni sube nada.
- La sección externa dice que Dissect subió el archivo y por qué.
- La subida sigue enviando el archivo con el nombre genérico `sample`, sin la ruta ni el nombre local.
- `tests/conftest.py` desactiva también la subida.

- `dissect analyze ARCHIVO`: el informe didáctico con una sección 5 de fuente externa (con `--virustotal` explícito si el valor por defecto está desactivado).
- `dissect analyze ARCHIVO --virustotal --upload-to-virustotal`: lo mismo, subiendo el archivo si VirusTotal no lo conoce.
- `dissect explain INFORME.json --virustotal`: consulta por el hash del informe, sin necesitar la muestra.
- `dissect virustotal ARCHIVO` o `dissect virustotal --sha256 HASH`: solo la consulta. `--format json` emite el documento.
- Un fallo de VirusTotal no invalida el análisis local: la sección externa dice por qué no hay datos, y el código de salida sigue siendo el del análisis. En `dissect virustotal`, un fallo sí termina con el código 1 y un error JSON.

## 6. Pruebas

Sin red en la CI: el cliente recibe la función de transporte, y las pruebas usan respuestas sintéticas con la estructura documentada. Casos cubiertos:
- archivo encontrado, no encontrado, cuota agotada, clave inválida o ausente;
- respuesta enorme, JSON inválido y campos de tipo inesperado;
- redirección rechazada;
- subida solo con la opción explícita y sin el nombre local;
- espera del análisis en cola;
- ausencia de la clave en cualquier salida;
- neutralización de textos hostiles en la sección renderizada.

Una prueba real con clave se deja como comando manual.
