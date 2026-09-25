# Interfaz web de Dissect

Estado: revisión 1 (2026-09-25), implementada. Petición del usuario: "una web sin *slop* de IA, con una gama de colores azules al estilo de GTI y VirusTotal, preparada para desplegarla y usable por cualquier persona". El usuario decidió:
- Despliegue en su Raspberry Pi, primero en la red local; el dominio y HTTPS, más adelante.
- Web pública con límites.
- VirusTotal igual que en la CLI: consulta por hash y subida si no conoce el archivo, con aviso.
- Los PR se dejan abiertos, sin merge.

## 1. Qué es y qué no es

La web es otra forma de usar `dissect analyze`: sube un archivo, lo analiza en el mismo worker aislado y muestra el mismo informe didáctico. No añade análisis ni conclusiones, y no ejecuta la muestra. Todo lo que muestra sale de un `Report` validado y de una `Explanation` que se regenera y valida antes de enviarse; VirusTotal aparece aparte, como fuente externa.

## 2. Arquitectura

```text
navegador ──HTTP(S)──> Caddy (proxy, HTTPS con dominio) ──> dissect-web (host, 127.0.0.1:8080)
                                                                │  run_isolated(): un contenedor
                                                                │  nuevo por análisis, sin red,
                                                                ▼  solo lectura, con límites
                                                   dissect-worker:0.6.0 (Docker)
```

- **`dissect-web` corre en el host, no en un contenedor**, igual que la CLI. Usa `run_isolated` y el transporte de la CLI de Docker sin cambios, así que cada análisis sigue en un contenedor nuevo, sin red, de solo lectura, sin privilegios y con límites de memoria, CPU, procesos y tiempo. Descartado: ejecutar la web en un contenedor con el socket de Docker montado. Añadiría la CLI de Docker a la imagen y daría el mismo control sobre Docker, con más piezas.
- **Límite de confianza, dicho sin rodeos:** el usuario del servicio pertenece al grupo `docker`, que en la práctica equivale a root en esa máquina. La web no analiza la muestra (solo lee sus bytes, calcula hashes y los pasa al worker por stdin), pero un fallo en ella tendría ese alcance. Mitigaciones: el servicio escucha solo en `127.0.0.1`, systemd lo aísla (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`…) y las dependencias web son dos (Starlette y uvicorn), en un extra opcional que la imagen del worker no instala.
- **Sin estado:** las muestras solo están en memoria durante su análisis. No se guardan ni la muestra ni el informe; el navegador ofrece descargar el JSON y el Markdown desde la propia respuesta. uvicorn no escribe registro de accesos.

## 3. API

- `POST /api/analyze?virustotal=1&upload=1`, con el cuerpo en bruto (`application/octet-stream`), sin multipart. Así el límite de 20 MiB se aplica mientras llega el cuerpo, sin guardar nada en disco. El nombre del archivo no se envía.
  - Respuesta 200: `sample`, `status`, `summary` (tácticas, ítems y avisos), `notes`, `items` (observados e inferidos, con sus extras, límite, evidencias y glosario), `omitted`, `glossary` (solo las entradas usadas, con fuentes), `virustotal` (o `null`) y `downloads` (el informe JSON y el Markdown).
  - Errores: `{error, message}` con 400 (vacío), 413 (demasiado grande), 429 (límite por IP), 503 (ocupado o Docker no disponible) y 500 (fallo del worker), con los mensajes revisados de `errors.py`.
- `GET /api/health`: si el worker y la imagen están disponibles, sin analizar nada.
- `GET /` y `/static/*`: la página.

## 4. Límites de uso (web pública)

| Límite | Por defecto | Variable |
| --- | --- | --- |
| Tamaño de archivo | 20 MiB (el de `Limits`) | — |
| Análisis por IP | 6 cada 10 minutos | `DISSECT_WEB_RATE` (`6/600`) |
| Análisis a la vez | 1 (un worker usa hasta 512 MiB y 1 CPU; una Raspberry Pi tiene 4–8 GB) | `DISSECT_WEB_CONCURRENCY` |
| Espera en cola | 60 s; después, 503 "ocupado" | `DISSECT_WEB_QUEUE_SECONDS` |

La IP es la de la conexión, salvo con `DISSECT_WEB_TRUST_PROXY=1`: entonces se usa la última entrada de `X-Forwarded-For`, la que añade Caddy. Nunca la primera, porque esa la puede inventar el cliente.

## 5. VirusTotal

Como en la CLI (decisión del usuario): si hay clave (`VT_API_KEY`), se consulta por SHA-256 y, si VirusTotal no conoce el archivo, se sube. La página lo dice antes de enviar, junto al botón: el contenido subido puede compartirse con los clientes de pago de VirusTotal. Dos casillas, marcadas por defecto, permiten no consultar o no subir para ese análisis. `DISSECT_VIRUSTOTAL=off` y `DISSECT_VIRUSTOTAL_UPLOAD=off` lo desactivan para todo el servidor, y entonces las casillas no aparecen. La cuota de la clave es del dueño del servidor (la pública: 4 por minuto y 500 al día); agotarla se comunica como tal.

**Revisión 2 (2026-09-25), tras probarla el usuario:** con la subida marcada, la web esperaba hasta 3 minutos el análisis de VirusTotal antes de mostrar nada, y parecía colgada.

**Revisión 3 (2026-09-25), petición del usuario: "que muestre el informe, que se vea en otro lado que se está analizando en VirusTotal, y que se analice si se marca; menos fricción".**
- **Una sola casilla**, "Analizar también en VirusTotal": consulta por SHA-256 y, si VirusTotal no conoce el archivo, lo sube (con el aviso al lado). Si el servidor prohíbe subir, la casilla dice "Consultar VirusTotal por el SHA-256".
- **El informe sale en cuanto termina el worker.** `POST /api/analyze` ya no consulta VirusTotal.
- **La página consulta aparte:** `POST /api/virustotal?upload=1` (`client.submit`) busca el archivo y, si no lo conoce, lo sube sin esperar. La respuesta lleva el identificador del análisis de VirusTotal.
- **Se sigue ese análisis, no el hash:** la página llama cada 20 s (el límite de la API pública son 4 por minuto) a `GET /api/virustotal/{sha256}?analysis=<id>` (`client.follow`). Mientras VirusTotal no dé el análisis por completado responde "en cola"; al completarse, trae el resultado. Consultar solo por hash podía dar el archivo por encontrado antes de que terminara su análisis.
- **Estado visible en la cabecera del resultado**, fuera de las pestañas:
  - "consultando";
  - "archivo subido, lo está analizando (m:ss)";
  - al terminar, "N de M motores lo marcan como malicioso", en rojo o verde y con enlace al detalle;
  - pasados 15 minutos, "sigue analizándolo".
- **Límites por IP propios:** consultas, 5 veces el de los análisis; seguimiento, suficiente para 15 minutos cada 20 s.
- La CLI no cambia: sigue esperando hasta 3 minutos tras subir.

## 6. Seguridad de la página## 6. Seguridad de la página

- Todo texto que procede de la muestra o de VirusTotal pasa por `render.safe.visible` en el servidor (controles, bidi e invisibles como escapes visibles) y el navegador lo inserta **solo con `textContent`**: el JavaScript no usa `innerHTML` (un test lo comprueba).
- Cabeceras: CSP sin nada en línea (`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin` y `Permissions-Policy` restrictiva; la API responde con `Cache-Control: no-store`.
- Sin cookies, sin terceros, sin fuentes externas ni analítica.

## 7. Diseño visual

Una herramienta, no una página de marketing. Referencia: la densidad y la sobriedad de VirusTotal y Google Threat Intelligence.
- Paleta: barra superior azul marino (`#0b1f3f`), acento azul (`#1a5fd0`), fondos gris azulado muy claro (`#f3f6fa`), bordes finos (`#d5deea`) y texto casi negro azulado. Sin degradados, sombras difusas, ilustraciones, emojis ni frases de relleno. Modo oscuro con la misma gama si el sistema lo pide.
- Tipografía del sistema, y monoespaciada para hashes, RVA y valores.
- Resultado: una cabecera con los hashes, el estado y la puntuación de VirusTotal si la hay. Debajo, pestañas en el orden del informe: Resumen, Hechos, Inferencias, Cobertura, VirusTotal y Glosario. Cada ítem muestra su frase, sus casos, su límite y las evidencias que cita.
- Accesible: HTML semántico, foco visible, pestañas con roles ARIA y teclado, y contraste AA.

## 8. Despliegue (revisión 4: un VPS, no la Raspberry Pi)

El usuario descartó su Raspberry Pi: una web pública conectada a su red doméstica es un riesgo. Por eso el despliegue es un VPS dedicado, gratis o barato:
- Oracle Cloud Free Tier (ARM Ampere, gratuito);
- Hetzner CAX11 (unos 4 €/mes);
- cualquier otro VPS.

`deploy/server/install.sh` admite Ubuntu 22.04/24.04 y Debian 12, en x86_64 o ARM64. Todas las dependencias nativas del worker tienen ruedas para las dos arquitecturas. Además de lo descrito en la sección 2, el instalador:
- instala `unattended-upgrades`;
- ajusta los análisis simultáneos a la memoria y las CPU de la máquina;
- abre los puertos 80 y 443 si las reglas de iptables del sistema los rechazan, como en las imágenes de Ubuntu de Oracle.

La guía `docs/deploy.md` cubre el alta en los dos proveedores, un dominio gratuito de DuckDNS con HTTPS automático de Caddy y el endurecimiento básico del servidor.

**Cuota global de VirusTotal** (`virustotal/quota.py`). La API pública permite 4 peticiones por minuto y 500 al día por clave, sea cual sea el número de visitantes. Todas las peticiones de la web pasan por un presupuesto común:
- si el minuto está lleno, espera su turno (65 s como máximo);
- si se agota el día (en UTC), rechaza la petición antes de llegar a VirusTotal;
- la web explica que la cuota es compartida, y un seguimiento que encuentra la cuota ocupada sigue intentándolo.

`DISSECT_VT_PER_MINUTE` y `DISSECT_VT_PER_DAY` la adaptan a una clave con más cuota.

## 9. Verificación (2026-09-25)

- **Pruebas automáticas** (`tests/test_web.py`, 21), con el worker simulado de `test_runner` devolviendo los códigos de salida reales:
  - cabeceras de seguridad, página sin código en línea ni `innerHTML` o similares, e ids únicos;
  - análisis en el worker con la muestra por stdin, y resumen, ítems y descargas;
  - capacidades de la 5.4 en un x64;
  - texto hostil neutralizado;
  - subidas vacías o de más de 20 MiB que nunca llegan al worker;
  - errores de Docker y del worker con su mensaje revisado;
  - VirusTotal solo cuando se pide y la subida solo si el servidor la permite;
  - límite por IP y ventana deslizante, IP detrás de un proxy de confianza, cola llena y `/api/health`.
- **Prueba real en local** con el worker `dissect-worker:0.6.0` y la consulta a VirusTotal activa, sin subida:
  - la muestra de demostración, en 2,8 s;
  - `setupapi.dll` (4,6 MiB), en 7,4 s, con una respuesta de 8,4 MB y VirusTotal 0/74.
- **Revisión en Chrome.** Encontró y corrigió:
  - un id duplicado que dejaba vacía la pestaña de VirusTotal;
  - un aviso desactualizado sobre las capacidades de varias llamadas;
  - un margen que otra regla anulaba;
  - el 0 de "maliciosos" en rojo;
  - que un error al pintar se mostraba como error de red;
  - que el navegador mezclaba un HTML en caché con el JavaScript nuevo. Por eso la página y sus recursos se sirven con `Cache-Control: no-cache`.
- **Rendimiento de la página.** Las pestañas se pintan al abrirlas: con `setupapi.dll`, la página recién cargada tiene 142 nodos en lugar de casi 19.000.
- **ARM64.**
  - La imagen del worker se construye para `linux/arm64` y analiza la muestra de demostración, emulada, en 17 s.
  - En un Debian Bookworm ARM64 emulado, el paso del instalador que crea el entorno (uv 0.8.22 comprobado con SHA-256, Python 3.12 y el extra `web`) funciona y la aplicación arranca.
  - `bash -n` y shellcheck pasan sobre los scripts.
- **Instalador de servidor (revisión 4), probado de principio a fin** en un Ubuntu 24.04 x86_64 limpio con systemd, dentro de un contenedor privilegiado con Docker anidado:
  - instala todo y el servicio arranca;
  - una página y un análisis completo pasan por Caddy, el servicio y el worker, con las cabeceras de seguridad;
  - `systemd-analyze security` califica el servicio con una exposición de 3,2 ("OK");
  - `update.sh` se puede repetir y conserva la configuración;
  - con reglas de iptables como las de Oracle (todo rechazado salvo SSH), la web deja de responder, y el instalador abre el 80 y el 443 antes del REJECT y la recupera;
  - shellcheck pasa sobre los scripts.
- Queda por hacer el despliegue en el proveedor elegido (Oracle Cloud o Hetzner).
