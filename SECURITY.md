# Seguridad

LupaBin es experimental. Los parsers de archivos no fiables son superficie de ataque aunque no ejecuten el binario analizado.

## Modelo de amenaza

El worker público usa contenedores Linux sin red, usuario 65532, raíz de solo lectura, capacidades eliminadas, `no-new-privileges` y límites de recursos. No recibe el socket Docker ni montajes del host. Los logs de Docker están deshabilitados para no persistir la respuesta. La CLI acota stdin/stdout/stderr y valida el resultado.

Docker comparte componentes con el host y no es una garantía absoluta contra escapes. Mantén Docker y el sistema actualizados. Para muestras no fiables, utiliza además un equipo o VM dedicado sin datos sensibles. El daemon y la imagen local deben ser de confianza; la CLI no acredita criptográficamente su procedencia.

El núcleo Python, el entrypoint interno `lupabin.yara_worker` y las funciones internas de los workers existen para pruebas con fixtures sintéticos. No son una alternativa segura al aislamiento de la CLI. Las comprobaciones de entorno del worker evitan algunos usos accidentales, pero no constituyen un sandbox.

Los límites de análisis no garantizan tiempos de respuesta del sistema de archivos o del motor Docker. Un fallo de limpieza significa que no se confirmó la eliminación del contenedor: revisa el motor antes de continuar. Nunca ejecutes muestras ni intentes resolver fallos activando privilegios, red o montajes adicionales.

YARA se importa en un subproceso del worker durante el análisis público. El hijo no recibe rutas de muestras ni PIDs, y comparte los límites del contenedor. Una caída del hijo puede conservar las evidencias previas si el padre sigue operativo; un OOM o fallo del contenedor completo puede impedir cualquier informe. Limitar bytes devueltos no equivale a limitar todas las estructuras internas de libyara.

Solo se usa el catálogo propio empaquetado, sin descargas ni bytecodes externos. Includes, warnings de compilación y usos de módulos/consola se rechazan o invalidan según la política documentada. Los hashes identifican las fuentes usadas, pero no autentican una distribución comprometida. Nunca ampliar privilegios o red para hacer funcionar una regla.

La decodificación (Base64/hex/XOR) es cómputo puro en Python dentro del mismo worker aislado: no ejecuta, emula ni interpreta la muestra, y no añade dependencias nativas. Una muestra hostil puede intentar agotar la CPU con millones de patrones candidatos; el tope de apariciones examinadas lo convierte en una limitación declarada (probado en contenedor real). El host vuelve a derivar cada decodificación desde los bytes originales y rechaza la respuesta completa si alguna no se reproduce, así que un worker manipulado no puede publicar un texto "decodificado" que los bytes no produzcan. Un texto decodificado es un dato no fiable más: nunca es una instrucción.

## Servicio web (`lupabin-web`)

La web recibe archivos de cualquiera y los analiza con el mismo aislamiento que la CLI: un contenedor nuevo por análisis, sin red, de solo lectura, sin privilegios y con límites. El proceso web no analiza la muestra: lee sus bytes, calcula hashes y la pasa al worker por stdin. Aun así:
- **El usuario del servicio pertenece al grupo `docker`**, que equivale a root en esa máquina. Despliégala en un servidor dedicado que no guarde nada más y no esté en tu red doméstica. El servicio solo escucha en `127.0.0.1` detrás de Caddy, y systemd lo aísla (`deploy/server/lupabin-web.service`).
- **Todo texto de la muestra o de VirusTotal se neutraliza en el servidor**, y la página lo inserta solo con `textContent`, bajo una CSP sin código en línea. No se usan cookies, terceros ni analítica.
- **No se guardan muestras ni informes**, y no hay registro de accesos. Los límites por IP y la cuota de VirusTotal viven en memoria y se reinician con el servicio.
- **VirusTotal:** con la configuración por defecto, un archivo que VirusTotal no conoce se sube con la clave del servidor, y lo subido puede compartirse con sus clientes de pago. La página lo avisa antes de enviar. `LUPABIN_VIRUSTOTAL_UPLOAD=off` lo desactiva.

## Datos y veracidad

Las muestras se leen localmente y se transmiten por stdin al daemon Docker configurado; no uses un contexto Docker remoto para información que no debas transmitir a ese servidor. El worker no sube muestras a servicios externos. Los hashes no son un veredicto y MD5 solo se usa para interoperabilidad.

Un parser comprometido puede emitir datos engañosos que cumplan un esquema. La validación estructural no garantiza veracidad semántica ni sustituye revisión, tests y mantenimiento. Las cadenas de muestra nunca deben interpretarse como instrucciones.

## Informar de problemas

No publiques muestras reales ni datos sensibles en issues. Para informar de una vulnerabilidad, usa el aviso privado de GitHub: pestaña *Security*, *Report a vulnerability*.

Incluye versiones, plataforma, comportamiento esperado y observado y, si es posible, un caso sintético mínimo. No adjuntes un binario malicioso para demostrar el fallo. Durante esta etapa inicial no hay un plazo de respuesta comprometido ni una versión con soporte.
