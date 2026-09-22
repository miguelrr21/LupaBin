# Seguridad

Dissect es experimental. Los parsers de archivos no fiables son superficie de ataque aunque no ejecuten el binario analizado.

## Modelo de amenaza

El worker público usa contenedores Linux sin red, usuario 65532, raíz de solo lectura, capacidades eliminadas, `no-new-privileges` y límites de recursos. No recibe el socket Docker ni montajes del host. Los logs de Docker están deshabilitados para no persistir la respuesta. La CLI acota stdin/stdout/stderr y valida el resultado.

Docker comparte componentes con el host y no es una garantía absoluta contra escapes. Mantén Docker y el sistema actualizados. Para muestras no fiables, utiliza además un equipo o VM dedicado sin datos sensibles. El daemon y la imagen local deben ser de confianza; la CLI no acredita criptográficamente su procedencia.

El núcleo Python, el entrypoint interno `dissect.yara_worker` y las funciones internas de los workers existen para pruebas con fixtures sintéticos. No son una alternativa segura al aislamiento de la CLI. Las comprobaciones de entorno del worker evitan algunos usos accidentales, pero no constituyen un sandbox.

Los límites de análisis no garantizan tiempos de respuesta del sistema de archivos o del motor Docker. Un fallo de limpieza significa que no se confirmó la eliminación del contenedor: revisa el motor antes de continuar. Nunca ejecutes muestras ni intentes resolver fallos activando privilegios, red o montajes adicionales.

YARA se importa en un subproceso del worker durante el análisis público. El hijo no recibe rutas de muestras ni PIDs, y comparte los límites del contenedor. Una caída del hijo puede conservar las evidencias previas si el padre sigue operativo; un OOM o fallo del contenedor completo puede impedir cualquier informe. Limitar bytes devueltos no equivale a limitar todas las estructuras internas de libyara.

Solo se usa el catálogo propio empaquetado, sin descargas ni bytecodes externos. Includes, warnings de compilación y usos de módulos/consola se rechazan o invalidan según la política documentada. Los hashes identifican las fuentes usadas, pero no autentican una distribución comprometida. Nunca ampliar privilegios o red para hacer funcionar una regla.

## Datos y veracidad

Las muestras se leen localmente y se transmiten por stdin al daemon Docker configurado; no uses un contexto Docker remoto para información que no debas transmitir a ese servidor. El worker no sube muestras a servicios externos. Los hashes no son un veredicto y MD5 solo se usa para interoperabilidad.

Un parser comprometido puede emitir datos engañosos que cumplan un esquema. La validación estructural no garantiza veracidad semántica ni sustituye revisión, tests y mantenimiento. Las cadenas de muestra nunca deben interpretarse como instrucciones.

## Informar de problemas

No publiques muestras reales ni datos sensibles en issues. Mientras no haya un canal privado de seguridad confirmado para el repositorio, contacta al responsable por un canal privado previamente acordado antes de compartir detalles. No se inventa aquí una dirección de contacto ni se asume que GitHub Private Vulnerability Reporting esté habilitado.

Incluye versiones, plataforma, comportamiento esperado/observado y un caso sintético mínimo, si es posible. No adjuntes un binario malicioso para demostrar el fallo. No se declara un plazo de respuesta ni una versión de producción soportada durante esta etapa inicial.
