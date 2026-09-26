from typing import Literal

FailureCode = Literal[
    "invalid_input",
    "input_not_found",
    "input_not_file",
    "input_permission",
    "input_empty",
    "input_limit",
    "input_changed",
    "docker_unavailable",
    "image_unavailable",
    "timeout",
    "output_limit",
    "invalid_worker_output",
    "incompatible_worker",
    "worker_failure",
    "cleanup_failure",
    "invalid_report",
    "report_mismatch",
    "glossary_invalid",
]
MESSAGES: dict[FailureCode, str] = {
    "invalid_input": "No se pudo leer una entrada regular no vacía.",
    "input_not_found": (
        "No existe ningún archivo en esa ruta. Comprueba la ruta; si contiene espacios, "
        "escríbela entre comillas."
    ),
    "input_not_file": "La ruta no es un archivo normal (por ejemplo, es una carpeta).",
    "input_permission": "No hay permiso para leer ese archivo.",
    "input_empty": "El archivo está vacío: no hay nada que analizar.",
    "input_limit": "La entrada supera el límite permitido.",
    "input_changed": "La entrada cambió durante la lectura; no se analizó.",
    "docker_unavailable": "El motor Docker Linux no está disponible; no se analizó en el host.",
    "image_unavailable": "No se pudo verificar lupabin-worker:0.9.0; no se descargaron imágenes.",
    "timeout": "El análisis superó el tiempo permitido; no se puede afirmar un resultado completo.",
    "output_limit": "La respuesta superó el límite permitido; no se publican datos incompletos.",
    "invalid_worker_output": "La respuesta del worker no pudo validarse; no se publican sus datos.",
    "incompatible_worker": "Esquema o catálogo incompatible; reconstruye lupabin-worker:0.9.0.",
    "worker_failure": "El worker falló; no se pudo determinar el resultado.",
    "cleanup_failure": "No se pudo confirmar la eliminación del contenedor de este análisis.",
    "invalid_report": "El informe no se pudo leer o no es un informe 0.9.0 válido.",
    "report_mismatch": "El informe no coincide con la muestra indicada; no se explica.",
    "glossary_invalid": "El glosario instalado no supera su validación; no se explica el informe.",
}


class LupaBinError(Exception):
    def __init__(self, code: FailureCode):
        self.code = code
        super().__init__(MESSAGES[code])
