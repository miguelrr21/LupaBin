from typing import Literal

FailureCode = Literal[
    "invalid_input",
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
]
MESSAGES: dict[FailureCode, str] = {
    "invalid_input": "No se pudo leer una entrada regular no vacía.",
    "input_limit": "La entrada supera el límite permitido.",
    "input_changed": "La entrada cambió durante la lectura; no se analizó.",
    "docker_unavailable": "El motor Docker Linux no está disponible; no se analizó en el host.",
    "image_unavailable": "La imagen local del worker no está disponible; no se descargó ninguna.",
    "timeout": "El análisis superó el tiempo permitido; no se puede afirmar un resultado completo.",
    "output_limit": "La respuesta superó el límite permitido; no se publican datos incompletos.",
    "invalid_worker_output": "La respuesta del worker no pudo validarse; no se publican sus datos.",
    "incompatible_worker": "El esquema del worker es incompatible; se requiere la imagen 0.2.0.",
    "worker_failure": "El worker falló; no se pudo determinar el resultado.",
    "cleanup_failure": "No se pudo confirmar la eliminación del contenedor de este análisis.",
}


class DissectError(Exception):
    def __init__(self, code: FailureCode):
        self.code = code
        super().__init__(MESSAGES[code])
