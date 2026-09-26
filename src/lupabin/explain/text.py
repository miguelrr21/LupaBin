"""Reviewed Spanish wording for sources, components and report codes."""

from lupabin.evidence.facts import LocalLinkEvidence
from lupabin.evidence.primitives import Component, Name, Source

SOURCES: dict[Source, str] = {
    "pe": "Estructura PE",
    "strings": "Cadenas",
    "yara": "Reglas YARA",
    "decode": "Decodificación",
    "code": "Código",
}

COMPONENTS: dict[Component, str] = {
    "headers": "cabeceras",
    "sections": "secciones",
    "entropy": "entropía",
    "imports_normal": "imports",
    "imports_delay": "imports retardados",
    "exports": "exports",
    "anomalies": "anomalías estructurales",
    "toolchain": "marcas de compilador",
    "ascii": "cadenas ASCII",
    "utf16le": "cadenas UTF-16LE",
    "yara_rules": "catálogo de reglas",
    "yara_scan": "búsqueda de reglas",
    "yara_evidence": "coincidencias",
    "decode_strings": "Base64 y hexadecimal",
    "decode_xor": "XOR",
    "disassembly": "recorrido del código",
    "api_calls": "llamadas a funciones importadas",
    "string_references": "textos que usa el código",
    "main_function": "función main",
    "call_arguments": "argumentos constantes de las llamadas",
}

STATUSES = {
    "complete": "completo",
    "partial": "parcial: solo se revisó una parte",
    "blocked": "bloqueado: no se pudo revisar",
}

# Every ErrorCode and YaraReason has exactly one message (a test enforces it).
MESSAGES: dict[str, str] = {
    "invalid_pe": (
        "El archivo parece PE, pero su estructura no es válida, así que no se pudo analizar "
        "como PE."
    ),
    "unsupported_format": (
        "El archivo no tiene formato PE, así que no hay información de estructura PE."
    ),
    "extractor_failure": (
        "El extractor falló de forma inesperada y su resultado no está disponible."
    ),
    "parser_warning": "El parser PE emitió avisos: algunos datos pueden estar incompletos.",
    "invalid_import_table": "La tabla de imports no se pudo leer de forma válida.",
    "invalid_export_table": "La tabla de exports no se pudo leer de forma válida.",
    "invalid_section_table": "La tabla de secciones no es válida.",
    "unsafe_mapping": (
        "La correspondencia entre direcciones en memoria y posiciones del archivo es ambigua; "
        "no se leyó para no elegir una interpretación arbitraria."
    ),
    "import_limit": "Se alcanzó el máximo de imports conservados: hay más que no aparecen.",
    "descriptor_limit": "Se alcanzó el máximo de DLL importadas que se revisan.",
    "export_limit": "Se alcanzó el máximo de exports conservados: hay más que no aparecen.",
    "export_name_limit": "Se alcanzó el máximo de nombres de export conservados.",
    "section_limit": "Se alcanzó el máximo de secciones que se revisan.",
    "string_limit": "Se alcanzó el máximo de cadenas conservadas: hay más que no aparecen.",
    "string_length_limit": (
        "Alguna cadena superaba el máximo de caracteres y solo se conservó su comienzo."
    ),
    "entropy_limit": (
        "Se agotó el presupuesto de bytes para medir entropía: algunas secciones no se midieron."
    ),
    "anomaly_limit": "Se alcanzó el máximo de anomalías conservadas.",
    "toolchain_limit": "Se alcanzó el máximo de marcas de GCC distintas conservadas.",
    "evidence_budget": "Se alcanzó el tamaño máximo del informe y se omitieron resultados.",
    "dependency_omitted": (
        "Faltan datos de los que depende este componente, así que parte de él no se calculó."
    ),
    "output_limit": "La respuesta del worker superó su tamaño máximo.",
    "decode_strings_limit": "Se alcanzó el máximo de decodificaciones Base64/hex conservadas.",
    "decode_xor_limit": "Se alcanzó el máximo de decodificaciones XOR conservadas.",
    "decode_xor_examined_limit": (
        "Se alcanzó el máximo de apariciones XOR examinadas: parte del archivo no se revisó con"
        " este método."
    ),
    "decode_time_limit": (
        "Se agotó el tiempo reservado a la búsqueda XOR: parte del archivo no se revisó con "
        "este método."
    ),
    "decoded_length_limit": (
        "Algún texto decodificado superaba el máximo de caracteres y se conservó recortado."
    ),
    "unsupported_architecture": (
        "El código no es x86 ni x64, las únicas arquitecturas que LupaBin sabe recorrer."
    ),
    "code_instruction_limit": (
        "Se alcanzó el máximo de instrucciones recorridas: parte del código no se revisó."
    ),
    "code_entry_limit": (
        "Se alcanzó el máximo de puntos de partida del recorrido: parte del código no se revisó."
    ),
    "code_time_limit": (
        "Se agotó el tiempo reservado al recorrido del código: parte del código no se revisó."
    ),
    "call_site_limit": (
        "Se alcanzó el máximo de llamadas examinadas: parte del código no se revisó."
    ),
    "api_call_limit": ("Se alcanzó el máximo de llamadas conservadas: hay más que no aparecen."),
    "call_argument_limit": (
        "Se alcanzó el máximo de argumentos conservados: hay más que no aparecen."
    ),
    "argument_instruction_limit": (
        "Se alcanzó el máximo de instrucciones examinadas en busca de argumentos:"
        " algunas llamadas no se revisaron."
    ),
    "yara_catalog_invalid": (
        "El catálogo de reglas no superó su validación, así que no se evaluó ninguna regla."
    ),
    "yara_unavailable": "El motor YARA no está disponible en este entorno.",
    "yara_compile_error": "Las reglas no compilaron.",
    "yara_scan_error": "La búsqueda de reglas falló.",
    "yara_timeout": "La búsqueda de reglas superó su tiempo máximo.",
    "yara_policy_violation": (
        "El proceso de reglas incumplió la política de aislamiento y se descartó su resultado."
    ),
    "yara_warning": "El motor YARA emitió avisos durante la búsqueda.",
    "yara_process_failure": "El proceso aislado de reglas terminó de forma anómala.",
    "yara_output_limit": "La respuesta del proceso de reglas superó su tamaño máximo.",
    "yara_result_invalid": (
        "La respuesta del proceso de reglas no superó la validación y se descartó."
    ),
    "yara_instance_limit": "Se alcanzó el máximo de apariciones conservadas por regla.",
    "yara_data_limit": "Se alcanzó el máximo de bytes capturados de las coincidencias.",
    "yara_match_limit": "Se alcanzó el máximo de reglas coincidentes conservadas.",
    "yara_catalog_mismatch": (
        "El catálogo de reglas usado no coincide con el esperado y se descartó el resultado."
    ),
}


def number(value: int) -> str:
    """Spanish thousands separator: 20971520 -> 20.971.520."""
    return f"{value:,}".replace(",", ".")


def hexadecimal(value: int, width: int = 8) -> str:
    return f"0x{value:0{width}x}"


def name(value: Name) -> str:
    """Sample-derived name as text; bytes that are not ASCII are shown, not guessed."""
    return value.text if value.text is not None else f"(bytes no ASCII: {value.raw_hex})"


def section_name(text: str | None, raw_hex: str) -> str:
    if text is None:
        return f"(nombre no UTF-8: {raw_hex})"
    return text if text else "(sin nombre)"


def frame_slot(fact: LocalLinkEvidence) -> str:
    """A local variable as the code names it: [ebp-0x8], [rsp+0x30]."""
    displacement = fact.data.slot.displacement
    sign = "-" if displacement < 0 else "+"
    return f"[{fact.data.slot.frame}{sign}{abs(displacement):#x}]"
