from dataclasses import dataclass

from lupabin.challenge.models import Level, RuleId

CATALOG = "lupabin-challenges-v1"


@dataclass(frozen=True)
class Rule:
    id: RuleId
    level: Level
    prompt: str
    choices: tuple[str, str, str]
    explanation: str
    not_proven: str


RULES = (
    Rule(
        "header",
        "observed",
        "¿Cuántas secciones declara NumberOfSections en la cabecera {id}?",
        ("{value}", "{alternative1}", "{alternative2}"),
        "{id} declara NumberOfSections = {value}. "
        "Se pregunta por el campo, no por contar resultados.",
        "El número declarado no garantiza que todas las secciones se hayan podido analizar.",
    ),
    Rule(
        "section",
        "observed",
        "En {id}, ¿qué representa SizeOfRawData = {value}?",
        (
            "El tamaño declarado de los datos de la sección en disco.",
            "El tamaño virtual declarado de la sección.",
            "La dirección virtual relativa donde comienza la sección.",
        ),
        "El campo data.raw_size de {id} vale {value}: "
        "es SizeOfRawData, un tamaño declarado en disco.",
        "No demuestra que ese rango esté íntegramente dentro del archivo "
        "ni sus permisos efectivos.",
    ),
    Rule(
        "import",
        "observed",
        "¿Qué acredita por sí sola la importación {id} ({label})?",
        (
            "Una entrada en la tabla de importaciones indicada.",
            "Una instrucción de llamada localizada en el código.",
            "Un símbolo en la tabla de exportaciones.",
        ),
        "{id} es kind=import, tabla {value}. "
        "Identifica una entrada de importación, no una llamada.",
        "Una importación no prueba ejecución, intención ni que haya una llamada a ella.",
    ),
    Rule(
        "call",
        "observed",
        "¿Qué añade la evidencia api_call {id} a la importación que cita?",
        (
            "Una transferencia de llamada reconocida en estático hacia la casilla de ese import.",
            "Solo el nombre de una cadena, sin relación estática con un import.",
            "Una entrada adicional en la tabla de exportaciones.",
        ),
        "{id} localiza bytes de una llamada reconocida por la forma {value} y cita su import.",
        "Reconocer una llamada en estático no demuestra que se ejecute ni con qué intención.",
    ),
    Rule(
        "string",
        "observed",
        "¿Cómo se clasifica el texto literal de {id} publicado por el extractor de cadenas?",
        (
            "Observación de bytes interpretados con la codificación indicada.",
            "Inferencia obtenida al aplicar un algoritmo de decodificación de contenido.",
            "Conocimiento educativo general, independiente de los bytes de la muestra.",
        ),
        "{id} es kind=string, confidence=observed, encoding={value}. "
        "Su texto procede de sus bytes.",
        "Una cadena no demuestra que el código la use. "
        "Un prefijo incompleto no es la cadena entera.",
    ),
    Rule(
        "decoded",
        "inferred",
        "¿Cómo se clasifica el resultado decoded_string de {id}?",
        (
            "Inferencia reproducible al transformar bytes con el método indicado.",
            "Observación literal sin transformación de esos mismos bytes.",
            "Conocimiento educativo general, sin referencia a esta muestra.",
        ),
        "{id} tiene confidence=inferred: el método {value} produce el texto publicado.",
        "No demuestra que el programa realice esa transformación ni que use el texto resultante.",
    ),
    Rule(
        "coverage",
        "general",
        "El componente {label} declara cobertura {value}. "
        "¿Cómo interpretar resultados que no publica?",
        (
            "No permite concluir ausencia: hay operaciones incompletas o bloqueadas.",
            "Permite tratar el componente como si su cobertura fuese complete.",
            "Obliga a descartar los hechos válidos de todos los demás componentes.",
        ),
        "La cobertura citada es {value}, no complete. "
        "Regla general: conservar lo validado y abstenerse sobre lo no determinado.",
        "Ni una cobertura completa ni una lista vacía son un veredicto de seguridad.",
    ),
)
