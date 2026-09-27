import hashlib
import json
import re
from dataclasses import asdict, dataclass

from lupabin.virustotal.models import Detection
from lupabin.virustotal.parse import TEXT

CATALOG_ID = "lupabin-vt-labels-v1"
CATALOG_SHA256 = "cab7920c58e15ff8f9cd7d60dd94f42b722861e54afa968181baa825b6be76cc"
REVIEWED = "2026-09-27"
LIMIT = (
    "Explica la nomenclatura del fabricante, no la causa exacta de esta detección. "
    "No confirma malware, ejecución, una familia ni un falso positivo."
)
UNKNOWN = (
    "El catálogo de LupaBin no contiene una interpretación documentada para esta "
    "combinación de motor y etiqueta, o el texto está ausente o puede estar recortado."
)


@dataclass(frozen=True)
class EditorialSource:
    publisher: str
    title: str
    url: str


@dataclass(frozen=True)
class LabelRule:
    id: str
    engine: str
    pattern: str
    category: str
    statement: str
    source: EditorialSource


@dataclass(frozen=True)
class LabelExplanation:
    engine: str
    label: str | None
    rule: str | None
    category: str
    statement: str
    not_proven: str
    sources: tuple[EditorialSource, ...]


RULES = (
    LabelRule(
        "microsoft.behavior_ml",
        "Microsoft",
        r"Behavior:Win32/(?:InitialAccess|Execution|Persistence|PrivilegeEscalation|"
        r"DefenseEvasion|CredentialAccess|Discovery|LateralMovement|Collection|"
        r"CommandAndControl|Exfiltration|Impact|Generic)\.[A-Za-z0-9_.-]+!ml",
        "behavior_ml",
        "Microsoft documenta este patrón concreto de nombre como una detección de "
        "aprendizaje automático basada en comportamiento. La etiqueta no revela las "
        "características ni los umbrales que decidieron el resultado de este archivo.",
        EditorialSource(
            "Microsoft Defender Security Research Team",
            "AI-driven behavior-based blocking (2019)",
            "https://www.microsoft.com/en-us/security/blog/2019/10/08/"
            "in-hot-pursuit-of-elusive-threats-ai-driven-behavior-based-blocking-stops-attacks-in-their-tracks/",
        ),
    ),
    LabelRule(
        "microsoft.internal_suffix",
        "Microsoft",
        r"[A-Za-z]+:[A-Za-z0-9_]+/[A-Za-z0-9_.-]+![A-Za-z0-9]+",
        "internal",
        "Microsoft describe los sufijos que empiezan por ! como un indicador interno. "
        "Esta regla no tiene una definición publicada más específica del sufijo y "
        "no le atribuye un algoritmo ni un motivo de detección.",
        EditorialSource(
            "Microsoft",
            "How Microsoft names malware: Suffixes",
            "https://learn.microsoft.com/en-us/defender-xdr/malware-naming",
        ),
    ),
    LabelRule(
        "fsecure.generic",
        "F-Secure",
        r"(?:Generic(?:\.malware)?\.|gen:win32\.malware\.|Gen:[Vv]ariant\.)[A-Za-z0-9_.@!-]+",
        "generic",
        "F-Secure documenta estos nombres como detecciones genéricas: patrones amplios "
        "de código o comportamiento similares a los de programas dañinos conocidos. "
        "No describen por sí solos el patrón concreto que coincidió en este archivo.",
        EditorialSource(
            "F-Secure", "Generic Detection", "https://www.f-secure.com/v-descs/other-w32-generic"
        ),
    ),
    LabelRule(
        "fsecure.heuristic",
        "F-Secure",
        r"(?:HEUR/APC|Heuristic|Gen:Heur|Gen:Trojan\.Heur|Deepscan:generic\.malware|"
        r"Memscan:[A-Za-z0-9_.-]+)",
        "heuristic",
        "F-Secure documenta estos nombres como detecciones heurísticas: el fabricante "
        "busca instrucciones o comportamientos que asocia con acciones dañinas. "
        "LupaBin no conoce qué condición concreta activó esa heurística en este archivo.",
        EditorialSource("F-Secure", "Heuristic", "https://www.f-secure.com/v-descs/heuristic"),
    ),
)


def catalog_digest() -> str:
    data = {
        "id": CATALOG_ID,
        "reviewed": REVIEWED,
        "rules": [asdict(rule) for rule in RULES],
        "limit": LIMIT,
        "unknown": UNKNOWN,
        "max_text": TEXT,
    }
    return hashlib.sha256(
        json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def interpret(detection: Detection) -> LabelExplanation:
    label = detection.result
    if label is not None and len(label) < TEXT:
        for rule in RULES:
            if detection.engine == rule.engine and re.fullmatch(rule.pattern, label, re.ASCII):
                return LabelExplanation(
                    detection.engine,
                    label,
                    rule.id,
                    rule.category,
                    rule.statement,
                    LIMIT,
                    (rule.source,),
                )
    return LabelExplanation(detection.engine, label, None, "unavailable", UNKNOWN, LIMIT, ())
