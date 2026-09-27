import hashlib
import json
import re
from dataclasses import dataclass
from typing import Literal

from lupabin.evidence.models import Report
from lupabin.explain.capabilities import (
    CAPABILITIES,
    CASES_SHOWN,
    CATALOG_ID,
    CATALOG_SHA256,
    TECHNIQUES,
    cases,
)
from lupabin.virustotal.models import VirusTotalReport

METHOD = "exact-technique-id-v1"
METHOD_SHA256 = "60365f591ab17059f63973d9d3c11ade8bd9a080f63cc088e87dc5b28a25ff05"
SOURCE = "https://docs.virustotal.com/reference/file-behaviour-summary"
LIMIT = (
    "Comparar el mismo identificador no demuestra las mismas acciones, su ejecución ni "
    "la causa del veredicto antivirus. VirusTotal puede incluir acciones de procesos hijos. "
    "Solo se comparan identificadores exactos: una técnica y su subtécnica no se equiparan."
)
NO_TECHNIQUES = (
    "No se recibieron técnicas de VirusTotal para contrastar; "
    "no demuestra ausencia de comportamiento."
)
Status = Literal[
    "static_match",
    "not_observed",
    "incomplete",
    "unsupported",
    "invalid_id",
    "identity_mismatch",
    "no_local_report",
]
MESSAGES: dict[Status, str] = {
    "static_match": (
        "El catálogo local asocia un caso estático a este mismo identificador, con las "
        "evidencias citadas. Es una inferencia, no una confirmación del comportamiento "
        "observado por VirusTotal."
    ),
    "not_observed": (
        "No se encontró un caso estático de esta técnica con las reglas y los caminos "
        "analizados. Esto no descarta lo que reporta VirusTotal."
    ),
    "incomplete": (
        "La extracción local de llamadas o argumentos está incompleta o no disponible. "
        "No se puede resolver la correspondencia; no se refuta lo que reporta VirusTotal."
    ),
    "unsupported": (
        "Este identificador no está entre las técnicas que el catálogo local puede "
        "contrastar. No se deduce una correspondencia por el nombre ni por una técnica más general."
    ),
    "invalid_id": (
        "El identificador recibido no tiene el formato de técnica ATT&CK admitido; "
        "no se interpreta."
    ),
    "identity_mismatch": (
        "Los SHA-256 del informe local y de VirusTotal no coinciden; no se comparan sus resultados."
    ),
    "no_local_report": "No hay un informe local para contrastar esta técnica.",
}


@dataclass(frozen=True)
class LocalTechnique:
    status: Status
    statement: str
    evidence: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    details: tuple[str, ...] = ()
    omitted_details: int = 0


@dataclass(frozen=True)
class LocalContext:
    sha256: str
    method: str
    catalog: str
    catalog_sha256: str
    techniques: dict[str, LocalTechnique]


@dataclass(frozen=True)
class Comparison:
    id: str
    external_index: int
    status: Status
    statement: str
    evidence: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    details: tuple[str, ...] = ()
    omitted_details: int = 0


def method_digest() -> str:
    data = {
        "method": METHOD,
        "messages": MESSAGES,
        "limit": LIMIT,
        "source": SOURCE,
        "no_techniques": NO_TECHNIQUES,
        "capabilities": [CATALOG_ID, CATALOG_SHA256],
        "techniques": list(TECHNIQUES),
        "details_limit": CASES_SHOWN,
    }
    return hashlib.sha256(
        json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def valid_id(value: str) -> bool:
    return re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", value, re.ASCII) is not None


def local_context(report: Report) -> LocalContext:
    parts: dict[str, str] = {
        part.name: part.status
        for run in report.extractor_runs
        if run.source == "code"
        for part in run.components
    }
    complete = all(
        parts.get(name) == "complete" for name in ("disassembly", "api_calls", "call_arguments")
    )
    evidence: dict[str, set[str]] = {key: set() for key in TECHNIQUES}
    rules: dict[str, list[str]] = {key: [] for key in TECHNIQUES}
    details: dict[str, list[str]] = {key: [] for key in TECHNIQUES}
    for capability in CAPABILITIES:
        if capability.technique is None:
            continue
        for case in cases(capability, report):
            if case.technique in evidence:
                evidence[case.technique].update(f.id for f in case.cited)
                details[case.technique].append(f"{case.heading}: {case.details}")
                if capability.rule_id not in rules[case.technique]:
                    rules[case.technique].append(capability.rule_id)
    result = {}
    for key, ids in evidence.items():
        status: Status = "static_match" if ids else "not_observed" if complete else "incomplete"
        result[key] = LocalTechnique(
            status,
            MESSAGES[status],
            tuple(f.id for f in report.evidence if f.id in ids),
            tuple(rules[key]),
            tuple(details[key][:CASES_SHOWN]),
            max(0, len(details[key]) - CASES_SHOWN),
        )
    return LocalContext(report.sample.sha256, METHOD, CATALOG_ID, CATALOG_SHA256, result)


def compare(vt: VirusTotalReport, local: LocalContext | None) -> tuple[Comparison, ...]:
    if vt.status != "found":
        return ()
    result = []
    for index, technique in enumerate(vt.behaviour.mitre_attack_techniques):
        if local is not None and local.sha256 != vt.sample_sha256:
            status: Status = "identity_mismatch"
        elif not valid_id(technique.id):
            status = "invalid_id"
        elif local is None:
            status = "no_local_report"
        elif technique.id not in local.techniques:
            status = "unsupported"
        else:
            row = local.techniques[technique.id]
            result.append(
                Comparison(
                    technique.id,
                    index,
                    row.status,
                    row.statement,
                    row.evidence,
                    row.rules,
                    row.details,
                    row.omitted_details,
                )
            )
            continue
        result.append(Comparison(technique.id, index, status, MESSAGES[status]))
    return tuple(result)
