"""Turn VirusTotal API v3 JSON into a bounded VirusTotalReport.

The response is untrusted input: only expected fields with the expected types are
kept, lists and texts are bounded, and anything dropped is counted, never guessed.
"""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from dissect.virustotal.models import (
    MAX_ITEMS,
    Behaviour,
    Detection,
    DnsLookup,
    HttpConversation,
    IpTraffic,
    RegistryWrite,
    SandboxVerdict,
    Technique,
)

TEXT = 2048
STATS = (
    "malicious",
    "suspicious",
    "undetected",
    "harmless",
    "timeout",
    "confirmed-timeout",
    "type-unsupported",
    "failure",
)


def text(value: Any) -> str | None:
    return value[:TEXT] if isinstance(value, str) and value else None


def integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def timestamp(value: Any) -> datetime | None:
    seconds = integer(value)
    if seconds is None or not 0 < seconds < 32503680000:  # before year 3000
        return None
    return datetime.fromtimestamp(seconds, UTC)


def texts(value: Any, limit: int = MAX_ITEMS) -> tuple[tuple[str, ...], int]:
    if not isinstance(value, list):
        return (), 0
    kept = [item for item in (text(v) for v in value) if item is not None]
    dropped = len(value) - len(kept)
    return tuple(kept[:limit]), dropped + max(0, len(kept) - limit)


def records[T](
    value: Any, build: Callable[[dict[str, Any]], T | None]
) -> tuple[tuple[T, ...], int]:
    if not isinstance(value, list):
        return (), 0
    kept = []
    for item in value:
        built = build(item) if isinstance(item, dict) else None
        if built is not None:
            kept.append(built)
    dropped = len(value) - len(kept)
    return tuple(kept[:MAX_ITEMS]), dropped + max(0, len(kept) - MAX_ITEMS)


def file_attributes(payload: Any) -> dict[str, Any]:
    data = payload.get("data") if isinstance(payload, dict) else None
    attributes = data.get("attributes") if isinstance(data, dict) else None
    if not isinstance(attributes, dict):
        raise ValueError("response has no file attributes")
    return attributes


def summary(attributes: dict[str, Any]) -> dict[str, Any]:
    stats_in = attributes.get("last_analysis_stats")
    stats = {}
    if isinstance(stats_in, dict):
        stats = {k: v for k in STATS if (v := integer(stats_in.get(k))) is not None and v >= 0}
    detections = []
    results = attributes.get("last_analysis_results")
    if isinstance(results, dict):
        for engine, result in sorted(results.items()):
            if not isinstance(result, dict):
                continue
            category = result.get("category")
            name = text(engine)
            if category in ("malicious", "suspicious") and name:
                detections.append(
                    Detection(engine=name, category=category, result=text(result.get("result")))
                )
    names, _ = texts(attributes.get("names"), 20)
    tags, _ = texts(attributes.get("tags"), 50)
    votes_in = attributes.get("total_votes")
    votes = {}
    if isinstance(votes_in, dict):
        votes = {
            k: v for k in ("harmless", "malicious") if (v := integer(votes_in.get(k))) is not None
        }
    verdicts = []
    sandboxes = attributes.get("sandbox_verdicts")
    if isinstance(sandboxes, dict):
        for key, verdict in sorted(sandboxes.items()):
            if not isinstance(verdict, dict) or not text(verdict.get("category")):
                continue
            confidence = integer(verdict.get("confidence"))
            verdicts.append(
                SandboxVerdict(
                    sandbox=text(verdict.get("sandbox_name")) or text(key) or "?",
                    category=text(verdict.get("category")) or "?",
                    confidence=confidence
                    if confidence is not None and 0 <= confidence <= 100
                    else None,
                    classification=texts(verdict.get("malware_classification"))[0],
                    malware_names=texts(verdict.get("malware_names"))[0],
                )
            )
    reputation = integer(attributes.get("reputation"))
    return {
        "stats": stats,
        "detections": tuple(detections[:MAX_ITEMS]),
        "detections_omitted": max(0, len(detections) - MAX_ITEMS),
        "meaningful_name": text(attributes.get("meaningful_name")),
        "names": names,
        "type_description": text(attributes.get("type_description")),
        "first_submission": timestamp(attributes.get("first_submission_date")),
        "last_analysis": timestamp(attributes.get("last_analysis_date")),
        "reputation": reputation,
        "votes": votes,
        "tags": tags,
        "sandbox_verdicts": tuple(verdicts[:20]),
    }


def _registry(item: dict[str, Any]) -> RegistryWrite | None:
    key = text(item.get("key"))
    return RegistryWrite(key=key, value=text(item.get("value"))) if key else None


def _dns(item: dict[str, Any]) -> DnsLookup | None:
    host = text(item.get("hostname"))
    return (
        DnsLookup(hostname=host, resolved_ips=texts(item.get("resolved_ips"))[0]) if host else None
    )


def _ip(item: dict[str, Any]) -> IpTraffic | None:
    ip = text(item.get("destination_ip"))
    port = integer(item.get("destination_port"))
    if not ip:
        return None
    return IpTraffic(
        destination_ip=ip,
        destination_port=port if port is not None and 0 <= port <= 65535 else None,
        protocol=text(item.get("transport_layer_protocol")),
    )


def _http(item: dict[str, Any]) -> HttpConversation | None:
    url = text(item.get("url"))
    return HttpConversation(url=url, method=text(item.get("request_method"))) if url else None


def _technique(item: dict[str, Any]) -> Technique | None:
    ident = item.get("id")
    if not isinstance(ident, str) or not 0 < len(ident) <= 32:
        return None
    return Technique(
        id=ident,
        description=text(item.get("signature_description")),
        severity=text(item.get("severity")),
    )


def _dropped(item: dict[str, Any]) -> str | None:
    return text(item.get("path"))


def behaviour(payload: Any) -> Behaviour:
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict):
        raise ValueError("behaviour summary has no data")
    omitted = 0
    fields: dict[str, Any] = {}
    for name in (
        "processes_created",
        "command_executions",
        "files_written",
        "files_deleted",
        "mutexes_created",
        "services_created",
    ):
        fields[name], dropped = texts(data.get(name))
        omitted += dropped
    builders: dict[str, Callable[[dict[str, Any]], Any]] = {
        "registry_keys_set": _registry,
        "dns_lookups": _dns,
        "ip_traffic": _ip,
        "http_conversations": _http,
        "mitre_attack_techniques": _technique,
        "files_dropped": _dropped,
    }
    for name, build in builders.items():
        fields[name], dropped = records(data.get(name), build)
        omitted += dropped
    return Behaviour(**fields, omitted=omitted)


def analysis_status(payload: Any) -> str | None:
    data = payload.get("data") if isinstance(payload, dict) else None
    attributes = data.get("attributes") if isinstance(data, dict) else None
    status = attributes.get("status") if isinstance(attributes, dict) else None
    return status if status in ("queued", "in-progress", "completed") else None


def analysis_id(payload: Any) -> str | None:
    data = payload.get("data") if isinstance(payload, dict) else None
    ident = data.get("id") if isinstance(data, dict) else None
    return ident if isinstance(ident, str) and 0 < len(ident) <= 256 else None
