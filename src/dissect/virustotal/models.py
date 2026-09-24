"""VirusTotalReport 0.1.0: third-party results, kept apart from Dissect's own facts."""

from typing import Annotated, Literal

from pydantic import AwareDatetime, Field

from dissect.evidence.primitives import Model

Text = Annotated[str, Field(max_length=2048)]
Count = Annotated[int, Field(ge=0)]
MAX_ITEMS = 100


class Detection(Model):
    engine: Text
    category: Literal["malicious", "suspicious"]
    result: Text | None = None


class SandboxVerdict(Model):
    sandbox: Text
    category: Text
    confidence: Annotated[int, Field(ge=0, le=100)] | None = None
    classification: Annotated[tuple[Text, ...], Field(max_length=MAX_ITEMS)] = ()
    malware_names: Annotated[tuple[Text, ...], Field(max_length=MAX_ITEMS)] = ()


class RegistryWrite(Model):
    key: Text
    value: Text | None = None


class DnsLookup(Model):
    hostname: Text
    resolved_ips: Annotated[tuple[Text, ...], Field(max_length=MAX_ITEMS)] = ()


class IpTraffic(Model):
    destination_ip: Text
    destination_port: Annotated[int, Field(ge=0, le=65535)] | None = None
    protocol: Text | None = None


class HttpConversation(Model):
    url: Text
    method: Text | None = None


class Technique(Model):
    id: Annotated[str, Field(max_length=32)]
    description: Text | None = None
    severity: Text | None = None


Items = Annotated[tuple[Text, ...], Field(max_length=MAX_ITEMS)]


class Behaviour(Model):
    processes_created: Items = ()
    command_executions: Items = ()
    files_written: Items = ()
    files_deleted: Items = ()
    files_dropped: Items = ()
    registry_keys_set: Annotated[tuple[RegistryWrite, ...], Field(max_length=MAX_ITEMS)] = ()
    dns_lookups: Annotated[tuple[DnsLookup, ...], Field(max_length=MAX_ITEMS)] = ()
    ip_traffic: Annotated[tuple[IpTraffic, ...], Field(max_length=MAX_ITEMS)] = ()
    http_conversations: Annotated[tuple[HttpConversation, ...], Field(max_length=MAX_ITEMS)] = ()
    mutexes_created: Items = ()
    services_created: Items = ()
    mitre_attack_techniques: Annotated[tuple[Technique, ...], Field(max_length=MAX_ITEMS)] = ()
    # entries dropped because a list was longer than MAX_ITEMS or had the wrong shape
    omitted: Count = 0

    def empty(self) -> bool:
        return not any(getattr(self, name) for name in type(self).model_fields if name != "omitted")


Status = Literal["found", "not_found", "queued", "unavailable"]
Problem = Literal[
    "key_missing",
    "auth_failed",
    "quota_exceeded",
    "network_error",
    "invalid_response",
    "too_large",
]


class VirusTotalReport(Model):
    schema_version: Literal["0.1.0"] = "0.1.0"
    source: Literal["virustotal"] = "virustotal"
    sample_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    retrieved_at: AwareDatetime
    status: Status
    problem: Problem | None = None
    uploaded: bool = False
    permalink: Annotated[
        str, Field(pattern=r"^https://www\.virustotal\.com/gui/file/[a-f0-9]{64}$")
    ]
    stats: dict[Annotated[str, Field(max_length=32)], Count] = Field(default_factory=dict)
    detections: Annotated[tuple[Detection, ...], Field(max_length=MAX_ITEMS)] = ()
    detections_omitted: Count = 0
    meaningful_name: Text | None = None
    names: Annotated[tuple[Text, ...], Field(max_length=20)] = ()
    type_description: Text | None = None
    first_submission: AwareDatetime | None = None
    last_analysis: AwareDatetime | None = None
    reputation: int | None = None
    votes: dict[Literal["harmless", "malicious"], Count] = Field(default_factory=dict)
    tags: Annotated[tuple[Text, ...], Field(max_length=50)] = ()
    sandbox_verdicts: Annotated[tuple[SandboxVerdict, ...], Field(max_length=20)] = ()
    behaviour: Behaviour = Field(default_factory=Behaviour)
