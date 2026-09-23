import asyncio
import json
import re
from uuid import uuid4

from pydantic import ValidationError

from dissect.errors import DissectError
from dissect.evidence.models import Limits, Report
from dissect.evidence.yara import validate_matches
from dissect.extractors.decode import verify_decodings
from dissect.ingest.reader import from_bytes
from dissect.rules.catalog import CatalogError, load_catalog
from dissect.transport import Completed as Completed
from dissect.transport import DockerCLI, Transport

IMAGE = "dissect-worker:0.5.0"
SOURCES = ("pe", "strings", "yara", "decode")
LABEL = "org.dissect.analysis"


def container_args(name: str, image: str, limits: Limits) -> tuple[str, ...]:
    return (
        "create",
        "--name",
        name,
        "--label",
        f"{LABEL}={name}",
        "--pull=never",
        "-i",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--user=65532:65532",
        f"--memory={limits.memory_bytes}",
        f"--memory-swap={limits.memory_bytes}",
        f"--cpus={limits.cpus}",
        f"--pids-limit={limits.pids}",
        "--ulimit=nofile=64:64",
        "--ulimit=core=0:0",
        "--log-driver=none",
        "--ipc=none",
        image,
        "--limits-json",
        limits.model_dump_json(),
    )


async def remove_owned_container(transport: Transport, name: str) -> None:
    try:
        inspected = await transport.run(
            (
                "container",
                "inspect",
                "--format",
                '{{index .Config.Labels "' + LABEL + '"}}',
                name,
            )
        )
        if inspected.code != 0:
            listed = await transport.run(
                (
                    "container",
                    "ls",
                    "--all",
                    "--filter",
                    f"name=^/{name}$",
                    "--format",
                    "{{.Names}}",
                )
            )
            if listed.code == 0 and not listed.stdout.strip():
                return
            raise DissectError("cleanup_failure")
        if inspected.stdout.strip() != name.encode("ascii"):
            raise DissectError("cleanup_failure")
        removed = await transport.run(("container", "rm", "--force", name))
        if removed.code != 0:
            raise DissectError("cleanup_failure")
    except DissectError:
        raise DissectError("cleanup_failure") from None


async def run_isolated(data: bytes, limits: Limits, transport: Transport) -> Report:
    blob = from_bytes(data, limits)
    info = await transport.run(("info", "--format", "{{.OSType}}"))
    if info.code != 0 or info.stdout.strip() != b"linux":
        raise DissectError("docker_unavailable")
    image = await transport.run(("image", "inspect", "--format", "{{.Id}}", IMAGE))
    if image.code != 0 or not re.fullmatch(rb"sha256:[a-f0-9]{64}", image.stdout.strip()):
        raise DissectError("image_unavailable")
    name = "dissect-" + uuid4().hex
    try:
        created = await transport.run(
            container_args(name, image.stdout.strip().decode("ascii"), limits)
        )
        if created.code != 0:
            raise DissectError("worker_failure")
        response = await transport.run(
            ("start", "--attach", "--interactive", name),
            data=blob.data,
            timeout=limits.timeout_seconds,
            limit=limits.output_bytes,
        )
        if response.code not in (0, 1, 3) or not response.stdout:
            raise DissectError("worker_failure")
        try:
            envelope = json.loads(response.stdout)
            if isinstance(envelope, dict) and isinstance(envelope.get("schema_version"), str):
                if envelope["schema_version"] != "0.5.0":
                    raise DissectError("incompatible_worker")
            report = Report.model_validate_json(response.stdout)
        except (ValidationError, ValueError, RecursionError):
            raise DissectError("invalid_worker_output") from None
        expected_exit = {"completed": 0, "partial": 3, "failed": 1}[report.analysis.status]
        if response.code != expected_exit:
            raise DissectError("invalid_worker_output")
        if (report.sample.sha256, report.sample.md5, report.sample.size) != (
            blob.sample.sha256,
            blob.sample.md5,
            blob.sample.size,
        ) or report.analysis.limits != limits:
            raise DissectError("invalid_worker_output")
        if tuple(run.source for run in report.extractor_runs) != SOURCES:
            raise DissectError("invalid_worker_output")
        try:
            verify_decodings(report.evidence, blob.data)
        except ValueError:
            raise DissectError("invalid_worker_output") from None
        context = report.yara_context
        if context is not None and context.catalog is not None:
            try:
                if context.catalog != load_catalog(limits.yara).info:
                    raise DissectError("incompatible_worker")
                matches = tuple(f.data for f in report.evidence if f.kind == "yara_match")
                validate_matches(matches, context, len(blob.data), limits.yara, blob.data)
            except CatalogError:
                raise DissectError("incompatible_worker") from None
            except ValueError:
                raise DissectError("invalid_worker_output") from None
        return report
    finally:
        await remove_owned_container(transport, name)


def analyze_isolated(data: bytes, limits: Limits) -> Report:
    return asyncio.run(run_isolated(data, limits, DockerCLI()))
