import asyncio
import json
import re
from uuid import uuid4

from pydantic import ValidationError

from lupabin.errors import LupaBinError
from lupabin.evidence.code import verify_calls
from lupabin.evidence.models import Limits, Report
from lupabin.evidence.toolchain_checks import verify_markers
from lupabin.evidence.upx_checks import verify_upx
from lupabin.evidence.yara import validate_matches
from lupabin.extractors.decode import verify_decodings
from lupabin.extractors.strings import verify_strings
from lupabin.ingest.reader import from_bytes
from lupabin.rules.catalog import CatalogError, load_catalog
from lupabin.transport import Completed as Completed
from lupabin.transport import DockerCLI, Transport

IMAGE = "lupabin-worker:0.12.0"
SOURCES = ("pe", "strings", "yara", "decode", "code")
LABEL = "org.lupabin.analysis"


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
            raise LupaBinError("cleanup_failure")
        if inspected.stdout.strip() != name.encode("ascii"):
            raise LupaBinError("cleanup_failure")
        removed = await transport.run(("container", "rm", "--force", name))
        if removed.code != 0:
            raise LupaBinError("cleanup_failure")
    except LupaBinError:
        raise LupaBinError("cleanup_failure") from None


async def run_isolated(data: bytes, limits: Limits, transport: Transport) -> Report:
    blob = from_bytes(data, limits)
    info = await transport.run(("info", "--format", "{{.OSType}}"))
    if info.code != 0 or info.stdout.strip() != b"linux":
        raise LupaBinError("docker_unavailable")
    image = await transport.run(("image", "inspect", "--format", "{{.Id}}", IMAGE))
    if image.code != 0 or not re.fullmatch(rb"sha256:[a-f0-9]{64}", image.stdout.strip()):
        raise LupaBinError("image_unavailable")
    name = "lupabin-" + uuid4().hex
    try:
        created = await transport.run(
            container_args(name, image.stdout.strip().decode("ascii"), limits)
        )
        if created.code != 0:
            raise LupaBinError("worker_failure")
        response = await transport.run(
            ("start", "--attach", "--interactive", name),
            data=blob.data,
            timeout=limits.timeout_seconds,
            limit=limits.output_bytes,
        )
        if response.code not in (0, 1, 3) or not response.stdout:
            raise LupaBinError("worker_failure")
        try:
            envelope = json.loads(response.stdout)
            if isinstance(envelope, dict) and isinstance(envelope.get("schema_version"), str):
                if envelope["schema_version"] != "0.12.0":
                    raise LupaBinError("incompatible_worker")
            report = Report.model_validate_json(response.stdout)
        except (ValidationError, ValueError, RecursionError):
            raise LupaBinError("invalid_worker_output") from None
        expected_exit = {"completed": 0, "partial": 3, "failed": 1}[report.analysis.status]
        if response.code != expected_exit:
            raise LupaBinError("invalid_worker_output")
        if (report.sample.sha256, report.sample.md5, report.sample.size) != (
            blob.sample.sha256,
            blob.sample.md5,
            blob.sample.size,
        ) or report.analysis.limits != limits:
            raise LupaBinError("invalid_worker_output")
        if tuple(run.source for run in report.extractor_runs) != SOURCES:
            raise LupaBinError("invalid_worker_output")
        try:
            verify_strings(report.evidence, blob.data)
            verify_decodings(report.evidence, blob.data)
            verify_calls(report.evidence, blob.data)
            verify_markers(report.evidence, blob.data)
            verify_upx(report.evidence, blob.data)
        except ValueError:
            raise LupaBinError("invalid_worker_output") from None
        context = report.yara_context
        if context is not None and context.catalog is not None:
            try:
                if context.catalog != load_catalog(limits.yara).info:
                    raise LupaBinError("incompatible_worker")
                matches = tuple(f.data for f in report.evidence if f.kind == "yara_match")
                validate_matches(matches, context, len(blob.data), limits.yara, blob.data)
            except CatalogError:
                raise LupaBinError("incompatible_worker") from None
            except ValueError:
                raise LupaBinError("invalid_worker_output") from None
        return report
    finally:
        await remove_owned_container(transport, name)


def analyze_isolated(data: bytes, limits: Limits) -> Report:
    return asyncio.run(run_isolated(data, limits, DockerCLI()))
