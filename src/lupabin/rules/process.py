import sys
from typing import Protocol

from lupabin.errors import LupaBinError
from lupabin.evidence.primitives import YaraLimits
from lupabin.evidence.yara import ScanResult, YaraReason, validate_scan
from lupabin.rules.catalog import Catalog
from lupabin.transport import Completed, run_command


class Executor(Protocol):
    async def __call__(
        self,
        executable: str,
        args: tuple[str, ...],
        *,
        data: bytes,
        timeout: float,
        limit: int,
        stderr_limit: int,
    ) -> Completed: ...


class YaraProcessError(Exception):
    def __init__(self, code: YaraReason):
        self.code = code
        super().__init__(code)


async def scan_child(
    data: bytes, limits: YaraLimits, catalog: Catalog, *, execute: Executor = run_command
) -> ScanResult:
    try:
        response = await execute(
            sys.executable,
            ("-m", "lupabin.yara_worker", "--limits-json", limits.model_dump_json()),
            data=data,
            timeout=limits.process_seconds,
            limit=limits.output_bytes,
            stderr_limit=limits.stderr_bytes,
        )
    except LupaBinError as exc:
        code: YaraReason = "yara_process_failure"
        if exc.code == "timeout":
            code = "yara_timeout"
        elif exc.code == "output_limit":
            code = "yara_output_limit"
        raise YaraProcessError(code) from None
    if response.code != 0:
        raise YaraProcessError("yara_process_failure")
    try:
        result = ScanResult.model_validate_json(response.stdout)
        validate_scan(result, data, catalog.info, limits)
        return result
    except (ValueError, RecursionError):
        raise YaraProcessError("yara_result_invalid") from None
