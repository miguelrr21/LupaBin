import asyncio
import json

import pytest

from lupabin.analysis import analyze_bytes
from lupabin.errors import LupaBinError
from lupabin.evidence.models import Limits
from lupabin.runner import Completed, run_isolated
from tests.fixtures.pe_builder import build_pe


class FakeDocker:
    def __init__(self, *, failure=None, output=None):
        self.failure = failure
        self.output = output
        self.calls = []
        self.token = None

    async def run(self, args, *, data=b"", timeout=10, limit=8192):
        self.calls.append((args, data))
        if args[0] == "info":
            if self.failure == "docker":
                return Completed(1, b"", b"private daemon details")
            return Completed(0, b"linux\n", b"")
        if args[:2] == ("image", "inspect"):
            return Completed(1 if self.failure == "image" else 0, b"sha256:" + b"a" * 64, b"")
        if args[0] == "create":
            self.token = args[args.index("--name") + 1]
            return Completed(0, b"c" * 64, b"")
        if args[0] == "start":
            if self.failure == "timeout":
                raise LupaBinError("timeout")
            if self.failure == "large":
                raise LupaBinError("output_limit")
            if self.failure == "worker":
                return Completed(1, b"", b"untrusted private message")
            payload = (
                self.output
                if self.output is not None
                else (await asyncio.to_thread(analyze_bytes, data)).model_dump_json().encode()
            )
            return Completed(0, payload, b"")
        if args[:2] == ("container", "inspect"):
            return Completed(0, (self.token or "").encode(), b"")
        if args[:2] == ("container", "rm"):
            return Completed(1 if self.failure == "cleanup" else 0, b"", b"")
        raise AssertionError(args)


def test_isolation_arguments_and_raw_stdin():
    docker = FakeDocker()
    sample = build_pe()
    result = asyncio.run(run_isolated(sample, Limits(), docker))
    assert result.analysis.status == "completed"
    create = next(args for args, _ in docker.calls if args[0] == "create")
    for flag in (
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--user=65532:65532",
        "--memory=536870912",
        "--memory-swap=536870912",
        "--cpus=1",
        "--pids-limit=64",
        "--pull=never",
    ):
        assert flag in create
    assert not any("mount" in arg or "volume" in arg for arg in create)
    assert next(data for args, data in docker.calls if args[0] == "start") == sample
    assert any(args[:2] == ("container", "rm") for args, _ in docker.calls)


@pytest.mark.parametrize(
    "failure,code",
    [
        ("docker", "docker_unavailable"),
        ("image", "image_unavailable"),
        ("timeout", "timeout"),
        ("large", "output_limit"),
        ("worker", "worker_failure"),
        ("cleanup", "cleanup_failure"),
    ],
)
def test_failures_are_explicit_and_cleanup_is_attempted(failure, code):
    docker = FakeDocker(failure=failure)
    with pytest.raises(LupaBinError) as caught:
        asyncio.run(run_isolated(build_pe(), Limits(), docker))
    assert caught.value.code == code
    if failure not in ("docker", "image"):
        assert any(args[:2] == ("container", "rm") for args, _ in docker.calls)
    assert "private" not in str(caught.value)


@pytest.mark.parametrize(
    "change",
    [
        lambda report: report["sample"].update(sha256="0" * 64),
        lambda report: report.update(schema_version="9.0.0"),
        lambda report: report.update(schema_version="0.1.0"),
        lambda report: report.update(schema_version="0.2.0"),
        lambda report: report.update(schema_version="0.3.0"),
        lambda report: report["analysis"]["limits"].update(imports=5),
    ],
)
def test_worker_response_must_match_original_input(change):
    report = json.loads(analyze_bytes(build_pe()).model_dump_json())
    change(report)
    docker = FakeDocker(output=json.dumps(report).encode())
    with pytest.raises(LupaBinError) as caught:
        asyncio.run(run_isolated(build_pe(), Limits(), docker))
    expected = (
        "incompatible_worker" if report["schema_version"] != "0.13.0" else "invalid_worker_output"
    )
    assert caught.value.code == expected


def test_invalid_json_is_not_repaired():
    with pytest.raises(LupaBinError) as caught:
        asyncio.run(run_isolated(build_pe(), Limits(), FakeDocker(output=b"not JSON")))
    assert caught.value.code == "invalid_worker_output"
