import asyncio
import json
from uuid import uuid4

import pytest

from lupabin.errors import LupaBinError
from lupabin.evidence.models import Limits
from lupabin.runner import IMAGE, container_args, remove_owned_container, run_isolated
from lupabin.transport import DockerCLI
from tests.fixtures.pe_builder import build_pe

pytestmark = pytest.mark.docker


@pytest.fixture(scope="module", autouse=True)
def require_docker():
    async def check():
        client = DockerCLI()
        info = await client.run(("info", "--format", "{{.OSType}}"))
        assert info.code == 0 and info.stdout.strip() == b"linux", "Linux Docker is required"
        image = await client.run(("image", "inspect", "--format", "{{.Id}}", IMAGE))
        assert image.code == 0, "Build lupabin-worker:0.10.0 before integration tests"

    asyncio.run(check())


@pytest.mark.parametrize("bits", [32, 64])
def test_real_worker_round_trip(bits):
    report = asyncio.run(run_isolated(build_pe(bits=bits), Limits(), DockerCLI()))
    assert report.analysis.status == "completed"
    assert (
        next(f for f in report.evidence if f.kind == "import").data.function.text == "ExitProcess"
    )
    assert {"pe_header", "section", "entropy", "string"} <= {f.kind for f in report.evidence}


@pytest.mark.parametrize("corrupt", [False, True])
def test_real_cli_full_and_partial_reports(tmp_path, corrupt):
    from typer.testing import CliRunner

    from lupabin.cli import app
    from tests.fixtures.pe_builder import build_demo

    path = tmp_path / "demo.bin"
    path.write_bytes(build_demo(corrupt=corrupt))
    result = CliRunner().invoke(app, ["analyze", str(path), "--json"])
    assert result.exit_code == (3 if corrupt else 0)
    report = json.loads(result.stdout)
    assert report["schema_version"] == "0.10.0"
    kinds = {fact["kind"] for fact in report["evidence"]}
    assert {"pe_header", "section", "entropy", "string"} <= kinds
    assert ("header_anomaly" in kinds) == corrupt
    assert "yara_match" in kinds
    assert report["yara_context"]["catalog"]["ruleset_sha256"]
    if not corrupt:
        assert "export" in kinds
    assert result.stderr == ""


def test_decodings_in_real_container_reverify_on_host():
    from tests.fixtures.pe_builder import DECODE_DEMO, build_decode_demo

    # run_isolated re-derives every decoding from the original bytes before returning
    report = asyncio.run(run_isolated(build_decode_demo(), Limits(), DockerCLI()))
    assert report.analysis.status == "completed"
    texts = [f.data.text for f in report.evidence if f.kind == "decoded_string"]
    assert texts == [item[1] for item in DECODE_DEMO]


def test_xor_flood_becomes_a_declared_limit_in_real_container():
    from tests.fixtures.pe_builder import xor_stream

    data = xor_stream("http://", b"\xa5") * 1_000_000
    report = asyncio.run(run_isolated(data, Limits(), DockerCLI()))
    assert report.analysis.status == "partial"
    codes = {r.code for r in report.limitations}
    assert {"decode_xor_examined_limit", "decode_xor_limit"} <= codes


def test_yara_limited_report_in_real_container():
    data = build_pe() + b"LUPABIN PRACTICE\0" * 20
    report = asyncio.run(run_isolated(data, Limits(), DockerCLI()))
    assert report.analysis.status == "partial"
    match = next(f for f in report.evidence if f.kind == "yara_match")
    assert len(match.data.instances) == 16
    assert match.data.omitted_instances == 4
    assert any(r.code == "yara_instance_limit" for r in report.limitations)


def test_yara_child_timeout_preserves_other_sources_in_container():
    script = (
        "from lupabin.rules.process import scan_child\n"
        "from lupabin.transport import run_command\n"
        "import lupabin.extractors.yara as adapter\n"
        "async def delayed(data, limits, catalog):\n"
        "    async def execute(executable, args, **kwargs):\n"
        "        kwargs['timeout'] = 0.1\n"
        "        command = ('-c', 'import time; time.sleep(60)')\n"
        "        return await run_command(executable, command, **kwargs)\n"
        "    return await scan_child(data, limits, catalog, execute=execute)\n"
        "adapter.scan_child = delayed\n"
        "from lupabin.worker import main\n"
        "raise SystemExit(main())\n"
    )

    class TimeoutChildDocker(DockerCLI):
        async def run(self, args, **kwargs):
            if args[0] == "create":
                index = next(i for i, value in enumerate(args) if value.startswith("sha256:"))
                args = (
                    *args[:index],
                    "--entrypoint=/app/.venv/bin/python",
                    args[index],
                    "-c",
                    script,
                    *args[index + 1 :],
                )
            return await super().run(args, **kwargs)

    report = asyncio.run(run_isolated(build_pe(), Limits(), TimeoutChildDocker()))
    assert report.analysis.status == "partial"
    assert any(f.kind == "import" for f in report.evidence)
    assert any(f.kind == "string" for f in report.evidence)
    assert not any(f.kind == "yara_match" for f in report.evidence)
    assert any(r.code == "yara_timeout" for r in report.extractor_errors)


def test_container_runtime_restrictions():
    async def check():
        client = DockerCLI()
        name = "lupabin-test-" + uuid4().hex
        args = container_args(name, IMAGE, Limits())
        prefix = args[: args.index(IMAGE)]
        probe = (
            "import os, json, socket\n"
            "result = {'uid': os.getuid(), 'interfaces': socket.if_nameindex()}\n"
            "try:\n"
            "    open('/tmp/lupabin-write-probe', 'wb').close()\n"
            "    result['write_errno'] = 0\n"
            "except OSError as e:\n"
            "    result['write_errno'] = e.errno\n"
            "print(json.dumps(result))\n"
        )
        try:
            created = await client.run(
                (*prefix, "--entrypoint=/app/.venv/bin/python", IMAGE, "-c", probe)
            )
            assert created.code == 0
            inspected = await client.run(("container", "inspect", name), limit=65536)
            config = json.loads(inspected.stdout)[0]
            host = config["HostConfig"]
            assert host["NetworkMode"] == "none"
            assert host["ReadonlyRootfs"] is True
            assert host["Memory"] == 536870912
            assert host["MemorySwap"] == 536870912
            assert host["NanoCpus"] == 1_000_000_000
            assert host["PidsLimit"] == 64
            assert "ALL" in host["CapDrop"]
            assert "no-new-privileges:true" in host["SecurityOpt"]
            assert config["Mounts"] == []
            result = await client.run(("start", "--attach", "--interactive", name))
            assert result.code == 0
            facts = json.loads(result.stdout)
            assert facts["uid"] == 65532
            assert [entry[1] for entry in facts["interfaces"]] == ["lo"]
            assert facts["write_errno"] == 30
        finally:
            await remove_owned_container(client, name)

    asyncio.run(check())


def test_timeout_removes_real_container():
    class SlowDocker(DockerCLI):
        def __init__(self):
            super().__init__()
            self.name = None

        async def run(self, args, **kwargs):
            if args[0] == "create":
                self.name = args[args.index("--name") + 1]
                image_index = next(i for i, arg in enumerate(args) if arg.startswith("sha256:"))
                args = (
                    *args[:image_index],
                    "--entrypoint=/app/.venv/bin/python",
                    args[image_index],
                    "-c",
                    "import time; time.sleep(60)",
                )
            return await super().run(args, **kwargs)

    async def check():
        client = SlowDocker()
        with pytest.raises(LupaBinError) as caught:
            await run_isolated(build_pe(), Limits(timeout_seconds=1), client)
        assert caught.value.code == "timeout"
        result = await client.run(
            (
                "container",
                "ls",
                "--all",
                "--filter",
                f"name=^/{client.name}$",
                "--format",
                "{{.Names}}",
            )
        )
        assert result.code == 0
        assert not result.stdout.strip()

    asyncio.run(check())


def test_real_cli_didactic_report_and_checked_explanation(tmp_path):
    from typer.testing import CliRunner

    from lupabin.cli import app
    from tests.fixtures.pe_builder import build_decode_demo

    runner = CliRunner()
    sample = tmp_path / "decode.bin"
    sample.write_bytes(build_decode_demo())
    readable = runner.invoke(app, ["analyze", str(sample)])
    assert readable.exit_code == 0
    assert "worker aislado" in readable.stdout
    assert "La clave la" in readable.stdout and "Límite:" in readable.stdout
    saved = runner.invoke(app, ["analyze", str(sample), "--json"])
    report = tmp_path / "report.json"
    report.write_text(saved.stdout, encoding="utf-8")
    checked = runner.invoke(app, ["explain", str(report), "--sample", str(sample)])
    assert checked.exit_code == 0
    assert "contrastado con la muestra" in checked.stdout
