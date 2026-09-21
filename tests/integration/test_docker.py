import asyncio
import json
from uuid import uuid4

import pytest

from dissect.errors import DissectError
from dissect.evidence.models import Limits
from dissect.runner import IMAGE, container_args, remove_owned_container, run_isolated
from dissect.transport import DockerCLI
from tests.fixtures.pe_builder import build_pe

pytestmark = pytest.mark.docker


@pytest.fixture(scope="module", autouse=True)
def require_docker():
    async def check():
        client = DockerCLI()
        info = await client.run(("info", "--format", "{{.OSType}}"))
        assert info.code == 0 and info.stdout.strip() == b"linux", "Linux Docker is required"
        image = await client.run(("image", "inspect", "--format", "{{.Id}}", IMAGE))
        assert image.code == 0, "Build dissect-worker:0.2.0 before integration tests"

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

    from dissect.cli import app
    from tests.fixtures.pe_builder import build_demo

    path = tmp_path / "demo.bin"
    path.write_bytes(build_demo(corrupt=corrupt))
    result = CliRunner().invoke(app, ["analyze", str(path), "--json"])
    assert result.exit_code == (3 if corrupt else 0)
    report = json.loads(result.stdout)
    assert report["schema_version"] == "0.2.0"
    kinds = {fact["kind"] for fact in report["evidence"]}
    assert {"pe_header", "section", "entropy", "string"} <= kinds
    assert ("header_anomaly" in kinds) == corrupt
    if not corrupt:
        assert "export" in kinds
    assert result.stderr == ""


def test_container_runtime_restrictions():
    async def check():
        client = DockerCLI()
        name = "dissect-test-" + uuid4().hex
        args = container_args(name, IMAGE, Limits())
        prefix = args[: args.index(IMAGE)]
        probe = (
            "import os, json, socket\n"
            "result = {'uid': os.getuid(), 'interfaces': socket.if_nameindex()}\n"
            "try:\n"
            "    open('/tmp/dissect-write-probe', 'wb').close()\n"
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
        with pytest.raises(DissectError) as caught:
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
