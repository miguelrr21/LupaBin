import asyncio
import json
import struct
from uuid import uuid4

import pytest

from lupabin.errors import LupaBinError
from lupabin.evidence.models import Limits
from lupabin.runner import IMAGE, container_args, remove_owned_container, run_isolated
from lupabin.transport import DockerCLI
from tests.fixtures.pe_builder import build_dotnet_demo, build_pe

pytestmark = pytest.mark.docker


@pytest.fixture(scope="module", autouse=True)
def require_docker():
    async def check():
        client = DockerCLI()
        info = await client.run(("info", "--format", "{{.OSType}}"))
        assert info.code == 0 and info.stdout.strip() == b"linux", "Linux Docker is required"
        image = await client.run(("image", "inspect", "--format", "{{.Id}}", IMAGE))
        assert image.code == 0, "Build lupabin-worker:0.15.0 before integration tests"

    asyncio.run(check())


@pytest.mark.parametrize("bits", [32, 64])
def test_real_worker_round_trip(bits):
    report = asyncio.run(run_isolated(build_pe(bits=bits), Limits(), DockerCLI()))
    assert report.analysis.status == "completed"
    assert (
        next(f for f in report.evidence if f.kind == "import").data.function.text == "ExitProcess"
    )
    assert {"pe_header", "section", "entropy", "string"} <= {f.kind for f in report.evidence}


@pytest.mark.parametrize("bits", [32, 64])
def test_dotnet_round_trip_has_all_five_kinds_and_host_checked_locations(bits):
    from lupabin.evidence.dotnet_checks import verify_dotnet
    from lupabin.evidence.models import Report

    data = build_dotnet_demo(bits=bits)
    report = asyncio.run(run_isolated(data, Limits(), DockerCLI()))
    restored = Report.model_validate_json(report.model_dump_json())
    assert restored.analysis.status == "completed"
    assert {
        "dotnet_metadata",
        "dotnet_pinvoke",
        "dotnet_string",
        "dotnet_member",
        "dotnet_type",
    } <= {fact.kind for fact in restored.evidence}
    verify_dotnet(restored.evidence, data, 1024)
    root = next(fact for fact in restored.evidence if fact.kind == "dotnet_metadata")
    assert root.data.assembly.name.raw_hex == b"training".hex()
    assert root.data.assembly.version == (1, 2, 3, 4)
    assert (root.data.type_defs, root.data.member_refs, root.data.pinvokes) == (2, 2, 1)
    for fact in restored.evidence:
        if fact.kind.startswith("dotnet_"):
            assert fact.location.offset + fact.location.length <= len(data)
            if fact is not root:
                assert fact.provenance.evidence_ids == (root.id,)


@pytest.mark.parametrize("bits", [32, 64])
def test_triage_round_trip_has_four_kinds_and_host_checked_bytes(bits):
    from lupabin.evidence.models import Report
    from lupabin.evidence.triage_checks import verify_triage
    from lupabin.explain.engine import explain, validate
    from lupabin.glossary.catalog import load_glossary
    from tests.test_triage import KINDS, PDB_PATH, build, facts, parts, reasons

    data = build(bits=bits)
    report = asyncio.run(run_isolated(data, Limits(), DockerCLI()))
    restored = Report.model_validate_json(report.model_dump_json())
    assert restored.schema_version == "0.15.0"
    assert restored.analysis.status == "completed"
    assert set(parts(restored).values()) == {"complete"}
    assert not reasons(restored)
    assert set(KINDS) <= {fact.kind for fact in restored.evidence}
    assert facts(restored, "pdb_reference")[0].data.path.raw_hex == PDB_PATH.hex()
    assert [(fact.data.key, fact.data.value) for fact in facts(restored, "version_string")] == [
        ("CompanyName", "Lupa Example"),
        ("OriginalFilename", "demo.exe"),
    ]
    entry = facts(restored, "certificate_entry")[0]
    assert (entry.data.revision, entry.data.certificate_type, entry.data.padding) == (0x200, 2, 4)
    assert [
        data[fact.location.offset : fact.location.offset + fact.location.length]
        for fact in facts(restored, "overlay")
    ] == [b"OVERLAY!", b"tail"]
    for fact in restored.evidence:
        if fact.kind in KINDS:
            assert fact.confidence == "observed"
            assert fact.location.offset + fact.location.length <= len(data)
    verify_triage(restored.evidence, data, restored.analysis.limits.string_characters)
    glossary = load_glossary()
    explanation = explain(restored, glossary)
    assert {
        "debug.pdb@1",
        "version.strings@1",
        "signature.certificates@1",
        "overlay.data@1",
    } <= {item.rule for item in explanation.items}
    assert len(validate(explanation, restored, glossary)) == len(explanation.items)


@pytest.mark.parametrize(
    "kind,field,value",
    [
        ("pdb_reference", "debug_index", 1),
        ("version_string", "language", 0x0C0A),
        ("certificate_entry", "content_sha256", "0" * 64),
        ("overlay", "sha256", "0" * 64),
    ],
)
def test_triage_host_rejects_tampered_real_worker_output(kind, field, value):
    from lupabin.evidence.models import Report
    from lupabin.transport import Completed
    from tests.test_triage import build

    class TamperedDocker(DockerCLI):
        altered = False
        removed = False

        async def run(self, args, **kwargs):
            result = await super().run(args, **kwargs)
            if args[0] == "start":
                assert result.code == 0
                document = json.loads(result.stdout)
                fact = next(item for item in document["evidence"] if item["kind"] == kind)
                fact["data"][field] = value
                payload = json.dumps(document).encode("utf-8")
                Report.model_validate_json(payload)
                self.altered = True
                return Completed(result.code, payload, result.stderr)
            if args[:2] == ("container", "rm"):
                self.removed = result.code == 0
            return result

    client = TamperedDocker()
    with pytest.raises(LupaBinError) as caught:
        asyncio.run(run_isolated(build(), Limits(), client))
    assert caught.value.code == "invalid_worker_output"
    assert client.altered and client.removed


def test_triage_malformed_certificate_blocks_overlay_in_container():
    from tests.test_triage import build, facts, parts, reasons

    malformed = struct.pack("<IHH", 4096, 0x200, 2) + b"\0" * 8
    report = asyncio.run(run_isolated(build(table=malformed), Limits(), DockerCLI()))
    assert report.analysis.status == "partial"
    assert not facts(report, "certificate_entry") and not facts(report, "overlay")
    assert facts(report, "pdb_reference") and facts(report, "version_string")
    assert parts(report)["certificates"] == "partial"
    assert parts(report)["overlay"] == "blocked"
    assert reasons(report) == {
        ("certificates", "triage_unreadable"),
        ("overlay", "dependency_omitted"),
    }


def test_triage_version_character_limit_is_declared_in_container():
    from tests.test_triage import build, facts, parts, reasons

    data = build(strings=(("Comments", "x" * 1025), ("ProductName", "Lupa")))
    report = asyncio.run(run_isolated(data, Limits(), DockerCLI()))
    assert report.analysis.status == "partial"
    assert [fact.data.key for fact in facts(report, "version_string")] == ["ProductName"]
    assert parts(report)["version_info"] == "partial"
    assert ("version_info", "triage_limit") in reasons(report)


def test_dotnet_unoptimized_layout_is_explicitly_blocked_in_container():
    report = asyncio.run(run_isolated(build_dotnet_demo(stream=b"#-"), Limits(), DockerCLI()))
    assert not any(fact.kind.startswith("dotnet_") for fact in report.evidence)
    assert "dotnet_unsupported_layout" in {
        issue.code for issue in (*report.extractor_errors, *report.limitations)
    }
    pe = next(run for run in report.extractor_runs if run.source == "pe")
    assert next(part for part in pe.components if part.name == "dotnet").status == "blocked"


def test_dotnet_unreadable_row_is_counted_and_keeps_next_ordinal_in_container():
    from lupabin.evidence import dotnet
    from lupabin.evidence.dotnet_checks import verify_dotnet

    data = build_dotnet_demo()
    offset = dotnet.read(data).members[0].offset + 2
    broken = data[:offset] + b"\xff\x7f" + data[offset + 2 :]
    report = asyncio.run(run_isolated(broken, Limits(), DockerCLI()))
    root = next(fact for fact in report.evidence if fact.kind == "dotnet_metadata")
    assert (root.data.unreadable, root.data.member_refs) == (1, 2)
    members = [fact for fact in report.evidence if fact.kind == "dotnet_member"]
    assert [(fact.data.row, fact.data.name.raw_hex) for fact in members] == [(2, b"Empty".hex())]
    assert "dotnet_unreadable_rows" in {
        issue.code for issue in (*report.extractor_errors, *report.limitations)
    }
    pe = next(run for run in report.extractor_runs if run.source == "pe")
    assert next(part for part in pe.components if part.name == "dotnet").status == "partial"
    verify_dotnet(report.evidence, broken, 1024)


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
    assert report["schema_version"] == "0.15.0"
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
