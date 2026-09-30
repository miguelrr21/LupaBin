import argparse
import asyncio
import hashlib
import json
import shutil
from importlib.resources import files
from pathlib import Path

from lupabin.evidence.models import Limits
from lupabin.ghidra import build_document
from lupabin.runner import run_isolated
from lupabin.transport import DockerCLI, run_command
from tests.fixtures.pe_builder import build_demo


async def verify(home: Path, root: Path, mutate_rollback: bool = False) -> None:
    java = shutil.which("java")
    if java is None:
        raise RuntimeError("Java is required")
    utility = home / "Ghidra/Framework/Utility/lib/Utility.jar"
    if not utility.is_file():
        raise ValueError("Ghidra installation not found")
    if any(part.startswith(".") for part in root.parts):
        raise ValueError("Ghidra projects require a path without dot-prefixed components")
    root.mkdir(parents=True, exist_ok=False)
    scripts = root / "scripts"
    projects = root / "projects"
    user_home = root / "home"
    settings, cache, temporary = (root / name for name in ("settings", "cache", "temporary"))
    for directory in (scripts, projects, user_home, settings, cache, temporary):
        directory.mkdir()
    data = build_demo() + b"\0LUPABIN UNMAPPED OVERLAY\0"
    sample = root / "sample.bin"
    sample.write_bytes(data)
    report = await run_isolated(data, Limits(), DockerCLI())
    document = build_document(report, data)
    exported = root / "lupabin-ghidra.json"
    exported.write_text(document.model_dump_json(), encoding="utf-8")
    source = files("lupabin.ghidra").joinpath("ImportLupaBin.java").read_bytes()
    if mutate_rollback:
        old = b"endTransaction(transaction, commit)"
        if source.count(old) != 1:
            raise ValueError("rollback mutation target changed")
        source = source.replace(old, b"endTransaction(transaction, true)")
    (scripts / "ImportLupaBin.java").write_bytes(source)
    document_hash = hashlib.sha256(exported.read_bytes()).hexdigest()
    shutil.copyfile(
        Path(__file__).parent / "fixtures/VerifyLupaBinReal.java",
        scripts / "VerifyLupaBinReal.java",
    )
    base = (
        "-Xmx512m",
        "-XX:ParallelGCThreads=1",
        "-XX:CICompilerCount=2",
        "-Djava.awt.headless=true",
        "-Djava.system.class.loader=ghidra.GhidraClassLoader",
        "-Dfile.encoding=UTF8",
        f"-Duser.home={user_home}",
        f"-Dapplication.settingsdir={settings}",
        f"-Dapplication.cachedir={cache}",
        f"-Dapplication.tempdir={temporary}",
        f"-Djava.io.tmpdir={temporary}",
        "-cp",
        str(utility),
        "ghidra.Ghidra",
        "ghidra.app.util.headless.AnalyzeHeadless",
        str(projects),
        "LupaBinSynthetic",
    )
    for mode in ("seed", "cancel", "apply", "persist"):
        load = (
            (
                "-import",
                str(sample),
                "-loader-loadLibraries",
                "false",
                "-loader-linkExistingProjectLibraries",
                "false",
                "-loader-libraryLoadDepth",
                "0",
            )
            if mode == "seed"
            else ("-process", "sample.bin")
        )
        result = await run_command(
            java,
            (
                *base,
                *load,
                "-noanalysis",
                "-max-cpu",
                "1",
                "-scriptPath",
                str(scripts),
                "-postScript",
                "VerifyLupaBinReal.java",
                str(exported),
                mode,
                str(root),
            ),
            timeout=180,
            limit=1024 * 1024,
            stderr_limit=1024 * 1024,
        )
        output = result.stdout + result.stderr
        (root / f"{mode}.log").write_bytes(output)
        if mutate_rollback and mode == "apply":
            if b"rollback left changes after normal outer commit" not in output:
                print(output.decode("utf-8", "replace"))
                raise RuntimeError("rollback mutation was not detected for the expected reason")
            print("LUPABIN_GHIDRA_MUTATION_DETECTED", flush=True)
            return
        result_file = root / f"{mode}-result.json"
        verified = (
            json.loads(result_file.read_text(encoding="utf-8")) if result_file.exists() else {}
        )
        valid = result.code == 0 and verified == {
            "phase": mode,
            "ok": True,
            "document_sha256": document_hash,
            "injection_reached": mode == "cancel",
        }
        if not valid:
            print(output.decode("utf-8", "replace"))
            raise RuntimeError(f"Real Ghidra integration verification failed: {mode}")
        print(json.dumps(verified), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ghidra", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mutate-rollback", action="store_true")
    args = parser.parse_args()
    asyncio.run(verify(args.ghidra.resolve(), args.root.resolve(), args.mutate_rollback))


if __name__ == "__main__":
    main()
