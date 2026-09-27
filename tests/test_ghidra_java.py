import asyncio
import os
import shutil
from pathlib import Path

import pytest

from lupabin.transport import run_command
from tests.fixtures.ghidra_stubs import STUBS

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "src/lupabin/ghidra/ImportLupaBin.java"


def ghidra_home():
    value = os.environ.get("LUPABIN_GHIDRA_HOME")
    if not value:
        pytest.skip("LUPABIN_GHIDRA_HOME no definido: comprobación opcional de APIs instaladas")
    path = Path(value)
    assert path.is_dir()
    return path


@pytest.mark.parametrize("real_gson", [False, True])
def test_java_importer_with_mock_program_only(tmp_path, real_gson):
    javac, java = shutil.which("javac"), shutil.which("java")
    if javac is None or java is None:
        pytest.skip("JDK no disponible: prueba del importador con dobles, no Ghidra real")
    classpath = str(tmp_path)
    if real_gson:
        jars = list(ghidra_home().glob("Ghidra/Framework/Generic/lib/gson-*.jar"))
        assert len(jars) == 1
        classpath += os.pathsep + str(jars[0])
    paths = []
    for name, content in STUBS.items():
        if real_gson and name.startswith("com/google/gson/"):
            continue
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        paths.append(str(path))
    paths += [str(SCRIPT), str(ROOT / "tests/fixtures/ImportLupaBinHarness.java")]
    result = asyncio.run(
        run_command(
            javac,
            (
                "-J-Xmx128m",
                "-encoding",
                "UTF-8",
                "-cp",
                classpath,
                "-d",
                str(tmp_path),
                *paths,
            ),
            timeout=60,
            limit=65536,
        )
    )
    assert result.code == 0, result.stdout + result.stderr
    result = asyncio.run(
        run_command(
            java,
            ("-Xmx128m", "-cp", classpath, "ImportLupaBinHarness", str(tmp_path))
            + (("real-gson",) if real_gson else ()),
            timeout=30,
            limit=65536,
        )
    )
    assert result.code == 0, result.stdout + result.stderr
    expected = 12 if real_gson else 11
    assert f"MOCK_ONLY: {expected} checks passed".encode() in result.stdout


def test_compile_against_installed_ghidra_without_running_it(tmp_path):
    home = ghidra_home()
    javac = shutil.which("javac")
    if javac is None:
        pytest.skip("JDK no disponible")
    directories = sorted(home.glob("Ghidra/**/lib"))
    assert directories
    classpath = os.pathsep.join(str(path / "*") for path in directories)
    result = asyncio.run(
        run_command(
            javac,
            (
                "-J-Xmx128m",
                "-encoding",
                "UTF-8",
                "-cp",
                classpath,
                "-d",
                str(tmp_path),
                str(SCRIPT),
            ),
            timeout=60,
            limit=65536,
        )
    )
    assert result.code == 0, result.stdout + result.stderr


def test_script_does_not_request_execution_or_analysis_and_requires_review():
    source = SCRIPT.read_text(encoding="utf-8")
    for forbidden in (
        "analyzeAll(",
        "analyzeChanges(",
        "disassemble(",
        "ProcessBuilder",
        "Runtime.getRuntime",
        "Emulator",
    ):
        assert forbidden not in source
    assert "return AnalysisMode.DISABLED" in source
    assert source.index("writeNew(previewPath, preview)") < source.index("!askYesNo(")
    assert source.index("!askYesNo(") < source.index("applyTransaction(document, entries")
    assert "currentProgram.endTransaction(transaction, commit)" in source
