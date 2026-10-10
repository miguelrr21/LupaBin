import os
import shutil
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SDIST_PATHS = [
    "src",
    "tests",
    "docs/evidence-schema.json",
    "docs/explanation-schema.json",
    "pyproject.toml",
    "LICENSE",
    "NOTICE",
    "TRADEMARKS.md",
    "CLA.md",
    "README.md",
]
RESOURCE_PATTERNS = (
    "ghidra/*.java",
    "glossary/entries/*.toml",
    "glossary/entries/*.json",
    "rules/YARA-LICENSE.txt",
    "rules/yara/*.yar",
    "rules/yara/*.json",
    "web/static/*",
)


def assert_metadata(data, project):
    metadata = BytesParser().parsebytes(data)
    assert metadata["Name"] == project["name"]
    assert metadata["Version"] == project["version"]
    assert metadata["License-Expression"] == project["license"]
    assert sorted(metadata.get_all("License-File", [])) == sorted(project["license-files"])


def assert_sdist(path, root):
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = config["project"]
    prefix = f"{project['name']}-{project['version']}/"
    root_files = SDIST_PATHS[2:]
    if (root / ".gitignore").is_file():
        root_files = [*root_files, ".gitignore"]
    with tarfile.open(path) as archive:
        names = archive.getnames()
        assert len(names) == len(set(names)), "duplicate archive members"
        for member in archive.getmembers():
            assert member.isfile()
            assert member.name.startswith(prefix)
            relative = member.name.removeprefix(prefix)
            assert relative in [*root_files, "PKG-INFO"] or relative.startswith(
                ("src/", "tests/")
            ), relative
        for relative in root_files:
            member = archive.extractfile(prefix + relative)
            assert member is not None
            with member:
                assert member.read() == (root / relative).read_bytes()
        for tree in ("src", "tests"):
            assert any(name.startswith(prefix + tree + "/") for name in names)
        member = archive.extractfile(prefix + "PKG-INFO")
        assert member is not None
        with member:
            assert_metadata(member.read(), project)


def test_sdist_selects_only_explicit_root_paths():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert config["tool"]["hatch"]["build"]["targets"]["sdist"] == {"only-include": SDIST_PATHS}


def test_hatchling_sdist_ignores_nested_worktrees(tmp_path):
    sdist = pytest.importorskip("hatchling.builders.sdist")
    if (ROOT / ".gitignore").is_file():
        shutil.copyfile(ROOT / ".gitignore", tmp_path / ".gitignore")
    for relative in SDIST_PATHS[2:]:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    for relative in (
        "src/lupabin/__init__.py",
        "tests/test_example.py",
        ".devin/worktrees/other/src/lupabin/ghidra/ImportLupaBin.java",
        "nested-worktree/src/lupabin/__init__.py",
        "nested-worktree/tests/test_example.py",
        "nested-worktree/README.md",
        "nested-worktree/LICENSE",
        "docs/unselected.json",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"fixture data\n")
    output = tmp_path / "dist"
    output.mkdir()
    built = list(sdist.SdistBuilder(str(tmp_path)).build(directory=str(output)))
    assert len(built) == 1
    assert_sdist(Path(built[0]), tmp_path)


def test_built_distributions_contain_only_expected_paths_and_resources():
    value = os.environ.get("LUPABIN_DISTRIBUTIONS")
    if not value:
        pytest.skip("LUPABIN_DISTRIBUTIONS no definido: requiere wheel y sdist ya construidos")
    directory = Path(value)
    wheels = list(directory.glob("lupabin-*.whl"))
    sources = list(directory.glob("lupabin-*.tar.gz"))
    assert len(wheels) == len(sources) == 1
    assert_sdist(sources[0], ROOT)
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    dist_info = f"{project['name']}-{project['version']}.dist-info/"
    with zipfile.ZipFile(wheels[0]) as wheel, tarfile.open(sources[0]) as source:
        names = wheel.namelist()
        assert len(names) == len(set(names)), "duplicate archive members"
        assert all(name.startswith(("lupabin/", dist_info)) for name in names)
        assert_metadata(wheel.read(dist_info + "METADATA"), project)
        for license_file in project["license-files"]:
            assert (
                wheel.read(dist_info + "licenses/" + license_file)
                == (ROOT / license_file).read_bytes()
            )
        for pattern in RESOURCE_PATTERNS:
            resources = list((ROOT / "src/lupabin").glob(pattern))
            assert resources, pattern
            for resource in resources:
                relative = resource.relative_to(ROOT / "src").as_posix()
                expected = resource.read_bytes()
                assert wheel.read(relative) == expected
                member = source.extractfile(
                    sources[0].name.removesuffix(".tar.gz") + "/src/" + relative
                )
                assert member is not None
                with member:
                    assert member.read() == expected


def test_package_version():
    import lupabin

    assert lupabin.__version__ == "0.14.0"
