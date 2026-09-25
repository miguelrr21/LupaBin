"""Relative links in the published documentation point to files of the repository."""

import os
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath

import pytest

ROOT = Path(__file__).parents[1]
LINK = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")


def tracked_files() -> set[str]:
    git = shutil.which("git")
    if git is None or not (ROOT / ".git").exists():
        pytest.skip("needs a git checkout (not an unpacked sdist)")
    listed = subprocess.run(  # noqa: S603 - fixed argv: the resolved git and a constant command
        [git, "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return set(listed.split("\n")) - {""}


def test_relative_links_point_to_tracked_files():
    # A local, untracked copy of a file must not hide a link that is broken for everyone
    # else, so targets are checked against what git publishes, not against the disk.
    tracked = tracked_files()
    folders = {str(parent) for name in tracked for parent in PurePosixPath(name).parents}
    documents = sorted(name for name in tracked if name.endswith(".md"))
    assert documents
    broken = []
    for name in documents:
        text = (ROOT / name).read_text(encoding="utf-8")
        for target in LINK.findall(text):
            if "://" in target or target.startswith("mailto:"):
                continue
            path = os.path.normpath(PurePosixPath(name).parent / target).replace("\\", "/")
            if path not in tracked and path not in folders:
                broken.append(f"{name} -> {target}")
    assert broken == []
