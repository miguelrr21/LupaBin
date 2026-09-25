"""The server installer only references files that exist next to it."""

import re
from pathlib import Path

SERVER = Path(__file__).parents[1] / "deploy" / "server"


def test_every_file_the_installer_copies_exists():
    script = (SERVER / "install.sh").read_text(encoding="utf-8")
    names = set(re.findall(r'"\$HERE/([\w.-]+)"', script))
    assert names, "the installer copies no files"
    assert sorted(n for n in names if not (SERVER / n).is_file()) == []
