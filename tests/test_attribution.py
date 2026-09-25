"""The author's attribution travels with every way LupaBin is distributed."""

import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[1]
AUTHOR = "Miguel Ángel Rodríguez Romero"
ATTRIBUTION = f"Based on LupaBin, by {AUTHOR}"


def test_notice_names_the_author_and_the_required_attribution():
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert AUTHOR in notice and ATTRIBUTION in notice
    assert "4(d)" in notice and "TRADEMARKS.md" in notice


def test_the_package_carries_the_notice_and_its_author():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["license"] == "Apache-2.0"
    assert "NOTICE" in project["license-files"]
    assert {"name": AUTHOR} in project["authors"]


def test_the_worker_image_carries_the_notice():
    dockerfile = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
    ignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
    assert "!NOTICE" in ignore
    assert "/app/NOTICE" in dockerfile


def test_the_web_page_credits_the_author():
    page = (ROOT / "src" / "lupabin" / "web" / "static" / "index.html").read_text(encoding="utf-8")
    assert AUTHOR in page


def test_contributions_go_through_the_agreement():
    template = (ROOT / ".github" / "pull_request_template.md").read_text(encoding="utf-8")
    assert "CLA.md" in template and "acepto" in template
    assert "relicen" in (ROOT / "CLA.md").read_text(encoding="utf-8")
