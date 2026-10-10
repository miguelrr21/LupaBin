import json

import pytest

from lupabin.evidence.models import Report
from lupabin.ingest.reader import from_bytes
from lupabin.saved_report import check_against_sample
from lupabin.web.guard import Settings
from tests import generate_web_example as generator
from tests.fixtures.pe_builder import build_capability_demo
from tests.test_web import client


def test_static_example_is_served_without_worker_or_virustotal():
    test = client(Settings(virustotal=True, upload=True))
    response = test.get("/static/example.json")
    assert response.status_code == 200
    body = response.json()
    assert body["example"] == "capability-demo" and body["virustotal"] is None
    report = Report.model_validate_json(body["downloads"]["report"])
    assert body["sample"]["sha256"] == report.sample.sha256
    check_against_sample(report, from_bytes(build_capability_demo(), report.analysis.limits))
    assert "EJEMPLO SINTÉTICO" in body["downloads"]["html"]
    assert not test.docker.calls and not test.vt_calls


def test_example_generator_refuses_to_overwrite_before_analyzing(tmp_path, monkeypatch):
    target = tmp_path / "example.json"
    target.write_text("keep this file", encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["generate_web_example", "--output", str(target)])
    monkeypatch.setattr(generator, "build_example", lambda: pytest.fail("must not analyze"))
    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        generator.main()
    assert target.read_text(encoding="utf-8") == "keep this file"


def test_example_generator_writes_only_the_selected_new_file(tmp_path, monkeypatch):
    target = tmp_path / "selected.json"
    default = tmp_path / "default.json"
    payload = {"example": "synthetic test output"}
    monkeypatch.setattr("sys.argv", ["generate_web_example", "--output", str(target)])
    monkeypatch.setattr(generator, "OUTPUT", default)
    monkeypatch.setattr(generator, "build_example", lambda: payload)
    generator.main()
    assert json.loads(target.read_text(encoding="utf-8")) == payload
    assert not default.exists()
