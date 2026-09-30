import asyncio
import base64
import io
import json
import threading
import zipfile

import httpx
import pytest
from typer.testing import CliRunner

from lupabin.analysis import analyze_bytes
from lupabin.cli import app
from lupabin.errors import LupaBinError
from lupabin.evidence.models import Report
from lupabin.explain.engine import ExplanationError
from lupabin.web import app as web
from lupabin.web.guard import Settings, Slots
from tests.fixtures.pe_builder import build_demo, build_pe
from tests.test_web import analyze, client


@pytest.mark.parametrize("data", [build_pe(), build_demo(corrupt=True), b"\0" * 32])
def test_one_web_report_preserves_facts_and_offers_both_learning_tools(data):
    response = analyze(client(), data)
    assert response.status_code == 200
    body = response.json()
    report = Report.model_validate_json(body["downloads"]["report"])
    assert body["challenge"]["challenge"]["sample_sha256"] == report.sample.sha256
    with zipfile.ZipFile(io.BytesIO(base64.b64decode(body["downloads"]["ghidra"]))) as archive:
        assert set(archive.namelist()) == {"lupabin-ghidra.json", "ImportLupaBin.java"}
        exported = json.loads(archive.read("lupabin-ghidra.json"))
    assert exported["report"] == report.model_dump(mode="json")
    assert body["virustotal"] is None
    assert body["status"] == report.analysis.status
    if report.analysis.status == "partial":
        assert body["notes"]
        assert any(q["rule"] == "coverage" for q in body["challenge"]["challenge"]["questions"])


def test_challenge_sample_check_rejects_forged_literal_before_generating_questions(tmp_path):
    literal = "LUPABIN LITERAL PROOF"
    data = build_pe() + b"\0" + literal.encode() + b"\0"
    document = analyze_bytes(data).model_dump(mode="json")
    fact = next(
        item
        for item in document["evidence"]
        if item["kind"] == "string" and item["data"]["text"] == literal
    )
    fact["data"]["text"] = "Z" * len(literal)
    fact["data"]["raw_hex"] = fact["data"]["text"].encode().hex()
    forged = Report.model_validate_json(json.dumps(document))
    sample = tmp_path / "sample.bin"
    saved = tmp_path / "report.json"
    sample.write_bytes(data)
    saved.write_text(forged.model_dump_json(), encoding="utf-8")
    result = CliRunner().invoke(app, ["challenge", str(saved), "--sample", str(sample), "--json"])
    assert result.exit_code == 1
    assert json.loads(result.stderr)["error"]["code"] == "report_mismatch"
    assert not result.stdout


@pytest.mark.parametrize("error", [ValueError, OSError, LupaBinError])
def test_export_failure_preserves_the_same_report_and_challenge(monkeypatch, error):
    data = build_pe()
    report = analyze_bytes(data)

    async def isolated(*args):
        return report

    monkeypatch.setattr(web, "run_isolated", isolated)
    expected = analyze(client(), data).json()

    def unavailable(*args):
        raise error("report_mismatch")

    monkeypatch.setattr(web, "ghidra_bundle", unavailable)
    response = analyze(client(), data)
    assert response.status_code == 200
    shown = response.json()
    assert shown["challenge"] == expected["challenge"]
    assert shown["downloads"]["report"] == expected["downloads"]["report"]
    assert shown["downloads"]["markdown"] == expected["downloads"]["markdown"]
    assert "ghidra" not in shown["downloads"]
    assert shown["downloads"]["ghidra_error"]


@pytest.mark.parametrize("stage", ["explain", "validate", "web_challenge"])
def test_host_response_failure_never_looks_complete_and_releases_the_slot(monkeypatch, stage):
    owner = web.view if stage == "web_challenge" else web
    original = getattr(owner, stage)

    def broken(*args):
        if stage == "web_challenge":
            raise ValueError("invalid challenge")
        raise ExplanationError("invalid explanation")

    test = client(Settings(virustotal=False, concurrency=1, queue_seconds=0.05))
    monkeypatch.setattr(owner, stage, broken)
    if stage == "web_challenge":
        with pytest.raises(ValueError, match="invalid challenge"):
            analyze(test, build_pe())
    else:
        response = analyze(test, build_pe())
        assert response.status_code == 500
        assert response.json()["error"] == "invalid_worker_output"
        assert "downloads" not in response.json()
    monkeypatch.setattr(owner, stage, original)
    assert analyze(test, build_pe()).status_code == 200


def test_all_host_response_work_keeps_the_slot_and_runs_off_the_event_loop(monkeypatch):
    active = []
    stages = []
    loop_threads = []

    class ObservedSlots(Slots):
        async def __aenter__(self):
            await super().__aenter__()
            active.append(True)
            loop_threads.append(threading.get_ident())

        async def __aexit__(self, *exc):
            active.pop()
            await super().__aexit__(*exc)

    monkeypatch.setattr(web, "Slots", ObservedSlots)
    for owner, name in (
        (web, "ghidra_bundle"),
        (web, "explain"),
        (web, "validate"),
        (web.view, "build"),
        (web.view, "web_challenge"),
        (web.view, "ghidra_download"),
        (web, "JSONResponse"),
    ):
        original = getattr(owner, name)

        def checked(*args, _original=original, _name=name, **kwargs):
            assert active, f"{_name} ran outside the analysis slot"
            assert threading.get_ident() != loop_threads[-1], f"{_name} blocked the event loop"
            stages.append(_name)
            return _original(*args, **kwargs)

        monkeypatch.setattr(owner, name, checked)
    response = analyze(client(), build_pe())
    assert response.status_code == 200
    assert set(stages) == {
        "ghidra_bundle",
        "explain",
        "validate",
        "build",
        "web_challenge",
        "ghidra_download",
        "JSONResponse",
    }
    assert not active


@pytest.mark.parametrize("cancel", [False, True])
def test_slow_host_work_cannot_admit_another_worker(monkeypatch, cancel):
    data = build_pe()
    report = analyze_bytes(data)
    entered, release = threading.Event(), threading.Event()
    calls = []
    original = web.explain

    async def isolated(*args):
        calls.append(True)
        return report

    def slow(*args):
        if not entered.is_set():
            entered.set()
            assert release.wait(5), "test did not release host work"
        return original(*args)

    monkeypatch.setattr(web, "run_isolated", isolated)
    monkeypatch.setattr(web, "explain", slow)

    async def scenario():
        application = web.create_app(Settings(virustotal=False, concurrency=1, queue_seconds=0.05))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application), base_url="http://test"
        ) as test:
            first = asyncio.create_task(test.post("/api/analyze", content=data))
            try:
                assert await asyncio.to_thread(entered.wait, 3)
                if cancel:
                    first.cancel()
                    await asyncio.sleep(0)
                    first.cancel()
                config = await asyncio.wait_for(test.get("/api/config"), 1)
                assert config.status_code == 200
                second = await test.post("/api/analyze", content=data)
                assert second.status_code == 503
                assert second.json()["error"] == "busy"
                assert len(calls) == 1
            finally:
                release.set()
                if cancel:
                    with pytest.raises(asyncio.CancelledError):
                        await first
                else:
                    assert (await first).status_code == 200
            assert (await test.post("/api/analyze", content=data)).status_code == 200
            assert len(calls) == 2

    asyncio.run(scenario())
