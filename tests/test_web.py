"""The web service: same isolated analysis and report as the CLI, limits and page safety."""

import json
import re
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from dissect.errors import DissectError
from dissect.evidence.models import Limits
from dissect.transport import Completed
from dissect.web import app as web
from dissect.web.guard import RateLimit, Settings, client_address
from tests.fixtures.pe_builder import build_call_demo, build_pe, build_same_function_demo
from tests.test_render import HOSTILE_DLL, HOSTILE_FUNCTION
from tests.test_runner import FakeDocker

STATIC = Path(web.__file__).parent / "static"
RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"


class Worker(FakeDocker):
    """FakeDocker whose worker exits as the real one does: 0, 3 or 1 by the report status."""

    async def run(self, args, *, data=b"", timeout=10, limit=8192):
        result = await super().run(args, data=data, timeout=timeout, limit=limit)
        if args[0] == "start" and result.code == 0 and self.output is None:
            status = json.loads(result.stdout)["analysis"]["status"]
            code = {"completed": 0, "partial": 3, "failed": 1}[status]
            return Completed(code, result.stdout, result.stderr)
        return result


def client(settings=None, docker=None, consult=None):
    """A test client whose worker is FakeDocker and whose VirusTotal calls are recorded."""
    docker = docker or Worker()
    calls = []

    def recorded(sha256, data, upload=False):
        calls.append((sha256, upload))
        if consult is None:
            raise AssertionError("VirusTotal must not be consulted")
        return consult(sha256, data, upload)

    app = web.create_app(
        settings or Settings(virustotal=False, upload=False),
        transport=lambda: docker,
        consult=recorded,
    )
    test = TestClient(app)
    test.docker, test.vt_calls = docker, calls
    return test


def analyze(test, data, query=""):
    return test.post(
        f"/api/analyze{query}", content=data, headers={"content-type": "application/octet-stream"}
    )


# --- the page and its headers ------------------------------------------------------------


def test_the_page_and_its_assets_are_served_with_strict_headers():
    test = client()
    page = test.get("/")
    assert page.status_code == 200 and "Analizar un archivo" in page.text
    csp = page.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp
    assert "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
    assert page.headers["x-content-type-options"] == "nosniff"
    assert page.headers["referrer-policy"] == "no-referrer"
    for asset in ("app.js", "app.css", "favicon.svg"):
        assert test.get(f"/static/{asset}").status_code == 200
    assert test.get("/api/config").headers["cache-control"] == "no-store"


def test_the_page_has_no_inline_code_and_the_script_never_builds_html_from_data():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", html), "inline script"
    assert "<style" not in html and " style=" not in html
    assert not re.search(r"\son[a-z]+=", html), "inline event handler"
    script = (STATIC / "app.js").read_text(encoding="utf-8")
    for sink in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
    ):
        assert sink not in script, sink


def test_element_ids_on_the_page_are_unique():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    ids = re.findall(r'id="([^"]+)"', html)
    assert len(ids) == len(set(ids))


def test_config_reports_the_limits_and_whether_virustotal_is_offered():
    shown = client(Settings(virustotal=True, upload=False)).get("/api/config").json()
    assert shown["max_bytes"] == Limits().input_bytes
    assert shown["virustotal"] is True and shown["upload"] is False


# --- analysis ---------------------------------------------------------------------------


def test_an_upload_is_analysed_in_the_isolated_worker_and_explained():
    test = client()
    data = build_call_demo("RegSetKeyValueW", {0: 0x80000001, 1: RUN, 2: "DissectTraining"})
    response = analyze(test, data)
    assert response.status_code == 200
    body = response.json()
    create = next(args for args, _ in test.docker.calls if args[0] == "create")
    assert "--network=none" in create and "--read-only" in create
    start = next(sent for args, sent in test.docker.calls if args[0] == "start")
    assert start == data  # the sample goes to the worker as raw stdin
    assert body["status"] == "completed" and body["sample"]["size"] == len(data)
    (group,) = body["summary"]["groups"]
    assert group["tactic"] == "Persistencia"
    assert group["items"][0]["techniques"][0].startswith("T1547.001")
    assert {item["level"] for item in body["items"]} == {"observed", "inferred"}
    assert json.loads(body["downloads"]["report"])["sample"]["sha256"] == body["sample"]["sha256"]
    assert body["downloads"]["markdown"].startswith("# Dissect: informe didáctico")
    assert body["virustotal"] is None and body["glossary"]


def test_x64_same_function_capabilities_reach_the_page():
    body = analyze(client(), build_same_function_demo()).json()
    rules = {item["rule"] for item in body["items"]}
    assert {"capability.run_key_open_and_set@1", "code.functions@1"} <= rules


def test_sample_text_is_neutralised_before_it_leaves_the_server():
    data = build_pe(dll=HOSTILE_DLL, function=HOSTILE_FUNCTION)
    body = analyze(client(), data).json()
    shown = json.dumps({k: v for k, v in body.items() if k != "downloads"}, ensure_ascii=False)
    assert "\x1b" not in shown and "\u202e" not in shown
    assert "\u27e8U+001B\u27e9" in shown


@pytest.mark.parametrize(
    ("data", "status", "code"),
    [
        pytest.param(b"", 400, "input_empty", id="empty"),
        pytest.param(b"\0" * (Limits().input_bytes + 1), 413, "input_limit", id="too-large"),
    ],
)
def test_empty_or_too_large_uploads_never_reach_the_worker(data, status, code):
    test = client()
    response = analyze(test, data)
    assert response.status_code == status and response.json()["error"] == code
    assert not any(args[0] == "create" for args, _ in test.docker.calls)


@pytest.mark.parametrize(
    ("failure", "status", "code"),
    [
        ("docker", 503, "docker_unavailable"),
        ("image", 503, "image_unavailable"),
        ("worker", 500, "worker_failure"),
    ],
)
def test_worker_failures_are_reported_with_their_reviewed_message(failure, status, code):
    response = analyze(client(docker=Worker(failure=failure)), build_pe())
    assert response.status_code == status
    assert response.json() == {"error": code, "message": DissectError(code).args[0]}


def test_a_docker_cli_that_is_missing_is_a_503():
    def missing():
        raise DissectError("docker_unavailable")

    app = web.create_app(Settings(virustotal=False), transport=missing)
    response = analyze(TestClient(app), build_pe())
    assert response.status_code == 503


# --- VirusTotal, as in the CLI ------------------------------------------------------------


def vt_report(sha256, data, upload):
    from datetime import UTC, datetime

    from dissect.virustotal.models import VirusTotalReport

    return VirusTotalReport(
        sample_sha256=sha256,
        retrieved_at=datetime(2026, 9, 25, tzinfo=UTC),
        status="found",
        uploaded=upload,
        permalink=f"https://www.virustotal.com/gui/file/{sha256}",
        stats={"malicious": 2, "undetected": 60},
    )


def test_virustotal_is_consulted_and_uploads_only_when_asked_and_allowed():
    test = client(Settings(virustotal=True, upload=True), consult=vt_report)
    body = analyze(test, build_pe(), "?virustotal=1&upload=1").json()
    assert body["virustotal"]["stats"] == {"malicious": 2, "undetected": 60}
    assert test.vt_calls[-1][1] is True
    analyze(test, build_pe(), "?virustotal=1&upload=0")
    assert test.vt_calls[-1][1] is False
    body = analyze(test, build_pe(), "?virustotal=0").json()
    assert body["virustotal"] is None and len(test.vt_calls) == 2


def test_the_server_can_forbid_uploads_whatever_the_page_asks():
    test = client(Settings(virustotal=True, upload=False), consult=vt_report)
    analyze(test, build_pe(), "?virustotal=1&upload=1")
    assert test.vt_calls == [(test.vt_calls[0][0], False)]


def test_settings_follow_the_same_switches_as_the_cli():
    assert Settings.from_env({"DISSECT_VIRUSTOTAL": "off"}).virustotal is False
    assert Settings.from_env({"DISSECT_VIRUSTOTAL": "off"}).upload is False
    assert Settings.from_env({"DISSECT_VIRUSTOTAL_UPLOAD": "0"}).upload is False
    shown = Settings.from_env({"DISSECT_WEB_RATE": "3/60", "DISSECT_WEB_CONCURRENCY": "2"})
    assert (shown.rate, shown.window, shown.concurrency) == (3, 60.0, 2)
    with pytest.raises(ValueError):
        Settings.from_env({"DISSECT_WEB_CONCURRENCY": "0"})


# --- limits of the public service ---------------------------------------------------------


def test_each_client_address_gets_its_own_budget():
    test = client(Settings(rate=2, window=600, virustotal=False))
    assert [analyze(test, build_pe()).status_code for _ in range(3)] == [200, 200, 429]
    assert "límite de 2 análisis" in analyze(test, build_pe()).json()["message"]


def test_the_rate_window_slides():
    now = [0.0]
    limit = RateLimit(2, 10, clock=lambda: now[0])
    assert limit.allow("a") and limit.allow("a") and not limit.allow("a")
    assert limit.allow("b")
    now[0] = 10.5
    assert limit.allow("a")


def test_only_a_trusted_local_proxy_decides_the_client_address():
    assert client_address("203.0.113.9", "198.51.100.1", trust_proxy=True) == "203.0.113.9"
    assert client_address("127.0.0.1", "1.1.1.1, 198.51.100.7", trust_proxy=True) == "198.51.100.7"
    assert client_address("127.0.0.1", "198.51.100.7", trust_proxy=False) == "127.0.0.1"


def test_a_request_that_waits_too_long_for_a_free_slot_is_told_to_retry():
    import asyncio

    from dissect.web.guard import Busy, Slots

    async def scenario():
        slots = Slots(1, 0.05)
        async with slots:
            with pytest.raises(Busy):
                async with slots:
                    pass

    asyncio.run(scenario())


def test_health_checks_the_worker_image_without_analysing():
    test = client()
    assert test.get("/api/health").json()["status"] == "ok"
    assert all(args[0] == "image" for args, _ in test.docker.calls)
    assert client(docker=Worker(failure="image")).get("/api/health").status_code == 503
