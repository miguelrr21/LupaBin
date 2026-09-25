"""The web service: same isolated analysis and report as the CLI, limits and page safety."""

import json
import re
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from lupabin.errors import LupaBinError
from lupabin.evidence.models import Limits
from lupabin.transport import Completed
from lupabin.web import app as web
from lupabin.web.guard import RateLimit, Settings, client_address
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
    """A test client whose worker is FakeDocker and whose VirusTotal calls are recorded.
    `consult(sha256, data, upload)` stands for VirusTotal: an upload of an unknown file
    comes back "queued" with the analysis ID "an=1", and following it completes."""
    docker = docker or Worker()
    calls = []

    def submit(sha256, data, upload=True):
        calls.append(("submit", sha256, upload))
        if consult is None:
            raise AssertionError("VirusTotal must not be consulted")
        report = consult(sha256, data, upload)
        return report, ("an=1" if report.status == "queued" else None)

    def follow(sha256, analysis):
        calls.append(("follow", sha256, analysis))
        return consult(sha256, None, True).model_copy(update={"status": "found"})

    app = web.create_app(
        settings or Settings(virustotal=False, upload=False),
        transport=lambda: docker,
        submit=submit,
        follow=follow,
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
    data = build_call_demo("RegSetKeyValueW", {0: 0x80000001, 1: RUN, 2: "LupaBinTraining"})
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
    assert body["downloads"]["markdown"].startswith("# LupaBin: informe didáctico")
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
    assert response.json() == {"error": code, "message": LupaBinError(code).args[0]}


def test_a_docker_cli_that_is_missing_is_a_503():
    def missing():
        raise LupaBinError("docker_unavailable")

    app = web.create_app(Settings(virustotal=False), transport=missing)
    response = analyze(TestClient(app), build_pe())
    assert response.status_code == 503


# --- VirusTotal, as in the CLI ------------------------------------------------------------


def vt_report(sha256, data, upload):
    from datetime import UTC, datetime

    from lupabin.virustotal.models import VirusTotalReport

    return VirusTotalReport(
        sample_sha256=sha256,
        retrieved_at=datetime(2026, 9, 25, tzinfo=UTC),
        status="found",
        uploaded=upload,
        permalink=f"https://www.virustotal.com/gui/file/{sha256}",
        stats={"malicious": 2, "undetected": 60},
    )


def vt_post(test, data, upload):
    return test.post(
        f"/api/virustotal?upload={upload}",
        content=data,
        headers={"content-type": "application/octet-stream"},
    )


def test_the_report_never_waits_for_virustotal():
    test = client(Settings(virustotal=True, upload=True), consult=vt_report)
    body = analyze(test, build_pe(), "?virustotal=1&upload=1").json()
    assert body["virustotal"] is None and test.vt_calls == []


def queued_when_uploaded(sha256, data, upload):
    report = vt_report(sha256, data, upload)
    return report.model_copy(update={"status": "queued"}) if upload else report


def test_virustotal_is_asked_apart_and_an_upload_is_followed_by_its_analysis_id():
    import hashlib

    test = client(Settings(virustotal=True, upload=True), consult=queued_when_uploaded)
    data = build_pe()
    shown = vt_post(test, data, 1).json()
    sha256 = hashlib.sha256(data).hexdigest()
    assert shown["status"] == "queued" and shown["analysis"] == "an=1"
    assert shown["sha256"] == sha256 and "La página sigue su análisis" in shown["note"]
    assert test.vt_calls[-1] == ("submit", sha256, True)
    done = test.get(f"/api/virustotal/{sha256}?analysis=an%3D1").json()
    assert done["status"] == "found" and done["stats"]["malicious"] == 2
    assert test.vt_calls[-1] == ("follow", sha256, "an=1")


def test_a_lookup_without_upload_has_nothing_to_follow():
    test = client(Settings(virustotal=True, upload=True), consult=queued_when_uploaded)
    shown = vt_post(test, build_pe(), 0).json()
    assert shown["status"] == "found" and shown["analysis"] is None
    assert test.vt_calls[-1][2] is False


@pytest.mark.parametrize(
    "path",
    [
        f"/api/virustotal/{'ab' * 32}",
        f"/api/virustotal/{'ab' * 32}?analysis=a b",
        "/api/virustotal/x?analysis=an",
    ],
)
def test_following_needs_a_hash_and_a_well_formed_analysis_id(path):
    test = client(Settings(virustotal=True, upload=True), consult=vt_report)
    assert test.get(path).status_code == 400 and test.vt_calls == []


def test_the_server_can_forbid_uploads_or_virustotal_whatever_the_page_asks():
    test = client(Settings(virustotal=True, upload=False), consult=vt_report)
    vt_post(test, build_pe(), 1)
    assert test.vt_calls[-1][2] is False
    off = client(Settings(virustotal=False, upload=False))
    assert vt_post(off, build_pe(), 1).status_code == 404
    assert off.get(f"/api/virustotal/{'ab' * 32}?analysis=an").status_code == 404


def test_settings_follow_the_same_switches_as_the_cli():
    assert Settings.from_env({"LUPABIN_VIRUSTOTAL": "off"}).virustotal is False
    assert Settings.from_env({"LUPABIN_VIRUSTOTAL": "off"}).upload is False
    assert Settings.from_env({"LUPABIN_VIRUSTOTAL_UPLOAD": "0"}).upload is False
    shown = Settings.from_env({"LUPABIN_WEB_RATE": "3/60", "LUPABIN_WEB_CONCURRENCY": "2"})
    assert (shown.rate, shown.window, shown.concurrency) == (3, 60.0, 2)
    with pytest.raises(ValueError):
        Settings.from_env({"LUPABIN_WEB_CONCURRENCY": "0"})


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


def test_behind_cloudflare_the_visitor_comes_from_cf_connecting_ip():
    def address(peer, forwarded, connecting, cloudflare=True, trust_proxy=True):
        return client_address(peer, forwarded, trust_proxy, connecting, cloudflare)

    # proxied DNS: Caddy saw a Cloudflare server; IPv4 and IPv6 ranges
    assert address("127.0.0.1", "172.70.1.2", "198.51.100.7") == "198.51.100.7"
    assert address("::1", "2a06:98c0:3600::103", " 2001:db8::1 ") == "2001:db8::1"
    # a Tunnel ending on this host: cloudflared reaches Caddy through the loopback
    assert address("127.0.0.1", "127.0.0.1", "198.51.100.7") == "198.51.100.7"
    assert address("127.0.0.1", None, "198.51.100.7") == "198.51.100.7"
    assert address("127.0.0.1", "::1", "198.51.100.7") == "198.51.100.7"


def test_a_forged_cf_connecting_ip_is_ignored():
    def address(peer, forwarded, connecting, cloudflare=True, trust_proxy=True):
        return client_address(peer, forwarded, trust_proxy, connecting, cloudflare)

    # straight to the server's IP, past Cloudflare: Caddy saw the sender itself
    assert address("127.0.0.1", "203.0.113.9", "198.51.100.7") == "203.0.113.9"
    # the sender's own X-Forwarded-For entries come before the one Caddy added
    assert address("127.0.0.1", "172.70.1.2, 203.0.113.9", "198.51.100.7") == "203.0.113.9"
    # no local proxy in front, or the switch off
    assert address("172.70.1.2", None, "198.51.100.7") == "172.70.1.2"
    assert address("127.0.0.1", "172.70.1.2", "198.51.100.7", trust_proxy=False) == "127.0.0.1"
    assert address("127.0.0.1", "172.70.1.2", "198.51.100.7", cloudflare=False) == "172.70.1.2"
    # a value that is not an address, or none at all
    assert address("127.0.0.1", "172.70.1.2", "unknown") == "172.70.1.2"
    assert address("127.0.0.1", "172.70.1.2", "198.51.100.7, 1.1.1.1") == "172.70.1.2"
    assert address("127.0.0.1", "172.70.1.2", None) == "172.70.1.2"
    assert address("127.0.0.1", "not an address", "198.51.100.7") == "not an address"


def test_visitors_behind_cloudflare_do_not_share_one_budget():
    settings = Settings(rate=1, window=600, trust_proxy=True, cloudflare=True, virustotal=False)
    app = web.create_app(settings, transport=lambda: Worker())
    test = TestClient(app, client=("127.0.0.1", 50000))

    def send(visitor):
        headers = {
            "content-type": "application/octet-stream",
            "x-forwarded-for": "172.70.1.2",
            "cf-connecting-ip": visitor,
        }
        return test.post("/api/analyze", content=build_pe(), headers=headers).status_code

    assert [send("198.51.100.7"), send("198.51.100.8"), send("198.51.100.7")] == [200, 200, 429]


def test_the_cloudflare_switch_is_off_unless_asked_for():
    assert Settings.from_env({}).cloudflare is False
    assert Settings.from_env({"LUPABIN_WEB_CLOUDFLARE": "on"}).cloudflare is True
    assert Settings.from_env({"LUPABIN_WEB_CLOUDFLARE": "off"}).cloudflare is False


def test_a_request_that_waits_too_long_for_a_free_slot_is_told_to_retry():
    import asyncio

    from lupabin.web.guard import Busy, Slots

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
