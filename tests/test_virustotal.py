import json

import pytest

from lupabin.virustotal.client import (
    MAX_RESPONSE,
    HttpRequest,
    HttpResponse,
    VirusTotalError,
    consult,
    urllib_transport,
)
from lupabin.virustotal.models import MAX_ITEMS, VirusTotalReport

SHA = "a" * 64
KEY = {"VT_API_KEY": "test-key-not-real"}
FILE = {
    "data": {
        "id": SHA,
        "type": "file",
        "attributes": {
            "last_analysis_stats": {
                "malicious": 2,
                "suspicious": 1,
                "undetected": 60,
                "harmless": 0,
                "timeout": 0,
                "confirmed-timeout": 0,
                "type-unsupported": 0,
                "failure": 0,
            },
            "last_analysis_results": {
                "EngineB": {"category": "malicious", "result": "Training.Sample"},
                "EngineA": {"category": "suspicious", "result": None},
                "EngineC": {"category": "undetected", "result": None},
            },
            "meaningful_name": "practice.exe",
            "names": ["practice.exe", "sample.bin"],
            "type_description": "Win32 EXE",
            "first_submission_date": 1758585600,
            "last_analysis_date": 1758672000,
            "reputation": -3,
            "total_votes": {"harmless": 0, "malicious": 1},
            "tags": ["peexe"],
            "sandbox_verdicts": {
                "SandboxX": {
                    "category": "suspicious",
                    "confidence": 70,
                    "sandbox_name": "SandboxX",
                    "malware_classification": ["UNKNOWN"],
                }
            },
            "unexpected_field": {"ignored": True},
        },
    }
}
BEHAVIOUR = {
    "data": {
        "processes_created": ["C:\\Windows\\System32\\cmd.exe /c echo training"],
        "command_executions": ["cmd.exe /c echo training"],
        "files_written": ["C:\\Users\\user\\AppData\\Local\\Temp\\training.tmp"],
        "registry_keys_set": [{"key": "HKCU\\Software\\Training", "value": "1"}, "bad"],
        "dns_lookups": [{"hostname": "training.invalid", "resolved_ips": ["192.0.2.1"]}],
        "ip_traffic": [
            {
                "destination_ip": "192.0.2.1",
                "destination_port": 443,
                "transport_layer_protocol": "TCP",
            }
        ],
        "http_conversations": [{"url": "https://training.invalid/", "request_method": "GET"}],
        "mutexes_created": ["Training_Mutex"],
        "mitre_attack_techniques": [
            {
                "id": "T1059",
                "signature_description": "Runs a command shell",
                "severity": "IMPACT_SEVERITY_LOW",
            }
        ],
    }
}


class Fake:
    """Scripted transport: (method, path) -> list of responses, recording requests."""

    def __init__(self, routes):
        self.routes = {key: list(value) for key, value in routes.items()}
        self.requests: list[HttpRequest] = []

    def __call__(self, request):
        self.requests.append(request)
        queue = self.routes[(request.method, request.path.split("?")[0])]
        status, payload = queue.pop(0) if len(queue) > 1 else queue[0]
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        return HttpResponse(status, body)


def lookup_routes(file=(200, FILE), behaviour=(200, BEHAVIOUR)):
    return {
        ("GET", f"/files/{SHA}"): [file],
        ("GET", f"/files/{SHA}/behaviour_summary"): [behaviour],
    }


def test_hash_lookup_reads_verdicts_and_behaviour_and_only_sends_the_hash():
    fake = Fake(lookup_routes())
    report = consult(SHA, b"MZ bytes that must not leave", transport=fake, environ=KEY)
    assert report.status == "found" and report.problem is None and not report.uploaded
    assert report.stats == FILE["data"]["attributes"]["last_analysis_stats"]
    assert [(d.engine, d.category) for d in report.detections] == [
        ("EngineA", "suspicious"),
        ("EngineB", "malicious"),
    ]
    assert report.first_submission.year == 2025
    assert report.behaviour.command_executions == ("cmd.exe /c echo training",)
    assert report.behaviour.registry_keys_set[0].key == "HKCU\\Software\\Training"
    assert report.behaviour.omitted == 1  # the malformed registry entry
    assert [t.id for t in report.behaviour.mitre_attack_techniques] == ["T1059"]
    assert all(r.method == "GET" and r.body is None for r in fake.requests)
    assert all(r.headers["x-apikey"] == "test-key-not-real" for r in fake.requests)
    assert VirusTotalReport.model_validate_json(report.model_dump_json()) == report


def test_unknown_file_is_not_uploaded_without_the_explicit_option():
    fake = Fake(lookup_routes(file=(404, {"error": {"code": "NotFoundError"}})))
    report = consult(SHA, b"data", transport=fake, environ=KEY)
    assert report.status == "not_found"
    assert [r.method for r in fake.requests] == ["GET"]


def test_explicit_upload_sends_a_generic_name_and_waits_for_the_analysis():
    routes = lookup_routes()
    routes[("GET", f"/files/{SHA}")] = [(404, {}), (200, FILE)]
    routes[("POST", "/files")] = [(200, {"data": {"type": "analysis", "id": "abc=="}})]
    routes[("GET", "/analyses/abc==")] = [
        (200, {"data": {"attributes": {"status": "queued"}}}),
        (200, {"data": {"attributes": {"status": "completed"}}}),
    ]
    fake, sleeps = Fake(routes), []
    report = consult(
        SHA, b"MZtraining", upload=True, transport=fake, sleep=sleeps.append, environ=KEY
    )
    assert report.status == "found" and report.uploaded
    from lupabin.render.external import to_text_lines

    shown = " ".join(to_text_lines(report, lambda text, indent, first=None: [text]))
    assert "LupaBin subió el archivo a VirusTotal porque no lo conocía" in shown
    post = next(r for r in fake.requests if r.method == "POST")
    assert b'filename="sample"' in post.body and b"MZtraining" in post.body
    assert post.headers["content-type"].startswith("multipart/form-data; boundary=")
    assert sleeps and all(s >= 15 for s in sleeps)  # respects 4 requests per minute


def test_upload_that_does_not_finish_in_time_is_reported_as_queued():
    routes = lookup_routes(file=(404, {}))
    routes[("POST", "/files")] = [(200, {"data": {"id": "abc=="}})]
    routes[("GET", "/analyses/abc==")] = [(200, {"data": {"attributes": {"status": "queued"}}})]
    report = consult(
        SHA, b"x", upload=True, transport=Fake(routes), sleep=lambda s: None, environ=KEY
    )
    assert report.status == "queued" and report.uploaded


def test_submit_uploads_an_unknown_file_and_returns_the_analysis_to_follow():
    from lupabin.virustotal.client import follow, submit

    routes = lookup_routes(file=(404, {}))
    routes[("POST", "/files")] = [(200, {"data": {"id": "abc=="}})]
    routes[("GET", "/analyses/abc==")] = [(200, {"data": {"attributes": {"status": "queued"}}})]
    report, analysis = submit(SHA, b"x", transport=Fake(routes), environ=KEY)
    assert report.status == "queued" and report.uploaded and analysis == "abc=="
    queued = follow(SHA, "abc==", transport=Fake(routes), environ=KEY)
    assert queued.status == "queued"
    known, analysis = submit(SHA, b"x", upload=False, transport=Fake(routes), environ=KEY)
    assert known.status == "not_found" and analysis is None
    missing, analysis = submit(SHA, b"x", transport=Fake(routes), environ={})
    assert missing.problem == "key_missing" and analysis is None


def test_an_upload_that_must_not_wait_returns_queued_at_once():
    """The web uploads without waiting and looks the hash up again later."""
    routes = lookup_routes(file=(404, {}))
    routes[("POST", "/files")] = [(200, {"data": {"id": "abc=="}})]
    fake, sleeps = Fake(routes), []
    report = consult(
        SHA, b"x", upload=True, wait_seconds=0, transport=fake, sleep=sleeps.append, environ=KEY
    )
    assert report.status == "queued" and report.uploaded and sleeps == []


@pytest.mark.parametrize(
    "status,problem",
    [(401, "auth_failed"), (403, "auth_failed"), (429, "quota_exceeded"), (503, "network_error")],
)
def test_http_failures_become_declared_problems(status, problem):
    report = consult(SHA, transport=Fake(lookup_routes(file=(status, {}))), environ=KEY)
    assert (report.status, report.problem) == ("unavailable", problem)


def test_missing_key_never_calls_the_api():
    fake = Fake(lookup_routes())
    report = consult(SHA, transport=fake, environ={})
    assert (report.status, report.problem) == ("unavailable", "key_missing")
    assert fake.requests == []


def test_behaviour_failure_keeps_the_verdicts():
    report = consult(SHA, transport=Fake(lookup_routes(behaviour=(429, {}))), environ=KEY)
    assert report.status == "found" and report.problem == "quota_exceeded"
    assert report.stats and report.behaviour.empty()


@pytest.mark.parametrize(
    "payload", [b"not json", {"data": []}, {"data": {"attributes": "x"}}, [1, 2]]
)
def test_malformed_responses_are_rejected_not_guessed(payload):
    report = consult(SHA, transport=Fake(lookup_routes(file=(200, payload))), environ=KEY)
    assert (report.status, report.problem) == ("unavailable", "invalid_response")


@pytest.mark.parametrize(
    ("field", "value"),
    [("id", "b" * 64), ("id", None), ("id", 7), ("type", "url"), ("type", None)],
)
@pytest.mark.parametrize("operation", ["consult", "submit", "follow"])
def test_file_identity_mismatch_is_rejected_without_upload_or_behaviour(field, value, operation):
    from lupabin.virustotal.client import follow, submit

    payload = json.loads(json.dumps(FILE))
    if value is None:
        payload["data"].pop(field)
    else:
        payload["data"][field] = value
    routes = lookup_routes(file=(200, payload))
    routes[("GET", "/analyses/training")] = [
        (200, {"data": {"attributes": {"status": "completed"}}})
    ]
    fake = Fake(routes)
    if operation == "consult":
        report = consult(SHA, b"synthetic", upload=True, transport=fake, environ=KEY)
    elif operation == "submit":
        report, analysis = submit(SHA, b"synthetic", transport=fake, environ=KEY)
        assert analysis is None
    else:
        report = follow(SHA, "training", transport=fake, environ=KEY)
    assert (report.status, report.problem) == ("unavailable", "invalid_response")
    assert report.sample_sha256 == SHA
    assert not report.stats and not report.detections and report.behaviour.empty()
    assert all(
        r.method == "GET" and not r.path.endswith("/behaviour_summary") for r in fake.requests
    )


@pytest.mark.parametrize("value", ["b" * 64, None, 7])
def test_file_attribute_hash_must_agree_when_present(value):
    payload = json.loads(json.dumps(FILE))
    payload["data"]["attributes"]["sha256"] = value
    report = consult(SHA, transport=Fake(lookup_routes(file=(200, payload))), environ=KEY)
    assert (report.status, report.problem) == ("unavailable", "invalid_response")


def test_file_attribute_hash_can_confirm_the_requested_file():
    payload = json.loads(json.dumps(FILE))
    payload["data"]["attributes"]["sha256"] = SHA
    report = consult(SHA, transport=Fake(lookup_routes(file=(200, payload))), environ=KEY)
    assert report.status == "found" and report.problem is None


@pytest.mark.parametrize(
    "stats",
    [
        {"suspicious": 0, "undetected": 60},
        {"malicious": "2", "suspicious": 0, "undetected": 60},
        {"malicious": True, "suspicious": 0, "undetected": 60},
        {"malicious": -1, "suspicious": 0, "undetected": 60},
        {"malicious": 1.5, "suspicious": 0, "undetected": 60},
        {"malicious": 2, "suspicious": 0, "undetected": 60},
        {},
        None,
    ],
)
def test_incomplete_statistics_never_invent_counts_or_totals(stats):
    from lupabin.render.external import structured, to_markdown_lines, to_text_lines
    from lupabin.web.view import virustotal

    payload = json.loads(json.dumps(FILE))
    payload["data"]["attributes"]["last_analysis_stats"] = stats
    report = consult(SHA, transport=Fake(lookup_routes(file=(200, payload))), environ=KEY)
    assert report.status == "found" and report.detections
    for rendered in (
        " ".join(to_text_lines(report, lambda text, *args: [text])),
        " ".join(to_markdown_lines(report)),
        json.dumps(structured(report), ensure_ascii=False),
        json.dumps(virustotal(report), ensure_ascii=False),
    ):
        assert "Total de motores: no disponible" in rendered
        assert " de 60 " not in rendered and " de 62 " not in rendered
        assert "Training.Sample" in rendered
        expected = (
            2
            if isinstance(stats, dict)
            and type(stats.get("malicious")) is int
            and stats["malicious"] == 2
            else "no disponible"
        )
        assert f"Maliciosos: {expected}" in rendered


def test_each_missing_statistic_prevents_a_total():
    from lupabin.render.external import structured
    from lupabin.virustotal.parse import STATS

    for key in STATS:
        payload = json.loads(json.dumps(FILE))
        stats = dict.fromkeys(STATS, 0) | {"malicious": 2, "undetected": 60}
        del stats[key]
        payload["data"]["attributes"]["last_analysis_stats"] = stats
        report = consult(SHA, transport=Fake(lookup_routes(file=(200, payload))), environ=KEY)
        rows = json.dumps(structured(report), ensure_ascii=False)
        assert "Total de motores: no disponible" in rows


def test_unknown_statistic_prevents_a_fabricated_total():
    from lupabin.render.external import structured
    from lupabin.virustotal.parse import STATS

    payload = json.loads(json.dumps(FILE))
    payload["data"]["attributes"]["last_analysis_stats"] = dict.fromkeys(STATS, 0) | {
        "malicious": 2,
        "undetected": 60,
        "new_category": 3,
    }
    report = consult(SHA, transport=Fake(lookup_routes(file=(200, payload))), environ=KEY)
    assert "Total de motores: no disponible" in json.dumps(structured(report), ensure_ascii=False)


def test_wrong_types_are_dropped_and_lists_are_bounded():
    attributes = FILE["data"]["attributes"] | {
        "last_analysis_stats": {"malicious": "2", "undetected": -1, "harmless": True},
        "names": ["x" * 5000, 7, None] + [f"n{i}" for i in range(40)],
        "first_submission_date": "yesterday",
    }
    behaviour = {"data": {"files_written": [f"f{i}" for i in range(MAX_ITEMS + 25)]}}
    routes = lookup_routes(
        file=(200, {"data": {"id": SHA, "type": "file", "attributes": attributes}}),
        behaviour=(200, behaviour),
    )
    report = consult(SHA, transport=Fake(routes), environ=KEY)
    assert report.stats == {}
    assert len(report.names) == 20 and len(report.names[0]) == 2048
    assert report.first_submission is None
    assert len(report.behaviour.files_written) == MAX_ITEMS and report.behaviour.omitted == 25


def test_the_key_never_appears_in_the_report():
    report = consult(SHA, transport=Fake(lookup_routes()), environ=KEY)
    assert "test-key-not-real" not in report.model_dump_json()


def test_real_transport_refuses_paths_outside_the_api_and_oversized_answers(monkeypatch):
    with pytest.raises(VirusTotalError):
        urllib_transport(HttpRequest("GET", "https://evil.invalid/"))

    class Big:
        status = 200

        def read(self, size):
            return b"x" * size

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class Opener:
        def open(self, request, timeout):
            assert request.full_url.startswith("https://www.virustotal.com/api/v3/")
            return Big()

    monkeypatch.setattr("urllib.request.build_opener", lambda *handlers: Opener())
    with pytest.raises(VirusTotalError) as error:
        urllib_transport(HttpRequest("GET", f"/files/{SHA}"))
    assert error.value.problem == "too_large"
    assert MAX_RESPONSE < 16 * 1024 * 1024


# --- CLI and rendering --------------------------------------------------------------

from typer.testing import CliRunner  # noqa: E402

from lupabin.analysis import analyze_bytes  # noqa: E402
from lupabin.cli import app  # noqa: E402
from lupabin.virustotal import client as vt_client  # noqa: E402
from tests.fixtures.pe_builder import build_pe  # noqa: E402

runner = CliRunner()
HOSTILE = "\x1b[2J`[x](https://evil.invalid)`"


def patch(monkeypatch, file=(200, FILE), behaviour=(200, BEHAVIOUR), environ=KEY):
    real = vt_client.consult
    calls = []

    def fake(sha256, data=None, *, upload=False, **_):
        code, payload = file
        if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
            payload = json.loads(json.dumps(payload))
            payload["data"]["id"] = sha256
        routes = {
            ("GET", f"/files/{sha256}"): [(code, payload)],
            ("GET", f"/files/{sha256}/behaviour_summary"): [behaviour],
        }
        calls.append((sha256, upload))
        return real(sha256, data, upload=upload, transport=Fake(routes), environ=environ)

    monkeypatch.setattr("lupabin.cli.virustotal_client.consult", fake)
    monkeypatch.setattr(
        "lupabin.cli.analyze_isolated", lambda data, limits: analyze_bytes(data, limits)
    )
    return calls


def sample(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(build_pe())
    return path


def test_analyze_adds_an_attributed_external_section(tmp_path, monkeypatch):
    hostile = json.loads(json.dumps(FILE))
    hostile["data"]["attributes"]["meaningful_name"] = HOSTILE
    calls = patch(monkeypatch, file=(200, hostile))
    for flag in ([], ["--markdown"]):
        result = runner.invoke(app, ["analyze", str(sample(tmp_path)), "--virustotal", *flag])
        assert result.exit_code == 0
        assert "Fuente externa: VirusTotal (no verificada por LupaBin)" in result.stdout
        assert "\x1b" not in result.stdout and "test-key-not-real" not in result.stdout
        assert "2 de 63 lo marcan como malicioso" in result.stdout
    assert all(upload is False for _, upload in calls)


def user_defaults(monkeypatch):
    """The CLI defaults, not the tests' ones: consult and upload."""
    monkeypatch.delenv("LUPABIN_VIRUSTOTAL")
    monkeypatch.delenv("LUPABIN_VIRUSTOTAL_UPLOAD")


def test_analyze_consults_and_uploads_by_default(tmp_path, monkeypatch):
    user_defaults(monkeypatch)
    monkeypatch.setattr("lupabin.cli.virustotal_client.api_key", lambda environ=None: "key")
    calls = patch(monkeypatch)
    result = runner.invoke(app, ["analyze", str(sample(tmp_path))])
    assert result.exit_code == 0 and len(calls) == 1
    assert "Fuente externa: VirusTotal (no verificada por LupaBin)" in result.stdout
    assert calls[0][1] is True  # uploaded only if VirusTotal does not know the file
    assert "se sube y se espera su análisis" in result.stderr


@pytest.mark.parametrize(
    ("arguments", "environ"),
    [(["--no-upload-to-virustotal"], None), ([], "off")],
)
def test_the_default_upload_can_be_turned_off(tmp_path, monkeypatch, arguments, environ):
    user_defaults(monkeypatch)
    if environ is not None:
        monkeypatch.setenv("LUPABIN_VIRUSTOTAL_UPLOAD", environ)
    calls = patch(monkeypatch)
    result = runner.invoke(app, ["analyze", str(sample(tmp_path)), *arguments])
    assert result.exit_code == 0 and calls[0][1] is False
    assert "se sube" not in result.stderr


def test_uploading_needs_the_consultation(tmp_path, monkeypatch):
    user_defaults(monkeypatch)
    calls = patch(monkeypatch)
    result = runner.invoke(app, ["analyze", str(sample(tmp_path)), "--no-virustotal"])
    assert result.exit_code == 0 and calls == []  # nothing consulted, nothing uploaded
    both = ["--no-virustotal", "--upload-to-virustotal"]
    assert runner.invoke(app, ["analyze", str(sample(tmp_path)), *both]).exit_code == 2


@pytest.mark.parametrize(
    ("arguments", "environ"),
    [
        (["--no-virustotal"], None),  # turned off for one analysis
        ([], "off"),  # turned off by LUPABIN_VIRUSTOTAL
        (["--json"], None),  # the fact report is not mixed with an external source
    ],
)
def test_the_default_consultation_can_be_turned_off(tmp_path, monkeypatch, arguments, environ):
    monkeypatch.delenv("LUPABIN_VIRUSTOTAL_UPLOAD")
    if environ is None:
        monkeypatch.delenv("LUPABIN_VIRUSTOTAL")
    else:
        monkeypatch.setenv("LUPABIN_VIRUSTOTAL", environ)
    calls = patch(monkeypatch)
    result = runner.invoke(app, ["analyze", str(sample(tmp_path)), *arguments])
    assert result.exit_code == 0 and calls == []


def test_without_a_key_the_default_consultation_explains_and_the_analysis_stands(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("LUPABIN_VIRUSTOTAL")
    calls = patch(monkeypatch, environ={})  # no VT_API_KEY and no .env
    result = runner.invoke(app, ["analyze", str(sample(tmp_path))])
    assert result.exit_code == 0 and len(calls) == 1
    assert "Fuente externa: VirusTotal" in result.stdout


def test_json_report_and_virustotal_are_not_mixed(tmp_path, monkeypatch):
    patch(monkeypatch)
    result = runner.invoke(app, ["analyze", str(sample(tmp_path)), "--json", "--virustotal"])
    assert result.exit_code == 2


def test_virustotal_command_emits_its_own_document(tmp_path, monkeypatch):
    patch(monkeypatch)
    result = runner.invoke(app, ["virustotal", "--sha256", SHA.upper(), "--format", "json"])
    assert result.exit_code == 0
    assert VirusTotalReport.model_validate_json(result.stdout).sample_sha256 == SHA
    text = runner.invoke(app, ["virustotal", str(sample(tmp_path))])
    assert text.exit_code == 0 and "Motores" in text.stdout


@pytest.mark.parametrize(
    "args",
    [
        ["virustotal"],
        ["virustotal", "--sha256", "xyz"],
        ["virustotal", "--sha256", SHA, "--upload-to-virustotal"],
        ["virustotal", "--sha256", SHA, "--format", "markdown"],
    ],
)
def test_virustotal_command_usage_errors(monkeypatch, args):
    patch(monkeypatch)
    assert runner.invoke(app, args).exit_code == 2


def test_missing_key_is_a_clear_error_without_a_request(monkeypatch):
    patch(monkeypatch, environ={})
    result = runner.invoke(app, ["virustotal", "--sha256", SHA])
    assert result.exit_code == 1
    assert json.loads(result.stderr)["error"]["code"] == "virustotal_key_missing"
    assert "VT_API_KEY" in result.stdout


def test_explain_consults_by_the_report_hash(tmp_path, monkeypatch):
    calls = patch(monkeypatch)
    path = sample(tmp_path)
    saved = runner.invoke(app, ["analyze", str(path), "--json"])
    report = tmp_path / "report.json"
    report.write_text(saved.stdout, encoding="utf-8")
    result = runner.invoke(app, ["explain", str(report), "--virustotal"])
    assert result.exit_code == 0 and "Fuente externa" in result.stdout
    assert calls == [(json.loads(saved.stdout)["sample"]["sha256"], False)]


def test_key_comes_from_the_environment_first_then_from_a_local_env_file(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text('OTHER=1\n# comment\nVT_API_KEY="from-file"\n', encoding="utf-8")
    monkeypatch.delenv("VT_API_KEY", raising=False)
    assert vt_client.api_key(env_file=env) == "from-file"
    monkeypatch.setenv("VT_API_KEY", "from-environment")
    assert vt_client.api_key(env_file=env) == "from-environment"
    monkeypatch.delenv("VT_API_KEY")
    assert vt_client.api_key(env_file=tmp_path / "missing.env") == ""
    env.write_bytes(b"x" * (vt_client.MAX_ENV_FILE + 1))
    assert vt_client.api_key(env_file=env) == ""


def test_the_repository_never_tracks_or_ships_an_env_file():
    from pathlib import Path

    root = Path(__file__).parents[1]
    assert ".env" in (root / ".gitignore").read_text(encoding="utf-8").splitlines()
    docker = (root / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert docker[0] == "*" and not any(".env" in line for line in docker)
