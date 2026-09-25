"""Host-only VirusTotal API v3 client (standard library, bounded, no redirects).

The worker never has network access; this runs in the host process after (or instead
of) the isolated analysis. Only the SHA-256 is sent unless upload is explicitly asked
for. The API key comes from the VT_API_KEY variable or, failing that, from a git-ignored
.env file in the current directory; it is never written to any output.
"""

import json
import os
import secrets
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lupabin.virustotal.models import Problem, VirusTotalReport
from lupabin.virustotal.parse import (
    analysis_id,
    analysis_status,
    behaviour,
    file_attributes,
    summary,
)

API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui/file/"
KEY_VARIABLE = "VT_API_KEY"
TIMEOUT = 30
MAX_RESPONSE = 8 * 1024 * 1024
MAX_UPLOAD = 32 * 1024 * 1024  # POST /files limit (larger files need another endpoint)


@dataclass(frozen=True)
class HttpRequest:
    method: str
    path: str  # below API, starting with "/"
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes


Transport = Callable[[HttpRequest], HttpResponse]


class VirusTotalError(Exception):
    def __init__(self, problem: Problem):
        self.problem = problem
        super().__init__(problem)


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # a redirect is answered as the 3xx response itself


def urllib_transport(request: HttpRequest) -> HttpResponse:
    if not request.path.startswith("/"):
        raise VirusTotalError("invalid_response")
    opener = urllib.request.build_opener(_NoRedirects())
    prepared = urllib.request.Request(  # noqa: S310 (fixed https origin)
        API + request.path, data=request.body, headers=request.headers, method=request.method
    )
    try:
        with opener.open(prepared, timeout=TIMEOUT) as response:
            body = response.read(MAX_RESPONSE + 1)
            status = response.status
    except urllib.error.HTTPError as error:
        body, status = error.read(MAX_RESPONSE + 1), error.code
    except (urllib.error.URLError, TimeoutError, OSError):
        raise VirusTotalError("network_error") from None
    if len(body) > MAX_RESPONSE:
        raise VirusTotalError("too_large")
    return HttpResponse(status, body)


def _problem(status: int) -> Problem:
    if status in (401, 403):
        return "auth_failed"
    if status == 429:
        return "quota_exceeded"
    return "network_error" if status >= 500 or 300 <= status < 400 else "invalid_response"


class Client:
    def __init__(
        self,
        key: str,
        transport: Transport = urllib_transport,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._key = key
        self._transport = transport
        self._sleep = sleep
        self._clock = clock

    def _call(self, method: str, path: str, **extra: Any) -> tuple[int, Any]:
        headers = {"x-apikey": self._key, "accept": "application/json", **extra.get("headers", {})}
        response = self._transport(HttpRequest(method, path, headers, extra.get("body")))
        if response.status == 404:
            return 404, None
        if response.status != 200:
            raise VirusTotalError(_problem(response.status))
        try:
            return 200, json.loads(response.body)
        except (ValueError, RecursionError):
            raise VirusTotalError("invalid_response") from None

    def _report(self, sha256: str, **fields: Any) -> VirusTotalReport:
        return VirusTotalReport(
            sample_sha256=sha256,
            retrieved_at=self._clock(),
            permalink=GUI + sha256,
            **fields,
        )

    def lookup(self, sha256: str, *, uploaded: bool = False) -> VirusTotalReport:
        status, payload = self._call("GET", f"/files/{sha256}")
        if status == 404:
            return self._report(sha256, status="not_found", uploaded=uploaded)
        try:
            fields = summary(file_attributes(payload))
        except ValueError:
            raise VirusTotalError("invalid_response") from None
        problem: Problem | None = None
        try:
            status, payload = self._call("GET", f"/files/{sha256}/behaviour_summary")
            if status == 200:
                fields["behaviour"] = behaviour(payload)
        except VirusTotalError as error:
            problem = error.problem  # the file verdicts stand; behaviour is missing
        except ValueError:
            problem = "invalid_response"
        return self._report(sha256, status="found", uploaded=uploaded, problem=problem, **fields)

    def send(self, data: bytes) -> str:
        """Upload a file; returns the ID of the analysis VirusTotal queues for it."""
        if len(data) > MAX_UPLOAD:
            raise VirusTotalError("too_large")
        boundary = secrets.token_hex(16)
        body = (
            (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="file"; filename="sample"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + data
            + f"\r\n--{boundary}--\r\n".encode()
        )
        headers = {"content-type": f"multipart/form-data; boundary={boundary}"}
        status, payload = self._call("POST", "/files", headers=headers, body=body)
        ident = analysis_id(payload) if status == 200 else None
        if ident is None:
            raise VirusTotalError("invalid_response")
        return ident

    def follow(self, sha256: str, ident: str) -> VirusTotalReport:
        """ "queued" while the uploaded file's analysis runs; its results once completed."""
        status, payload = self._call("GET", f"/analyses/{ident}")
        if status == 200 and analysis_status(payload) == "completed":
            return self.lookup(sha256, uploaded=True)
        return self._report(sha256, status="queued", uploaded=True)

    def upload(
        self, data: bytes, sha256: str, *, wait_seconds: float = 180, interval: float = 20
    ) -> VirusTotalReport:
        ident = self.send(data)
        waited = 0.0
        while waited < wait_seconds:
            self._sleep(interval)  # public API: 4 requests per minute
            waited += interval
            report = self.follow(sha256, ident)
            if report.status != "queued":
                return report
        return self._report(sha256, status="queued", uploaded=True)


def submit(
    sha256: str,
    data: bytes,
    *,
    upload: bool = True,
    transport: Transport = urllib_transport,
    environ: dict[str, str] | None = None,
) -> tuple[VirusTotalReport, str | None]:
    """Look the file up and, if VirusTotal does not know it and `upload`, send it without
    waiting. Returns the report and, after an upload, the analysis ID to follow (the web
    shows the report at once and follows VirusTotal's analysis apart). Never raises."""
    key = api_key(environ)
    client = Client(key, transport)
    if not key:
        return client._report(sha256, status="unavailable", problem="key_missing"), None
    try:
        report = client.lookup(sha256)
        if report.status != "not_found" or not upload:
            return report, None
        ident = client.send(data)
        return client._report(sha256, status="queued", uploaded=True), ident
    except VirusTotalError as error:
        return client._report(sha256, status="unavailable", problem=error.problem), None


def follow(
    sha256: str,
    ident: str,
    *,
    transport: Transport = urllib_transport,
    environ: dict[str, str] | None = None,
) -> VirusTotalReport:
    """One check of an uploaded file's analysis: "queued", or its results. Never raises."""
    key = api_key(environ)
    client = Client(key, transport)
    if not key:
        return client._report(sha256, status="unavailable", problem="key_missing")
    try:
        return client.follow(sha256, ident)
    except VirusTotalError as error:
        return client._report(sha256, status="unavailable", problem=error.problem)


MAX_ENV_FILE = 64 * 1024


def key_from_env_file(path: Path) -> str:
    """VT_API_KEY from a local .env file (KEY=VALUE lines); other variables are ignored.

    The file is git-ignored and never enters the worker image or the package.
    """
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_ENV_FILE + 1)
    except OSError:
        return ""
    if len(raw) > MAX_ENV_FILE:
        return ""
    for line in raw.decode("utf-8", "replace").splitlines():
        name, separator, value = line.strip().partition("=")
        if separator and name.strip().removeprefix("export ").strip() == KEY_VARIABLE:
            return value.strip().strip("'\"")
    return ""


def api_key(environ: dict[str, str] | None = None, env_file: Path | None = None) -> str:
    """The environment variable wins; otherwise .env in the current directory."""
    value = (environ if environ is not None else os.environ).get(KEY_VARIABLE, "").strip()
    if value or environ is not None:
        return value
    return key_from_env_file(env_file if env_file is not None else Path.cwd() / ".env")


def consult(
    sha256: str,
    data: bytes | None = None,
    *,
    upload: bool = False,
    wait_seconds: float = 180,
    transport: Transport = urllib_transport,
    sleep: Callable[[float], None] = time.sleep,
    environ: dict[str, str] | None = None,
) -> VirusTotalReport:
    """Never raises: failures become status "unavailable" with their problem.

    After an upload, waits up to `wait_seconds` for VirusTotal's analysis; with 0 it
    returns at once with status "queued" (the web asks again later by hash)."""
    key = api_key(environ)
    client = Client(key, transport, sleep)
    if not key:
        return client._report(sha256, status="unavailable", problem="key_missing")
    try:
        report = client.lookup(sha256)
        if report.status == "not_found" and upload and data is not None:
            report = client.upload(data, sha256, wait_seconds=wait_seconds)
        return report
    except VirusTotalError as error:
        return client._report(sha256, status="unavailable", problem=error.problem)
