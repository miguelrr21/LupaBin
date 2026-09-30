"""LupaBin on the web: the same isolated analysis and didactic report as the CLI.

See docs/metodo.md, «Interfaz web». The server never stores a
sample or a report, runs every analysis in a fresh worker container exactly like the
CLI (runner.run_isolated), and sends only items that regenerate from their citations.
"""

import asyncio
import functools
import hashlib
import os
import re
from collections.abc import Awaitable, Callable, MutableMapping
from importlib.resources import files
from typing import Any

from starlette.applications import Starlette
from starlette.requests import ClientDisconnect, Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from lupabin.errors import MESSAGES, FailureCode, LupaBinError
from lupabin.evidence.models import Limits, Report
from lupabin.explain.engine import ExplanationError, explain, validate
from lupabin.ghidra import build_bundle as ghidra_bundle
from lupabin.glossary.catalog import load_glossary
from lupabin.runner import IMAGE, run_isolated
from lupabin.transport import DockerCLI, Transport
from lupabin.virustotal import client as virustotal_client
from lupabin.virustotal.quota import Quota
from lupabin.web import view
from lupabin.web.guard import Busy, RateLimit, Settings, Slots, client_address

STATIC = files("lupabin.web") / "static"
ANALYSIS_ID = re.compile(r"[A-Za-z0-9_=-]{1,200}")  # VirusTotal analysis IDs (base64url)
STATUS: dict[FailureCode, int] = {
    "input_empty": 400,
    "invalid_input": 400,
    "input_limit": 413,
    "docker_unavailable": 503,
    "image_unavailable": 503,
    "timeout": 504,
}
SECURITY_HEADERS = {
    "content-security-policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "x-frame-options": "DENY",
}
Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGI = Callable[[Scope, Receive, Send], Awaitable[None]]


class SecurityHeaders:
    """Adds the page's security headers to every HTTP response."""

    def __init__(self, app: ASGI):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                for name, value in SECURITY_HEADERS.items():
                    if name.encode() not in present:
                        headers.append((name.encode(), value.encode()))
                if scope["path"].startswith("/api/"):
                    headers.append((b"cache-control", b"no-store"))
                else:  # the page and its assets: revalidate, so an update is seen at once
                    headers.append((b"cache-control", b"no-cache"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, with_headers)


def failure(code: str, status: int, message: str | None = None) -> JSONResponse:
    known: dict[str, str] = {key: value for key, value in MESSAGES.items()}
    text = message if message is not None else known.get(code, code)
    return JSONResponse({"error": code, "message": text}, status_code=status)


async def read_limited(request: Request, limit: int) -> bytes:
    """The request body, refused as soon as it passes `limit` bytes (nothing on disk)."""
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise LupaBinError("input_limit")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise LupaBinError("input_limit")
    if not body:
        raise LupaBinError("input_empty")
    return bytes(body)


def create_app(
    settings: Settings | None = None,
    transport: Callable[[], Transport] = DockerCLI,
    submit: Callable[..., Any] | None = None,
    follow: Callable[..., Any] | None = None,
) -> Starlette:
    settings = settings or Settings.from_env()
    # one budget of VirusTotal requests for every visitor (virustotal/quota.py)
    quota = Quota(settings.vt_per_minute, settings.vt_per_day)
    budgeted = quota.transport(virustotal_client.urllib_transport)
    if submit is None:
        submit = functools.partial(virustotal_client.submit, transport=budgeted)
    if follow is None:
        follow = functools.partial(virustotal_client.follow, transport=budgeted)
    limits = Limits()
    glossary = load_glossary()
    rate = RateLimit(settings.rate, settings.window)
    # lookups spend the server owner's VirusTotal quota; re-checks of a queued file count
    vt_rate = RateLimit(settings.rate * 5, settings.window)
    # following an uploaded file's analysis: one check every 20 s for up to 15 minutes
    follow_rate = RateLimit(settings.rate * 10 + 45, settings.window)
    slots = Slots(settings.concurrency, settings.queue_seconds)

    async def index(request: Request) -> Response:
        return FileResponse(str(STATIC / "index.html"), media_type="text/html; charset=utf-8")

    async def config(request: Request) -> Response:
        return JSONResponse(
            {
                "max_bytes": limits.input_bytes,
                "virustotal": settings.virustotal,
                "upload": settings.upload,
                "rate": settings.rate,
                "window_minutes": round(settings.window / 60),
            }
        )

    async def health(request: Request) -> Response:
        try:
            docker = transport()
            image = await docker.run(("image", "inspect", "--format", "{{.Id}}", IMAGE))
        except LupaBinError as error:
            return failure(error.code, 503)
        if image.code != 0:
            return failure("image_unavailable", 503)
        return JSONResponse({"status": "ok", "image": IMAGE})

    def visitor(request: Request) -> str:
        return client_address(
            request.client.host if request.client else None,
            request.headers.get("x-forwarded-for"),
            settings.trust_proxy,
            request.headers.get("cf-connecting-ip"),
            settings.cloudflare,
        )

    def build_response(report: Report, data: bytes) -> Response:
        try:
            archive = ghidra_bundle(report, data)
        except (LupaBinError, ValueError, OSError):
            archive = None
        try:
            explanation = explain(report, glossary)
            items = validate(explanation, report, glossary)
        except ExplanationError:
            return failure("invalid_worker_output", 500)
        # VirusTotal is asked separately (/api/virustotal), so the report never waits for it
        shown = view.build(report, explanation, items, glossary, None)
        if archive is not None:
            view.ghidra_download(shown, archive)
        else:
            shown["downloads"]["ghidra_error"] = "No se pudo crear una exportación Ghidra válida."
        return JSONResponse(shown)

    async def analyze(request: Request) -> Response:
        client = visitor(request)
        if not rate.allow(client):
            minutes = round(settings.window / 60)
            return failure(
                "rate_limited",
                429,
                f"Has alcanzado el límite de {settings.rate} análisis cada {minutes} minutos. "
                "Espera un poco y vuelve a intentarlo.",
            )
        try:
            data = await read_limited(request, limits.input_bytes)
        except LupaBinError as error:
            return failure(error.code, STATUS.get(error.code, 400))
        except ClientDisconnect:
            return failure("invalid_input", 400)
        try:
            async with slots:
                report = await run_isolated(data, limits, transport())
                pending = asyncio.gather(
                    asyncio.to_thread(build_response, report, data), return_exceptions=True
                )
                cancelled = False
                while not pending.done():
                    try:
                        await asyncio.shield(pending)
                    except asyncio.CancelledError:
                        cancelled = True
                result = pending.result()[0]
                if cancelled:
                    raise asyncio.CancelledError
                if isinstance(result, BaseException):
                    raise result
                return result
        except Busy:
            return failure(
                "busy",
                503,
                "El servidor está analizando otros archivos. Vuelve a intentarlo en un minuto.",
            )
        except LupaBinError as error:
            return failure(error.code, STATUS.get(error.code, 500))

    def vt_refused(request: Request, limit: RateLimit) -> Response | None:
        if not settings.virustotal:
            return failure("virustotal_off", 404, "Este servidor no consulta VirusTotal.")
        client = visitor(request)
        if not limit.allow(client):
            return failure(
                "rate_limited",
                429,
                "Has alcanzado el límite de consultas a VirusTotal. Espera unos minutos.",
            )
        return None

    async def virustotal(request: Request) -> Response:
        """Lookup by SHA-256 and, if VirusTotal does not know the file and the page asks for
        it, upload it without waiting: the answer carries the analysis ID to follow."""
        refused = vt_refused(request, vt_rate)
        if refused is not None:
            return refused
        try:
            data = await read_limited(request, limits.input_bytes)
        except LupaBinError as error:
            return failure(error.code, STATUS.get(error.code, 400))
        except ClientDisconnect:
            return failure("invalid_input", 400)
        upload = settings.upload and request.query_params.get("upload") == "1"
        sha256 = hashlib.sha256(data).hexdigest()
        found, analysis = await asyncio.to_thread(submit, sha256, data, upload=upload)
        return JSONResponse({**view.virustotal(found), "analysis": analysis})

    async def virustotal_follow(request: Request) -> Response:
        """One check of an uploaded file's analysis: "queued" until VirusTotal completes it,
        then its results."""
        sha256 = request.path_params["sha256"]
        analysis = request.query_params.get("analysis", "")
        if not re.fullmatch(r"[a-f0-9]{64}", sha256) or not ANALYSIS_ID.fullmatch(analysis):
            return failure("invalid_input", 400)
        refused = vt_refused(request, follow_rate)
        if refused is not None:
            return refused
        found = await asyncio.to_thread(follow, sha256, analysis)
        return JSONResponse({**view.virustotal(found), "analysis": analysis})

    app = Starlette(
        routes=[
            Route("/", index),
            Route("/api/config", config),
            Route("/api/health", health),
            Route("/api/analyze", analyze, methods=["POST"]),
            Route("/api/virustotal", virustotal, methods=["POST"]),
            Route("/api/virustotal/{sha256}", virustotal_follow),
            Mount("/static", StaticFiles(directory=str(STATIC)), name="static"),
        ]
    )
    app.add_middleware(SecurityHeaders)
    return app


def main() -> None:
    """`lupabin-web`: serve on LUPABIN_WEB_HOST:LUPABIN_WEB_PORT (127.0.0.1:8080)."""
    import uvicorn

    uvicorn.run(
        create_app(),
        host=os.environ.get("LUPABIN_WEB_HOST", "127.0.0.1"),
        port=int(os.environ.get("LUPABIN_WEB_PORT", "8080")),
        access_log=False,
        proxy_headers=False,  # the client address is decided by guard.client_address
        server_header=False,
    )
