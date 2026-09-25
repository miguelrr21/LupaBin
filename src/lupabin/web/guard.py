"""Limits of the public web service."""

import asyncio
import os
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    rate: int = 6  # analyses per window and client address
    window: float = 600.0  # seconds
    concurrency: int = 1  # analyses at the same time; each worker may use 512 MiB and 1 CPU
    queue_seconds: float = 60.0  # how long a request waits for a free slot
    trust_proxy: bool = False  # client address from the last X-Forwarded-For entry
    virustotal: bool = True  # consult VirusTotal when the page asks (and a key exists)
    upload: bool = True  # upload unknown files when the page asks
    vt_per_minute: int = 4  # VirusTotal requests for the whole server (public API limits)
    vt_per_day: int = 500

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if environ is None else environ

        def switched_on(name: str, default: bool) -> bool:
            value = env.get(name)
            if value is None:
                return default
            return value.strip().lower() not in ("0", "off", "no", "false")

        rate, window = cls.rate, cls.window
        if "LUPABIN_WEB_RATE" in env:
            count, _, seconds = env["LUPABIN_WEB_RATE"].partition("/")
            rate, window = int(count), float(seconds or cls.window)
        settings = cls(
            rate=rate,
            window=window,
            concurrency=int(env.get("LUPABIN_WEB_CONCURRENCY", cls.concurrency)),
            queue_seconds=float(env.get("LUPABIN_WEB_QUEUE_SECONDS", cls.queue_seconds)),
            trust_proxy=switched_on("LUPABIN_WEB_TRUST_PROXY", False),
            virustotal=switched_on("LUPABIN_VIRUSTOTAL", True),
            upload=switched_on("LUPABIN_VIRUSTOTAL", True)
            and switched_on("LUPABIN_VIRUSTOTAL_UPLOAD", True),
            vt_per_minute=int(env.get("LUPABIN_VT_PER_MINUTE", cls.vt_per_minute)),
            vt_per_day=int(env.get("LUPABIN_VT_PER_DAY", cls.vt_per_day)),
        )
        if settings.rate < 1 or settings.window <= 0 or settings.concurrency < 1:
            raise ValueError("invalid web limits")
        if settings.vt_per_minute < 1 or settings.vt_per_day < 1:
            raise ValueError("invalid web limits")
        return settings


class RateLimit:
    """At most `rate` requests per `window` seconds for each client address."""

    MAX_CLIENTS = 100_000  # addresses remembered at once; older windows are dropped first

    def __init__(self, rate: int, window: float, clock: Callable[[], float] = time.monotonic):
        self.rate, self.window, self.clock = rate, window, clock
        self.seen: dict[str, deque[float]] = {}

    def allow(self, client: str) -> bool:
        now = self.clock()
        if len(self.seen) >= self.MAX_CLIENTS:
            self.seen = {
                key: times
                for key, times in self.seen.items()
                if times and times[-1] > now - self.window
            }
        times = self.seen.setdefault(client, deque())
        while times and times[0] <= now - self.window:
            times.popleft()
        if len(times) >= self.rate:
            return False
        times.append(now)
        return True


class Busy(Exception):
    pass


class Slots:
    """How many analyses run at once; a request waits at most `seconds` for its turn."""

    def __init__(self, count: int, seconds: float):
        self.semaphore = asyncio.Semaphore(count)
        self.seconds = seconds

    async def __aenter__(self) -> None:
        try:
            await asyncio.wait_for(self.semaphore.acquire(), self.seconds)
        except TimeoutError:
            raise Busy from None

    async def __aexit__(self, *exc: object) -> None:
        self.semaphore.release()


def client_address(peer: str | None, forwarded: str | None, trust_proxy: bool) -> str:
    """The address a limit applies to. Behind a trusted proxy on this host, the last
    X-Forwarded-For entry is the one the proxy added; earlier ones come from the client."""
    if trust_proxy and forwarded and peer in ("127.0.0.1", "::1"):
        last = forwarded.split(",")[-1].strip()
        if last:
            return last
    return peer or "unknown"
