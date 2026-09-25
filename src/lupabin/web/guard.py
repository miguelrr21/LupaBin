"""Limits of the public web service (design of the web, section 4)."""

import asyncio
import ipaddress
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
    cloudflare: bool = False  # behind Cloudflare: the visitor is in CF-Connecting-IP
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
            cloudflare=switched_on("LUPABIN_WEB_CLOUDFLARE", False),
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


# Cloudflare's published ranges (https://www.cloudflare.com/ips/, checked 2026-09-25). A
# request from a range missing here keeps the proxy's address: the limit then groups more
# visitors together, but a forged header is never believed.
CLOUDFLARE = tuple(
    ipaddress.ip_network(network)
    for network in (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    )
)


def _address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text.strip())
    except ValueError:
        return None


def _from_cloudflare(text: str) -> bool:
    """A Cloudflare server (proxied DNS), or this host (a Cloudflare Tunnel ending here)."""
    address = _address(text)
    return address is not None and (
        address.is_loopback or any(address in network for network in CLOUDFLARE)
    )


def client_address(
    peer: str | None,
    forwarded: str | None,
    trust_proxy: bool,
    connecting: str | None = None,
    cloudflare: bool = False,
) -> str:
    """The address a limit applies to. Behind a trusted proxy on this host, the last
    X-Forwarded-For entry is the one the proxy added; earlier ones come from the client.
    Behind Cloudflare that entry is a Cloudflare server or this host, and the visitor is in
    CF-Connecting-IP, which Cloudflare sets on every request; it is believed only then."""
    if not (trust_proxy and peer in ("127.0.0.1", "::1")):
        return peer or "unknown"
    address = peer
    if forwarded:
        last = forwarded.split(",")[-1].strip()
        if last:
            address = last
    if cloudflare and connecting and _from_cloudflare(address):
        visitor = _address(connecting)
        if visitor is not None:
            return str(visitor)
    return address
