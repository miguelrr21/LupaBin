"""A server-wide budget of VirusTotal API requests, for the public web service.

VirusTotal's public API allows 4 requests per minute and 500 per day for one key,
whoever the visitors are. Every request the web makes (lookups, behaviour summaries,
uploads and follow-ups) goes through one Quota: it waits for a free slot in the
minute, and refuses once the day's budget is spent, so the key is never throttled or
blocked mid-analysis. The CLI does not use it: one person, one key, no sharing.
"""

import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, date, datetime

from dissect.virustotal.client import HttpRequest, HttpResponse, Transport, VirusTotalError


class Quota:
    def __init__(
        self,
        per_minute: int = 4,
        per_day: int = 500,
        *,
        max_wait: float = 65.0,  # one full minute window and a margin
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        today: Callable[[], date] = lambda: datetime.now(UTC).date(),
    ) -> None:
        if per_minute < 1 or per_day < 1:
            raise ValueError("a VirusTotal quota needs at least one request")
        self.per_minute, self.per_day, self.max_wait = per_minute, per_day, max_wait
        self._clock, self._sleep, self._today = clock, sleep, today
        self._lock = threading.Lock()
        self._recent: deque[float] = deque()
        self._day = today()
        self.used_today = 0

    def exhausted_today(self) -> bool:
        with self._lock:
            self._roll_day()
            return self.used_today >= self.per_day

    def _roll_day(self) -> None:
        day = self._today()
        if day != self._day:  # VirusTotal counts days in UTC
            self._day, self.used_today = day, 0

    def acquire(self) -> None:
        """Take one request from the budget, waiting at most `max_wait` seconds for the
        minute's window; raise VirusTotalError("quota_exceeded") otherwise."""
        deadline = self._clock() + self.max_wait
        while True:
            with self._lock:
                self._roll_day()
                if self.used_today >= self.per_day:
                    raise VirusTotalError("quota_exceeded")
                now = self._clock()
                while self._recent and self._recent[0] <= now - 60:
                    self._recent.popleft()
                if len(self._recent) < self.per_minute:
                    self._recent.append(now)
                    self.used_today += 1
                    return
                wait = self._recent[0] + 60 - now + 0.05
            if self._clock() + wait > deadline:
                raise VirusTotalError("quota_exceeded")
            self._sleep(wait)

    def transport(self, inner: Transport) -> Transport:
        def send(request: HttpRequest) -> HttpResponse:
            self.acquire()
            return inner(request)

        return send
