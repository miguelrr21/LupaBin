"""The server-wide VirusTotal budget of the web service (public API: 4/min, 500/day)."""

from datetime import date

import pytest

from lupabin.virustotal.client import HttpResponse, VirusTotalError, follow, submit
from lupabin.virustotal.quota import Quota
from lupabin.web import view
from lupabin.web.guard import Settings

SHA = "ab" * 32
KEY = {"VT_API_KEY": "k" * 64}


class Clock:
    def __init__(self):
        self.now = 1000.0
        self.day = date(2026, 9, 25)
        self.slept = []

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def quota(clock, per_minute=4, per_day=500, max_wait=65.0):
    return Quota(
        per_minute,
        per_day,
        max_wait=max_wait,
        clock=lambda: clock.now,
        sleep=clock.sleep,
        today=lambda: clock.day,
    )


def test_the_fifth_request_in_a_minute_waits_for_the_first_to_leave_the_window():
    clock = Clock()
    budget = quota(clock)
    for _ in range(4):
        budget.acquire()
    assert clock.slept == []
    budget.acquire()
    assert len(clock.slept) == 1 and 59 < clock.slept[0] < 61
    assert budget.used_today == 5


def test_a_wait_longer_than_allowed_is_refused_as_quota_exceeded():
    clock = Clock()
    budget = quota(clock, max_wait=10)
    for _ in range(4):
        budget.acquire()
    with pytest.raises(VirusTotalError) as error:
        budget.acquire()
    assert error.value.problem == "quota_exceeded" and clock.slept == []


def test_the_daily_budget_is_a_hard_stop_until_the_utc_day_changes():
    clock = Clock()
    budget = quota(clock, per_minute=100, per_day=3)
    for _ in range(3):
        budget.acquire()
    assert budget.exhausted_today()
    with pytest.raises(VirusTotalError):
        budget.acquire()
    clock.day = date(2026, 9, 26)
    budget.acquire()
    assert budget.used_today == 1


def test_every_request_of_a_submission_counts_and_none_is_sent_past_the_budget():
    clock = Clock()
    budget = quota(clock, per_minute=100, per_day=2)
    sent = []

    def transport(request):
        sent.append((request.method, request.path))
        if request.method == "POST":
            return HttpResponse(200, b'{"data": {"id": "an=="}}')
        return HttpResponse(404, b"")

    report, analysis = submit(SHA, b"x", transport=budget.transport(transport), environ=KEY)
    assert report.status == "queued" and analysis == "an=="
    assert [method for method, _ in sent] == ["GET", "POST"]
    later = follow(SHA, "an==", transport=budget.transport(transport), environ=KEY)
    assert later.status == "unavailable" and later.problem == "quota_exceeded"
    assert len(sent) == 2  # the follow-up was refused before reaching VirusTotal


def test_an_exhausted_quota_is_explained_to_the_visitor():
    from datetime import UTC, datetime

    from lupabin.virustotal.models import VirusTotalReport

    report = VirusTotalReport(
        sample_sha256=SHA,
        retrieved_at=datetime(2026, 9, 25, tzinfo=UTC),
        status="unavailable",
        problem="quota_exceeded",
        permalink=f"https://www.virustotal.com/gui/file/{SHA}",
    )
    assert "la comparten todos los visitantes" in view.virustotal(report)["note"]


def test_the_budget_is_configurable_and_validated():
    shown = Settings.from_env({"LUPABIN_VT_PER_MINUTE": "30", "LUPABIN_VT_PER_DAY": "20000"})
    assert (shown.vt_per_minute, shown.vt_per_day) == (30, 20000)
    with pytest.raises(ValueError):
        Settings.from_env({"LUPABIN_VT_PER_DAY": "0"})
    with pytest.raises(ValueError):
        Quota(0, 1)
