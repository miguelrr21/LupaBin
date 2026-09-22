"""Repeating-key XOR (1-8 bytes) located by crib differentials over raw sample bytes.

If c[i] = p[i] ^ k[i mod L], then c[i] ^ c[i+L] = p[i] ^ p[i+L] for any key of
period L. Searching a crib's lag-L differential in the sample's lag-L differential
finds that crib under every period-L key at once; the key is then derived from the
bytes, never chosen among candidates. Design: docs/superpowers/specs/
2026-09-22-static-decoding-design.md, sections 3.3-3.5 and 8.
"""

import hashlib
import json
from dataclasses import dataclass
from typing import Literal, NamedTuple

from dissect.evidence.facts import DecodedStringData, DecodedStringEvidence, XorAnchor
from dissect.evidence.primitives import Location, Transform, minimal_period

Encoding = Literal["ascii", "utf-16-le"]
ENCODINGS: tuple[Encoding, ...] = ("ascii", "utf-16-le")

CATALOG_ID: Literal["dissect-xor-cribs-v1"] = "dissect-xor-cribs-v1"
# Neutral anchors chosen for length, not meaning: finding one says nothing about
# capability or intent. Changing this tuple requires a new CATALOG_ID and digest.
CRIBS: tuple[str, ...] = (
    "http://",
    "https://",
    "This program cannot be run in DOS mode",
    "kernel32.dll",
    "ntdll.dll",
    "advapi32.dll",
    "user32.dll",
    "ws2_32.dll",
    "wininet.dll",
    "Software\\Microsoft\\Windows\\CurrentVersion",
    "cmd.exe",
    "powershell",
    "LoadLibrary",
    "GetProcAddress",
    "VirtualAlloc",
    "CreateProcess",
    "CreateRemoteThread",
    "WriteProcessMemory",
    "URLDownloadToFile",
    "InternetOpen",
    "HttpSendRequest",
    "ShellExecute",
    "Mozilla/",
    "Mozilla/5.0 (Windows NT ",
    "User-Agent: ",
    "\\AppData\\Roaming\\",
    "SeDebugPrivilege",
    "-----BEGIN ",
)
CATALOG_SHA256 = "478c295913a45a14232b175bdb77a8a5691f21846053f283b3a453411a0197a9"

MAX_KEY_LENGTH = 8
# A zero in a differential matches any run of repeated bytes (padding, alignment),
# so only non-zero differential bytes count as verification.
MIN_VERIFIED_BYTES = 5
# Windows whose bytes are already text are rejected: text XOR text produces the
# small differentials that collide with crib differentials (design section 8).
_TEXTLIKE = bytes(range(0x20, 0x7F)) + b"\x00\t\n\r"


def catalog_digest(cribs: tuple[str, ...] = CRIBS) -> str:
    canonical = json.dumps(
        {"catalog": CATALOG_ID, "cribs": list(cribs)}, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Plan:
    crib_index: int
    encoding: Encoding
    encoded: bytes
    lag: int
    pattern: bytes


def plan_crib(crib_index: int, crib: str, encoding: Encoding) -> list[Plan]:
    encoded = crib.encode(encoding)
    usable: dict[int, bytes] = {}
    for lag in range(1, min(MAX_KEY_LENGTH, len(encoded) - 1) + 1):
        pattern = bytes(a ^ b for a, b in zip(encoded, encoded[lag:], strict=False))
        if sum(1 for byte in pattern if byte) >= MIN_VERIFIED_BYTES:
            usable[lag] = pattern
    covered: set[int] = set()
    plans = []
    for lag in sorted(usable, reverse=True):
        periods = {period for period in range(1, lag + 1) if lag % period == 0}
        if not periods <= covered:
            plans.append(Plan(crib_index, encoding, encoded, lag, usable[lag]))
            covered |= periods
    return plans


def covered_periods(crib: str, encoding: Encoding) -> frozenset[int]:
    return frozenset(
        period
        for plan in plan_crib(0, crib, encoding)
        for period in range(1, plan.lag + 1)
        if plan.lag % period == 0
    )


PLANS: tuple[Plan, ...] = tuple(
    sorted(
        (
            plan
            for index, crib in enumerate(CRIBS)
            for encoding in ENCODINGS
            for plan in plan_crib(index, crib, encoding)
        ),
        key=lambda plan: (plan.lag, plan.crib_index, ENCODINGS.index(plan.encoding)),
    )
)


def lag_xor(data: bytes, lag: int) -> bytes:
    size = len(data) - lag
    if size <= 0:
        return b""
    view = memoryview(data)
    left = int.from_bytes(view[:size], "big")
    right = int.from_bytes(view[lag:], "big")
    return (left ^ right).to_bytes(size, "big")


@dataclass(frozen=True)
class _Candidate:
    offset: int
    plan: Plan
    key: bytes  # minimal period, aligned to offset


@dataclass(frozen=True)
class XorHit:
    start: int
    end: int
    encoding: Encoding
    key: bytes  # minimal period, aligned to start
    crib: str
    crib_offset: int  # in characters of the decoded text
    complete: bool
    plaintext: bytes


@dataclass(frozen=True)
class XorScan:
    hits: tuple[XorHit, ...]
    examined: int
    examined_limit: bool
    hit_limit: bool


def _step(encoding: str) -> int:
    return 1 if encoding == "ascii" else 2


def _unit(data: bytes, position: int, key: bytes, origin: int, step: int) -> bool:
    if position < 0 or position + step > len(data):
        return False
    size = len(key)
    if not 0x20 <= data[position] ^ key[(position - origin) % size] <= 0x7E:
        return False
    return step == 1 or data[position + 1] ^ key[(position + 1 - origin) % size] == 0


def _candidate(data: bytes, position: int, plan: Plan) -> _Candidate | None:
    window = data[position : position + len(plan.encoded)]
    if not window.translate(None, _TEXTLIKE):
        return None
    key = minimal_period(bytes(data[position + j] ^ plan.encoded[j] for j in range(plan.lag)))
    if not any(key):
        return None
    size = len(key)
    if any(data[position + j] ^ key[j % size] != byte for j, byte in enumerate(plan.encoded)):
        return None  # the differential match makes this unreachable; kept as a guard
    return _Candidate(position, plan, key)


def _covered(candidate: _Candidate, active: list[XorHit]) -> bool:
    span_end = candidate.offset + len(candidate.plan.encoded)
    step = _step(candidate.plan.encoding)
    for hit in active:
        if (
            hit.encoding == candidate.plan.encoding
            and hit.start <= candidate.offset
            and span_end <= hit.end
            and (candidate.offset - hit.start) % step == 0
        ):
            shift = (candidate.offset - hit.start) % len(hit.key)
            if hit.key[shift:] + hit.key[:shift] == candidate.key:
                return True
    return False


def _extend(data: bytes, candidate: _Candidate, max_chars: int) -> XorHit:
    plan, key, origin = candidate.plan, candidate.key, candidate.offset
    step = _step(plan.encoding)
    budget = max_chars - len(plan.encoded) // step
    span_end = origin + len(plan.encoded)
    left = 0
    while left <= budget and _unit(data, origin - (left + 1) * step, key, origin, step):
        left += 1
    right = 0
    while right <= budget and _unit(data, span_end + right * step, key, origin, step):
        right += 1
    complete = left + right <= budget
    if not complete:
        take_left = min(left, budget // 2)
        right = min(right, budget - take_left)
        left = min(left, budget - right)
    start, end = origin - left * step, span_end + right * step
    size = len(key)
    plaintext = bytes(data[p] ^ key[(p - origin) % size] for p in range(start, end))
    shift = (start - origin) % size
    return XorHit(
        start=start,
        end=end,
        encoding=plan.encoding,
        key=key[shift:] + key[:shift],
        crib=CRIBS[plan.crib_index],
        crib_offset=left,
        complete=complete,
        plaintext=plaintext,
    )


def scan(
    data: bytes, *, max_hits: int = 256, max_examined: int = 200_000, max_chars: int = 1024
) -> XorScan:
    if max_chars < 64:
        raise ValueError("max_chars must leave room for the longest crib")
    candidates: list[_Candidate] = []
    examined = 0
    examined_limit = False
    lag, diff = 0, b""
    for plan in PLANS:
        if plan.lag != lag:
            lag, diff = plan.lag, b""
            diff = lag_xor(data, lag)
        position = diff.find(plan.pattern)
        while position != -1:
            if examined >= max_examined:
                examined_limit = True
                break
            examined += 1
            if (candidate := _candidate(data, position, plan)) is not None:
                candidates.append(candidate)
            position = diff.find(plan.pattern, position + 1)
        if examined_limit:
            break
    del diff
    candidates.sort(key=lambda c: (c.offset, c.plan.crib_index, ENCODINGS.index(c.plan.encoding)))
    hits: list[XorHit] = []
    active: list[XorHit] = []
    hit_limit = False
    for candidate in candidates:
        active = [hit for hit in active if hit.end > candidate.offset]
        if _covered(candidate, active):
            continue
        if len(hits) >= max_hits:
            hit_limit = True
            break
        hit = _extend(data, candidate, max_chars)
        hits.append(hit)
        active.append(hit)
    hits.sort(key=lambda h: (h.start, h.end, ENCODINGS.index(h.encoding), h.key))
    return XorScan(tuple(hits), examined, examined_limit, hit_limit)


class XorParts(NamedTuple):
    data: DecodedStringData
    location: Location
    transform: Transform
    anchor: XorAnchor


def parts(hit: XorHit) -> XorParts:
    text = hit.plaintext.decode(hit.encoding)
    return XorParts(
        data=DecodedStringData(
            encoding=hit.encoding,
            text=text,
            raw_hex=hit.plaintext.hex(),
            characters=len(text),
            complete=hit.complete,
            total_characters=len(text) if hit.complete else None,
        ),
        location=Location(offset=hit.start, length=hit.end - hit.start),
        transform=Transform(name="xor-repeating-v1", key_hex=hit.key.hex()),
        anchor=XorAnchor(catalog=CATALOG_ID, crib=hit.crib, crib_offset=hit.crib_offset),
    )


def evidence(hit: XorHit, evidence_id: str) -> DecodedStringEvidence:
    built = parts(hit)
    return DecodedStringEvidence(
        id=evidence_id,
        component="decode_xor",
        location=built.location,
        transform=built.transform,
        anchor=built.anchor,
        data=built.data,
    )


def verify(evidence: DecodedStringEvidence, data: bytes) -> None:
    anchor, key_hex = evidence.anchor, evidence.transform.key_hex
    if evidence.transform.name != "xor-repeating-v1" or anchor is None or key_hex is None:
        raise ValueError("not an XOR decoding")
    if anchor.catalog != CATALOG_ID or anchor.crib not in CRIBS:
        raise ValueError("anchor is not part of this crib catalog")
    offset, length = evidence.location.offset, evidence.location.length
    if offset is None or length is None or offset + length > len(data):
        raise ValueError("region lies outside the sample")
    key = bytes.fromhex(key_hex)
    encoding = evidence.data.encoding
    if len(key) not in covered_periods(anchor.crib, encoding):
        raise ValueError("this crib cannot verify a key of that period")
    region = data[offset : offset + length]
    decoded = bytes(byte ^ key[i % len(key)] for i, byte in enumerate(region))
    if decoded.hex() != evidence.data.raw_hex:
        raise ValueError("the published decoding cannot be reproduced")
    step = _step(encoding)
    window_start = anchor.crib_offset * step
    window = region[window_start : window_start + len(anchor.crib) * step]
    if not window.translate(None, _TEXTLIKE):
        raise ValueError("the anchor window is plain text; the method never publishes it")
    if evidence.data.complete and (
        _unit(data, offset - step, key, offset, step)
        or _unit(data, offset + length, key, offset, step)
    ):
        raise ValueError("a run declared complete continues past its boundaries")
