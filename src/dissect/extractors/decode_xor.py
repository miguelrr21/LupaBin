"""Repeating-key XOR (1-8 bytes) located by crib differentials over raw sample bytes.

If c[i] = p[i] ^ k[i mod L], then c[i] ^ c[i+L] = p[i] ^ p[i+L] for any key of
period L. Searching a crib's lag-L differential in the sample's lag-L differential
finds that crib under every period-L key at once; the key is then derived from the
bytes, never chosen among candidates. Design: docs/superpowers/specs/
2026-09-22-static-decoding-design.md, sections 3.3-3.5 and 8.
"""

import hashlib
import json
import time
from dataclasses import dataclass, replace
from typing import Literal, NamedTuple

from dissect.evidence.facts import DecodedStringData, DecodedStringEvidence, XorAnchor
from dissect.evidence.primitives import (
    Location,
    Provenance,
    Transform,
    canonical_key,
    minimal_period,
)

Encoding = Literal["ascii", "utf-16-le"]
ENCODINGS: tuple[Encoding, ...] = ("ascii", "utf-16-le")

CATALOG_ID: Literal["dissect-xor-cribs-v3"] = "dissect-xor-cribs-v3"
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
    # v2: longer anchors, so that single strings can verify keys of up to 8 bytes
    "GetModuleHandle",
    "VirtualProtect",
    "IsDebuggerPresent",
    "CreateToolhelp32Snapshot",
    "NtUnmapViewOfSection",
    "InternetReadFile",
    "HttpOpenRequest",
    "RegSetValueEx",
    "Content-Type: ",
    "Content-Length: ",
    "Accept-Language: ",
    "HTTP/1.1",
    "powershell.exe",
    "rundll32.exe",
    "cmd.exe /c ",
    "schtasks /create",
    "http://www.",
    "https://www.",
    "\\Microsoft\\Windows\\",
    "C:\\Windows\\System32",
    # v3: path and registry fragments, chosen by coverage of real path strings in
    # benign binaries (design section 8), plus two common persistence locations.
    "\\Microsoft\\",
    "\\windows\\",
    "\\Windows\\",
    "\\CurrentControlSet\\",
    "\\system32\\",
    "\\System32\\",
    "\\Device\\",
    "SOFTWARE\\",
    "Software\\",
    "\\Users\\",
    "\\Registry\\Machine\\",
    "\\ProgramData\\",
    "%APPDATA%\\",
    "\\Temp\\",
)
CATALOG_SHA256 = "517bf2b5b557fab3f75724a3fa7fb946605e11335a234c2d68fb5d8b5ff6ca5c"

MAX_KEY_LENGTH = 8
# Distinct keys (period >= 2) whose reuse is searched after the first pass; each one
# costs a pass over the sample, so the count is bounded.
MAX_REUSE_KEYS = 8
# A zero in a differential matches any run of repeated bytes (padding, alignment),
# so only non-zero differential bytes count as verification.
MIN_VERIFIED_BYTES = 5
# Under a reused key the key equality verifies the match; the differential only has to
# be selective enough not to flood the search (about one random hit per 16 MiB). Below
# this, the exact ciphertext of the crib under each key rotation is searched instead.
_REUSE_SELECTIVE_BYTES = 3
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

COVERAGE: dict[tuple[int, Encoding], frozenset[int]] = {
    (index, encoding): covered_periods(crib, encoding)
    for index, crib in enumerate(CRIBS)
    for encoding in ENCODINGS
}


class Differentials:
    """data[i] ^ data[i + lag] for any lag, from one big-integer copy of the sample.

    Converting the sample once and deriving each lag with a shift, a mask and a XOR is
    cheaper than converting two slices per lag, and the result is the same bytes.
    """

    def __init__(self, data: bytes) -> None:
        self.size = len(data)
        self.number = int.from_bytes(data, "big")

    def lag(self, lag: int) -> bytes:
        size = self.size - lag
        if size <= 0:
            return b""
        low = self.number & ((1 << (8 * size)) - 1)
        return ((self.number >> (8 * lag)) ^ low).to_bytes(size, "big")


def lag_xor(data: bytes, lag: int) -> bytes:
    return Differentials(data).lag(lag)


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
    # None: the anchor itself verified the key. Otherwise the self-verified hit that
    # established this exact key elsewhere in the sample (key reuse).
    verified_by: "XorHit | None" = None


@dataclass(frozen=True)
class _Candidate:
    offset: int
    plan: Plan
    key: bytes  # minimal period, aligned to offset
    verified_by: XorHit | None = None


@dataclass(frozen=True)
class XorScan:
    hits: tuple[XorHit, ...]
    examined: int
    examined_limit: bool
    hit_limit: bool
    time_limit: bool = False  # the deadline stopped the scan between two searches


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
        verified_by=candidate.verified_by,
    )


class _Budget:
    def __init__(self, limit: int, deadline: float = float("inf")) -> None:
        self.limit, self.examined, self.exhausted = limit, 0, False
        self.deadline, self.late = deadline, False

    def expired(self) -> bool:
        """Checked before each search of the whole buffer: a slow machine or an input
        built against bytes.find stops here, partial, instead of timing out."""
        if not self.late and time.monotonic() > self.deadline:
            self.late = True
        return self.late

    def take(self) -> bool:
        if self.examined >= self.limit:
            self.exhausted = True
            return False
        self.examined += 1
        return True


def _self_verified(data: bytes, differentials: Differentials, budget: _Budget) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    lag, diff = 0, b""
    for plan in PLANS:
        if budget.expired():
            break
        if plan.lag != lag:
            lag, diff = plan.lag, b""
            diff = differentials.lag(lag)
        position = diff.find(plan.pattern)
        while position != -1 and budget.take():
            if (candidate := _candidate(data, position, plan)) is not None:
                candidates.append(candidate)
            position = diff.find(plan.pattern, position + 1)
        if budget.exhausted:
            break
    return candidates


def _reused(
    data: bytes,
    differentials: Differentials,
    verifiers: dict[bytes, XorHit],
    budget: _Budget,
) -> list[_Candidate]:
    """Anchors too short to verify a key by themselves, under a key verified elsewhere.

    A match must reproduce the whole crib under a key identical (up to phase) to one a
    self-verified hit established, so a coincidence needs len(crib) random bytes to
    align: 256**-7 or less per position for the shortest crib.
    """
    candidates: list[_Candidate] = []
    periods = sorted({len(key) for key in verifiers})
    for period in periods:
        table = {key: hit for key, hit in verifiers.items() if len(key) == period}
        diff = differentials.lag(period)
        for index, crib in enumerate(CRIBS):
            for encoding in ENCODINGS:
                if period in COVERAGE[index, encoding]:
                    continue  # the anchor verifies this period on its own (first pass)
                if budget.expired():
                    return candidates
                encoded = crib.encode(encoding)
                pattern = bytes(a ^ b for a, b in zip(encoded, encoded[period:], strict=False))
                if sum(1 for byte in pattern if byte) >= _REUSE_SELECTIVE_BYTES:
                    plan = Plan(index, encoding, encoded, period, pattern)
                    position = diff.find(pattern)
                    while position != -1 and budget.take():
                        if (candidate := _candidate(data, position, plan)) is not None:
                            verifier = table.get(canonical_key(candidate.key))
                            if verifier is not None and len(candidate.key) == period:
                                candidates.append(replace(candidate, verified_by=verifier))
                        position = diff.find(pattern, position + 1)
                    continue
                for key, verifier in table.items():
                    for shift in range(period):
                        rotated = key[shift:] + key[:shift]
                        pattern = bytes(b ^ rotated[j % period] for j, b in enumerate(encoded))
                        plan = Plan(index, encoding, encoded, period, pattern)
                        position = data.find(pattern)
                        while position != -1 and budget.take():
                            window = data[position : position + len(encoded)]
                            if window.translate(None, _TEXTLIKE):
                                candidates.append(_Candidate(position, plan, rotated, verifier))
                            position = data.find(pattern, position + 1)
            if budget.exhausted:
                return candidates
    return candidates


def _accept(
    data: bytes,
    candidates: list[_Candidate],
    hits: list[XorHit],
    max_hits: int,
    max_chars: int,
) -> bool:
    """Extend uncovered candidates into hits in offset order; True if the cap cut some."""
    candidates.sort(key=lambda c: (c.offset, c.plan.crib_index, ENCODINGS.index(c.plan.encoding)))
    existing = sorted(hits, key=lambda h: h.start)
    pointer = 0
    active: list[XorHit] = []
    for candidate in candidates:
        while pointer < len(existing) and existing[pointer].start <= candidate.offset:
            active.append(existing[pointer])
            pointer += 1
        active = [hit for hit in active if hit.end > candidate.offset]
        if _covered(candidate, active):
            continue
        if len(hits) >= max_hits:
            return True
        hit = _extend(data, candidate, max_chars)
        hits.append(hit)
        active.append(hit)
    return False


def scan(
    data: bytes,
    *,
    max_hits: int = 256,
    max_examined: int = 200_000,
    max_chars: int = 1024,
    reuse_keys: int = MAX_REUSE_KEYS,
    deadline: float = float("inf"),
) -> XorScan:
    if max_chars < 64:
        raise ValueError("max_chars must leave room for the longest crib")
    budget = _Budget(max_examined, deadline)
    differentials = Differentials(data)
    hits: list[XorHit] = []
    hit_limit = _accept(
        data, _self_verified(data, differentials, budget), hits, max_hits, max_chars
    )
    verifiers: dict[bytes, XorHit] = {}
    for hit in sorted(hits, key=lambda h: h.start):
        if len(hit.key) >= 2:  # every crib already verifies 1-byte keys on its own
            verifiers.setdefault(canonical_key(hit.key), hit)
    verifiers = dict(list(verifiers.items())[:reuse_keys])
    if verifiers and not budget.exhausted and not budget.late and not hit_limit:
        reused = _reused(data, differentials, verifiers, budget)
        hit_limit = _accept(data, reused, hits, max_hits, max_chars)
    hits.sort(key=lambda h: (h.start, h.end, ENCODINGS.index(h.encoding), h.key))
    return XorScan(tuple(hits), budget.examined, budget.exhausted, hit_limit, budget.late)


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


def evidence(
    hit: XorHit, evidence_id: str, verified_by_id: str | None = None
) -> DecodedStringEvidence:
    if (hit.verified_by is None) != (verified_by_id is None):
        raise ValueError("a reused key must cite the evidence that verified it")
    built = parts(hit)
    return DecodedStringEvidence(
        id=evidence_id,
        component="decode_xor",
        location=built.location,
        provenance=Provenance(evidence_ids=(verified_by_id,) if verified_by_id else ()),
        transform=built.transform,
        anchor=built.anchor,
        data=built.data,
    )


def verify(
    evidence: DecodedStringEvidence,
    data: bytes,
    verifier: DecodedStringEvidence | None = None,
) -> None:
    """Re-derive a published XOR decoding from the original bytes; raise if it differs.

    A decoding that cites another one reuses its key: the cited decoding must itself be
    self-verified with the same key, and the anchor then need not verify the period.
    """
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
    if evidence.provenance.evidence_ids:
        cited_key = verifier.transform.key_hex if verifier is not None else None
        if (
            verifier is None
            or verifier.provenance.evidence_ids
            or evidence.provenance.evidence_ids != (verifier.id,)
            or cited_key is None
            or canonical_key(bytes.fromhex(cited_key)) != canonical_key(key)
        ):
            raise ValueError("a reused key must come from a self-verified decoding")
        verify(verifier, data)
    elif len(key) not in covered_periods(anchor.crib, encoding):
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
