"""Reproduce the Fase 4 measurements of calls to imported functions.

    uv run python -m tests.code_eval corpus DIR [DIR ...] [--recursive] [--ext .exe,.dll]
        [--stride N] [--limit N]
    uv run python -m tests.code_eval worst

`corpus` treats every file as benign and runs the PE and code extractors on it: every
report must validate and every call must match the sample's bytes (a single failure
would invalidate a report). In x64 it also counts calls outside the functions that
`.pdata` declares, the error indicator of the walk. Files are only read as bytes:
nothing is executed, and they never enter the repository. `worst` times synthetic
20 MiB inputs built to maximise decoded instructions and published calls. Not part
of the package or of CI.
"""

import argparse
import bisect
import struct
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

from dissect.analysis import analyze_bytes
from dissect.evidence.code import verify_calls
from dissect.evidence.facts import ApiCallEvidence, ImportEvidence
from dissect.evidence.models import Limits, Report
from dissect.extractors import code as code_extractor
from dissect.extractors import code_entries
from dissect.extractors.code import CodeExtractor
from dissect.extractors.pe import PEExtractor
from dissect.extractors.pe_layout import InvalidPE, InvalidTable, parse_layout
from tests.fixtures.pe_builder import build_code_pe

MAX_INPUT = 20 * 1024 * 1024


def files(roots: list[Path], recursive: bool, ext: tuple[str, ...], stride: int) -> Iterator[Path]:
    for root in roots:
        found = sorted(root.rglob("*") if recursive else root.iterdir())
        chosen = [p for p in found if p.suffix.lower() in ext and p.is_file()]
        yield from chosen[::stride]


def functions(data: bytes) -> list[tuple[int, int]] | None:
    """x64 `.pdata` ranges (begin, end), read here independently of the extractor."""
    try:
        layout = parse_layout(data, Limits())
        if layout.bits != 64 or len(layout.directories) <= 3:
            return None
        rva, size = layout.directories[3]
        if not rva or size < 12:
            return None
        offset, _ = layout.locate(rva, size - size % 12)
    except (InvalidPE, InvalidTable, struct.error):
        return None
    return sorted(struct.unpack_from("<II", data, offset + 12 * i) for i in range(size // 12))


def outside(calls: list[ApiCallEvidence], ranges: list[tuple[int, int]]) -> int:
    starts = [begin for begin, _ in ranges]
    count = 0
    for call in calls:
        rva = call.location.rva or 0
        index = bisect.bisect_right(starts, rva) - 1
        if index < 0 or rva >= ranges[index][1]:
            count += 1
    return count


def use_entries(names: str) -> None:
    """Walk only from the entry point, exports and these tables (a measured variant)."""
    chosen = frozenset(name for name in names.split(",") if name)
    unknown = chosen - code_entries.SOURCES
    if unknown:
        raise SystemExit(f"unknown entry sources: {sorted(unknown)}")

    def entries(layout, exports, limit):  # type: ignore[no-untyped-def]
        return code_entries.entries(layout, exports, limit, chosen)

    code_extractor.entries = entries  # type: ignore[assignment]


def corpus(args: argparse.Namespace) -> None:
    use_entries(args.entries)
    ext = tuple(e.strip().lower() for e in args.ext.split(","))
    totals: Counter[str] = Counter()
    via: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    times: list[tuple[float, str, int]] = []
    for path in files([Path(d) for d in args.dirs], args.recursive, ext, args.stride):
        if args.limit and totals["files"] >= args.limit:
            break
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if not data.startswith(b"MZ") or len(data) > MAX_INPUT:
            continue
        totals["files"] += 1
        start = time.perf_counter()
        try:
            report = analyze_bytes(data, extractors=(PEExtractor(), CodeExtractor()))
        except ValueError as error:  # a report that does not validate
            totals["invalid_reports"] += 1
            print("INVALID", path, str(error)[:200])
            continue
        elapsed = time.perf_counter() - start
        run = next(r for r in report.extractor_runs if r.source == "code")
        parts = {part.name: part for part in run.components}
        if parts["disassembly"].status == "blocked":
            totals["blocked"] += 1
            continue
        try:
            verify_calls(report.evidence, data)
        except ValueError:
            totals["verify_failures"] += 1
            print("VERIFY", path)
        calls = [f for f in report.evidence if isinstance(f, ApiCallEvidence)]
        named = {f.id for f in report.evidence if isinstance(f, ImportEvidence) and f.data.function}
        called = {f.provenance.evidence_ids[0] for f in calls}
        ranges = functions(data)
        if ranges:
            layout = parse_layout(data, Limits())
            starts = {begin for begin, _ in ranges}
            guard = code_entries.guard_targets(layout, 1 << 20)
            totals["x64_guard_targets"] += len(guard)
            totals["x64_guard_targets_in_pdata"] += sum(t in starts for t in guard)
            totals["x64_files"] += 1
            totals["x64_calls"] += len(calls)
            totals["outside_pdata"] += outside(calls, ranges)
        totals["walked"] += 1
        totals["calls"] += len(calls)
        totals["imports_named"] += len(named)
        totals["imports_called"] += len(called & named)
        totals["instructions"] += parts["disassembly"].examined or 0
        via.update(f.data.via for f in calls)
        reasons.update(
            r.code for r in report.limitations + report.extractor_errors if r.source == "code"
        )
        times.append((elapsed, path.name, parts["disassembly"].examined or 0))
    times.sort()
    print(dict(totals))
    print("via", dict(via), "code limits", dict(reasons))
    if times:
        pick = [times[int(len(times) * q)] for q in (0.5, 0.9, 0.99)] + [times[-1]]
        print("PE+code seconds p50/p90/p99/max:", ", ".join(f"{t:.2f}" for t, _, _ in pick))
        for seconds, name, instructions in times[-5:]:
            print(f"  {seconds:6.2f}s {instructions:>9} instr  {name}")


def peak_memory() -> int:
    """Peak resident memory of this process in bytes (Windows or Linux)."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        current = ctypes.windll.kernel32.GetCurrentProcess
        current.restype = wintypes.HANDLE
        query = ctypes.windll.psapi.GetProcessMemoryInfo
        query.argtypes = (wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD)
        if not query(current(), ctypes.byref(counters), counters.cb):
            raise OSError("GetProcessMemoryInfo failed")
        return int(counters.PeakWorkingSetSize)
    import resource

    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024


def worst_case(name: str) -> bytes:
    size = MAX_INPUT - 0x1400
    absolute = struct.pack("<I", 0x400000 + 0x1140)
    units = {
        "nops": bytes([0x90]),
        "jumps": bytes([0x74, 0x00]),  # jz to the next instruction: a block per instruction
        "relative-calls": bytes([0xE8, 0, 0, 0, 0]),  # a call site per instruction
        "import-calls": bytes([0xFF, 0x15]) + absolute,  # a published call per instruction
    }
    unit = units[name]
    return build_code_pe(unit * (size // len(unit)))


WORST = ("nops", "jumps", "relative-calls", "import-calls")


def worst(args: argparse.Namespace) -> None:
    if args.case is None:  # each case in its own process, for its own peak memory
        for name in WORST:
            command = [sys.executable, "-m", "tests.code_eval", "worst", "--case", name]
            subprocess.run(command, check=True)  # noqa: S603 - this interpreter, fixed args
        return
    data = worst_case(args.case)
    baseline = peak_memory()
    start = time.perf_counter()
    report = analyze_bytes(data, extractors=(PEExtractor(), CodeExtractor()))
    elapsed = time.perf_counter() - start
    peak = peak_memory()
    Report.model_validate_json(report.model_dump_json())
    verify_calls(report.evidence, data)
    run = next(r for r in report.extractor_runs if r.source == "code")
    parts = {p.name: (p.status, p.examined, p.evidence_count) for p in run.components}
    print(
        f"{args.case}: {elapsed:.2f}s, peak {peak / 2**20:.0f} MiB "
        f"(input and interpreter: {baseline / 2**20:.0f} MiB), {parts}",
        flush=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("corpus")
    run.add_argument("dirs", nargs="+")
    run.add_argument("--recursive", action="store_true")
    run.add_argument("--ext", default=".exe,.dll,.sys")
    run.add_argument("--stride", type=int, default=1)
    run.add_argument("--limit", type=int, default=0)
    run.add_argument(
        "--entries",
        default=",".join(sorted(code_entries.SOURCES)),
        help="tables the walk starts from, besides the entry point and exports",
    )
    run.set_defaults(handler=corpus)
    case = commands.add_parser("worst")
    case.add_argument("--case", choices=WORST)
    case.set_defaults(handler=worst)
    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
