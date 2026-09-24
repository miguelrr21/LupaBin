"""Reproduce the Fase 4 measurements of calls to imported functions.

    uv run python -m tests.code_eval corpus DIR [DIR ...] [--recursive] [--ext .exe,.dll]
        [--stride N] [--limit N] [--review N] [--seed N]
    uv run python -m tests.code_eval worst

`corpus` treats every file as benign and runs the PE and code extractors on it: every
report must validate and every call must match the sample's bytes (a single failure
would invalidate a report). In x64 it also counts calls outside the functions that
`.pdata` declares, the error indicator of the walk, and for call arguments the
constants that the parameter's type rejects, the error indicator of the stretch rule
(`--review N` prints N random published arguments with their stretch). Files are only read as bytes:
nothing is executed, and they never enter the repository. `worst` times synthetic
20 MiB inputs built to maximise decoded instructions and published calls. Not part
of the package or of CI.
"""

import argparse
import bisect
import json
import random
import struct
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

from dissect.analysis import analyze_bytes
from dissect.evidence import argument_forms
from dissect.evidence.code import verify_calls
from dissect.evidence.facts import ApiCallEvidence, ImportEvidence
from dissect.evidence.models import Limits, Report
from dissect.extractors import code as code_extractor
from dissect.extractors import code_args, code_entries
from dissect.extractors.code import CodeExtractor
from dissect.extractors.pe import PEExtractor
from dissect.extractors.pe_layout import InvalidPE, InvalidTable, parse_layout
from tests.fixtures.pe_builder import CODE_RVA, build_code_pe

MAX_INPUT = 20 * 1024 * 1024
STACK = " [pila]"  # marks an argument read from an x64 stack slot (design section 11)


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


class ArgumentProbe:
    """Records, inside the extractor, every constant the stretch rule recovers for a
    catalog parameter and whether its type accepted it (design section 7).

    Published arguments are type-coherent by construction; the error indicator is the
    recovered constants the type rejects, each of which is examined. A random sample
    of published ones is printed with its stretch disassembled, for manual review.
    """

    def __init__(self) -> None:
        self.name = ""
        self.recovered: Counter[tuple[int, str]] = Counter()
        self.accepted: Counter[tuple[int, str]] = Counter()
        self.rejected: list[tuple[int, str, str, str, int, int, str]] = []
        self.stretches: dict[int, int] = {}  # call rva -> stretch start, current file
        self.starts: dict[tuple[str, int], int] = {}  # (path, call rva) -> stretch start
        self.published: list[tuple[str, int, int, int, str, str]] = []
        self.detail = 0
        self.seconds = 0.0
        self.examined: Counter[int] = Counter()
        original_argument = code_extractor._argument
        original_constants = code_args.ArgumentFinder.constants
        original_arguments = code_extractor._arguments
        probe = self

        def argument(parameter, entry, found, layout, characters):  # type: ignore[no-untyped-def]
            data = original_argument(parameter, entry, found, layout, characters)
            label = f"{entry.name}.{parameter.name}"
            key = (layout.bits, label)
            probe.recovered[key] += 1
            if data is not None:
                probe.accepted[key] += 1
            else:
                reason = probe.reason(parameter, found, layout)
                probe.rejected.append(
                    (layout.bits, label, reason, probe.name, found.setter[0],
                     found.setting.value, found.setting.kind)
                )  # fmt: skip
            return data

        def constants(finder, start, call):  # type: ignore[no-untyped-def]
            probe.stretches[call] = start
            probe.examined[finder.bits] += 1
            return original_constants(finder, start, call)

        def arguments(layout, code, targets, catalog, calls, collector, progress, deadline):  # type: ignore[no-untyped-def]
            began = time.perf_counter()
            budget = code_args.Budget
            used: list[code_args.Budget] = []

            def tracked(*a, **k):  # type: ignore[no-untyped-def]
                used.append(budget(*a, **k))
                return used[-1]

            code_extractor.Budget = tracked  # type: ignore[assignment,misc]
            try:
                original_arguments(
                    layout, code, targets, catalog, calls, collector, progress, deadline
                )
            finally:
                code_extractor.Budget = budget  # type: ignore[misc]
            probe.seconds += time.perf_counter() - began
            probe.detail += sum(b.used for b in used)

        code_extractor._argument = argument  # type: ignore[assignment]
        code_args.ArgumentFinder.constants = constants  # type: ignore[method-assign]
        code_extractor._arguments = arguments  # type: ignore[assignment]

    @staticmethod
    def reason(parameter, found, layout) -> str:  # type: ignore[no-untyped-def]
        setting = found.setting
        if parameter.type == "hkey":
            return "not a listed key"
        if parameter.type == "integer":
            return "an address, not an immediate"
        target = argument_forms.address_of(setting, layout.bits, layout.header.image_base)
        if target is None:
            return "not an address in the image"
        for item in layout.sections:
            section = item.data
            if section.raw_status == "present" and section.rva <= target < (
                section.rva + section.raw_size
            ):
                return "writable section" if "write" in section.permissions else "not a string"
        return "not in a section on disk"

    def record(self, report: Report, path: Path) -> None:
        facts = {f.id: f for f in report.evidence}
        bits = 32 if report.sample.type == "PE32" else 64
        for fact in report.evidence:
            if fact.kind != "call_argument":
                continue
            call = facts[fact.provenance.evidence_ids[0]]
            callee = facts[call.provenance.evidence_ids[0]]
            function = (
                callee.data.function.text
                if callee.kind == "import" and callee.data.function
                else "?"
            )
            data = fact.data
            shown = data.constant or (data.string.text if data.string else hex(data.value))
            rva = call.location.rva or 0
            self.starts[(str(path), rva)] = self.stretches.get(rva, rva - 64)
            self.published.append(
                (
                    str(path),
                    bits,
                    rva,
                    fact.location.rva or 0,
                    f"{function}.{data.name}{STACK if data.method == 'stack-slot-v1' else ''}",
                    shown,
                )
            )
        self.stretches.clear()

    def report(self, review: int, seed: int, match: str = "") -> None:
        for bits in (32, 64):
            names = sorted({name for b, name in self.recovered if b == bits})
            print(f"x{'86' if bits == 32 else '64'}: catalog calls examined {self.examined[bits]}")
            for name in names:
                key = (bits, name)
                print(
                    f"  {name:11} recovered {self.recovered[key]:6}"
                    f"  accepted {self.accepted[key]:6}"
                )
        reasons = Counter((bits, name, reason) for bits, name, reason, *_ in self.rejected)
        print("rejected by type:", dict(reasons))
        for bits, name, reason, path, rva, value, kind in self.rejected[:40]:
            print(f"  REJECTED x{bits} {name} {reason}: {path} setter {rva:#x} {kind} {value:#x}")
        print(f"argument pass: {self.detail} detail instructions, {self.seconds:.2f} s")
        rng = random.Random(seed)  # noqa: S311 - a reproducible review sample
        chosen = []
        for pattern in match.split(",") if match else [""]:
            pool = [item for item in self.published if pattern in item[4]]
            chosen += rng.sample(pool, min(review, len(pool)))
        for path, bits, call, setter, name, shown in chosen:
            print(
                f"\nREVIEW {path} x{'86' if bits == 32 else '64'} call {call:#x}: {name} = {shown}"
            )
            self.disassemble(Path(path), bits, call, setter)

    def disassemble(self, path: Path, bits: int, call: int, setter: int) -> None:
        import capstone

        data = path.read_bytes()
        layout = parse_layout(data, Limits())
        start = min(self.starts.get((str(path), call), call - 64), setter)
        start = max(start, call - 256)
        offset, _ = layout.locate(start, call + 16 - start)
        engine = capstone.Cs(
            capstone.CS_ARCH_X86, capstone.CS_MODE_32 if bits == 32 else capstone.CS_MODE_64
        )
        for insn in engine.disasm(data[offset : offset + call + 16 - start], start):
            mark = (
                "  <- setter"
                if insn.address == setter
                else ("  <- call" if insn.address == call else "")
            )
            print(
                f"    {insn.address:#010x}  {insn.bytes.hex():20}"
                f" {insn.mnemonic} {insn.op_str}{mark}"
            )
            if insn.address >= call:
                break


def corpus(args: argparse.Namespace) -> None:
    use_entries(args.entries)
    probe = ArgumentProbe()
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
        probe.name = str(path)
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
        probe.record(report, path)
        totals["arguments"] += sum(f.kind == "call_argument" for f in report.evidence)
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
    probe.report(args.review, args.seed, args.review_match)
    if args.dump:
        # every published and rejected argument, for analyses that should not walk the
        # corpus again (design section 10.6)
        with open(args.dump, "w", encoding="utf-8") as stream:
            json.dump({"published": probe.published, "rejected": probe.rejected}, stream)


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
        # calls to a catalog function: long stretches exhaust the detail-mode budget,
        # constant pushes the published-argument quota
        "argument-stretches": bytes([0x90]) * 63 + bytes([0xFF, 0x15]) + absolute,
        "argument-values": (
            bytes([0x68])
            + struct.pack("<I", 0x20019)  # push samDesired
            + bytes([0x6A, 0x00])  # push ulOptions
            + bytes([0x6A, 0x00])  # push lpSubKey (not a string)
            + bytes([0x68])
            + struct.pack("<I", 0x80000001)  # push hKey
            + bytes([0xFF, 0x15])
            + absolute
        ),  # fmt: skip
    }
    if name == "argument-stack-x64":
        # x64 calls to RegCreateKeyExW, each after 15 stores to a stack slot: every
        # instruction goes through the stack-slot rule (design section 11)
        stores = bytes.fromhex("c744242806000200") * 15  # mov dword ptr [rsp+0x28], imm32
        body = bytearray()
        while len(body) + len(stores) + 6 <= size:
            body += stores
            call = CODE_RVA + len(body)
            body += bytes.fromhex("ff15") + struct.pack("<i", 0x1140 - (call + 6))
        return build_code_pe(bytes(body), bits=64, dll=b"advapi32.dll", function=b"RegCreateKeyExW")
    unit = units[name]
    code = unit * (size // len(unit))
    if name.startswith("argument"):
        return build_code_pe(code, dll=b"advapi32.dll", function=b"RegOpenKeyExW")
    return build_code_pe(code)


WORST = (
    "nops",
    "jumps",
    "relative-calls",
    "import-calls",
    "argument-stretches",
    "argument-values",
    "argument-stack-x64",
)


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
    run.add_argument("--review", type=int, default=0, help="arguments to print for review")
    run.add_argument("--seed", type=int, default=2026)
    run.add_argument("--dump", help="write published and rejected arguments as JSON")
    run.add_argument(
        "--review-match", default="", help="review only Function.parameter labels containing this"
    )
    run.set_defaults(handler=corpus)
    case = commands.add_parser("worst")
    case.add_argument("--case", choices=WORST)
    case.set_defaults(handler=worst)
    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
