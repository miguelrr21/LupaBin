"""Reproduce the decoding measurements on a directory of benign binaries.

    uv run python -m tests.decode_eval false-positives DIR [DIR ...] [--limit N]
        [--recursive] [--ext .exe,.dll] [--stride N] [--only all|xor|text]
    uv run python -m tests.decode_eval recall DIR [--trials N] [--seed S]
    uv run python -m tests.decode_eval timing

Every file in DIR is treated as benign, so any decoding found there counts as a
false positive. Files are only read as bytes: nothing is executed, and they never
enter the repository. Not part of the package or of CI.
"""

import argparse
import hashlib
import itertools
import time
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

from lupabin.evidence.collector import Collector, Progress
from lupabin.evidence.facts import StringEvidence
from lupabin.evidence.models import Limits
from lupabin.evidence.primitives import minimal_period
from lupabin.extractors import decode_strings, decode_xor
from lupabin.extractors.strings import StringsExtractor

MAX_INPUT = 20 * 1024 * 1024

# Realistic strings by category, written independently of the crib catalog; the last
# category deliberately contains no anchor and is expected never to be found.
PLAINTEXTS: dict[str, tuple[str, ...]] = {
    "URL": (
        "http://update-check.invalid/v2/ping",
        "https://cdn-assets.invalid/img/logo.png",
        "http://www.example.invalid/index.php?q=1",
        "https://api.sample.invalid:8443/v1/beacon",
        "http://10.0.0.5:8080/upload",
        "https://www.training.invalid/dl/setup.exe",
        "http://files.invalid/a.bin",
        "https://t.invalid/x",
    ),
    "HTTP": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0)",
        "Content-Type: application/x-www-form-urlencoded",
        "Accept-Language: en-US,en;q=0.9",
        "POST /gate.php HTTP/1.1",
    ),
    "ruta/registro": (
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "C:\\Windows\\System32\\svchost.exe",
        "%APPDATA%\\Microsoft\\update.exe",
        "C:\\Users\\Public\\Documents\\cfg.dat",
        "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu",
        "C:\\ProgramData\\svc\\log.txt",
    ),
    "API": (
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "GetProcAddress",
        "LoadLibraryA",
        "IsDebuggerPresent",
        "NtUnmapViewOfSection",
        "InternetOpenUrlA",
        "URLDownloadToFileW",
        "RegSetValueExA",
    ),
    "comando": (
        "cmd.exe /c del /q %TEMP%\\*.tmp",
        "powershell.exe -nop -w hidden -enc",
        "schtasks /create /tn Updater /tr",
        "rundll32.exe shell32.dll,Control_RunDLL",
        "vssadmin list shadows",
        "net user guest /active:no",
    ),
    "DLL": ("kernel32.dll", "ntdll.dll", "advapi32.dll"),
    "sin ancla": (
        "Global\\MyMutex_7731",
        "secret-config-key-v2",
        "botnet-id=48213",
        "campaign_2026_q3",
    ),
}
# A second string under the same key, as in real string tables, for the "shared" mode.
COMPANION = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"


class Stream:
    """Seeded deterministic byte stream (SHA-256 in counter mode), for reproducibility."""

    def __init__(self, seed: str) -> None:
        self.seed, self.counter, self.pool = seed, 0, b""

    def bytes(self, size: int) -> bytes:
        if len(self.pool) < size:
            count = (size - len(self.pool)) // 32 + 1
            blocks = (
                hashlib.sha256(f"{self.seed}:{self.counter + n}".encode()).digest()
                for n in range(count)
            )
            self.pool += b"".join(blocks)  # one join: repeated += would be quadratic
            self.counter += count
        out, self.pool = self.pool[:size], self.pool[size:]
        return out

    def below(self, bound: int) -> int:
        return int.from_bytes(self.bytes(8), "big") % bound


def files_in(
    directory: Path,
    limit: int,
    *,
    recursive: bool = False,
    extensions: frozenset[str] | None = None,
    stride: int = 1,
) -> list[Path]:
    """Regular files up to the input limit, sorted; every `stride`-th one (deterministic)."""
    candidates = directory.rglob("*") if recursive else directory.iterdir()
    paths = []
    for path in candidates:
        try:
            if not path.is_file() or path.stat().st_size > MAX_INPUT:
                continue
        except OSError:
            continue
        if extensions is None or path.suffix.lower() in extensions:
            paths.append(path)
    return sorted(paths)[::stride][:limit]


def string_facts(data: bytes) -> Iterator[StringEvidence]:
    collector = Collector(Limits())
    StringsExtractor().extract(data, collector, Progress("strings", "eval"))
    for fact in collector.facts:
        if isinstance(fact, StringEvidence):
            yield fact


def false_positives(
    directories: list[Path],
    limit: int,
    *,
    recursive: bool = False,
    extensions: frozenset[str] | None = None,
    stride: int = 1,
    only: str = "all",
) -> None:
    kinds: Counter[str] = Counter()
    examples: list[tuple[str, str, str]] = []
    total, started = 0, time.perf_counter()
    paths = [
        path
        for directory in directories
        for path in files_in(
            directory, limit, recursive=recursive, extensions=extensions, stride=stride
        )
    ]
    for count, path in enumerate(paths, 1):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        total += len(data)
        if only in ("all", "xor"):
            for hit in decode_xor.scan(data).hits:
                kinds["xor"] += 1
                text = hit.plaintext.decode(hit.encoding)[:48]
                examples.append((str(path), f"xor key={hit.key.hex()} crib={hit.crib!r}", text))
        if only in ("all", "text"):
            next_id = map("E{}".format, itertools.count(1)).__next__
            for fact in string_facts(data):
                for evidence in decode_strings.candidates(fact, next_id):
                    kinds[evidence.transform.name] += 1
                    examples.append((str(path), evidence.transform.name, evidence.data.text[:48]))
        if count % 500 == 0:
            elapsed = time.perf_counter() - started
            print(
                f"  ... {count}/{len(paths)} files, {total / 2**20:.0f} MiB, {elapsed:.0f}s, "
                f"{sum(kinds.values())} decodings",
                flush=True,
            )
    elapsed = time.perf_counter() - started
    print(f"{len(paths)} files, {total / 2**20:.0f} MiB, {elapsed:.1f}s ({only})")
    counts = " ".join(
        f"{name}={kinds[key]}"
        for name, key in (("xor", "xor"), ("base64", "base64-strict-v1"), ("hex", "hex-strict-v1"))
    )
    print(f"false positives: {counts}")
    for example in examples[:200]:
        print("  ", example)


def recovered(data: bytes, start: int, length: int, key: bytes) -> bool:
    canonical = minimal_period(key)
    for hit in decode_xor.scan(data).hits:
        if hit.start < start + length and start < hit.end:
            shift = (start - hit.start) % len(hit.key)
            if hit.key[shift:] + hit.key[:shift] == canonical:
                return True
    return False


def recall(directory: Path, trials: int, seed: str) -> None:
    backgrounds = [p.read_bytes()[: 1 << 20] for p in files_in(directory, 60)]
    texts = [(cat, text) for cat, items in PLAINTEXTS.items() for text in items]
    printable = bytes(range(0x21, 0x7F))
    configs: list[tuple[str, int, str]] = [
        ("1 byte 1..255", 1, "any"),
        ("1 byte >= 0x80", 1, "high"),
        ("2 bytes", 2, "any"),
        ("4 bytes", 4, "any"),
        ("8 bytes", 8, "any"),
        ("4 bytes ASCII", 4, "ascii"),
        ("8 bytes ASCII", 8, "ascii"),
    ]
    stream = Stream(seed)
    per_category: dict[tuple[str, str], list[int]] = {}
    print(
        f"{'key':16} {'ascii/solo':>11} {'ascii/comp.':>12} {'utf16/solo':>11} {'utf16/comp.':>12}"
    )
    for label, length, kind in configs:
        row = []
        for encoding in decode_xor.ENCODINGS:
            for shared in (False, True):
                found = 0
                for _ in range(trials):
                    if kind == "ascii":
                        key = bytes(printable[stream.below(len(printable))] for _ in range(length))
                    else:
                        floor = 0x80 if kind == "high" else 0
                        key = bytes(floor + stream.below(256 - floor) for _ in range(length))
                    if not any(key):
                        key = bytes([1]) + key[1:]
                    category, text = texts[stream.below(len(texts))]
                    data = bytearray(backgrounds[stream.below(len(backgrounds))])
                    plain = text.encode(encoding)
                    half = len(data) // 2
                    start = stream.below(half - len(plain))
                    data[start : start + len(plain)] = bytes(
                        b ^ key[i % length] for i, b in enumerate(plain)
                    )
                    if shared:
                        companion = COMPANION.encode(encoding)
                        at = half + stream.below(half - len(companion))
                        data[at : at + len(companion)] = bytes(
                            b ^ key[(i + at - start) % length] for i, b in enumerate(companion)
                        )
                    ok = recovered(bytes(data), start, len(plain), key)
                    found += ok
                    if length == 8 and kind == "any" and encoding == "ascii":
                        tally = per_category.setdefault((category, str(shared)), [0, 0])
                        tally[0] += ok
                        tally[1] += 1
                row.append(found / trials)
        print(f"{label:16} {row[0]:11.1%} {row[1]:12.1%} {row[2]:11.1%} {row[3]:12.1%}")
    print("\n8 bytes, ASCII, by category (solo / compartida):")
    for category in PLAINTEXTS:
        cells = []
        for shared in ("False", "True"):
            hit, total = per_category.get((category, shared), [0, 0])
            cells.append(f"{hit / total:6.1%} (n={total})" if total else "  -  ")
        print(f"  {category:14} {cells[0]:>16} {cells[1]:>16}")


def timing() -> None:
    data = Stream("timing").bytes(MAX_INPUT)
    started = time.perf_counter()
    result = decode_xor.scan(data)
    elapsed = time.perf_counter() - started
    print(f"scan of {MAX_INPUT / 2**20:.0f} MiB: {elapsed:.2f}s, hits={len(result.hits)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    fp = sub.add_parser("false-positives")
    fp.add_argument("directories", type=Path, nargs="+")
    fp.add_argument("--limit", type=int, default=1_000_000, help="max files per directory")
    fp.add_argument("--recursive", action="store_true")
    fp.add_argument("--ext", default="", help="comma-separated suffixes, e.g. .exe,.dll")
    fp.add_argument("--stride", type=int, default=1, help="keep every n-th sorted file")
    fp.add_argument("--only", choices=("all", "xor", "text"), default="all")
    rc = sub.add_parser("recall")
    rc.add_argument("directory", type=Path)
    rc.add_argument("--trials", type=int, default=300)
    rc.add_argument("--seed", default="lupabin-decode-eval")
    sub.add_parser("timing")
    args = parser.parse_args()
    if args.command == "false-positives":
        extensions = frozenset(e.strip().lower() for e in args.ext.split(",") if e.strip())
        false_positives(
            args.directories,
            args.limit,
            recursive=args.recursive,
            extensions=extensions or None,
            stride=args.stride,
            only=args.only,
        )
    elif args.command == "recall":
        recall(args.directory, args.trials, args.seed)
    else:
        timing()


if __name__ == "__main__":
    main()
