"""Measurements of the UPX reader (docs/metodo.md, «UPX»). Not part of the CI.

pairs <packed> <originals> --output <new.jsonl>
    Every file in <packed> is a copy of a benign program that the evaluator packed with
    UPX; its original is the file in <originals> whose name is the packed file's name up
    to the first dot. Compares what LupaBin derives with the original read by pefile:
    entry point, image base, section table and, function by function, the imports
    (DLL, name or ordinal, import slot).
strings <packed> <originals> --output <new.jsonl>
    Every string LupaBin would publish from the rebuilt image must be the run of
    characters that starts at the same RVA of the original image (or its beginning, if cut).
false-positives <dir>... --output <new.jsonl>
    Programs that are not packed: any UPX block found is a false positive.

Files are only read as bytes; nothing is executed.
"""

import argparse
import heapq
import json
import os
import time
from pathlib import Path

import pefile

from lupabin.evidence import upx
from lupabin.evidence.upx_checks import string_data
from lupabin.extractors.strings import ascii_runs, utf16_runs

# pefile cuts import names at 512 bytes; UPX keeps decorated C++ names whole
pefile.MAX_IMPORT_NAME_LENGTH = 0x1000
SUFFIXES = (".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr")
MAX_FILE = 20 * 1024 * 1024


def spans(pe: pefile.PE) -> list[upx.Span]:
    return [
        upx.Span(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData)
        for s in pe.sections
    ]


def original(path: Path) -> dict[str, object]:
    pe = pefile.PE(str(path))
    base = pe.OPTIONAL_HEADER.ImageBase
    imports = sorted(
        [
            (
                entry.dll.decode("latin-1").lower(),
                None if item.import_by_ordinal else item.name.decode("latin-1"),
                item.ordinal if item.import_by_ordinal else None,
                item.address - base,
            )
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
            for item in entry.imports
        ],
        key=repr,
    )
    return {
        "entry": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "base": base,
        "sections": [(s.Name.hex(), s.VirtualAddress, s.Misc_VirtualSize) for s in pe.sections],
        "imports": imports,
    }


def derived(data: bytes) -> tuple[dict[str, object] | None, str | None, float]:
    pe = pefile.PE(data=data, fast_load=True)
    start = time.perf_counter()
    found = upx.derive(data, spans(pe))
    seconds = time.perf_counter() - start
    if found is None:
        return None, None, seconds
    tail, dlls = found.unpacked.tail, found.dlls
    method = found.unpacked.header.method
    if tail is None or dlls is None:
        return {}, method, seconds
    imports = sorted(
        [
            (
                dll.decode("latin-1").lower(),
                None if item.function is None else item.function.decode("latin-1"),
                item.ordinal,
                item.iat_rva,
            )
            for dll, item in zip(dlls, tail.imports, strict=True)
        ],
        key=repr,
    )
    return (
        {
            "entry": tail.entry_rva,
            "base": tail.image_base,
            "sections": [(s.name.hex(), s.rva, s.virtual_size) for s in tail.sections],
            "imports": imports,
        },
        method,
        seconds,
    )


def pairs(packed: Path, originals: Path, output: Path) -> int:
    counts: dict[str, int] = {}
    with output.open("x", encoding="utf-8") as stream:
        for path in sorted(packed.iterdir()):
            source = originals / (path.name.split(".")[0] + path.suffix)
            if not path.is_file() or not source.is_file():
                continue
            got, method, seconds = derived(path.read_bytes())
            want = original(source)
            if got is None:
                outcome = "not_found"
            elif not got:
                outcome = "tail_abstained"
            else:
                outcome = "exact" if got == want else "mismatch"
            mismatched = [] if not got else [key for key in want if got.get(key) != want[key]]
            counts[outcome] = counts.get(outcome, 0) + 1
            row = {
                "packed": str(path),
                "original": str(source),
                "method": method,
                "outcome": outcome,
                "mismatched": mismatched,
                "imports": len(want["imports"]),  # type: ignore[arg-type]
                "seconds": round(seconds, 3),
            }
            stream.write(json.dumps(row) + "\n")
    print(json.dumps(counts))
    return 1 if counts.get("mismatch") else 0


def false_positives(roots: list[Path], output: Path) -> int:
    counts = {"files": 0, "with_magic": 0, "found": 0}
    with output.open("x", encoding="utf-8") as stream:
        for root in roots:
            for folder, _, names in os.walk(root):
                for name in names:
                    path = Path(folder) / name
                    if not name.lower().endswith(SUFFIXES):
                        continue
                    try:
                        if path.stat().st_size > MAX_FILE:
                            continue
                        data = path.read_bytes()
                    except OSError:
                        continue
                    counts["files"] += 1
                    if upx.MAGIC not in data:
                        continue
                    counts["with_magic"] += 1
                    try:
                        got = derived(data)[0]
                    except pefile.PEFormatError:
                        got = None
                    counts["found"] += got is not None
                    stream.write(json.dumps({"path": str(path), "found": got is not None}) + "\n")
    print(json.dumps(counts))
    return 0


def strings(packed: Path, originals: Path, output: Path) -> int:
    counts = {"files": 0, "strings": 0, "differ": 0}
    with output.open("x", encoding="utf-8") as stream:
        for path in sorted(packed.iterdir()):
            source = originals / (path.name.split(".")[0] + path.suffix)
            if not path.is_file() or not source.is_file():
                continue
            data = path.read_bytes()
            found = upx.derive(data, spans(pefile.PE(data=data, fast_load=True)))
            if found is None or found.image is None:
                continue
            texts = string_data(found, 1024, 10**9)
            mapped = pefile.PE(str(source)).get_memory_mapped_image()
            truth = {
                (start, encoding): mapped[start:end].decode(encoding)
                for start, encoding, end in heapq.merge(
                    ascii_runs(mapped), utf16_runs(mapped, 0), utf16_runs(mapped, 1)
                )
            }
            differ = [
                text
                for text in texts
                if (truth.get((text.rva, text.encoding)) or "") != text.text
                and not (
                    not text.complete
                    and (truth.get((text.rva, text.encoding)) or "").startswith(text.text)
                )
            ]
            counts["files"] += 1
            counts["strings"] += len(texts)
            counts["differ"] += len(differ)
            row = {
                "packed": str(path),
                "strings": len(texts),
                "differ": [(text.rva, text.text[:80]) for text in differ[:10]],
            }
            stream.write(json.dumps(row) + "\n")
    print(json.dumps(counts))
    return 1 if counts["differ"] else 0


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    one = commands.add_parser("pairs")
    one.add_argument("packed", type=Path)
    one.add_argument("originals", type=Path)
    one.add_argument("--output", type=Path, required=True)
    three = commands.add_parser("strings")
    three.add_argument("packed", type=Path)
    three.add_argument("originals", type=Path)
    three.add_argument("--output", type=Path, required=True)
    two = commands.add_parser("false-positives")
    two.add_argument("roots", type=Path, nargs="+")
    two.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "pairs":
        raise SystemExit(pairs(args.packed, args.originals, args.output))
    if args.command == "strings":
        raise SystemExit(strings(args.packed, args.originals, args.output))
    raise SystemExit(false_positives(args.roots, args.output))


if __name__ == "__main__":
    main()
