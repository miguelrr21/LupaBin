"""Reproduce the measurements of the .NET metadata reader on benign assemblies.

    uv run --with dnfile python -m tests.dotnet_eval corpus DIR [DIR ...] [--recursive]
        [--ext .exe,.dll] [--stride N] [--limit N] [--out differences.jsonl]

`corpus` treats every file as benign. For each PE file with a CLR directory it reads the
metadata with `lupabin.evidence.dotnet` and, when it reads it, compares every published
row with what dnfile, an independent parser, gives for the same row: the library,
function and method of each P/Invoke declaration, each literal of the #US stream at its
index, the name of each member reference,
the namespace, name and number of methods of each type, and the names of the referenced
assemblies. It also derives the facts and checks them as the host does. It counts the
files read, the files left unread by reason, the rows left out, and any file where a
row differs, a check fails or the reader raises anything but ValueError. `--out` lists
each difference so that it can be examined by hand.

dnfile is only used here: it is not a dependency of the package. Files are only read as
bytes: nothing is executed or loaded, and they never enter the repository. Not part of
the package or of CI.
"""

import argparse
import json
import logging
import time
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from lupabin.evidence import dotnet
from lupabin.evidence.dotnet_checks import derive

MAX_INPUT = 20 * 1024 * 1024


def files(roots: list[Path], recursive: bool, ext: tuple[str, ...], stride: int) -> Iterator[Path]:
    for root in roots:
        found = sorted(root.rglob("*") if recursive else root.iterdir())
        chosen = [p for p in found if p.suffix.lower() in ext and p.is_file()]
        yield from chosen[::stride]


def text(raw: bytes | None) -> str:
    return "" if raw is None else raw.decode("utf-8", "replace")


def reference(path: Path) -> dict[str, list[Any]] | None:
    """The same rows as dnfile reads them, by row number."""
    import dnfile  # noqa: PLC0415

    net = dnfile.dnPE(str(path)).net
    if net is None or net.mdtables is None:
        return None
    tables = net.mdtables
    rows: dict[str, list[Any]] = {"pinvokes": [], "members": [], "types": [], "references": []}
    rows["literals"] = [net.user_strings]
    for row in tables.ImplMap.rows if tables.ImplMap is not None else ():
        scope = row.ImportScope.row if row.ImportScope is not None else None
        forwarded = row.MemberForwarded.row if row.MemberForwarded is not None else None
        rows["pinvokes"].append(
            (
                "" if scope is None else str(scope.Name),
                str(row.ImportName),
                str(getattr(forwarded, "Name", "")) if forwarded is not None else "",
            )
        )
    for row in tables.MemberRef.rows if tables.MemberRef is not None else ():
        rows["members"].append(str(row.Name))
    for row in tables.TypeDef.rows if tables.TypeDef is not None else ():
        rows["types"].append((str(row.TypeNamespace), str(row.TypeName), len(row.MethodList)))
    for row in tables.AssemblyRef.rows if tables.AssemblyRef is not None else ():
        rows["references"].append(str(row.Name))
    return rows


def differences(metadata: dotnet.Metadata, expected: dict[str, list[Any]]) -> dict[str, Any]:
    """Each published row against the same row of the reference."""
    found: dict[str, Any] = {}

    def compare(label: str, rows: list[tuple[int, Any]]) -> None:
        wrong = [
            (number, mine, expected[label][number - 1] if number <= len(expected[label]) else None)
            for number, mine in rows
            if number > len(expected[label]) or expected[label][number - 1] != mine
        ]
        if wrong:
            found[label] = wrong[:5]

    compare(
        "pinvokes",
        [(p.row, (text(p.module), text(p.function), text(p.method))) for p in metadata.pinvokes],
    )
    compare("members", [(m.row, text(m.name)) for m in metadata.members])
    compare(
        "types", [(t.row, (text(t.namespace), text(t.name), t.methods)) for t in metadata.types]
    )
    heap = expected["literals"][0]
    wrong = []
    for literal in metadata.user_strings:
        theirs = None if heap is None else heap.get(literal.entry)
        value = getattr(theirs, "value", None)
        if value is None or value[: len(literal.raw) // 2] != literal.raw.decode("utf-16-le"):
            wrong.append((literal.entry, literal.raw.decode("utf-16-le"), value))
        elif len(value) != literal.characters:
            wrong.append((literal.entry, literal.characters, len(value)))
    if wrong:
        found["literals"] = wrong[:5]
    if metadata.unreadable == 0:
        names = [text(item.name) for item in metadata.assembly_refs]
        if names != expected["references"][: dotnet.ASSEMBLY_REFS]:
            found["references"] = [names[:5], expected["references"][:5]]
    return found


def corpus(args: argparse.Namespace) -> None:
    logging.disable(logging.CRITICAL)  # dnfile logs every signature it cannot parse
    ext = tuple(item.strip().lower() for item in args.ext.split(","))
    counts: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    worst = 0.0
    started = time.monotonic()
    out = open(args.out, "w", encoding="utf-8") if args.out else None  # noqa: SIM115
    try:
        for path in files([Path(d) for d in args.dirs], args.recursive, ext, args.stride):
            if args.limit and counts["assemblies"] >= args.limit:
                break
            try:
                if path.stat().st_size > MAX_INPUT:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            if data[:2] != b"MZ":
                continue
            counts["pe"] += 1
            before = time.perf_counter()
            try:
                metadata = dotnet.read(data)
            except ValueError as problem:
                counts["assemblies"] += 1
                counts["unread"] += 1
                reasons[str(problem)] += 1
                continue
            except Exception as problem:  # noqa: BLE001
                counts["reader_failures"] += 1
                if out is not None:
                    out.write(json.dumps({"path": str(path), "failure": repr(problem)}) + "\n")
                continue
            worst = max(worst, time.perf_counter() - before)
            if metadata is None:
                continue
            counts["assemblies"] += 1
            counts["read"] += 1
            counts["rows_unreadable"] += metadata.unreadable
            counts["files_with_unreadable_rows"] += bool(metadata.unreadable)
            counts["pinvokes"] += len(metadata.pinvokes)
            counts["members"] += len(metadata.members)
            counts["members_of_another_assembly"] += sum(
                member.assembly is not None for member in metadata.members
            )
            counts["types"] += len(metadata.types)
            counts["literals"] += len(metadata.user_strings)
            counts["literal_entries"] += metadata.user_entries
            counts["files_with_literals_cut"] += not metadata.user_complete
            try:
                derived = derive(data, 1024)
                if derived is None or len(derived[1]) != 1 + len(metadata.pinvokes) + len(
                    metadata.members
                ) + len(metadata.types) + len(metadata.user_strings):
                    counts["derive_failures"] += 1
            except Exception:  # noqa: BLE001
                counts["derive_failures"] += 1
            try:
                expected = reference(path)
            except Exception:  # noqa: BLE001
                counts["reference_failures"] += 1
                continue
            if expected is None:
                counts["reference_reads_nothing"] += 1
                continue
            counts["compared"] += 1
            if counts["compared"] % 500 == 0:
                print(json.dumps(dict(counts)), flush=True)  # so far, if the run is cut short
            wrong = differences(metadata, expected)
            if wrong:
                counts["files_with_differences"] += 1
                if out is not None:
                    row = {"path": str(path), "differences": wrong}
                    out.write(json.dumps(row, default=str) + "\n")
    finally:
        if out is not None:
            out.close()
    print(json.dumps(dict(counts)))
    for reason, count in reasons.most_common():
        print(f"{count:8d}  unread: {reason}")
    print(f"slowest read: {worst:.3f} s; total {time.monotonic() - started:.0f} s")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("corpus")
    run.add_argument("dirs", nargs="+")
    run.add_argument("--recursive", action="store_true")
    run.add_argument("--ext", default=".exe,.dll")
    run.add_argument("--stride", type=int, default=1)
    run.add_argument("--limit", type=int, default=0)
    run.add_argument("--out", help="write each difference or failure as JSON lines")
    args = parser.parse_args()
    corpus(args)


if __name__ == "__main__":
    main()
