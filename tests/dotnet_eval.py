"""Compare published .NET metadata with dnfile 0.17.0 on benign assemblies.

    uv run --with dnfile==0.17.0 python -m tests.dotnet_eval corpus DIR [DIR ...]
        [--recursive] [--ext .exe,.dll] [--stride N] [--limit N] --out results.jsonl

The reference uses dnfile's row structures, heaps and coded indexes, not LupaBin's
reader or table schema. It compares raw names, P/Invoke flags, member origins and
signature kind, type flags/method counts, assembly identities, root flags/version/
entry point, table counts, streams, literals and file locations. Scope is bounded to
1024 P/Invokes/types, 4096 members, 128 references, eight enclosing types and 2048
published literals. All row ordinals survive unreadable reference rows. Only published
rows are assertions under test; omitted rows and reference limits are counted, not
silently called matches. None is a known missing value, never a wildcard.

Unavailable reference fields are recorded separately from differences. The reader's
rejection counter is not an independent dnfile observation; it is checked only in the
full derive projection, along with every payload field and location. This is not an
independent verification of IL, execution, intent or completeness beyond these bounds.

Output is exclusive JSONL: configuration, per-file hashes/status/coverage, progress,
and a final summary. Exit 0 means comparisons completed without differences; 1 means
a discrepancy or real failure; 2 means invalid configuration or incomplete comparison
(including no assemblies). Files are bounded, read one at a time, never executed or
loaded as assemblies. dnfile is an evaluation-only dependency, not part of the package.
"""

import argparse
import hashlib
import json
import logging
import platform
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from lupabin.evidence import dotnet, dotnet_checks, facts
from lupabin.evidence.dotnet_checks import derive

MAX_INPUT = 20 * 1024 * 1024
ROW_LIMITS = {
    "pinvokes": ("ImplMap", 1024),
    "members": ("MemberRef", 4096),
    "types": ("TypeDef", 1024),
    "references": ("AssemblyRef", 128),
}
SCOPE_LIMIT = 8
NAME_LIMIT = 512
LITERAL_LIMIT = 2048
LITERAL_STEPS = 262144


@dataclass(frozen=True)
class Unavailable:
    reason: str


@dataclass
class Snapshot:
    root: dict[str, Any]
    rows: dict[str, dict[int, Any]]
    excluded: dict[str, int] = field(default_factory=dict)
    notices: dict[str, str] = field(default_factory=dict)


@dataclass
class Comparison:
    compared: int = 0
    wrong: dict[str, Any] = field(default_factory=dict)
    unavailable: dict[str, str] = field(default_factory=dict)
    omitted: dict[str, list[int]] = field(default_factory=dict)

    def check(self, path: str, mine: Any, theirs: Any) -> None:
        if isinstance(theirs, Unavailable):
            self.unavailable[path] = theirs.reason
        else:
            self.compared += 1
            if mine != theirs:
                self.wrong[path] = {"reader": mine, "reference": theirs}


def capture(operation: Callable[[], Any]) -> Any:
    try:
        return operation()
    except (AttributeError, IndexError, TypeError, ValueError) as problem:
        return Unavailable(f"{type(problem).__name__}: {problem}")


def files(roots: list[Path], recursive: bool, ext: tuple[str, ...], stride: int) -> Iterator[Path]:
    def walk(root):
        for path in sorted(root.iterdir()):
            if path.is_symlink():
                continue
            if path.is_dir() and recursive:
                yield from walk(path)
            elif path.is_file() and path.suffix.lower() in ext:
                yield path

    for root in roots:
        for selected, path in enumerate(walk(root)):
            if selected % stride == 0:
                yield path


def name(net: Any, row: Any, column: str, optional: bool = False) -> bytes | None:
    index = getattr(row.struct, column + "_StringIndex")
    if optional and index == 0:
        return None
    if not index or net.strings is None:
        raise ValueError("required name has no string heap entry")
    item = net.strings.get(index, max_length=NAME_LIMIT)
    if item is None:
        raise ValueError("dnfile cannot read name within the name bound")
    raw = item.value_bytes()
    if not raw or len(raw) > NAME_LIMIT:
        raise ValueError("empty or overlong required name")
    if net.strings.get_data_at_rva(item.rva + len(raw), 1) != b"\0":
        raise ValueError("name is not NUL terminated in the string heap")
    return raw


def table_row(table: Any, number: int) -> Any:
    if table is None or not 1 <= number <= table.num_rows:
        raise ValueError("row index outside reference table")
    row = table.rows[number - 1]
    if row is None:
        raise ValueError("dnfile did not read the row")
    return row


def target(net: Any, kind: str, value: int) -> tuple[str, Any]:
    from dnfile import codedindex

    index = getattr(codedindex, kind)(value, list(net.mdtables.tables.values()))
    if index.table is None:
        raise ValueError("coded index has no reference table")
    return index.table.name, table_row(index.table, index.row_index)


def assembly(net: Any, row: Any) -> tuple[Any, tuple[int, ...]]:
    return name(net, row, "Name"), tuple(
        getattr(row.struct, field)
        for field in ("MajorVersion", "MinorVersion", "BuildNumber", "RevisionNumber")
    )


def scope_assembly(net: Any, row: Any) -> bytes | None:
    seen = set()
    for _ in range(SCOPE_LIMIT):
        value = row.struct.ResolutionScope_CodedIndex
        if value in seen:
            raise ValueError("cyclic TypeRef scope")
        seen.add(value)
        if value == 0:
            return None
        kind, parent = target(net, "ResolutionScope", value)
        if kind == "AssemblyRef":
            return name(net, parent, "Name")
        if kind != "TypeRef":
            return None
        row = parent
    raise ValueError("TypeRef scope exceeds reference depth bound")


def member_origin(net: Any, row: Any) -> dict[str, Any]:
    kind, parent = target(net, "MemberRefParent", row.struct.Class_CodedIndex)
    labels = {
        "TypeRef": "type_ref",
        "TypeDef": "type_def",
        "ModuleRef": "module_ref",
        "MethodDef": "method_def",
        "TypeSpec": "type_spec",
    }
    result = dict(parent=labels[kind], assembly=None, namespace=None, type=None)
    if kind in ("TypeRef", "TypeDef"):
        result["namespace"] = capture(lambda: name(net, parent, "TypeNamespace", True))
        result["type"] = capture(lambda: name(net, parent, "TypeName"))
        if kind == "TypeRef":
            result["assembly"] = capture(lambda: scope_assembly(net, parent))
    elif kind == "ModuleRef":
        result["type"] = capture(lambda: name(net, parent, "Name"))
    return result


def member_kind(net: Any, row: Any) -> str:
    index = row.struct.Signature_BlobIndex
    blob = None if net.blobs is None or index == 0 else net.blobs.get(index)
    if blob is None or not blob.value_bytes() or blob.item_size != len(blob.value_bytes()):
        raise ValueError("unreadable or truncated member signature")
    return "field" if blob.value_bytes()[0] == 6 else "method"


def reference_row(net: Any, group: str, number: int) -> dict[str, Any]:
    table = getattr(net.mdtables, ROW_LIMITS[group][0])
    row = table_row(table, number)
    result = {
        "row": number,
        "offset": capture(lambda: row.struct.get_file_offset()),
        "length": capture(lambda: row.struct.sizeof()),
    }
    if group == "pinvokes":

        def module():
            parent = table_row(net.mdtables.ModuleRef, row.struct.ImportScope_Index)
            return name(net, parent, "Name", True)

        def method():
            kind, parent = target(net, "MemberForwarded", row.struct.MemberForwarded_CodedIndex)
            return name(net, parent, "Name") if kind == "MethodDef" else None

        result.update(
            flags=capture(lambda: row.struct.MappingFlags),
            module=capture(module),
            function=capture(lambda: name(net, row, "ImportName", True)),
            method=capture(method),
        )
    elif group == "members":
        origin = capture(lambda: member_origin(net, row))
        result.update(
            origin
            if isinstance(origin, dict)
            else dict.fromkeys(("parent", "assembly", "namespace", "type"), origin)
        )
        result.update(
            name=capture(lambda: name(net, row, "Name")),
            member=capture(lambda: member_kind(net, row)),
        )
    elif group == "types":

        def methods():
            first = row.struct.MethodList_Index
            total = 0 if net.mdtables.MethodDef is None else net.mdtables.MethodDef.num_rows
            last = (
                table_row(table, number + 1).struct.MethodList_Index
                if number < table.num_rows
                else total + 1
            )
            if not 1 <= first <= last <= total + 1:
                raise ValueError("invalid reference MethodList range")
            return last - first

        result.update(
            flags=capture(lambda: row.struct.Flags),
            namespace=capture(lambda: name(net, row, "TypeNamespace", True)),
            name=capture(lambda: name(net, row, "TypeName")),
            methods=capture(methods),
        )
    return result


def reference_literals(net: Any, characters: int) -> tuple[dict[int, Any], int, bool]:
    heap = net.user_strings
    found: dict[int, Any] = {}
    entries, at = 0, 1
    if heap is None:
        return found, entries, True
    for _ in range(LITERAL_STEPS):
        if at >= heap.struct.Size:
            return found, entries, True
        if len(found) >= LITERAL_LIMIT:
            break
        item = capture(lambda at=at: heap.get(at))
        if isinstance(item, Unavailable) or item is None:
            break
        size = int(item.item_size)
        prefix = item.item_size.raw_size
        if item.raw_size != size + prefix or at + item.raw_size > heap.struct.Size:
            break
        entry = at
        at += item.raw_size
        if not size:
            continue
        entries += 1
        raw = item.value_bytes()
        if size % 2 == 0 or len(raw) < 8:
            continue
        if any(raw[1::2]) or any(not 32 <= byte <= 126 for byte in raw[::2]):
            continue
        found[entry] = dict(
            entry=entry,
            offset=heap.get_file_offset(item.rva) + prefix,
            characters=len(raw) // 2,
            raw=raw[: characters * 2],
        )
    return found, entries, False


def reference_from_pe(pe: Any, characters: int = 1024) -> Snapshot | None:
    net = pe.net
    if net is None or net.mdtables is None or net.metadata is None:
        return None
    root = net.metadata.struct
    streams = net.metadata.streams_list
    root_at = root.get_file_offset()
    values = dict(
        offset=root_at,
        length=root.sizeof() + sum(s.stream_table_entry_size() for s in streams),
        version=root.Version.split(b"\0", 1)[0].decode("ascii"),
        flags=net.struct.Flags,
        entry_point=net.struct.EntryPointTokenOrRva,
        streams=tuple(
            (s.struct.Name.decode("ascii"), s.file_offset, s.struct.Size) for s in streams
        ),
        rows=tuple(
            net.mdtables.tables[i].num_rows if i in net.mdtables.tables else 0 for i in range(45)
        ),
        assembly=None
        if net.mdtables.Assembly is None
        else capture(lambda: assembly(net, table_row(net.mdtables.Assembly, 1))),
    )
    groups: dict[str, dict[int, Any]] = {}
    excluded = {}
    for group, (table_name, limit) in ROW_LIMITS.items():
        table = getattr(net.mdtables, table_name)
        total = 0 if table is None else table.num_rows
        excluded[group] = max(0, total - limit)
        groups[group] = {}
        for number in range(1, min(total, limit) + 1):
            groups[group][number] = capture(
                lambda table=table, number=number, group=group: assembly(
                    net, table_row(table, number)
                )
                if group == "references"
                else reference_row(net, group, number)
            )
    refs = groups.pop("references")
    unreadable = [number for number, value in refs.items() if isinstance(value, Unavailable)]
    notices = {f"references.{number}": refs[number].reason for number in unreadable}
    values["assembly_refs"] = (
        Unavailable(
            f"cannot align references without published ordinals; unreadable rows: {unreadable}"
        )
        if unreadable
        else tuple(refs.values())
    )
    values["assembly_refs_total"] = (
        0 if net.mdtables.AssemblyRef is None else net.mdtables.AssemblyRef.num_rows
    )
    groups["literals"], values["user_entries"], values["user_complete"] = reference_literals(
        net, characters
    )
    if not values["user_complete"]:
        notices["literals.tail"] = (
            "reference literal traversal stopped at a bound or unreadable entry"
        )
    return Snapshot(values, groups, excluded, notices)


def reference(data: bytes, characters: int = 1024) -> Snapshot | None:
    """A detached, bounded projection of dnfile; close its PE before returning."""
    import dnfile  # noqa: PLC0415

    pe = dnfile.dnPE(data=data, clr_lazy_load=True)
    try:
        return reference_from_pe(pe, characters)
    finally:
        pe.close()


def metadata_root(metadata: dotnet.Metadata) -> dict[str, Any]:
    return {
        field: getattr(metadata, field)
        for field in (
            "offset",
            "length",
            "version",
            "flags",
            "entry_point",
            "streams",
            "rows",
            "assembly",
            "assembly_refs",
            "assembly_refs_total",
            "user_entries",
            "user_complete",
        )
    }


def differences(metadata: dotnet.Metadata, expected: Snapshot) -> Comparison:
    """Compare every published field; report unavailable and omitted rows separately."""
    result = Comparison(unavailable=dict(expected.notices))
    for key, value in metadata_root(metadata).items():
        result.check(
            f"root.{key}", value, expected.root.get(key, Unavailable("missing root field"))
        )
    for group in ("pinvokes", "members", "types", "literals"):
        rows = metadata.user_strings if group == "literals" else getattr(metadata, group)
        theirs = expected.rows.get(group, {})
        published = set()
        for row in rows:
            number = row.entry if group == "literals" else row.row
            published.add(number)
            other = theirs.get(number)
            if isinstance(other, Unavailable):
                result.unavailable[f"{group}.{number}"] = other.reason
                continue
            if other is None:
                result.check(f"{group}.{number}", row._asdict(), None)
                continue
            for key, value in row._asdict().items():
                result.check(
                    f"{group}.{number}.{key}",
                    value,
                    other.get(key, Unavailable("missing reference field")),
                )
        omitted = sorted(theirs.keys() - published)
        if omitted:
            result.omitted[group] = omitted
        for number in omitted:
            other = theirs[number]
            if isinstance(other, Unavailable):
                result.unavailable[f"{group}.{number}"] = other.reason
            elif isinstance(other, dict):
                for key, value in other.items():
                    if isinstance(value, Unavailable):
                        result.unavailable[f"{group}.{number}.{key}"] = value.reason
    return result


def derived_differences(metadata: dotnet.Metadata, derived: Any) -> Comparison:
    result = Comparison()
    if derived is None:
        result.check("derive", "metadata", None)
        return result
    result.check("derive.metadata", metadata, derived[0])

    def raw_name(value, path):
        if value is None:
            return None
        raw = bytes.fromhex(value.raw_hex)
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            text = None
        result.check(path + ".text", value.text, text)
        return raw

    def raw_assembly(value, path):
        return None if value is None else (raw_name(value.name, path + ".name"), value.version)

    root = metadata_root(metadata)
    rows = root.pop("rows")
    root.pop("user_complete")
    root["references"] = root.pop("assembly_refs")
    root["assembly_refs"] = root.pop("assembly_refs_total")
    root["user_strings"] = root.pop("user_entries")
    root["unreadable"] = metadata.unreadable
    root["method_id"] = "ecma335-metadata-v1"
    root.update(
        {
            key: rows[index]
            for key, index in (
                ("type_refs", 1),
                ("type_defs", 2),
                ("methods", 6),
                ("member_refs", 10),
                ("module_refs", 26),
                ("pinvokes", 28),
            )
        }
    )
    wanted = {"pe:dotnet": root}
    for group, label in (("pinvokes", "pinvoke"), ("members", "member"), ("types", "type")):
        for row in getattr(metadata, group):
            wanted[f"pe:dotnet:{label}:{row.row}"] = row._asdict()
    for row in metadata.user_strings:
        kept = len(row.raw) // 2
        wanted[f"pe:dotnet:string:{row.entry}"] = dict(
            index=row.entry,
            encoding="utf-16-le",
            repertoire="ascii-printable-v1",
            text=row.raw.decode("utf-16-le"),
            raw_hex=row.raw.hex(),
            characters=kept,
            complete=kept == row.characters,
            total_characters=row.characters,
            offset=row.offset,
            length=len(row.raw),
        )
    result.check(
        "derive.keys",
        [key for key, _, _ in derived[1]],
        [
            "pe:dotnet",
            *(f"pe:dotnet:pinvoke:{p.row}" for p in metadata.pinvokes),
            *(f"pe:dotnet:string:{s.entry}" for s in metadata.user_strings),
            *(f"pe:dotnet:member:{m.row}" for m in metadata.members),
            *(f"pe:dotnet:type:{t.row}" for t in metadata.types),
        ],
    )
    for key, payload, location in derived[1]:
        values = payload.model_dump()
        path = f"derive.{key}"
        for name_field in ("module", "function", "method", "namespace", "type", "name"):
            if name_field in values:
                values[name_field] = raw_name(getattr(payload, name_field), path + "." + name_field)
        if "assembly" in values:
            values["assembly"] = (
                raw_assembly(payload.assembly, path + ".assembly")
                if key == "pe:dotnet"
                else raw_name(payload.assembly, path + ".assembly")
            )
        if key == "pe:dotnet":
            values["references"] = tuple(
                raw_assembly(a, f"{path}.references.{i}") for i, a in enumerate(payload.references)
            )
            values["streams"] = tuple((s.name, s.offset, s.size) for s in payload.streams)
        result.check(path + ".rva", location.rva, None)
        result.check(
            path + ".section",
            None if location.section is None else location.section.model_dump(),
            None,
        )
        values.update(offset=location.offset, length=location.length)
        expected = wanted.get(key, {})
        for column in sorted(values.keys() | expected.keys()):
            result.check(f"derive.{key}.{column}", values.get(column), expected.get(column))
    return result


def json_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


def corpus(args: argparse.Namespace) -> int:
    ext = tuple(item.strip().lower() for item in args.ext.split(","))
    if args.stride < 1 or args.limit < 0 or args.progress < 1 or not args.out:
        print("invalid limits or missing exclusive --out", file=sys.stderr)
        return 2
    if any(not Path(root).is_dir() for root in args.dirs):
        print("every corpus root must be an existing directory", file=sys.stderr)
        return 2
    try:
        out = open(args.out, "x", encoding="utf-8")  # noqa: SIM115
    except OSError as problem:
        print(f"cannot create exclusive output: {problem}", file=sys.stderr)
        return 2
    previous_logging = logging.root.manager.disable
    logging.disable(logging.CRITICAL)  # dnfile logs every signature it cannot parse
    counts: Counter[str] = Counter(
        {
            "candidates": 0,
            "assemblies": 0,
            "compared": 0,
            "reference_fields_compared": 0,
            "reference_differences": 0,
            "reference_unavailable": 0,
            "derive_fields_compared": 0,
            "derive_differences": 0,
        }
    )
    reasons: Counter[str] = Counter()
    started = time.monotonic()
    worst = 0.0
    failures = incomplete = False

    def emit(record):
        out.write(json.dumps(record, default=json_value, sort_keys=True) + "\n")
        out.flush()

    def record_comparison(record, label, result):
        counts[label + "_fields_compared"] += result.compared
        counts[label + "_differences"] += len(result.wrong)
        counts[label + "_unavailable"] += len(result.unavailable)
        record[label] = dict(
            compared=result.compared,
            difference_count=len(result.wrong),
            differences=dict(sorted(result.wrong.items())[:20]),
            difference_details_omitted=max(0, len(result.wrong) - 20),
            unavailable=result.unavailable,
            omitted=result.omitted,
        )
        for reason in result.unavailable.values():
            reasons["unavailable: " + reason] += 1
        for group, numbers in result.omitted.items():
            counts["reader_omitted_" + group] += len(numbers)

    try:
        versions = {}
        for package in ("dnfile", "pefile"):
            try:
                versions[package] = version(package)
            except PackageNotFoundError:
                versions[package] = "not installed"
        emit(
            dict(
                event="start",
                configuration=vars(args),
                selection="sorted depth-first; stride over eligible files per root",
                python=platform.python_version(),
                dnfile=versions["dnfile"],
                pefile=versions["pefile"],
                evaluator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                reader_sha256=hashlib.sha256(Path(dotnet.__file__).read_bytes()).hexdigest(),
                dotnet_checks_sha256=hashlib.sha256(
                    Path(dotnet_checks.__file__).read_bytes()
                ).hexdigest(),
                facts_sha256=hashlib.sha256(Path(facts.__file__).read_bytes()).hexdigest(),
                max_input=MAX_INPUT,
                scope=ROW_LIMITS,
                scope_depth=SCOPE_LIMIT,
                name_bytes=NAME_LIMIT,
                literal_limit=LITERAL_LIMIT,
                literal_steps=LITERAL_STEPS,
                characters=1024,
                independent_exclusions=[
                    "reader rejection counter",
                    "unpublished rows beyond bounds",
                    "IL and execution",
                ],
            )
        )
        for path in files([Path(d) for d in args.dirs], args.recursive, ext, args.stride):
            if args.limit and counts["assemblies"] >= args.limit:
                break
            counts["candidates"] += 1
            record: dict[str, Any] = dict(event="file", path=str(path.resolve()))
            try:
                if path.stat().st_size > MAX_INPUT:
                    record["status"] = "oversize"
                    reasons["oversize"] += 1
                    emit(record)
                    continue
                with path.open("rb") as source:
                    data = source.read(MAX_INPUT + 1)
                if len(data) > MAX_INPUT:
                    record["status"] = "grew_beyond_input_limit"
                    reasons[record["status"]] += 1
                    emit(record)
                    continue
                record.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
                if data[:2] != b"MZ":
                    record["status"] = "not_pe"
                    reasons["not_pe"] += 1
                    emit(record)
                    continue
                counts["pe"] += 1
                before = time.perf_counter()
                try:
                    try:
                        metadata = dotnet.read(data)
                    finally:
                        worst = max(worst, time.perf_counter() - before)
                except ValueError as problem:
                    counts["assemblies"] += 1
                    counts["unread"] += 1
                    reasons["reader unread: " + str(problem)] += 1
                    record.update(status="reader_unread", reason=str(problem))
                    incomplete = True
                    emit(record)
                    continue
                except Exception as problem:  # noqa: BLE001
                    counts["reader_failures"] += 1
                    reasons["reader failure: " + type(problem).__name__] += 1
                    failures = True
                    record.update(status="reader_failure", failure=repr(problem))
                    emit(record)
                    continue
                if metadata is None:
                    record["status"] = "no_metadata"
                    reasons["no_metadata"] += 1
                    emit(record)
                    continue
                counts["assemblies"] += 1
                counts["read"] += 1
                counts["rows_unreadable"] += metadata.unreadable
                record["reader_unreadable"] = metadata.unreadable
                for group in ("pinvokes", "members", "types", "user_strings"):
                    counts[group] += len(getattr(metadata, group))
                file_failed = False
                try:
                    derived = derived_differences(metadata, derive(data, 1024))
                    record_comparison(record, "derive", derived)
                    file_failed = bool(derived.wrong)
                    failures |= file_failed
                except Exception as problem:  # noqa: BLE001
                    counts["derive_failures"] += 1
                    reasons["derive failure: " + type(problem).__name__] += 1
                    failures = file_failed = True
                    record["derive_failure"] = repr(problem)
                try:
                    expected = reference(data)
                except Exception as problem:  # noqa: BLE001
                    counts["reference_failures"] += 1
                    reasons["reference failure: " + type(problem).__name__] += 1
                    failures = True
                    record.update(status="reference_failure", reference_failure=repr(problem))
                    emit(record)
                    continue
                if expected is None:
                    counts["reference_reads_nothing"] += 1
                    reasons["reference has no metadata"] += 1
                    incomplete = True
                    record["status"] = "reference_unavailable"
                    emit(record)
                    continue
                counts["compared"] += 1
                compared = differences(metadata, expected)
                record_comparison(record, "reference", compared)
                record["reference_excluded"] = expected.excluded
                for group, count in expected.excluded.items():
                    counts["reference_excluded_" + group] += count
                failures |= bool(compared.wrong)
                partial = bool(
                    compared.unavailable
                    or compared.omitted
                    or metadata.unreadable
                    or any(expected.excluded.values())
                    or not metadata.user_complete
                )
                incomplete |= partial
                if compared.wrong:
                    counts["files_with_differences"] += 1
                record["status"] = (
                    "derive_failure"
                    if file_failed
                    else "different"
                    if compared.wrong
                    else "incomplete"
                    if partial
                    else "compared"
                )
                emit(record)
            except OSError as problem:
                failures = True
                counts["io_failures"] += 1
                reasons["io: " + type(problem).__name__] += 1
                record.update(status="io_failure", failure=repr(problem))
                emit(record)
            finally:
                if counts["candidates"] % args.progress == 0:
                    progress = dict(event="progress", counts=dict(counts))
                    print(json.dumps(progress), flush=True)  # so far, if the run is cut short
                    emit(progress)
    except KeyboardInterrupt:
        incomplete = True
        counts["interrupted"] += 1
        emit(dict(event="interrupted"))
    except Exception as problem:
        failures = True
        counts["evaluation_failures"] += 1
        emit(dict(event="failure", failure=repr(problem)))
    finally:
        code = 1 if failures else 2 if incomplete or not counts["reference_fields_compared"] else 0
        summary = dict(
            event="summary",
            status={0: "passed", 1: "failed", 2: "incomplete"}[code],
            exit_code=code,
            counts=dict(counts),
            reasons=dict(reasons),
            slowest_read_seconds=worst,
            seconds=time.monotonic() - started,
        )
        try:
            emit(summary)
        finally:
            out.close()
            logging.disable(previous_logging)
        print(json.dumps(summary), flush=True)
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("corpus")
    run.add_argument("dirs", nargs="+")
    run.add_argument("--recursive", action="store_true")
    run.add_argument("--ext", default=".exe,.dll")
    run.add_argument("--stride", type=int, default=1)
    run.add_argument("--limit", type=int, default=0)
    run.add_argument("--progress", type=int, default=100)
    run.add_argument("--out", required=True, help="exclusively create a JSONL evaluation log")
    args = parser.parse_args()
    if args.stride < 1 or args.limit < 0 or args.progress < 1:
        parser.error("stride/progress must be positive and limit must be nonnegative")
    return corpus(args)


if __name__ == "__main__":
    raise SystemExit(main())
