"""Deterministic explanation rules.

Each rule is a pure function of the evidence it cites (plus the report, for rules
that summarise a whole group and must prove the group is complete). The validator
re-runs the rule on the cited evidence and requires the exact same item, so a
statement can never say more than its citations support.
"""

import weakref
from collections.abc import Callable
from dataclasses import dataclass

from lupabin.evidence import toolchain
from lupabin.evidence.facts import (
    AnomalyEvidence,
    ApiCallEvidence,
    CallArgumentEvidence,
    CodeFunctionEvidence,
    CodeReachEvidence,
    DecodedStringEvidence,
    EntropyEvidence,
    Evidence,
    ExportEvidence,
    HeaderEvidence,
    ImportEvidence,
    LocalLinkEvidence,
    MainCallEvidence,
    SectionEvidence,
    StringEvidence,
    StringReferenceEvidence,
    ToolchainEvidence,
    YaraEvidence,
)
from lupabin.evidence.models import Report
from lupabin.explain.capabilities import CAPABILITIES, derive
from lupabin.explain.families import FAMILIES, PREVALENCE, family_of
from lupabin.explain.models import SlotValue
from lupabin.explain.text import frame_slot, hexadecimal, name, number, section_name

Slots = dict[str, SlotValue]
Derived = tuple[Slots, tuple[str, ...]]  # slots and glossary entry ids


@dataclass(frozen=True)
class Rule:
    id: str
    template: str
    not_proven: str
    derive: Callable[[tuple[Evidence, ...], Report], Derived | None]

    def statement(self, slots: Slots) -> str:
        return self.template.format(**slots)


MACHINES = {0x014C: "x86", 0x8664: "x64", 0xAA64: "ARM64"}
RUNTIME_LINKING = frozenset(
    {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress"}
)
PERMISSIONS = {"read": "lectura", "write": "escritura", "execute": "ejecución"}
EXPORT_NAMES_SHOWN = 50
# Didactic context, not a detector: on 2026-09-23, 475 of 139,057
# sections of at least 4 KiB (0.34 %) in 55,313 benign binaries from System32 and
# Program Files reached 7.2 bits per byte. Smaller sections are not compared: with few
# bytes the estimate approaches 8 merely because few values repeat.
HIGH_ENTROPY = 7.2
HIGH_ENTROPY_MIN_BYTES = 4096


@dataclass(frozen=True)
class Groups:
    """The report's groups that summaries must cite whole, built once per report.

    A rule re-derives its item from its citations and the report; without this index
    each summary scanned the whole report, which made explaining a large binary
    quadratic (shell32.dll: about 14 s). The groups are the same, in report order."""

    imports: dict[tuple[str, str], tuple[str, ...]]  # (DLL raw hex, table) -> imports
    calls: dict[str, tuple[str, ...]]  # import ID -> its calls
    arguments: dict[str, tuple[str, ...]]  # call ID -> its arguments
    facts: dict[str, Evidence]


# By object identity: hashing a frozen report would walk all of it on every lookup. The
# weak reference drops the entry when the report goes away, so an ID reused by another
# object never returns stale groups.
_GROUPS: dict[int, tuple[weakref.ref[Report], Groups]] = {}


def groups(report: Report) -> Groups:
    key = id(report)
    entry = _GROUPS.get(key)
    if entry is not None and entry[0]() is report:
        return entry[1]
    imports: dict[tuple[str, str], list[str]] = {}
    calls: dict[str, list[str]] = {}
    arguments: dict[str, list[str]] = {}
    for fact in report.evidence:
        if isinstance(fact, ImportEvidence):
            imports.setdefault((fact.data.dll.raw_hex, fact.data.table), []).append(fact.id)
        elif isinstance(fact, ApiCallEvidence):
            calls.setdefault(fact.provenance.evidence_ids[0], []).append(fact.id)
        elif isinstance(fact, CallArgumentEvidence):
            arguments.setdefault(fact.provenance.evidence_ids[0], []).append(fact.id)
    found = Groups(
        {group: tuple(ids) for group, ids in imports.items()},
        {parent: tuple(ids) for parent, ids in calls.items()},
        {parent: tuple(ids) for parent, ids in arguments.items()},
        {fact.id: fact for fact in report.evidence},
    )

    def forget(_: weakref.ref[Report]) -> None:
        _GROUPS.pop(key, None)

    _GROUPS[key] = (weakref.ref(report, forget), found)
    return found


def _section_label(section: SectionEvidence) -> str:
    return section_name(section.data.name_text, section.data.name_raw_hex)


# --- PE -------------------------------------------------------------------------


def _header(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    if len(cited) != 1 or not isinstance(cited[0], HeaderEvidence):
        return None
    data = cited[0].data
    machine = hexadecimal(data.machine, 4)
    if data.machine in MACHINES:
        machine = f"{MACHINES[data.machine]}, {machine}"
    slots: Slots = {
        "format": "PE32" if data.optional_magic == 0x10B else "PE32+",
        "bits": 32 if data.optional_magic == 0x10B else 64,
        "machine": machine,
        "entry": hexadecimal(data.entry_point_rva),
        "size_of_image": number(data.size_of_image),
    }
    return slots, ("pe.format", "pe.header")


TOOLCHAIN_GLOSSARY = {
    "rich_header": "toolchain.rich_header",
    "gcc_ident": "toolchain.gcc_ident",
    "mingw_w64_runtime": "toolchain.mingw_w64",
    "go_buildinfo": "toolchain.go_buildinfo",
    "clr_header": "toolchain.clr_header",
    "pyinstaller_cookie": "toolchain.pyinstaller",
}


def _marker(
    marker: toolchain.Marker, versioned: bool | None = None
) -> Callable[[tuple[Evidence, ...], Report], Derived | None]:
    """One marker; for GCC, every ident the report publishes, in report order."""

    def derive(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
        facts = [fact for fact in cited if isinstance(fact, ToolchainEvidence)]
        if not facts or len(facts) != len(cited) or any(f.data.marker != marker for f in facts):
            return None
        first = facts[0]
        if marker == "gcc_ident":
            group = tuple(
                fact.id
                for fact in report.evidence
                if isinstance(fact, ToolchainEvidence) and fact.data.marker == marker
            )
            if tuple(fact.id for fact in facts) != group:
                return None
        elif len(facts) != 1:
            return None
        if versioned is not None and (first.data.text is not None) != versioned:
            return None
        where = first.location
        slots: Slots
        if marker == "rich_header":
            entries = (len(first.data.raw_hex) // 2 - 24) // 8
            slots = {
                "offset": hexadecimal(where.offset or 0),
                "entries": entries,
                "noun": "entrada" if entries == 1 else "entradas",
            }
        elif marker == "gcc_ident":
            slots = {
                "count": len(facts),
                "noun": "texto" if len(facts) == 1 else "textos distintos",
                "idents": "; ".join(fact.data.text or "" for fact in facts),
            }
        elif marker == "mingw_w64_runtime":
            slots = {
                "message": toolchain.MINGW_W64.decode("ascii"),
                "offset": hexadecimal(where.offset or 0),
            }
        elif marker == "go_buildinfo":
            slots = {"rva": hexadecimal(where.rva or 0)}
            if first.data.text is not None:
                slots["version"] = first.data.text
        elif marker == "clr_header":
            slots = {"rva": hexadecimal(where.rva or 0)}
        else:
            slots = {"offset": hexadecimal(where.offset or 0), "library": first.data.text or ""}
        return slots, (TOOLCHAIN_GLOSSARY[marker], "toolchain.marker")

    return derive


def _section(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    if len(cited) != 1 or not isinstance(cited[0], SectionEvidence):
        return None
    data = cited[0].data
    permissions = ", ".join(PERMISSIONS[p] for p in data.permissions) or "ninguno"
    slots: Slots = {
        "index": data.index,
        "name": _section_label(cited[0]),
        "virtual_size": number(data.virtual_size),
        "raw_size": number(data.raw_size),
        "permissions": permissions,
    }
    return slots, ("pe.section", "pe.section.permissions")


def _writable_executable(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    if len(cited) != 1 or not isinstance(cited[0], SectionEvidence):
        return None
    if not {"write", "execute"} <= set(cited[0].data.permissions):
        return None
    slots: Slots = {"index": cited[0].data.index, "name": _section_label(cited[0])}
    return slots, ("pe.section.permissions",)


def _entropy(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    if len(cited) != 2:
        return None
    entropy, section = cited
    if not isinstance(entropy, EntropyEvidence) or not isinstance(section, SectionEvidence):
        return None
    if entropy.provenance.evidence_ids != (section.id,):
        return None
    slots: Slots = {
        "bytes": number(entropy.data.byte_count),
        "name": _section_label(section),
        "bits": f"{entropy.data.bits_per_byte:.2f}".replace(".", ","),
    }
    return slots, ("entropy.shannon",)


def _high_entropy(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    derived = _entropy(cited, report)
    entropy = cited[0]
    if derived is None or not isinstance(entropy, EntropyEvidence):
        return None
    if (
        entropy.data.bits_per_byte < HIGH_ENTROPY
        or entropy.data.byte_count < HIGH_ENTROPY_MIN_BYTES
    ):
        return None
    return derived


def _imports(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    if not cited or not all(isinstance(fact, ImportEvidence) for fact in cited):
        return None
    imports = [fact for fact in cited if isinstance(fact, ImportEvidence)]
    key = (imports[0].data.dll.raw_hex, imports[0].data.table)
    if any((fact.data.dll.raw_hex, fact.data.table) != key for fact in imports):
        return None
    if tuple(fact.id for fact in imports) != groups(report).imports.get(key):
        return None  # a summary must cite the whole group, in report order
    functions = tuple(
        name(fact.data.function) if fact.data.function else f"ordinal {fact.data.ordinal}"
        for fact in imports
    )
    delay = key[1] == "delay"
    glossary = ["pe.imports"]
    if delay:
        glossary.append("pe.imports.delay")
    if any(fact.data.ordinal is not None for fact in imports):
        glossary.append("pe.imports.ordinal")
    if RUNTIME_LINKING & set(functions):
        glossary.append("pe.imports.runtime_linking")
    slots: Slots = {
        "table": "tabla de imports retardados" if delay else "tabla de imports",
        "dll": name(imports[0].data.dll),
        "count": len(imports),
        "noun": "función" if len(imports) == 1 else "funciones",
        "functions": functions,
    }
    return slots, tuple(glossary)


def _family(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    """All imports, from any DLL or table, whose name is on one curated family list."""
    imports = [fact for fact in cited if isinstance(fact, ImportEvidence)]
    if not imports or len(imports) != len(cited):
        return None
    names = [name(fact.data.function) if fact.data.function else None for fact in imports]
    families = {family_of(n) if n is not None else None for n in names}
    family = families.pop() if len(families) == 1 else None
    if family is None:
        return None
    group = tuple(
        fact.id
        for fact in report.evidence
        if isinstance(fact, ImportEvidence)
        and fact.data.function is not None
        and family_of(name(fact.data.function)) == family
    )
    if tuple(fact.id for fact in imports) != group:
        return None
    slots: Slots = {
        "count": len(imports),
        "noun": "import pertenece" if len(imports) == 1 else "imports pertenecen",
        "family": FAMILIES[family][0],
        "share": PREVALENCE[family],
        "functions": tuple(n for n in names if n is not None),
    }
    return slots, (f"api.family.{family}", "pe.imports")


def _exports(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    exports = [fact for fact in cited if isinstance(fact, ExportEvidence)]
    if not exports or len(exports) != len(cited):
        return None
    everything = tuple(fact.id for fact in report.evidence if isinstance(fact, ExportEvidence))
    if tuple(fact.id for fact in exports) != everything:
        return None
    named = sum(1 for fact in exports if fact.data.names)
    forwarded = sum(1 for fact in exports if fact.data.target_kind != "declared_rva")
    shown = tuple(
        name(fact.data.names[0]) if fact.data.names else f"ordinal {fact.data.ordinal}"
        for fact in exports[:EXPORT_NAMES_SHOWN]
    )
    glossary = ("pe.exports", "pe.exports.forwarder") if forwarded else ("pe.exports",)
    slots: Slots = {
        "count": number(len(exports)),
        "named": number(named),
        "forwarded": number(forwarded),
        "names": shown,
    }
    return slots, glossary


def _anomaly(code: str) -> Callable[[tuple[Evidence, ...], Report], Derived | None]:
    def derive(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
        if not cited or not isinstance(cited[0], AnomalyEvidence):
            return None
        anomaly, refs = cited[0], cited[1:]
        if anomaly.data.code != code or tuple(r.id for r in refs) != (
            anomaly.provenance.evidence_ids
        ):
            return None
        sections = [ref for ref in refs if isinstance(ref, SectionEvidence)]
        headers = [ref for ref in refs if isinstance(ref, HeaderEvidence)]
        slots: Slots = {}
        if code == "section_raw_out_of_bounds" and len(sections) == 1:
            data = sections[0].data
            slots = {
                "name": _section_label(sections[0]),
                "offset": hexadecimal(data.raw_offset),
                "size": number(data.raw_size),
                "file_size": number(report.sample.size),
            }
        elif code in ("section_raw_overlap", "section_virtual_overlap") and len(sections) == 2:
            slots = {"a": _section_label(sections[0]), "b": _section_label(sections[1])}
        elif code == "section_exceeds_image" and len(sections) == len(headers) == 1:
            slots = {
                "name": _section_label(sections[0]),
                "size_of_image": number(headers[0].data.size_of_image),
            }
        elif code == "entry_point_outside_image" and len(headers) == 1:
            slots = {
                "entry": hexadecimal(headers[0].data.entry_point_rva),
                "size_of_image": number(headers[0].data.size_of_image),
            }
        else:
            return None
        return slots, (f"pe.anomaly.{code}",)

    return derive


# --- cadenas, YARA y decodificación ---------------------------------------------


def _strings(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    strings = [fact for fact in cited if isinstance(fact, StringEvidence)]
    if not strings or len(strings) != len(cited):
        return None
    everything = tuple(fact.id for fact in report.evidence if isinstance(fact, StringEvidence))
    if tuple(fact.id for fact in strings) != everything:
        return None
    ascii_count = sum(1 for fact in strings if fact.data.encoding == "ascii")
    slots: Slots = {
        "ascii": number(ascii_count),
        "utf16": number(len(strings) - ascii_count),
    }
    return slots, ("strings.literal",)


def _yara(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    if len(cited) != 1 or not isinstance(cited[0], YaraEvidence):
        return None
    data = cited[0].data
    more = " (hay más, omitidas por un límite)" if data.instances_status == "partial" else ""
    slots: Slots = {
        "rule": data.rule_id,
        "revision": data.revision,
        "kept": len(data.instances),
        "more": more,
        "description": data.description,
    }
    return slots, ("yara.match", "yara.rule")


def _bytes(count: int) -> str:
    return f"{count} byte" if count == 1 else f"{number(count)} bytes"


def _decoded_text(fact: DecodedStringEvidence) -> Slots:
    offset = fact.location.offset if fact.location.offset is not None else 0
    length = fact.location.length if fact.location.length is not None else 0
    return {
        "offset": hexadecimal(offset),
        "length": number(length),
        "characters": number(fact.data.characters),
        "text": fact.data.text,
        "complete": fact.data.complete,
    }


def _base_n(transform: str) -> Callable[[tuple[Evidence, ...], Report], Derived | None]:
    def derive(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
        if len(cited) != 2:
            return None
        decoded, source = cited
        if not isinstance(decoded, DecodedStringEvidence) or not isinstance(source, StringEvidence):
            return None
        if decoded.transform.name != transform or decoded.provenance.evidence_ids != (source.id,):
            return None
        entry = "decode.base64" if transform == "base64-strict-v1" else "decode.hex"
        return _decoded_text(decoded), (entry, "evidence.confidence")

    return derive


def _xor(reused: bool) -> Callable[[tuple[Evidence, ...], Report], Derived | None]:
    def derive(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
        if not cited or not isinstance(cited[0], DecodedStringEvidence):
            return None
        decoded, refs = cited[0], cited[1:]
        if decoded.transform.key_hex is None or decoded.anchor is None:
            return None
        if tuple(ref.id for ref in refs) != decoded.provenance.evidence_ids:
            return None
        if reused != bool(refs):
            return None
        slots = _decoded_text(decoded)
        slots.update(
            {
                "key": decoded.transform.key_hex,
                "key_bytes": _bytes(len(decoded.transform.key_hex) // 2),
                "encoding": "ASCII" if decoded.data.encoding == "ascii" else "UTF-16LE",
                "crib": decoded.anchor.crib,
            }
        )
        glossary = ["decode.xor", "decode.crib", "evidence.confidence"]
        if reused:
            slots["verifier"] = refs[0].id
            glossary.append("decode.key_reuse")
        return slots, tuple(glossary)

    return derive


# --- code -------------------------------------------------------------------------

CALL_SITES_SHOWN = 20
VIA = {
    "direct": "directa",
    "thunk": "a través de un thunk",
    "register": "por registro",
    "tail": "salto en cola",
}
NOT_EXECUTED = (
    "Que el código contenga la llamada no demuestra que se ejecute: depende de condiciones "
    "y entradas que el análisis estático no resuelve, y un binario empaquetado solo muestra "
    "el código de su desempaquetador."
)


def _import_label(fact: ImportEvidence) -> str:
    data = fact.data
    return name(data.function) if data.function is not None else f"ordinal {data.ordinal}"


def _calls(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    """One import and every call the report publishes to it, in report order."""
    if len(cited) < 2 or not isinstance(cited[0], ImportEvidence):
        return None
    target = cited[0]
    calls = [fact for fact in cited[1:] if isinstance(fact, ApiCallEvidence)]
    if len(calls) != len(cited) - 1:
        return None
    if tuple(fact.id for fact in calls) != groups(report).calls.get(target.id):
        return None  # a summary must cite every call to the import, in report order
    sites = tuple(
        f"{hexadecimal(fact.location.rva or 0)} ({VIA[fact.data.via]})"
        for fact in calls[:CALL_SITES_SHOWN]
    )
    if len(calls) > CALL_SITES_SHOWN:
        sites += (f"y {number(len(calls) - CALL_SITES_SHOWN)} más",)
    slots: Slots = {
        "function": _import_label(target),
        "dll": name(target.data.dll),
        "count": number(len(calls)),
        "noun": "llamada" if len(calls) == 1 else "llamadas",
        "sites": sites,
    }
    return slots, ("code.import_call", "pe.imports")


ARGUMENT_TEXT_SHOWN = 200


def _argument_value(fact: CallArgumentEvidence) -> str:
    data = fact.data
    if data.constant is not None:
        return data.constant
    if data.string is not None:
        text = data.string.text
        if len(text) > ARGUMENT_TEXT_SHOWN:
            text = f"{text[:ARGUMENT_TEXT_SHOWN]}… ({number(len(data.string.text))} caracteres)"
        return f"«{text}»"
    return f"{data.value:#x}"


RESOLVED_NAMES_SHOWN = 50


def procedure_name(fact: Evidence, facts: dict[str, Evidence]) -> str | None:
    """The name a published GetProcAddress argument passes, or None."""
    if not isinstance(fact, CallArgumentEvidence) or fact.data.string is None:
        return None
    if fact.data.name != "lpProcName":
        return None
    call = facts.get(fact.provenance.evidence_ids[0])
    callee = None if call is None else facts.get(call.provenance.evidence_ids[0])
    if not isinstance(callee, ImportEvidence) or callee.data.function is None:
        return None
    return fact.data.string.text if name(callee.data.function) == "GetProcAddress" else None


def _resolved_names(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    """Every name the code passes to GetProcAddress, in report order."""
    facts = {fact.id: fact for fact in report.evidence}
    group = tuple(f.id for f in report.evidence if procedure_name(f, facts) is not None)
    if not cited or tuple(fact.id for fact in cited) != group:
        return None
    names = tuple(dict.fromkeys(procedure_name(fact, facts) or "" for fact in cited))
    slots: Slots = {
        "count": number(len(cited)),
        "noun": "nombre" if len(cited) == 1 else "nombres",
        "distinct": number(len(names)),
        "dnoun": "distinto" if len(names) == 1 else "distintos",
        "names": names[:RESOLVED_NAMES_SHOWN],
    }
    pe = next((run for run in report.extractor_runs if run.source == "pe"), None)
    tables = [p for p in (pe.components if pe else ()) if p.name.startswith("imports_")]
    if tables and all(part.status == "complete" for part in tables):
        # only a complete import table can show that a name is absent from it
        imported = {
            name(fact.data.function)
            for fact in report.evidence
            if isinstance(fact, ImportEvidence) and fact.data.function is not None
        }
        slots["unlisted"] = tuple(text for text in names if text not in imported)[
            :RESOLVED_NAMES_SHOWN
        ]
    return slots, ("pe.imports.runtime_linking", "code.call_argument", "evidence.confidence")


def _arguments(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    """One call and every argument the report publishes for it, in report order."""
    if len(cited) < 2 or not isinstance(cited[0], ApiCallEvidence):
        return None
    call = cited[0]
    values = [fact for fact in cited[1:] if isinstance(fact, CallArgumentEvidence)]
    if len(values) != len(cited) - 1:
        return None
    if tuple(fact.id for fact in values) != groups(report).arguments.get(call.id):
        return None  # every published argument of the call, in report order
    target = groups(report).facts.get(call.provenance.evidence_ids[0])
    if not isinstance(target, ImportEvidence):
        return None
    shown = sorted(values, key=lambda fact: fact.data.position)
    slots: Slots = {
        "site": hexadecimal(call.location.rva or 0),
        "function": _import_label(target),
        "arguments": ", ".join(f"{f.data.name} = {_argument_value(f)}" for f in shown),
    }
    return slots, ("code.call_argument", "code.import_call", "evidence.confidence")


def _local_link(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    """One link, with the call that writes the variable and the call that reads it."""
    if len(cited) != 3:
        return None
    link, writer, reader = cited
    if not isinstance(link, LocalLinkEvidence):
        return None
    if (writer.id, reader.id) != tuple(link.provenance.evidence_ids):
        return None
    if not isinstance(writer, ApiCallEvidence) or not isinstance(reader, ApiCallEvidence):
        return None
    facts = groups(report).facts
    writes = facts.get(writer.provenance.evidence_ids[0])
    reads = facts.get(reader.provenance.evidence_ids[0])
    if not isinstance(writes, ImportEvidence) or not isinstance(reads, ImportEvidence):
        return None
    slots: Slots = {
        "reader": _import_label(reads),
        "reader_site": hexadecimal(reader.location.rva or 0),
        "reader_parameter": link.data.reader_name,
        "slot": frame_slot(link),
        "writer": _import_label(writes),
        "writer_site": hexadecimal(writer.location.rva or 0),
        "writer_parameter": link.data.writer_name,
    }
    return slots, ("code.local_link", "code.call_argument", "evidence.confidence")


RANGES_SHOWN = 20


def _functions(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    """Every x64 .pdata range the report publishes, in report order."""
    group = tuple(fact for fact in report.evidence if isinstance(fact, CodeFunctionEvidence))
    if not group or tuple(fact.id for fact in cited) != tuple(fact.id for fact in group):
        return None
    ranges = tuple(
        f"{hexadecimal(fact.data.begin)}-{hexadecimal(fact.data.end)}"
        for fact in group[:RANGES_SHOWN]
    )
    if len(group) > RANGES_SHOWN:
        ranges += (f"y {number(len(group) - RANGES_SHOWN)} más",)
    slots: Slots = {
        "count": number(len(group)),
        "noun": "rango" if len(group) == 1 else "rangos",
        "ranges": ranges,
    }
    return slots, ("code.function_range", "code.import_call")


# Didactic context, not a detector: on 2026-09-24, among 1,053
# native benign binaries (System32 --stride 3, SysWOW64 --stride 5) with a complete
# walk and at least 64 KiB of executable sections, 3 (0.28 %) had fewer than 20 walked
# instructions per KiB: a resource DLL and two COM proxy stubs. Managed assemblies,
# whose native code is only a stub, are left out; so are smaller code sections, where
# keyboard layouts and resource DLLs make low densities common (6.7 % below 5 per KiB
# at 4 KiB).
WALK_DENSITY = 20
WALK_DENSITY_MIN_BYTES = 65536
MANAGED_ENTRIES = frozenset({"_CorDllMain", "_CorExeMain"})


def executable_sections(report: Report) -> tuple[SectionEvidence, ...]:
    return tuple(
        fact
        for fact in report.evidence
        if isinstance(fact, SectionEvidence)
        and "execute" in fact.data.permissions
        and fact.data.raw_status == "present"
    )


def _walk_density(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    """A walk that decodes few instructions for the size of its executable sections."""
    sections = executable_sections(report)
    if not sections or tuple(fact.id for fact in cited) != tuple(fact.id for fact in sections):
        return None
    runs = {run.source: run for run in report.extractor_runs}
    if "code" not in runs or "pe" not in runs:
        return None
    walk = next(p for p in runs["code"].components if p.name == "disassembly")
    tables = [p for p in runs["pe"].components if p.name.startswith("imports_")]
    if walk.status != "complete" or any(p.status != "complete" for p in tables):
        return None  # a partial walk is short by its limits; managed code needs imports
    if any(
        isinstance(fact, ImportEvidence)
        and fact.data.function is not None
        and name(fact.data.function) in MANAGED_ENTRIES
        for fact in report.evidence
    ):
        return None  # a managed assembly's native code is only a stub
    size = sum(fact.data.raw_size for fact in sections)
    instructions = walk.examined or 0
    if size < WALK_DENSITY_MIN_BYTES or instructions * 1024 >= WALK_DENSITY * size:
        return None
    slots: Slots = {
        "instructions": number(instructions),
        "kib": number(size // 1024),
        "density": f"{instructions * 1024 / size:.1f}".replace(".", ","),
    }
    return slots, ("code.import_call", "analysis.coverage")


def _code_family(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    """Every published call to an import on one curated family list."""
    calls = [fact for fact in cited if isinstance(fact, ApiCallEvidence)]
    if not calls or len(calls) != len(cited):
        return None
    facts = {fact.id: fact for fact in report.evidence}

    def family(call: ApiCallEvidence) -> str | None:
        target = facts.get(call.provenance.evidence_ids[0])
        if not isinstance(target, ImportEvidence) or target.data.function is None:
            return None
        return family_of(name(target.data.function))

    families = {family(call) for call in calls}
    chosen = families.pop() if len(families) == 1 else None
    if chosen is None:
        return None
    group = tuple(
        fact.id
        for fact in report.evidence
        if isinstance(fact, ApiCallEvidence) and family(fact) == chosen
    )
    if tuple(fact.id for fact in calls) != group:
        return None
    functions = tuple(
        dict.fromkeys(
            _import_label(target)
            for call in calls
            if isinstance(target := facts[call.provenance.evidence_ids[0]], ImportEvidence)
        )
    )
    slots: Slots = {
        "count": number(len(calls)),
        "noun": "llamada" if len(calls) == 1 else "llamadas",
        "distinct": len(functions),
        "fnoun": "función" if len(functions) == 1 else "funciones",
        "family": FAMILIES[chosen][0],
        "functions": functions,
    }
    return slots, (f"api.family.{chosen}", "code.import_call")


MAIN_FUNCTIONS_SHOWN = 40


def _main_call(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    """The call that enters main, with the call to __getmainargs it rests on."""
    if len(cited) != 2:
        return None
    main, anchor = cited
    if not isinstance(main, MainCallEvidence) or not isinstance(anchor, ApiCallEvidence):
        return None
    if main.provenance.evidence_ids != (anchor.id,):
        return None
    callee = groups(report).facts.get(anchor.provenance.evidence_ids[0])
    if not isinstance(callee, ImportEvidence) or callee.data.function is None:
        return None
    slots: Slots = {
        "site": hexadecimal(main.location.rva or 0),
        "target": hexadecimal(main.data.target),
        "function": _import_label(callee),
        "anchor": hexadecimal(anchor.location.rva or 0),
    }
    return slots, ("code.main_function", "code.import_call", "evidence.confidence")


def _reach(root: str) -> Callable[[tuple[Evidence, ...], Report], Derived | None]:
    def derive(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
        if len(cited) != 2:
            return None
        reach, main = cited
        if not isinstance(reach, CodeReachEvidence) or not isinstance(main, MainCallEvidence):
            return None
        if reach.data.root != root:
            return None
        if reach.provenance.evidence_ids != (main.id,):
            return None
        facts = groups(report).facts
        names: dict[str, None] = {}
        for call_id in reach.data.calls:
            call = facts.get(call_id)
            callee = None if call is None else facts.get(call.provenance.evidence_ids[0])
            if not isinstance(callee, ImportEvidence):
                return None
            names[_import_label(callee)] = None
        count, distinct = len(reach.data.calls), len(names)
        shown = tuple(sorted(names)[:MAIN_FUNCTIONS_SHOWN])
        if distinct > MAIN_FUNCTIONS_SHOWN:
            shown += (f"y {number(distinct - MAIN_FUNCTIONS_SHOWN)} más",)
        slots: Slots = {
            "target": hexadecimal(main.data.target),
            "count": number(count),
            "noun": "llamada" if count == 1 else "llamadas",
            "distinct": number(distinct),
            "fnoun": "función" if distinct == 1 else "funciones",
            "functions": shown,
        }
        return slots, ("code.reach", "code.main_function", "code.import_call")

    return derive


TEXTS_SHOWN = 20


def _texts(references: list[StringReferenceEvidence], report: Report) -> tuple[str, ...] | None:
    facts = groups(report).facts
    texts: list[str] = []
    for reference in references:
        string = facts.get(reference.provenance.evidence_ids[0])
        if not isinstance(string, StringEvidence):
            return None
        texts.append(f"«{string.data.text}»")
    shown = tuple(texts[:TEXTS_SHOWN])
    if len(texts) > TEXTS_SHOWN:
        shown += (f"y {number(len(texts) - TEXTS_SHOWN)} más",)
    return shown


def _references(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    """Every string reference the report publishes, in report order."""
    group = [fact for fact in report.evidence if isinstance(fact, StringReferenceEvidence)]
    if not group or tuple(fact.id for fact in cited) != tuple(fact.id for fact in group):
        return None
    texts = _texts(group, report)
    if texts is None:
        return None
    slots: Slots = {
        "count": number(len(group)),
        "noun": "cadena" if len(group) == 1 else "cadenas",
        "texts": texts,
    }
    return slots, ("code.string_reference", "strings.literal")


def _main_texts(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    """The references a walk from main decoded, with the reach that lists them."""
    if len(cited) < 2:
        return None
    reach = cited[0]
    if not isinstance(reach, CodeReachEvidence) or reach.data.root != "main":
        return None
    references = [fact for fact in cited[1:] if isinstance(fact, StringReferenceEvidence)]
    if tuple(fact.id for fact in references) != reach.data.strings or not references:
        return None
    texts = _texts(references, report)
    if texts is None:
        return None
    main = groups(report).facts.get(reach.provenance.evidence_ids[0])
    if not isinstance(main, MainCallEvidence):
        return None
    slots: Slots = {
        "target": hexadecimal(main.data.target),
        "count": number(len(references)),
        "noun": "cadena" if len(references) == 1 else "cadenas",
        "texts": texts,
    }
    return slots, ("code.string_reference", "code.reach")


def _areas(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
    """The curated families the calls reachable from main belong to, and those none does."""
    if len(cited) != 1 or not isinstance(cited[0], CodeReachEvidence):
        return None
    reach = cited[0]
    if reach.data.root != "main":
        return None
    facts = groups(report).facts
    main = facts.get(reach.provenance.evidence_ids[0])
    if not isinstance(main, MainCallEvidence):
        return None
    seen: set[str] = set()
    for call_id in reach.data.calls:
        call = facts.get(call_id)
        callee = None if call is None else facts.get(call.provenance.evidence_ids[0])
        if not isinstance(callee, ImportEvidence):
            return None
        if callee.data.function is not None:
            family = family_of(name(callee.data.function))
            if family is not None:
                seen.add(family)
    touched = tuple(FAMILIES[family][0] for family in FAMILIES if family in seen)
    untouched = tuple(FAMILIES[family][0] for family in FAMILIES if family not in seen)
    slots: Slots = {
        "target": hexadecimal(main.data.target),
        "count": number(len(touched)),
        "total": number(len(FAMILIES)),
        "touched": touched or ("ninguna",),
        "untouched": untouched or ("ninguna",),
    }
    return slots, ("code.reach", "code.import_call")


RULES: dict[str, Rule] = {
    rule.id: rule
    for rule in (
        Rule(
            "pe.header@1",
            "El archivo es {format} ({bits} bits, máquina {machine}). Declara el punto de "
            "entrada en la RVA {entry} y un tamaño de imagen de {size_of_image} bytes.",
            "Son valores declarados por el archivo: no garantizan que Windows lo cargue así "
            "ni dicen nada de lo que hace el programa.",
            _header,
        ),
        Rule(
            "toolchain.rich_header@1",
            "El archivo contiene una cabecera Rich (desplazamiento {offset}, {entries} {noun}) "
            "cuyo checksum coincide con los bytes que la preceden: es la estructura que "
            "escribe el enlazador de Microsoft (link.exe), el de Visual Studio.",
            "Una cabecera Rich puede copiarse de otro programa o fabricarse con un checksum "
            "válido. No dice quién compiló el programa ni qué hace.",
            _marker("rich_header"),
        ),
        Rule(
            "toolchain.gcc_ident@1",
            "El archivo contiene {count} {noun} de identificación de GCC, la marca que GCC "
            "añade a cada archivo que compila: «{idents}».",
            "La marca puede quitarse o copiarse. Indica que al menos parte del código se "
            "compiló con GCC, no quién lo compiló ni qué hace el programa.",
            _marker("gcc_ident"),
        ),
        Rule(
            "toolchain.mingw_w64_runtime@1",
            "El archivo contiene el mensaje «{message}» (desplazamiento {offset}), del código "
            "de arranque que MinGW-w64 añade a los programas que compila.",
            "Indica que el archivo incluye ese código de arranque; no dice quién lo compiló "
            "ni qué hace el resto del programa.",
            _marker("mingw_w64_runtime"),
        ),
        Rule(
            "toolchain.go_buildinfo@1",
            "El archivo contiene la cabecera de información de compilación que el enlazador "
            "de Go escribe en sus programas (RVA {rva}); declara la versión «{version}».",
            "La cabecera y la versión son lo que declara el archivo: pueden copiarse o "
            "manipularse. No dicen qué hace el programa.",
            _marker("go_buildinfo", versioned=True),
        ),
        Rule(
            "toolchain.go_buildinfo_pointer@1",
            "El archivo contiene la cabecera de información de compilación que el enlazador "
            "de Go escribe en sus programas (RVA {rva}), en el formato que guarda la versión "
            "fuera de la cabecera: LupaBin no la lee.",
            "La cabecera es lo que declara el archivo: puede copiarse o manipularse. No dice "
            "qué hace el programa.",
            _marker("go_buildinfo", versioned=False),
        ),
        Rule(
            "toolchain.clr_header@1",
            "El directorio «CLR Runtime Header» apunta a una cabecera CLR válida (RVA {rva}): "
            "el archivo es un ensamblado .NET, con código gestionado (IL).",
            "LupaBin solo recorre código x86 y x64: no ve el código IL de .NET, así que no "
            "encontrar llamadas ni capacidades en este archivo no dice nada de lo que hace.",
            _marker("clr_header"),
        ),
        Rule(
            "toolchain.pyinstaller_cookie@1",
            "Después de las secciones está la cookie de un archivo de PyInstaller "
            "(desplazamiento {offset}), que declara la biblioteca de Python «{library}»: es el "
            "formato en que PyInstaller empaqueta un programa Python con su intérprete.",
            "LupaBin solo analiza el cargador que abre ese archivo, no el código Python que "
            "contiene. La cookie puede copiarse.",
            _marker("pyinstaller_cookie"),
        ),
        Rule(
            "pe.section@1",
            "Sección {index} «{name}»: {virtual_size} bytes en memoria y {raw_size} en disco; "
            "permisos declarados: {permissions}.",
            "El nombre y los permisos son declarados: no demuestran qué contiene la sección "
            "ni cómo la usa el programa.",
            _section,
        ),
        Rule(
            "pe.section.writable_executable@1",
            "La sección {index} «{name}» declara permisos de escritura y de ejecución a la vez.",
            "No demuestra que se escriba código en ella ni que se ejecute: también lo hacen "
            "algunos compiladores, enlazadores y protectores legítimos.",
            _writable_executable,
        ),
        Rule(
            "entropy.value@1",
            "Los {bytes} bytes en disco de la sección «{name}» tienen una entropía de "
            "{bits} bits por byte (el máximo es 8).",
            "La entropía no demuestra empaquetado ni cifrado: los datos comprimidos legítimos "
            "(imágenes, recursos) también la tienen alta.",
            _entropy,
        ),
        Rule(
            "entropy.high@1",
            "La entropía de «{name}» ({bits} bits por byte) es alta: en binarios benignos "
            "medidos, solo el 0,34 % de las secciones de 4 KiB o más alcanza 7,2.",
            "No demuestra empaquetado ni cifrado: ese 0,34 % son programas legítimos con datos "
            "comprimidos, y un empaquetador puede dejar secciones con entropía baja.",
            _high_entropy,
        ),
        Rule(
            "imports.dll@1",
            "La {table} declara {count} {noun} de «{dll}».",
            "Un import no demuestra que la función se ejecute ni con qué fin; y un programa "
            "puede usar funciones que no aparecen en esta tabla.",
            _imports,
        ),
        Rule(
            "imports.family@1",
            "{count} {noun} a la familia «{family}» de la lista curada de LupaBin. En "
            "binarios benignos medidos, el {share} importa alguna función de esta familia.",
            "Estar en la lista no demuestra que el programa haga eso: es una pista para "
            "estudiar, y muchos programas legítimos importan estas funciones.",
            _family,
        ),
        Rule(
            "code.calls@1",
            "El código contiene {count} {noun} a la función importada «{function}» de «{dll}».",
            NOT_EXECUTED,
            _calls,
        ),
        Rule(
            "code.family@1",
            "El código contiene {count} {noun} a {distinct} {fnoun} de la familia «{family}» "
            "de la lista curada de LupaBin.",
            "Estar en la lista no demuestra que el programa haga eso: muchos programas "
            "legítimos llaman a estas funciones. " + NOT_EXECUTED,
            _code_family,
        ),
        Rule(
            "code.walk_density@1",
            "El recorrido del código decodificó {instructions} instrucciones en {kib} KiB de "
            "secciones ejecutables ({density} por KiB). En binarios benignos medidos con al "
            "menos 64 KiB de código nativo, solo el 0,28 % se queda por debajo de 20 por KiB.",
            "No demuestra empaquetado ni cifrado: también ocurre con secciones que guardan "
            "sobre todo datos o con código al que solo se llega por saltos indirectos. Pero "
            "un binario empaquetado muestra poco más que su desempaquetador hasta que se "
            "ejecuta, y el recorrido estático no puede ir más allá.",
            _walk_density,
        ),
        Rule(
            "code.resolved_names@1",
            "El código pasa {count} {noun} de función a GetProcAddress ({distinct} {dnoun}).",
            "Que el código pase un nombre a GetProcAddress no demuestra que la llamada se "
            "ejecute, que esa función exista ni que se use; y un programa también puede "
            "resolver funciones por ordinal o con nombres que construye o descifra al "
            "ejecutarse, que LupaBin no ve.",
            _resolved_names,
        ),
        Rule(
            "code.arguments@1",
            "En {site} el código llama a «{function}» con {arguments}.",
            "Es una inferencia a partir de las instrucciones que preceden a la llamada en el "
            "mismo tramo: no demuestra que la llamada se ejecute, ni descarta que un camino "
            "que el recorrido no ve llegue a ella con otros valores.",
            _arguments,
        ),
        Rule(
            "code.local_link@1",
            "La llamada a «{reader}» de {reader_site} recibe como {reader_parameter} el valor "
            "de la variable local {slot}, donde la llamada a «{writer}» de {writer_site} deja "
            "el identificador que devuelve ({writer_parameter}).",
            "Es una inferencia a partir de las instrucciones entre las dos llamadas: ninguna "
            "cambia esa variable y no hay otro camino hasta la segunda. No demuestra que las "
            "llamadas se ejecuten ni que la primera tenga éxito; si falla, la variable no "
            "guarda una clave abierta.",
            _local_link,
        ),
        Rule(
            "code.functions@1",
            "La tabla .pdata declara {count} {noun} de función con llamadas a funciones del "
            "catálogo de argumentos de LupaBin.",
            "Es lo que declara el archivo: un binario manipulado puede declarar rangos falsos. "
            "Cada rango es un tramo contiguo de una función, y una función puede ocupar varios.",
            _functions,
        ),
        Rule(
            "code.main_call@1",
            "En {site}, el código de arranque del compilador llama a la función de {target} "
            "con los valores de las tres variables que rellenó {function} ({anchor}): argc, "
            "argv y envp. Es la función main del programa, donde el arranque le entrega el "
            "control.",
            "Es una inferencia a partir de las direcciones que comparten las dos llamadas, sin "
            "ejecutar nada. No demuestra que el programa llegue a main, y antes de main puede "
            "ejecutarse otro código del programa, como constructores de C++ o funciones TLS.",
            _main_call,
        ),
        Rule(
            "code.reach_main@1",
            "Desde main ({target}), siguiendo solo llamadas y saltos directos, el recorrido "
            "alcanza {count} {noun} a {distinct} {fnoun} importadas.",
            "Incluye código que el autor no escribió pero su programa usa, como las "
            "bibliotecas que enlaza o las comprobaciones que añade el compilador. No incluye "
            "lo que main alcanza por llamadas indirectas, ni demuestra que esas llamadas se "
            "ejecuten.",
            _reach("main"),
        ),
        Rule(
            "code.reach_startup@1",
            "{count} {noun} a {distinct} {fnoun} importadas solo las alcanza el código de "
            "arranque del compilador: desde el punto de entrada y las funciones TLS, sin pasar "
            "por main ({target}).",
            "Es código que el compilador añade a sus programas: que llame a una función no dice "
            "nada de lo que hace el programa. Si el autor también la llama por un camino que el "
            "recorrido no ve, no aparece aquí.",
            _reach("startup"),
        ),
        Rule(
            "strings.references@1",
            "Instrucciones del código recorrido toman la dirección donde empiezan {count} "
            "{noun} del archivo: son textos que el código usa, no solo bytes que parecen texto.",
            "Que una instrucción tome la dirección de un texto no demuestra que se ejecute ni "
            "para qué se usa el texto. No aparecen los textos que el código construye o descifra "
            "al ejecutarse, ni los que solo alcanza por caminos que el recorrido no ve.",
            _references,
        ),
        Rule(
            "strings.from_main@1",
            "Desde main ({target}), el código alcanzable siguiendo llamadas y saltos directos "
            "usa {count} {noun} del archivo.",
            "Incluye los textos de las bibliotecas que el programa usa desde main, no solo los "
            "que escribió el autor. No demuestra que esas instrucciones se ejecuten.",
            _main_texts,
        ),
        Rule(
            "code.areas@1",
            "Las llamadas alcanzables desde main ({target}) son de {count} de las {total} "
            "familias de funciones de la lista curada de LupaBin.",
            "Una llamada alcanzable no demuestra que se ejecute. Que no se vea ninguna llamada "
            "de una familia no demuestra que el programa no haga eso: puede usar funciones que "
            "no están en la lista, cargarlas al ejecutarse o llegar a ellas por caminos que el "
            "recorrido no ve.",
            _areas,
        ),
        Rule(
            "exports.table@1",
            "La tabla de exports declara {count} entradas: {named} con nombre y {forwarded} "
            "reenviadas a otra DLL.",
            "Los nombres exportados los elige el autor: no demuestran lo que hace el código.",
            _exports,
        ),
        Rule(
            "strings.summary@1",
            "Se extrajeron {ascii} cadenas ASCII y {utf16} cadenas UTF-16LE de al menos cuatro "
            "caracteres imprimibles.",
            "Una cadena no demuestra que el programa la use: puede venir de una biblioteca "
            "incluida o de datos que nunca se leen.",
            _strings,
        ),
        Rule(
            "anomaly.section_raw_out_of_bounds@1",
            "Los datos de la sección «{name}» (desde {offset}, {size} bytes) terminan más allá "
            "del final del archivo, que tiene {file_size} bytes.",
            "No demuestra manipulación ni intención maliciosa: también ocurre en archivos "
            "truncados.",
            _anomaly("section_raw_out_of_bounds"),
        ),
        Rule(
            "anomaly.section_raw_overlap@1",
            "Las secciones «{a}» y «{b}» declaran datos en disco que se solapan.",
            "No demuestra intención maliciosa: algunos empaquetadores y herramientas legítimas "
            "lo hacen.",
            _anomaly("section_raw_overlap"),
        ),
        Rule(
            "anomaly.section_virtual_overlap@1",
            "Las secciones «{a}» y «{b}» declaran rangos en memoria que se solapan "
            "(comprobación conservadora sobre los campos declarados).",
            "No reproduce el cargador de Windows ni demuestra intención maliciosa.",
            _anomaly("section_virtual_overlap"),
        ),
        Rule(
            "anomaly.section_exceeds_image@1",
            "La sección «{name}» se extiende en memoria más allá del tamaño de imagen declarado "
            "({size_of_image} bytes).",
            "Solo indica que la cabecera y la tabla de secciones no son coherentes entre sí.",
            _anomaly("section_exceeds_image"),
        ),
        Rule(
            "anomaly.entry_point_outside_image@1",
            "El punto de entrada declarado ({entry}) queda fuera del tamaño de imagen "
            "({size_of_image} bytes).",
            "No demuestra intención maliciosa ni cómo se comportará el archivo.",
            _anomaly("entry_point_outside_image"),
        ),
        Rule(
            "yara.match@1",
            "La regla «{rule}» (revisión {revision}) del catálogo de LupaBin coincide; se "
            "conservaron {kept} apariciones de sus patrones{more}.",
            "Una coincidencia no identifica una familia ni un comportamiento; lo que significa "
            "está en la descripción de la regla.",
            _yara,
        ),
        Rule(
            "decoded.base64@1",
            "La cadena del desplazamiento {offset} es Base64 válido y decodifica a un texto de "
            "{characters} caracteres.",
            "No demuestra que el programa decodifique esa cadena ni que use el texto.",
            _base_n("base64-strict-v1"),
        ),
        Rule(
            "decoded.hex@1",
            "La cadena del desplazamiento {offset} es hexadecimal válido y decodifica a un "
            "texto de {characters} caracteres.",
            "No demuestra que el programa decodifique esa cadena ni que use el texto.",
            _base_n("hex-strict-v1"),
        ),
        Rule(
            "decoded.xor@1",
            "Aplicar XOR con la clave {key} ({key_bytes}) a los {length} bytes del "
            "desplazamiento {offset} produce un texto {encoding} de {characters} caracteres, "
            "anclado por la crib «{crib}».",
            "No demuestra que el programa haga esta operación ni que use el texto.",
            _xor(reused=False),
        ),
        Rule(
            "decoded.xor_reused@1",
            "Aplicar XOR con la clave {key} ({key_bytes}) a los {length} bytes del "
            "desplazamiento {offset} produce un texto {encoding} de {characters} caracteres, "
            "anclado por la crib «{crib}». La clave la estableció la decodificación {verifier}.",
            "No demuestra que el programa haga esta operación, ni que use el texto, ni que "
            "los dos textos se usen juntos.",
            _xor(reused=True),
        ),
    )
}
# One rule per capability of the catalog (explain/capabilities.py).
RULES.update(
    {
        capability.rule_id: Rule(
            capability.rule_id, capability.template, capability.not_proven, derive(capability)
        )
        for capability in CAPABILITIES
    }
)
