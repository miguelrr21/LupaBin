"""Deterministic explanation rules.

Each rule is a pure function of the evidence it cites (plus the report, for rules
that summarise a whole group and must prove the group is complete). The validator
re-runs the rule on the cited evidence and requires the exact same item, so a
statement can never say more than its citations support.
"""

from collections.abc import Callable
from dataclasses import dataclass

from dissect.evidence.facts import (
    AnomalyEvidence,
    DecodedStringEvidence,
    EntropyEvidence,
    Evidence,
    ExportEvidence,
    HeaderEvidence,
    ImportEvidence,
    SectionEvidence,
    StringEvidence,
    YaraEvidence,
)
from dissect.evidence.models import Report
from dissect.explain.families import FAMILIES, PREVALENCE, family_of
from dissect.explain.models import SlotValue
from dissect.explain.text import hexadecimal, name, number, section_name

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
# Didactic context, not a detector (design section 6.2): on 2026-09-23, 475 of 139,057
# sections of at least 4 KiB (0.34 %) in 55,313 benign binaries from System32 and
# Program Files reached 7.2 bits per byte. Smaller sections are not compared: with few
# bytes the estimate approaches 8 merely because few values repeat.
HIGH_ENTROPY = 7.2
HIGH_ENTROPY_MIN_BYTES = 4096


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
    group = tuple(
        fact.id
        for fact in report.evidence
        if isinstance(fact, ImportEvidence) and (fact.data.dll.raw_hex, fact.data.table) == key
    )
    if tuple(fact.id for fact in imports) != group:
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
            "{count} {noun} a la familia «{family}» de la lista curada de Dissect. En "
            "binarios benignos medidos, el {share} importa alguna función de esta familia.",
            "Estar en la lista no demuestra que el programa haga eso: es una pista para "
            "estudiar, y muchos programas legítimos importan estas funciones.",
            _family,
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
            "La regla «{rule}» (revisión {revision}) del catálogo de Dissect coincide; se "
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
