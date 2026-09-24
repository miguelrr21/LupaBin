"""Phase 5 capabilities: explanation rules over calls and their constant arguments."""

import pytest

from dissect.analysis import analyze_bytes
from dissect.evidence import api_catalog
from dissect.evidence.facts import CallArgumentData
from dissect.evidence.models import Limits
from dissect.evidence.primitives import CodeLimits
from dissect.explain import capabilities, winapi
from dissect.explain.engine import check_item, explain, validate
from dissect.explain.rules import RULES
from dissect.glossary.catalog import load_glossary
from dissect.render import document
from dissect.render.document import to_markdown, to_text
from dissect.render.safe import code_span
from tests.fixtures.pe_builder import build_call_demo, build_code_pe
from tests.test_code_arguments import create_service

GLOSSARY = load_glossary()
HKCR, HKCU, HKLM, HKU = 0x80000000, 0x80000001, 0x80000002, 0x80000003
RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
WINLOGON = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"


def found(data):
    """(report, explanation, capability items by rule) of an inert sample."""
    report = analyze_bytes(data)
    explanation = explain(report, GLOSSARY)  # explain() also validates every item
    items = {i.rule: i for i in explanation.items if i.rule.startswith("capability.")}
    return report, explanation, items


def only_case(data):
    _, _, items = found(data)
    assert len(items) == 1, items
    ((rule, item),) = items.items()
    assert item.level == "inferred"
    return rule, item.slots["cases"]


# --- catalog ---------------------------------------------------------------------------


def test_catalog_is_pinned_and_follows_the_argument_catalog():
    assert capabilities.catalog_digest() == capabilities.CATALOG_SHA256, (
        "new CATALOG_ID, digest and measurement"
    )
    assert capabilities.API_CATALOG == api_catalog.CATALOG_ID
    assert CallArgumentData.model_fields["catalog"].default == capabilities.API_CATALOG


def test_every_capability_reads_parameters_the_argument_catalog_interprets():
    for capability in capabilities.CAPABILITIES:
        assert capability.tactic in capabilities.TACTICS
        assert RULES[capability.rule_id].template == capability.template
        for function, parameters in capability.reads.items():
            entry = api_catalog.FUNCTIONS[function]
            known = {parameter.name for parameter in entry.parameters}
            assert set(parameters) <= known, (capability.id, function)
            assert all(ref in GLOSSARY.entries for ref in capability.glossary_ids)


def test_capabilities_never_read_load_library():
    """Measured in 53 % of benign binaries (design section 3): it tells nothing apart."""
    read = {f for capability in capabilities.CAPABILITIES for f in capability.reads}
    assert not {f for f in read if f.startswith(("LoadLibrary", "GetProcAddress"))}


def test_composite_constants_match_the_sdk_headers():
    # the values Windows SDK 10.0.26100.0 winnt.h gives once its macros are expanded
    assert winapi.KEY_READ == 0x20019
    assert winapi.KEY_WRITE == 0x20006
    assert winapi.KEY_ALL_ACCESS == 0xF003F
    assert winapi.PROCESS_ALL_ACCESS == 0x1FFFFF
    assert winapi.service_type(0x110) == "SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS"
    assert winapi.service_type(0x1234) == "0x1234"
    assert winapi.start_type(9) == "0x9"


# --- what each capability says -----------------------------------------------------------

POSITIVE = [
    (
        "RegSetKeyValueW",
        {0: HKCU, 1: RUN, 2: "DissectTraining"},
        "run_key_value",
        "RegSetKeyValueW: «HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run»"
        ", valor «DissectTraining» (T1547.001)",
    ),
    (
        "RegSetKeyValueA",
        {0: HKLM, 1: r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"},
        "run_key_value",
        "RegSetKeyValueA: «HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\"
        "CurrentVersion\\RunOnce» (T1547.001)",
    ),
    (
        "RegSetKeyValueW",
        {0: HKU, 1: "S-1-5-21-1\\" + RUN + "\\"},
        "run_key_value",
        "RegSetKeyValueW: «HKEY_USERS\\S-1-5-21-1\\Software\\Microsoft\\Windows\\"
        "CurrentVersion\\Run\\» (T1547.001)",
    ),
    (
        "RegOpenKeyExW",
        {0: HKCU, 1: RUN, 3: winapi.KEY_WRITE},
        "run_key_open_write",
        "RegOpenKeyExW: «HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run»"
        ", samDesired = 0x20006 (KEY_WRITE)",
    ),
    (
        "RegCreateKeyExW",
        {0: HKLM, 1: RUN + r"Services", 4: 0, 5: winapi.KEY_ALL_ACCESS},
        "run_key_open_write",
        "RegCreateKeyExW: «HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\"
        "RunServices», samDesired = 0xf003f (KEY_ALL_ACCESS)",
    ),
    (
        "RegOpenKeyExA",
        {0: HKLM, 1: WINLOGON, 3: winapi.KEY_SET_VALUE | winapi.KEY_QUERY_VALUE},
        "winlogon_open_write",
        "RegOpenKeyExA: «HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
        "Winlogon», samDesired = 0x3",
    ),
    (
        "WinExec",
        {0: "cmd.exe /c echo dissect", 1: 0},
        "command_execution",
        "WinExec: orden «cmd.exe /c echo dissect» (T1059.003)",
    ),
    (
        "CreateProcessA",
        {1: "notepad.exe C:\\Dissect\\training.txt"},
        "command_execution",
        "CreateProcessA: línea de órdenes «notepad.exe C:\\Dissect\\training.txt»",
    ),
    (
        "CreateProcessW",
        {0: r"C:\Windows\System32\rundll32.exe"},
        "command_execution",
        "CreateProcessW: programa «C:\\Windows\\System32\\rundll32.exe»",
    ),
    (
        "ShellExecuteW",
        {1: "open", 2: "notepad.exe", 3: "training.txt"},
        "command_execution",
        "ShellExecuteW: destino «notepad.exe», parámetros «training.txt», operación «open»",
    ),
    (
        "URLDownloadToFileW",
        {1: "http://training.invalid/file.txt", 2: r"C:\Dissect\file.txt"},
        "download_to_file",
        "URLDownloadToFileW: URL «http://training.invalid/file.txt», archivo "
        "«C:\\Dissect\\file.txt» (T1105)",
    ),
    (
        "InternetConnectW",
        {1: "training.invalid", 2: 443},
        "network_destination",
        "InternetConnectW: servidor «training.invalid», puerto 443",
    ),
    (
        "WinHttpConnect",
        {1: "training.invalid", 2: 0},
        "network_destination",
        "WinHttpConnect: servidor «training.invalid», puerto predeterminado del servicio (0)",
    ),
    (
        "InternetOpenUrlA",
        {1: "https://training.invalid/"},
        "network_destination",
        "InternetOpenUrlA: URL «https://training.invalid/»",
    ),
    (
        "InternetOpenW",
        {0: "DissectTraining/1.0", 1: 0},
        "user_agent",
        "InternetOpenW: agente «DissectTraining/1.0»",
    ),
    (
        "VirtualAlloc",
        {2: 0x3000, 3: winapi.PAGE_EXECUTE_READWRITE},
        "executable_writable_memory",
        "VirtualAlloc: PAGE_EXECUTE_READWRITE",
    ),
    (
        "VirtualProtectEx",
        {3: winapi.PAGE_EXECUTE_WRITECOPY | winapi.PAGE_GUARD},
        "executable_writable_memory",
        "VirtualProtectEx: PAGE_EXECUTE_WRITECOPY | PAGE_GUARD, la función admite otro "
        "proceso; cuál, no se determina",
    ),
    (
        "OpenProcess",
        {0: winapi.PROCESS_ALL_ACCESS},
        "process_memory_access",
        "OpenProcess: dwDesiredAccess = 0x1fffff (PROCESS_ALL_ACCESS); no se determina qué proceso",
    ),
    (
        "OpenProcess",
        {0: 0x28},
        "process_memory_access",
        "OpenProcess: dwDesiredAccess = 0x28 (PROCESS_VM_WRITE, PROCESS_VM_OPERATION); no se "
        "determina qué proceso",
    ),
    (
        "MoveFileExW",
        {0: r"C:\Dissect\old.txt", 2: winapi.MOVEFILE_DELAY_UNTIL_REBOOT},
        "move_on_reboot",
        "MoveFileExW: origen «C:\\Dissect\\old.txt», dwFlags = 0x4",
    ),
    (
        "CreateMutexW",
        {2: "DissectTraining"},
        "named_mutex",
        "CreateMutexW: nombre «DissectTraining»",
    ),
    (
        "OpenMutexW",
        {0: 0x1F0001, 2: "DissectTraining"},
        "named_mutex",
        "OpenMutexW: nombre «DissectTraining»",
    ),
    (
        "BCryptOpenAlgorithmProvider",
        {1: "AES"},
        "crypto_algorithm",
        "BCryptOpenAlgorithmProvider: algoritmo «AES»",
    ),
    (
        "CryptAcquireContextW",
        {2: "Microsoft Enhanced Cryptographic Provider v1.0", 3: 1},
        "crypto_algorithm",
        "CryptAcquireContextW: proveedor «Microsoft Enhanced Cryptographic Provider v1.0»",
    ),
]


@pytest.mark.parametrize(("function", "call", "capability", "case"), POSITIVE)
def test_a_call_that_meets_the_condition_is_described(function, call, capability, case):
    rule, cases = only_case(build_call_demo(function, call))
    assert rule == f"capability.{capability}@1"
    assert len(cases) == 1 and cases[0].startswith("0x0000")
    assert cases[0].split(" ", 1)[1] == case


def test_every_capability_has_a_positive_fixture():
    tested = {capability for _, _, capability, _ in POSITIVE}
    assert tested | {"service_create"} == {c.id for c in capabilities.CAPABILITIES}


@pytest.mark.parametrize("bits", [32, 64])
def test_service_creation_names_the_service_binary_and_start(bits):
    rule, cases = only_case(create_service(bits))
    assert rule == "capability.service_create@1"
    assert cases[0].split(" ", 1)[1] == (
        "CreateServiceW: servicio «DissectTraining», binario «C:\\Dissect\\training.exe», "
        "inicio SERVICE_AUTO_START, tipo SERVICE_WIN32_OWN_PROCESS (T1543.003)"
    )


def test_the_fixture_generator_writes_the_capability_demo(tmp_path, monkeypatch):
    import sys

    from tests.fixtures import pe_builder

    path = tmp_path / "capability.bin"
    argv = ["pe_builder", "--scenario", "capability-demo", "--output", str(path)]
    monkeypatch.setattr(sys, "argv", argv)
    pe_builder.main()
    assert path.read_bytes() == pe_builder.build_capability_demo()
    rule, cases = only_case(path.read_bytes())
    assert rule == "capability.run_key_value@1" and cases[0].endswith(
        "valor «DissectTraining» (T1547.001)"
    )


def test_a_run_key_under_an_unknown_root_says_so():
    _, cases = only_case(build_call_demo("RegSetKeyValueW", {1: RUN}))
    assert cases[0].endswith(
        "«Software\\Microsoft\\Windows\\CurrentVersion\\Run», bajo una clave que no se pudo "
        "determinar (T1547.001)"
    )
    assert "HKEY_" not in cases[0]


# --- MITRE ATT&CK -------------------------------------------------------------------------


def test_every_technique_has_its_glossary_entry_with_its_attack_page():
    for technique, title in capabilities.TECHNIQUES.items():
        entry = GLOSSARY.entries[capabilities.technique_entry(technique)]
        page = "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"
        assert (title.split(": ")[-1], page) in {
            (s.title.split(": ")[-1], s.url) for s in entry.sources
        }
    attack = {ref for ref in GLOSSARY.entries if ref.startswith("attack.t") and ref[8:9].isdigit()}
    assert attack == {capabilities.technique_entry(t) for t in capabilities.TECHNIQUES}


@pytest.mark.parametrize(
    ("function", "call", "technique"),
    [
        ("WinExec", {0: "cmd /c dir"}, "T1059.003"),
        ("CreateProcessA", {1: '"C:\\Windows\\System32\\cmd.exe" /c echo'}, "T1059.003"),
        (
            "CreateProcessW",
            {0: r"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.EXE"},
            "T1059.001",
        ),
        ("ShellExecuteW", {2: "pwsh", 3: "-File training.ps1"}, "T1059.001"),
        ("ShellExecuteA", {2: "C:/Windows/System32/cmd.exe"}, "T1059.003"),
    ],
)
def test_an_interpreter_is_associated_with_its_technique(function, call, technique):
    _, _, items = found(build_call_demo(function, call))
    item = items["capability.command_execution@1"]
    assert item.slots["cases"][0].endswith(f" ({technique})")
    assert item.slots["techniques"] == (f"{technique} ({capabilities.TECHNIQUES[technique]})",)
    assert {"attack.technique", capabilities.technique_entry(technique)} <= set(item.glossary_ids)
    assert len(item.glossary_ids) <= 8


@pytest.mark.parametrize(
    "command",
    [
        r"C:\Windows\System32\rundll32.exe dissect.dll,Training",  # T1218.011 is its abuse
        "regsvr32 /s dissect.dll",
        "mshta training.hta",
        "wscript training.js",  # VBScript or JScript: the call does not say which
        "cscript //nologo training.vbs",
        "cmdtool.exe",
        "C:\\Program Files\\cmd.exe",  # unquoted: the program is C:\Program
        "notepad.exe powershell.exe",
    ],
)
def test_other_programs_are_described_without_a_technique(command):
    _, _, items = found(build_call_demo("WinExec", {0: command}))
    item = items["capability.command_execution@1"]
    assert "techniques" not in item.slots
    assert not item.slots["cases"][0].endswith(")")
    assert not any(ref.startswith("attack.") for ref in item.glossary_ids)


def test_only_the_cases_that_meet_a_technique_carry_it():
    _, _, items = found(build_call_demo("WinExec", {0: "notepad.exe"}, {0: "cmd.exe /c dir"}))
    cases = items["capability.command_execution@1"].slots["cases"]
    assert not cases[0].endswith(")") and cases[1].endswith(" (T1059.003)")


@pytest.mark.parametrize(
    ("function", "call"),
    [
        ("RegOpenKeyExW", {0: HKCU, 1: RUN, 3: winapi.KEY_WRITE}),  # opening writes nothing
        ("RegOpenKeyExA", {0: HKLM, 1: WINLOGON, 3: winapi.KEY_WRITE}),
        ("VirtualAlloc", {3: winapi.PAGE_EXECUTE_READWRITE}),  # not injection by itself
        ("OpenProcess", {0: winapi.PROCESS_ALL_ACCESS}),
    ],
)
def test_capabilities_without_a_matching_technique_name_none(function, call):
    _, _, items = found(build_call_demo(function, call))
    (item,) = items.values()
    assert "techniques" not in item.slots
    assert not any(ref.startswith("attack.") for ref in item.glossary_ids)


NEGATIVE = [
    # a key opened or created to read, or with rights that may not include writing
    ("RegOpenKeyExW", {0: HKCU, 1: RUN, 3: winapi.KEY_READ}),
    ("RegOpenKeyExW", {0: HKCU, 1: RUN, 3: winapi.MAXIMUM_ALLOWED}),
    ("RegOpenKeyExW", {0: HKCU, 1: RUN}),  # samDesired unknown
    ("RegCreateKeyExW", {0: HKCU, 1: RUN, 5: winapi.KEY_READ}),
    ("RegOpenKeyExA", {0: HKLM, 1: WINLOGON, 3: winapi.KEY_READ}),
    # functions that do not say whether they read or write
    ("RegOpenKeyW", {0: HKCU, 1: RUN}),
    ("RegCreateKeyW", {0: HKCU, 1: RUN}),
    # not a Run key
    ("RegSetKeyValueW", {0: HKCR, 1: RUN}),
    ("RegSetKeyValueW", {0: HKLM, 1: r"Microsoft\Windows\CurrentVersion\Run"}),
    ("RegSetKeyValueW", {0: HKCU, 1: RUN + "Dissect"}),
    ("RegSetKeyValueW", {1: RUN + "ner"}),
    ("RegSetKeyValueW", {0: HKU, 1: RUN}),  # no user below HKEY_USERS
    # executable but not writable, unsupported, or with a bit Dissect does not name
    ("VirtualAlloc", {3: winapi.PAGE_EXECUTE_READ}),
    ("VirtualAlloc", {3: winapi.PAGE_EXECUTE_WRITECOPY}),
    ("VirtualAlloc", {3: 0x04}),
    ("VirtualProtect", {2: 0x40000040}),
    ("VirtualProtect", {2: winapi.PAGE_EXECUTE_READWRITE | winapi.PAGE_EXECUTE}),
    ("VirtualProtect", {}),
    # rights that do not modify memory, or MAXIMUM_ALLOWED
    ("OpenProcess", {0: 0x10}),
    ("OpenProcess", {0: winapi.MAXIMUM_ALLOWED}),
    # the flag or the value the condition needs is absent or unknown
    ("MoveFileExW", {0: r"C:\Dissect\old.txt", 2: 1}),
    ("MoveFileExW", {0: r"C:\Dissect\old.txt"}),
    ("CreateServiceW", {3: 0xF01FF, 5: 2}),
    ("WinExec", {1: 0}),
    ("ShellExecuteW", {1: "open"}),
    ("CreateMutexW", {}),
    ("InternetConnectW", {2: 443}),
    ("URLDownloadToFileW", {}),
    ("CryptAcquireContextW", {3: 1}),
]


@pytest.mark.parametrize(("function", "call"), NEGATIVE)
def test_a_call_that_does_not_meet_the_condition_is_not_a_capability(function, call):
    _, explanation, items = found(build_call_demo(function, call))
    assert items == {}
    assert explanation.items  # the call itself is still explained


# --- citations and validation ------------------------------------------------------------


def two_mutexes():
    return build_call_demo("CreateMutexW", {2: "DissectOne"}, {}, {2: "DissectTwo"})


def test_an_item_cites_every_case_with_all_its_arguments_in_report_order():
    report, _, items = found(two_mutexes())
    item = items["capability.named_mutex@1"]
    calls = [f for f in report.evidence if f.kind == "api_call"]
    names = [f for f in report.evidence if f.kind == "call_argument"]
    assert len(calls) == 3 and len(names) == 2  # the middle call has no known name
    assert item.evidence_ids == (calls[0].id, names[0].id, calls[2].id, names[1].id)
    assert item.slots["count"] == "2" and item.slots["noun"] == "llamadas"


def test_hiding_a_case_or_altering_the_statement_does_not_validate():
    report, _, items = found(two_mutexes())
    item = items["capability.named_mutex@1"]
    for changed in (
        item.model_copy(update={"evidence_ids": item.evidence_ids[:2]}),
        item.model_copy(update={"evidence_ids": item.evidence_ids[:-1]}),
        item.model_copy(update={"statement": item.statement.replace("2", "1")}),
        item.model_copy(update={"slots": {**item.slots, "cases": item.slots["cases"][:1]}}),
        item.model_copy(update={"rule": "capability.user_agent@1"}),
    ):
        assert check_item(changed, report, GLOSSARY) is not None
    assert check_item(item, report, GLOSSARY) is None


def test_long_lists_of_cases_are_cut_and_say_how_many_more():
    names = [{2: f"Dissect{n:02}"} for n in range(capabilities.CASES_SHOWN + 3)]
    _, _, items = found(build_call_demo("CreateMutexW", *names))
    cases = items["capability.named_mutex@1"].slots["cases"]
    assert len(cases) == capabilities.CASES_SHOWN + 1
    assert cases[-1] == "y 3 más"


def test_long_strings_are_cut_in_the_case():
    text = "D" * 300
    _, cases = only_case(build_call_demo("CreateMutexW", {2: text}))
    assert cases[0].endswith(f"«{'D' * capabilities.TEXT_SHOWN}…» (300 caracteres)")


def test_capabilities_are_rendered_with_their_cases_and_sample_text_is_inert():
    report, explanation, items = found(build_call_demo("CreateMutexW", {2: "`x` *y* <b>"}))
    chosen = tuple(explanation.items)
    text = to_text(explanation, chosen, report, GLOSSARY)
    assert "de este tipo: crear o abrir un mutex con nombre." in text
    (case,) = items["capability.named_mutex@1"].slots["cases"]
    assert f"Casos (RVA de la llamada): {case}" in text
    markdown = to_markdown(explanation, chosen, report, GLOSSARY)
    assert f"  - Casos (RVA de la llamada): {code_span(case)}" in markdown.splitlines()


# --- the summary that opens the didactic report (design section 6) -----------------------


def rendered(data, kind="text", limits=None):
    report = analyze_bytes(data) if limits is None else analyze_bytes(data, limits)
    explanation = explain(report, GLOSSARY)
    items = validate(explanation, report, GLOSSARY)
    render = to_text if kind == "text" else to_markdown
    return render(explanation, items, report, GLOSSARY)


def summary_of(output):
    return output.split(document.SUMMARY_TITLE)[1].split("1. Qué se pudo analizar")[0]


@pytest.mark.parametrize("kind", ["text", "markdown"])
def test_the_summary_comes_first_and_groups_capabilities_by_tactic(kind):
    output = rendered(build_call_demo("WinExec", {0: "cmd.exe /c dir"}), kind)
    marks = [document.SUMMARY_TITLE, "1. Qué se pudo", "2. Hechos", "3. Inferencias"]
    positions = [output.index(mark) for mark in marks]
    assert positions == sorted(positions)
    part = summary_of(output)
    assert "Ejecución" in part and "de este tipo: ejecutar un programa" in part
    assert "T1059" in part and document.ONE_CALL.split(":")[0] in part
    assert document.NO_CAPABILITY.split(".")[0] not in part


def test_the_summary_says_when_nothing_was_recognised_and_why_that_proves_nothing():
    part = summary_of(rendered(build_call_demo("CreateMutexW", {})))
    assert "No se reconoció ninguna capacidad" in part and "no demuestra" in part


def test_the_summary_says_when_the_code_could_not_be_walked():
    part = summary_of(rendered(b"just some text, not a PE file at all " * 4))
    assert "El código no se pudo recorrer" in part


def test_the_summary_warns_about_create_process_w_command_lines():
    part = summary_of(rendered(build_call_demo("CreateProcessW", {})))
    assert "CreateProcessW, cuya línea de órdenes Dissect no lee" in part


def test_the_summary_warns_when_the_arguments_are_partial():
    limits = Limits(code=CodeLimits(argument_instructions=1))
    part = summary_of(rendered(build_call_demo("CreateMutexW", {2: "Dissect"}), limits=limits))
    assert "quedaron incompletos" in part


def test_the_summary_repeats_the_low_walk_density_note():
    data = build_code_pe(bytes.fromhex("c3") + bytes.fromhex("cc") * 0xFFFF)
    part = " ".join(summary_of(rendered(data)).split())
    assert "se queda por debajo de 20 por KiB" in part


# --- benign context (design section 5) ------------------------------------------------------


def test_every_capability_states_its_measured_benign_prevalence():
    assert set(capabilities.BENIGN) == {c.id for c in capabilities.CAPABILITIES}
    assert all(0 <= n <= capabilities.BENIGN_FILES for n in capabilities.BENIGN.values())
    _, _, items = found(build_call_demo("CreateMutexW", {2: "Dissect"}))
    statement = items["capability.named_mutex@1"].statement
    assert statement.endswith(
        "En binarios benignos medidos, 105 de 3.087 (3,40 %) contienen algún caso."
    )


def test_a_capability_never_seen_in_benign_binaries_says_so():
    _, _, items = found(build_call_demo("URLDownloadToFileW", {1: "http://training.invalid/"}))
    statement = items["capability.download_to_file@1"].statement
    assert statement.endswith("Ninguno de los 3.087 binarios benignos medidos contiene un caso.")
