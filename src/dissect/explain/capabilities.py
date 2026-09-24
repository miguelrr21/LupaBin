"""Catalog `dissect-capabilities-v1`: what one call contains, from its constant arguments.

Design of Phase 5, sections 2 and 3. A capability is an explanation rule, not a fact:
it reads `api_call` and `call_argument` facts that the report already validates, and
its item cites every call of the report that meets its condition, each with all of
its published arguments, in report order. The statement says what the code contains,
never that the program does it or why.

Conditions only read the parameters listed for each function, which must exist in
the argument catalog named by API_CATALOG (a test checks both). A parameter that was
not published is unknown: a condition that needs it does not hold, and wording that
could use it says less instead of guessing.
"""

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import NamedTuple

from dissect.evidence.facts import ApiCallEvidence, CallArgumentEvidence, Evidence, ImportEvidence
from dissect.evidence.models import Report
from dissect.explain import winapi
from dissect.explain.models import SlotValue
from dissect.explain.text import hexadecimal, name, number

CATALOG_ID = "dissect-capabilities-v2"
CATALOG_SHA256 = "645d7769beda20be36df239f8241f760e1c5e1dd46261ccae9c6e94188cb5a13"
API_CATALOG = "dissect-api-semantics-v4"

Arguments = dict[str, CallArgumentEvidence]
Slots = dict[str, SlotValue]
Derived = tuple[Slots, tuple[str, ...]]  # slots and glossary entry ids

# Benign context (design section 5): on 2026-09-24, binaries with at least one case among
# 3,087 benign PE files (System32 --stride 3: 1,363; SysWOW64 --stride 5: 521; Program
# Files and Program Files (x86) --recursive --stride 40: 1,203), measured with
# `uv run python -m tests.capability_eval`. Each of the 816 cases was reviewed by hand
# (803 with catalog v1, and the 13 that v2 adds; section 10 of the design).
BENIGN_FILES = 3087
BENIGN = {
    "run_key_value": 0,
    "run_key_open_write": 9,
    "winlogon_open_write": 1,
    "winlogon_value": 0,
    "service_create": 2,
    "command_execution": 26,
    "download_to_file": 0,
    "network_destination": 3,
    "user_agent": 39,
    "executable_writable_memory": 72,
    "process_memory_access": 22,
    "move_on_reboot": 9,
    "named_mutex": 105,
    "crypto_algorithm": 152,
}


def benign_context(capability_id: str) -> str:
    count, total = BENIGN[capability_id], number(BENIGN_FILES)
    if count == 0:
        return f"Ninguno de los {total} binarios benignos medidos contiene un caso."
    share = f"{100 * count / BENIGN_FILES:.2f}".replace(".", ",")
    return (
        f"En binarios benignos medidos, {number(count)} de {total} ({share} %) contienen "
        "algún caso."
    )


TACTICS = {
    "persistence": "persistencia",
    "execution": "ejecución",
    "network": "comunicaciones",
    "memory": "manipulación de memoria y procesos",
    "files": "archivos",
    "sync_crypto": "sincronización y criptografía",
}
CASES_SHOWN = 20
TEXT_SHOWN = 200

# MITRE ATT&CK techniques whose definition a case's mechanism meets (design section 4),
# with their names as attack.mitre.org gives them on 2026-09-24.
TECHNIQUES = {
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1547.004": "Boot or Logon Autostart Execution: Winlogon Helper DLL",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1105": "Ingress Tool Transfer",
}


def technique_entry(technique: str) -> str:
    """The glossary entry of a technique: T1547.001 -> attack.t1547_001."""
    return "attack." + technique.lower().replace(".", "_")


@dataclass(frozen=True)
class Capability:
    id: str
    tactic: str
    label: str  # an infinitive: what the calls would do, never that the program does it
    # function -> the catalog parameters its condition and wording read
    reads: dict[str, tuple[str, ...]]
    # (function, its published arguments by name) -> the case's details, or None
    describe: Callable[[str, Arguments], str | None]
    caveat: str  # why this is not proof of intent: legitimate uses
    glossary_ids: tuple[str, ...]
    # the ATT&CK technique of every case, or a function that gives it for each case
    technique: str | Callable[[str, Arguments], str | None] | None = None

    def technique_of(self, function: str, args: Arguments) -> str | None:
        if self.technique is None or isinstance(self.technique, str):
            return self.technique
        return self.technique(function, args)

    @property
    def rule_id(self) -> str:
        return f"capability.{self.id}@1"

    @property
    def template(self) -> str:
        return (
            f"El código contiene {{count}} {{noun}} de este tipo: {self.label}. "
            + benign_context(self.id)
        )

    @property
    def not_proven(self) -> str:
        return (
            f"{self.caveat} Los argumentos son una inferencia a partir de las instrucciones "
            "que preceden a cada llamada: que el código la contenga no demuestra que se "
            "ejecute, y un binario empaquetado solo muestra el código de su desempaquetador."
        )


# --- reading arguments ---------------------------------------------------------------


def _text(args: Arguments, parameter: str) -> str | None:
    fact = args.get(parameter)
    if fact is None or fact.data.string is None:
        return None
    return fact.data.string.text


def _quoted(text: str) -> str:
    if len(text) > TEXT_SHOWN:
        return f"«{text[:TEXT_SHOWN]}…» ({number(len(text))} caracteres)"
    return f"«{text}»"


def _integer(args: Arguments, parameter: str) -> int | None:
    fact = args.get(parameter)
    return fact.data.value if fact is not None and fact.data.type == "integer" else None


def _parts(*parts: str | None) -> str | None:
    shown = [part for part in parts if part]
    return ", ".join(shown) if shown else None


def _labelled(label: str, text: str | None) -> str | None:
    return None if text is None else f"{label} {_quoted(text)}"


# --- registry ------------------------------------------------------------------------


# Paths below HKEY_CURRENT_USER\Software or HKEY_LOCAL_MACHINE\Software (also through
# Wow6432Node), compared without case as the registry does.
class Key(NamedTuple):
    """A registry key, as a path below Software, compared without case."""

    path: str
    # predefined roots under which Software\<path> is this key (HKEY_USERS: <SID>\Software)
    roots: frozenset[str]
    descendants: bool = False  # its subkeys count as well
    # below a key that is not predefined (a handle), compare only the end of the subkey
    unknown_root: bool = True


USER_ROOTS = frozenset({"HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE", "HKEY_USERS"})
RUN_KEYS = (
    Key("microsoft\\windows\\currentversion\\run", USER_ROOTS),
    Key("microsoft\\windows\\currentversion\\runonce", USER_ROOTS),
    Key("microsoft\\windows\\currentversion\\runservices", USER_ROOTS),
    Key("microsoft\\windows\\currentversion\\runservicesonce", USER_ROOTS),
    Key("microsoft\\windows\\currentversion\\policies\\explorer\\run", USER_ROOTS),
    # ATT&CK T1547.001 places RunOnceEx, and its subkeys such as 0001\Depend, in HKLM
    Key(
        "microsoft\\windows\\currentversion\\runonceex",
        frozenset({"HKEY_LOCAL_MACHINE"}),
        descendants=True,
        unknown_root=False,
    ),
)
WINLOGON = Key("microsoft\\windows nt\\currentversion\\winlogon", USER_ROOTS)
# ATT&CK T1547.004: Winlogon\Notify and its subkeys, and the Shell and Userinit values
WINLOGON_NOTIFY = Key(
    "microsoft\\windows nt\\currentversion\\winlogon\\notify", USER_ROOTS, descendants=True
)
WINLOGON_VALUES = frozenset({"shell", "userinit"})
KEY_WRITE_RIGHTS = winapi.KEY_SET_VALUE | winapi.GENERIC_WRITE | winapi.GENERIC_ALL
KEY_ACCESS_NAMES = {
    winapi.KEY_WRITE: "KEY_WRITE",
    winapi.KEY_ALL_ACCESS: "KEY_ALL_ACCESS",
    winapi.KEY_SET_VALUE: "KEY_SET_VALUE",
    winapi.GENERIC_WRITE: "GENERIC_WRITE",
    winapi.GENERIC_ALL: "GENERIC_ALL",
}


def _is(key: Key, rest: str) -> bool:
    """Whether a path below Software is the key (or, if allowed, one of its subkeys)."""
    return rest == key.path or (key.descendants and rest.startswith(key.path + "\\"))


def _below_software(key: Key, path: str) -> bool:
    return any(
        path.startswith(prefix) and _is(key, path[len(prefix) :])
        for prefix in ("software\\", "software\\wow6432node\\")
    )


def matched_key(args: Arguments, keys: tuple[Key, ...]) -> Key | None:
    """The key of `keys` that the call names, or None.

    With a predefined root the whole path must be that key; with an unknown root (a
    handle from another call) only the end of the subkey can be compared."""
    subkey = _text(args, "lpSubKey")
    if subkey is None:
        return None
    path = subkey.lower().rstrip("\\")
    root_fact = args.get("hKey")
    root = None if root_fact is None else root_fact.data.constant
    for key in keys:
        if root is None:
            if not key.unknown_root:
                continue
            tail = "\\" + path
            if tail.endswith("\\" + key.path) or (
                key.descendants and "\\" + key.path + "\\" in tail
            ):
                return key
        elif root in key.roots:
            if root == "HKEY_USERS":  # <SID>\Software\...
                user, _, rest = path.partition("\\")
                if user and _below_software(key, rest):
                    return key
            elif _below_software(key, path):
                return key
    return None


def _key_path(args: Arguments, keys: tuple[Key, ...]) -> str | None:
    """How the case names the key, if it is one of `keys`; the root is said or said unknown."""
    if matched_key(args, keys) is None:
        return None
    subkey = _text(args, "lpSubKey") or ""
    root_fact = args.get("hKey")
    root = None if root_fact is None else root_fact.data.constant
    if root is None:
        return f"{_quoted(subkey)}, bajo una clave que no se pudo determinar"
    return _quoted(f"{root}\\{subkey}")


def _access(value: int) -> str:
    known = KEY_ACCESS_NAMES.get(value)
    return f"samDesired = {value:#x}" + (f" ({known})" if known else "")


def _open_for_write(keys: tuple[Key, ...]) -> Callable[[str, Arguments], str | None]:
    def describe(function: str, args: Arguments) -> str | None:
        access = _integer(args, "samDesired")
        if access is None or not access & KEY_WRITE_RIGHTS:
            return None  # read-only, MAXIMUM_ALLOWED alone, or unknown
        path = _key_path(args, keys)
        return None if path is None else f"{path}, {_access(access)}"

    return describe


def _winlogon_value(function: str, args: Arguments) -> str | None:
    path = _key_path(args, (WINLOGON, WINLOGON_NOTIFY))
    if path is None:
        return None
    return _parts(path, _labelled("valor", _text(args, "lpValueName")))


def _winlogon_technique(function: str, args: Arguments) -> str | None:
    """T1547.004 only for the keys and values its definition names."""
    if matched_key(args, (WINLOGON_NOTIFY,)) is not None:
        return "T1547.004"
    value = _text(args, "lpValueName")
    if value is not None and value.lower() in WINLOGON_VALUES:
        return "T1547.004"
    return None


def _run_value(function: str, args: Arguments) -> str | None:
    path = _key_path(args, RUN_KEYS)
    if path is None:
        return None
    return _parts(path, _labelled("valor", _text(args, "lpValueName")))


# --- services and execution ----------------------------------------------------------


def _service(function: str, args: Arguments) -> str | None:
    service = _text(args, "lpServiceName")
    binary = _text(args, "lpBinaryPathName")
    if service is None and binary is None:
        return None
    start = _integer(args, "dwStartType")
    kind = _integer(args, "dwServiceType")
    return _parts(
        _labelled("servicio", service),
        _labelled("binario", binary),
        None if start is None else f"inicio {winapi.start_type(start)}",
        None if kind is None else f"tipo {winapi.service_type(kind)}",
    )


def _execution(function: str, args: Arguments) -> str | None:
    if function == "WinExec":
        return _labelled("orden", _text(args, "lpCmdLine"))
    if function.startswith("CreateProcess"):
        return _parts(
            _labelled("programa", _text(args, "lpApplicationName")),
            _labelled("línea de órdenes", _text(args, "lpCommandLine")),
        )
    target = _text(args, "lpFile")  # ShellExecute
    if target is None:
        return None
    return _parts(
        _labelled("destino", target),
        _labelled("parámetros", _text(args, "lpParameters")),
        _labelled("operación", _text(args, "lpOperation")),
    )


# Interpreters whose use is the mechanism of a technique. wscript and cscript are left
# out: they run VBScript (T1059.005) or JScript (T1059.007), and the call does not say
# which.
INTERPRETERS = {"cmd": "T1059.003", "powershell": "T1059.001", "pwsh": "T1059.001"}


def _first_token(command: str) -> str:
    command = command.lstrip()
    if command.startswith('"'):
        return command[1:].partition('"')[0]
    return command.split(maxsplit=1)[0] if command else ""


def program(function: str, args: Arguments) -> str | None:
    """The file name that the call runs, lowercase and without directory or ".exe"."""
    if function.startswith("ShellExecute"):
        path = _text(args, "lpFile")
    elif function == "WinExec":
        command = _text(args, "lpCmdLine")
        path = None if command is None else _first_token(command)
    else:  # CreateProcess: the application name, else the start of the command line
        path = _text(args, "lpApplicationName")
        if path is None:
            command = _text(args, "lpCommandLine")
            path = None if command is None else _first_token(command)
    if not path:
        return None
    base = path.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    return base.removesuffix(".exe")


def _interpreter(function: str, args: Arguments) -> str | None:
    return INTERPRETERS.get(program(function, args) or "")


# --- network -------------------------------------------------------------------------


def _download(function: str, args: Arguments) -> str | None:
    return _parts(
        _labelled("URL", _text(args, "szURL")), _labelled("archivo", _text(args, "szFileName"))
    )


def _port(value: int | None) -> str | None:
    if value is None:
        return None
    return "puerto predeterminado del servicio (0)" if value == 0 else f"puerto {value}"


def _destination(function: str, args: Arguments) -> str | None:
    if function.startswith("InternetOpenUrl"):
        return _labelled("URL", _text(args, "lpszUrl"))
    server = _text(args, "pswzServerName" if function == "WinHttpConnect" else "lpszServerName")
    if server is None:
        return None
    return _parts(_labelled("servidor", server), _port(_integer(args, "nServerPort")))


def _agent(function: str, args: Arguments) -> str | None:
    return _labelled(
        "agente", _text(args, "pszAgentW" if function == "WinHttpOpen" else "lpszAgent")
    )


# --- memory and processes ------------------------------------------------------------

ANY_PROCESS = "la función admite otro proceso; cuál, no se determina"


def _protection(value: int, allowed: tuple[int, ...], targets: str) -> str | None:
    """The name of an executable and writable protection, with its modifiers; None if the
    base protection is another one or an unknown bit is set. `targets` names the Control
    Flow Guard bit as the function's documentation does."""
    base, modifiers = value & 0xFF, value & ~0xFF
    if base not in allowed or modifiers & ~(winapi.PAGE_MODIFIER_MASK | winapi.PAGE_TARGETS):
        return None
    names = [winapi.PAGE_NAMES[base]]
    names += [text for bit, text in winapi.PAGE_MODIFIERS.items() if modifiers & bit]
    if modifiers & winapi.PAGE_TARGETS:
        names.append(targets)
    return " | ".join(names)


def _executable_writable(function: str, args: Arguments) -> str | None:
    allowed: tuple[int, ...]
    if function.startswith("VirtualAlloc"):
        # Learn: PAGE_EXECUTE_WRITECOPY is not supported by VirtualAlloc(Ex)
        value, allowed = _integer(args, "flProtect"), (winapi.PAGE_EXECUTE_READWRITE,)
        targets = "PAGE_TARGETS_INVALID"
    else:
        value = _integer(args, "flNewProtect")
        allowed = (winapi.PAGE_EXECUTE_READWRITE, winapi.PAGE_EXECUTE_WRITECOPY)
        targets = "PAGE_TARGETS_NO_UPDATE"  # Learn: the same bit, as VirtualProtect reads it
    shown = None if value is None else _protection(value, allowed, targets)
    if shown is None:
        return None
    return _parts(shown, ANY_PROCESS if function.endswith("Ex") else None)


def _process_access(function: str, args: Arguments) -> str | None:
    access = _integer(args, "dwDesiredAccess")
    if access is None:
        return None
    rights = [
        text
        for bit, text in (
            (winapi.PROCESS_VM_WRITE, "PROCESS_VM_WRITE"),
            (winapi.PROCESS_VM_OPERATION, "PROCESS_VM_OPERATION"),
        )
        if access & bit
    ]
    if not rights:
        return None
    if access == winapi.PROCESS_ALL_ACCESS:
        rights = ["PROCESS_ALL_ACCESS"]
    return f"dwDesiredAccess = {access:#x} ({', '.join(rights)}); no se determina qué proceso"


# --- files, synchronization and cryptography -----------------------------------------


def _on_reboot(function: str, args: Arguments) -> str | None:
    flags = _integer(args, "dwFlags")
    if flags is None or not flags & winapi.MOVEFILE_DELAY_UNTIL_REBOOT:
        return None
    return _parts(
        _labelled("origen", _text(args, "lpExistingFileName")),
        _labelled("destino", _text(args, "lpNewFileName")),
        f"dwFlags = {flags:#x}",
    )


def _mutex(function: str, args: Arguments) -> str | None:
    return _labelled("nombre", _text(args, "lpName"))


def _crypto(function: str, args: Arguments) -> str | None:
    if function == "BCryptOpenAlgorithmProvider":
        return _labelled("algoritmo", _text(args, "pszAlgId"))
    return _labelled("proveedor", _text(args, "szProvider"))


# --- catalog ---------------------------------------------------------------------------


def _aw(names: tuple[str, ...], reads: tuple[str, ...]) -> dict[str, tuple[str, ...]]:
    return {f"{base}{suffix}": reads for base in names for suffix in ("A", "W")}


EVIDENCE = ("capability.static", "code.call_argument", "code.import_call", "evidence.confidence")
REGISTRY_OPEN = ("hKey", "lpSubKey", "samDesired")

CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        "run_key_value",
        "persistence",
        "escribir un valor en una clave de arranque automático (Run)",
        _aw(("RegSetKeyValue",), ("hKey", "lpSubKey", "lpValueName")),
        _run_value,
        "Muchos instaladores y programas legítimos se registran así para arrancar con Windows.",
        ("api.family.registry", *EVIDENCE),
        "T1547.001",
    ),
    Capability(
        "run_key_open_write",
        "persistence",
        "abrir una clave de arranque automático (Run) con permiso para escribir en ella",
        _aw(("RegOpenKeyEx", "RegCreateKeyEx"), REGISTRY_OPEN),
        _open_for_write(RUN_KEYS),
        "Abrir la clave para escribir no escribe nada en ella; muchos instaladores y "
        "programas legítimos gestionan así su arranque con Windows.",
        ("api.family.registry", *EVIDENCE),
    ),
    Capability(
        "winlogon_open_write",
        "persistence",
        "abrir la clave Winlogon con permiso para escribir en ella",
        _aw(("RegOpenKeyEx", "RegCreateKeyEx"), REGISTRY_OPEN),
        _open_for_write((WINLOGON,)),
        "Abrir la clave para escribir no escribe nada en ella, ni dice qué valor cambiaría; "
        "componentes de Windows y programas de administración legítimos la usan.",
        ("api.family.registry", *EVIDENCE),
    ),
    Capability(
        "winlogon_value",
        "persistence",
        "escribir un valor en la clave Winlogon",
        _aw(("RegSetKeyValue",), ("hKey", "lpSubKey", "lpValueName")),
        _winlogon_value,
        "Componentes de Windows y programas de administración legítimos escriben en ella; "
        "solo los valores Shell y Userinit y la subclave Notify se usan para ejecutar "
        "programas al iniciar sesión.",
        ("api.family.registry", *EVIDENCE),
        _winlogon_technique,
    ),
    Capability(
        "service_create",
        "persistence",
        "crear un servicio de Windows",
        _aw(
            ("CreateService",),
            ("lpServiceName", "lpBinaryPathName", "dwServiceType", "dwStartType"),
        ),
        _service,
        "Instaladores, controladores y programas de administración legítimos crean servicios.",
        ("api.family.services", *EVIDENCE),
        "T1543.003",
    ),
    Capability(
        "command_execution",
        "execution",
        "ejecutar un programa o una orden, o pedir al shell de Windows que abra algo (un "
        "archivo, una URL o un elemento del sistema), cuyo nombre está en el código",
        {
            "WinExec": ("lpCmdLine",),
            **_aw(("CreateProcess",), ("lpApplicationName", "lpCommandLine")),
            **_aw(("ShellExecute",), ("lpOperation", "lpFile", "lpParameters")),
        },
        _execution,
        "Muchos programas legítimos lanzan otros programas o abren archivos. Además, "
        "Dissect nunca lee la línea de órdenes de CreateProcessW (tiene que estar en "
        "memoria escribible), así que no ver esta capacidad no demuestra que el código no "
        "lance procesos.",
        ("api.family.process_creation", *EVIDENCE),
        _interpreter,
    ),
    Capability(
        "download_to_file",
        "network",
        "descargar una URL a un archivo",
        _aw(("URLDownloadToFile",), ("szURL", "szFileName")),
        _download,
        "Actualizadores e instaladores legítimos descargan archivos; la llamada no dice qué "
        "contendría la descarga.",
        ("api.family.http", *EVIDENCE),
        "T1105",
    ),
    Capability(
        "network_destination",
        "network",
        "indicar un servidor o una URL de destino",
        {
            **_aw(("InternetConnect",), ("lpszServerName", "nServerPort")),
            **_aw(("InternetOpenUrl",), ("lpszUrl",)),
            "WinHttpConnect": ("pswzServerName", "nServerPort"),
        },
        _destination,
        "Un destino en el código no demuestra que haya conexión ni qué se enviaría; muchos "
        "programas legítimos contactan con sus servidores.",
        ("api.family.http", *EVIDENCE),
    ),
    Capability(
        "user_agent",
        "network",
        "declarar el agente de usuario de las conexiones a Internet",
        {**_aw(("InternetOpen",), ("lpszAgent",)), "WinHttpOpen": ("pszAgentW",)},
        _agent,
        "El agente lo elige el autor: no identifica el programa ni demuestra que haya conexiones.",
        ("api.family.http", *EVIDENCE),
    ),
    Capability(
        "executable_writable_memory",
        "memory",
        "reservar memoria o cambiar su protección para que sea ejecutable y escribible",
        {
            "VirtualAlloc": ("flProtect",),
            "VirtualAllocEx": ("flProtect",),
            "VirtualProtect": ("flNewProtect",),
            "VirtualProtectEx": ("flNewProtect",),
        },
        _executable_writable,
        "No es por sí sola inyección de código: compiladores JIT, intérpretes y protectores "
        "legítimos también lo hacen.",
        EVIDENCE,
    ),
    Capability(
        "process_memory_access",
        "memory",
        "abrir un proceso con derechos para modificar su memoria",
        {"OpenProcess": ("dwDesiredAccess",)},
        _process_access,
        "Depuradores, herramientas de diagnóstico y programas de seguridad legítimos piden "
        "estos derechos; el proceso puede ser el propio programa.",
        ("api.family.process_memory", *EVIDENCE),
    ),
    Capability(
        "move_on_reboot",
        "files",
        "mover, renombrar o borrar un archivo al reiniciar el equipo",
        _aw(("MoveFileEx",), ("lpExistingFileName", "lpNewFileName", "dwFlags")),
        _on_reboot,
        "Instaladores y actualizadores legítimos lo usan para reemplazar archivos que están "
        "en uso.",
        EVIDENCE,
    ),
    Capability(
        "named_mutex",
        "sync_crypto",
        "crear o abrir un mutex con nombre",
        {**_aw(("CreateMutex",), ("lpName",)), "OpenMutexW": ("lpName",)},
        _mutex,
        "Muchos programas legítimos usan un mutex con nombre, por ejemplo para no "
        "ejecutarse dos veces a la vez.",
        EVIDENCE,
    ),
    Capability(
        "crypto_algorithm",
        "sync_crypto",
        "abrir un algoritmo o un proveedor criptográfico por su nombre",
        {
            "BCryptOpenAlgorithmProvider": ("pszAlgId",),
            **_aw(("CryptAcquireContext",), ("szProvider",)),
        },
        _crypto,
        "Usar criptografía es habitual en programas legítimos (conexiones seguras, firmas, "
        "hashes); no dice qué datos se cifrarían.",
        ("api.family.crypto", *EVIDENCE),
    ),
)
BY_RULE = {capability.rule_id: capability for capability in CAPABILITIES}


def catalog_digest() -> str:
    """SHA-256 of the catalog's data and wording; a test pins it to CATALOG_ID."""
    content = {
        "id": CATALOG_ID,
        "api_catalog": API_CATALOG,
        "run_keys": RUN_KEYS,
        "winlogon": [WINLOGON, WINLOGON_NOTIFY, sorted(WINLOGON_VALUES)],
        "benign": [BENIGN_FILES, BENIGN],
        "key_write_rights": KEY_WRITE_RIGHTS,
        "techniques": TECHNIQUES,
        "interpreters": INTERPRETERS,
        "technique_of": {
            c.id: c.technique if not callable(c.technique) else c.technique.__name__
            for c in CAPABILITIES
        },
        "capabilities": [
            [c.id, c.tactic, c.template, c.not_proven, c.reads, c.glossary_ids]
            for c in CAPABILITIES
        ],
    }
    text = json.dumps(content, sort_keys=True, default=sorted)  # frozensets, in order
    return hashlib.sha256(text.encode()).hexdigest()


# --- matching and the explanation rule -----------------------------------------------


@dataclass(frozen=True)
class Case:
    call: ApiCallEvidence
    arguments: tuple[CallArgumentEvidence, ...]  # all the call's published arguments
    function: str
    details: str
    technique: str | None

    @property
    def cited(self) -> tuple[Evidence, ...]:
        return (self.call, *self.arguments)


def cases(capability: Capability, report: Report) -> list[Case]:
    """Every call of the report that meets the condition, in report order."""
    facts = {fact.id: fact for fact in report.evidence}
    arguments: dict[str, list[CallArgumentEvidence]] = {}
    for fact in report.evidence:
        if isinstance(fact, CallArgumentEvidence):
            arguments.setdefault(fact.provenance.evidence_ids[0], []).append(fact)
    found = []
    for fact in report.evidence:
        if not isinstance(fact, ApiCallEvidence):
            continue
        target = facts.get(fact.provenance.evidence_ids[0])
        if not isinstance(target, ImportEvidence) or target.data.function is None:
            continue
        function = name(target.data.function)
        if function not in capability.reads:
            continue
        published = tuple(arguments.get(fact.id, ()))
        args = {a.data.name: a for a in published}
        details = capability.describe(function, args)
        if details is not None:
            technique = capability.technique_of(function, args)
            found.append(Case(fact, published, function, details, technique))
    return found


def derive(capability: Capability) -> Callable[[tuple[Evidence, ...], Report], Derived | None]:
    def rule(cited: tuple[Evidence, ...], report: Report) -> Derived | None:
        found = cases(capability, report)
        expected = tuple(fact.id for case in found for fact in case.cited)
        if not found or tuple(fact.id for fact in cited) != expected:
            return None  # every case of the report, each with all its arguments, in order
        shown = tuple(
            f"{hexadecimal(case.call.location.rva or 0)} {case.function}: {case.details}"
            + (f" ({case.technique})" if case.technique else "")
            for case in found[:CASES_SHOWN]
        )
        if len(found) > CASES_SHOWN:
            shown += (f"y {number(len(found) - CASES_SHOWN)} más",)
        slots: Slots = {
            "count": number(len(found)),
            "noun": "llamada" if len(found) == 1 else "llamadas",
            "cases": shown,
        }
        techniques = tuple(dict.fromkeys(case.technique for case in found if case.technique))
        if not techniques:
            return slots, capability.glossary_ids
        slots["techniques"] = tuple(f"{t} ({TECHNIQUES[t]})" for t in techniques)
        entries = ("attack.technique", *(technique_entry(t) for t in techniques))
        return slots, (*capability.glossary_ids, *entries)

    return rule
