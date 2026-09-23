"""Curated families of Windows API names, for didactic grouping of imports only.

Membership says "this imported name is on the list", never "the sample does this".
Names are matched exactly; for functions with ANSI and wide variants both the A and
W names are listed. Imports by ordinal cannot be matched and are not guessed.
Changing the lists requires a new FAMILIES_ID and a new benign-prevalence measurement
(design of Phase 3, section 6.3).
"""

import hashlib
import json

FAMILIES_ID = "dissect-api-families-v1"
FAMILIES_SHA256 = "0778e9479d2841a8300cdbab212e32716f22354a0ddc598dc1caa7ac21232f52"


def _aw(*names: str) -> tuple[str, ...]:
    return tuple(f"{name}{suffix}" for name in names for suffix in ("A", "W"))


# family id -> (Spanish label, exact imported names)
FAMILIES: dict[str, tuple[str, tuple[str, ...]]] = {
    "process_memory": (
        "memoria de otros procesos",
        (
            "OpenProcess",
            "VirtualAllocEx",
            "VirtualProtectEx",
            "ReadProcessMemory",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "CreateRemoteThreadEx",
        ),
    ),
    "dynamic_loading": (
        "carga dinámica de bibliotecas",
        (*_aw("LoadLibrary", "LoadLibraryEx", "GetModuleHandle"), "GetProcAddress"),
    ),
    "process_creation": (
        "creación de procesos",
        (*_aw("CreateProcess", "CreateProcessAsUser", "ShellExecute", "ShellExecuteEx"), "WinExec"),
    ),
    "http": (
        "HTTP y descargas",
        (
            *_aw("InternetOpen", "InternetOpenUrl", "InternetConnect", "HttpOpenRequest"),
            *_aw("HttpSendRequest", "URLDownloadToFile"),
            "InternetReadFile",
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpOpenRequest",
            "WinHttpSendRequest",
            "WinHttpReadData",
        ),
    ),
    "sockets": (
        "sockets de red",
        (
            "WSAStartup",
            "socket",
            "connect",
            "bind",
            "listen",
            "accept",
            "send",
            "recv",
            "getaddrinfo",
            "gethostbyname",
            *_aw("WSASocket"),
        ),
    ),
    "registry": (
        "registro de Windows",
        _aw(
            "RegOpenKeyEx",
            "RegCreateKeyEx",
            "RegSetValueEx",
            "RegQueryValueEx",
            "RegDeleteKey",
            "RegDeleteValue",
            "RegEnumKeyEx",
        ),
    ),
    "services": (
        "servicios de Windows",
        (
            *_aw("OpenSCManager", "CreateService", "OpenService", "StartService"),
            *_aw("ChangeServiceConfig"),
            "ControlService",
            "DeleteService",
        ),
    ),
    "crypto": (
        "criptografía",
        (
            *_aw("CryptAcquireContext"),
            "CryptEncrypt",
            "CryptDecrypt",
            "CryptGenKey",
            "CryptImportKey",
            "BCryptOpenAlgorithmProvider",
            "BCryptGenerateSymmetricKey",
            "BCryptEncrypt",
            "BCryptDecrypt",
        ),
    ),
    "debugger_checks": (
        "comprobación de depuradores",
        (
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            *_aw("OutputDebugString"),
            "NtQueryInformationProcess",
        ),
    ),
}


# Share of 55,035 benign PE files (System32, Program Files, Program Files (x86)) that
# import at least one name of the family, measured on 2026-09-23 with these lists.
PREVALENCE: dict[str, str] = {
    "process_memory": "3,7 %",
    "dynamic_loading": "34,8 %",
    "process_creation": "4,8 %",
    "http": "1,0 %",
    "sockets": "2,1 %",
    "registry": "10,6 %",
    "services": "1,7 %",
    "crypto": "3,0 %",
    "debugger_checks": "32,2 %",
}


def families_digest() -> str:
    canonical = json.dumps(
        {"id": FAMILIES_ID, "families": {k: list(v[1]) for k, v in FAMILIES.items()}},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def family_of(function: str) -> str | None:
    for family, (_, names) in FAMILIES.items():
        if function in names:
            return family
    return None
