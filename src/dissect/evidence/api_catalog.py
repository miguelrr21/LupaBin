"""Catalog `dissect-api-semantics-v3`: which parameters of which imported functions
Dissect interprets, with their type (design section 4).

Each entry's arity, parameter names and exporting DLLs were checked against the page
published on Microsoft Learn (the URL is kept with the entry; the DLLs are the page's
`api_location` list). Parameters that are not listed, such as outputs, are never
read. Changing an entry requires checking it again.
"""

import hashlib
import json
from typing import Literal, NamedTuple

ParameterType = Literal["hkey", "string", "integer"]
Encoding = Literal["ascii", "utf-16-le"]


class Parameter(NamedTuple):
    position: int  # 0-based position in the signature
    name: str
    type: ParameterType
    bits: int | None  # an integer's width (read modulo 2**bits); None: pointer-sized


class Function(NamedTuple):
    name: str
    arity: int
    encoding: Encoding  # of its string parameters
    parameters: tuple[Parameter, ...]
    dlls: frozenset[str]  # lowercase names of the DLLs that export it
    source: str


CATALOG_ID = "dissect-api-semantics-v3"

# The predefined keys that Microsoft Learn lists for the hKey parameter of the
# functions below, with their values in winreg.h (Windows SDK 10.0.26100.0):
# `((HKEY)(ULONG_PTR)((LONG)0x80000001))`, so in x64 the value is sign-extended.
# winreg.h defines other predefined keys (0x80000004, 0x80000006, 0x80000007,
# 0x80000050, 0x80000060) that these pages do not list for hKey: Dissect abstains.
HKEYS = {
    0x80000000: "HKEY_CLASSES_ROOT",
    0x80000001: "HKEY_CURRENT_USER",
    0x80000002: "HKEY_LOCAL_MACHINE",
    0x80000003: "HKEY_USERS",
    0x80000005: "HKEY_CURRENT_CONFIG",
}


def hkey_name(value: int, bits: int) -> str | None:
    """The predefined key a register or stack value holds, or None.

    x86: the 32-bit constant. x64: only its sign extension, which is the value the
    header defines; a zero-extended 0x80000001 is a different pointer.
    """
    if bits == 64:
        if value >> 32 != 0xFFFFFFFF:
            return None
        value &= 0xFFFFFFFF
    elif value >> 32:
        return None
    return HKEYS.get(value)


_LEARN = "https://learn.microsoft.com/en-us/windows/win32/api/"
_REGISTRY_DLLS = frozenset(
    {
        "advapi32.dll",
        "kernelbase.dll",
        "minkernelbase.dll",
        "api-ms-win-core-registry-l1-1-0.dll",
        "api-ms-win-core-registry-l1-1-1.dll",
        "api-ms-win-core-registry-l1-1-2.dll",
        "api-ms-win-core-localregistry-l1-1-0.dll",
        "api-ms-win-downlevel-advapi32-l1-1-0.dll",
        "api-ms-win-downlevel-advapi32-l1-1-1.dll",
    }
)


def _registry_open(name: str, encoding: Encoding, dlls: frozenset[str]) -> Function:
    return Function(
        name,
        5,  # hKey, lpSubKey, ulOptions, samDesired, phkResult
        encoding,
        (
            Parameter(0, "hKey", "hkey", None),
            Parameter(1, "lpSubKey", "string", None),
            Parameter(3, "samDesired", "integer", 32),  # REGSAM, a DWORD
        ),
        dlls,
        _LEARN + f"winreg/nf-winreg-{name.lower()}",
    )


def _registry_create(name: str, encoding: Encoding) -> Function:
    return Function(
        name,
        # hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired,
        # lpSecurityAttributes, phkResult, lpdwDisposition
        9,
        encoding,
        (
            Parameter(0, "hKey", "hkey", None),
            Parameter(1, "lpSubKey", "string", None),
            Parameter(4, "dwOptions", "integer", 32),  # DWORD; on the stack in x64
            Parameter(5, "samDesired", "integer", 32),  # REGSAM; on the stack in x64
        ),
        _REGISTRY_DLLS,
        _LEARN + f"winreg/nf-winreg-{name.lower()}",
    )


_LIBRARY_LOADER_DLLS = frozenset(
    {
        "kernel32.dll",
        "kernelbase.dll",
        "minkernelbase.dll",
        "vertdll.dll",
        "api-ms-win-core-libraryloader-l1-1-0.dll",
        "api-ms-win-core-libraryloader-l1-1-1.dll",
        "api-ms-win-core-libraryloader-l1-2-0.dll",
        "api-ms-win-core-libraryloader-l1-2-1.dll",
        "api-ms-win-core-libraryloader-l1-2-2.dll",
        "api-ms-win-core-libraryloader-l1-2-3.dll",
        "api-ms-win-downlevel-kernel32-l1-1-0.dll",
    }
)

# GetProcAddress(hModule, lpProcName): the name is always ANSI. Learn: lpProcName may
# instead be an ordinal in the low-order word, which is not an address in the image,
# so the string type abstains on it.
_GET_PROC_ADDRESS = Function(
    "GetProcAddress",
    2,
    "ascii",
    (Parameter(1, "lpProcName", "string", None),),
    _LIBRARY_LOADER_DLLS,
    _LEARN + "libloaderapi/nf-libloaderapi-getprocaddress",
)


FUNCTIONS: dict[str, Function] = {
    function.name: function
    for function in (
        # the ANSI page also lists kernel32.dll ("on legacy versions of Windows")
        _registry_open("RegOpenKeyExA", "ascii", _REGISTRY_DLLS | {"kernel32.dll"}),
        _registry_open("RegOpenKeyExW", "utf-16-le", _REGISTRY_DLLS),
        _registry_create("RegCreateKeyExA", "ascii"),
        _registry_create("RegCreateKeyExW", "utf-16-le"),
        _GET_PROC_ADDRESS,
    )
}


def lookup(dll: bytes, function: bytes) -> Function | None:
    """The catalog entry for an import, by exact function name and exporting DLL."""
    try:
        entry = FUNCTIONS.get(function.decode("ascii"))
        library = dll.decode("ascii").lower()
    except UnicodeDecodeError:
        return None
    return entry if entry is not None and library in entry.dlls else None


def digest() -> str:
    """SHA-256 of the catalog's content; a test pins it to CATALOG_ID, so changing an
    entry requires a new catalog version."""
    content = {
        "id": CATALOG_ID,
        "hkeys": {hex(value): name for value, name in HKEYS.items()},
        "functions": [
            [f.name, f.arity, f.encoding, [list(p) for p in f.parameters], sorted(f.dlls), f.source]
            for f in FUNCTIONS.values()
        ],
    }
    return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()
