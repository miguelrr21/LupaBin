"""Catalog `dissect-api-semantics-v4`: which parameters of which imported functions
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


CATALOG_ID = "dissect-api-semantics-v4"

# The predefined keys that every Microsoft Learn page below lists for its hKey
# parameter, with their values in winreg.h (Windows SDK 10.0.26100.0):
# `((HKEY)(ULONG_PTR)((LONG)0x80000001))`, so in x64 the value is sign-extended.
# Some pages list more (the HKEY_PERFORMANCE_* keys for RegQueryValueEx, RegSetValueEx
# and RegGetValue), and winreg.h defines others (0x80000006, 0x80000007): Dissect
# abstains on all of those.
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


# Catalog v4 (2026-09-24): the rest of design section 4. Each entry's parameter names
# and positions were checked against the source of its Learn page (MicrosoftDocs/
# sdk-api; URLDownloadToFile, in the archived Internet Explorer reference, against
# the page itself), its widths against the Windows SDK 10.0.26100.0 prototype, and its
# DLLs are the page's api_location. OpenMutexA has no page of its own: it is left out.
# Handles, structures and SIZE_T sizes are not interpreted.
_DLLS_1 = frozenset(
    [
        "advapi32.dll",
        "api-ms-win-core-localregistry-l1-1-0.dll",
        "api-ms-win-core-registry-l1-1-0.dll",
        "api-ms-win-core-registry-l1-1-1.dll",
        "api-ms-win-core-registry-l1-1-2.dll",
        "api-ms-win-downlevel-advapi32-l1-1-0.dll",
        "api-ms-win-downlevel-advapi32-l1-1-1.dll",
        "kernelbase.dll",
        "minkernelbase.dll",
    ]
)
_DLLS_2 = frozenset(
    [
        "advapi32.dll",
        "api-ms-win-core-localregistry-l1-1-0.dll",
        "api-ms-win-core-registry-l1-1-0.dll",
        "api-ms-win-core-registry-l1-1-1.dll",
        "api-ms-win-core-registry-l1-1-2.dll",
        "api-ms-win-downlevel-advapi32-l1-1-0.dll",
        "api-ms-win-downlevel-advapi32-l1-1-1.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "minkernelbase.dll",
    ]
)
_DLLS_3 = frozenset(
    [
        "advapi32.dll",
        "advapi32legacy.dll",
        "api-ms-win-core-registry-l2-1-0.dll",
        "api-ms-win-core-registry-l2-2-0.dll",
        "api-ms-win-core-registry-l2-3-0.dll",
        "api-ms-win-deprecated-apis-advapi-l1-1-0.dll",
        "kernel32.dll",
    ]
)
_DLLS_4 = frozenset(
    [
        "advapi32.dll",
        "advapi32legacy.dll",
        "api-ms-win-core-registry-l2-1-0.dll",
        "api-ms-win-core-registry-l2-2-0.dll",
        "api-ms-win-core-registry-l2-3-0.dll",
        "api-ms-win-deprecated-apis-advapi-l1-1-0.dll",
    ]
)
_DLLS_5 = frozenset(
    [
        "advapi32.dll",
        "advapi32legacy.dll",
        "api-ms-win-core-registry-l1-1-1.dll",
        "api-ms-win-core-registry-l1-1-2.dll",
        "api-ms-win-core-registry-l2-1-0.dll",
        "kernelbase.dll",
        "minkernelbase.dll",
    ]
)
_DLLS_6 = frozenset(
    [
        "advapi32.dll",
        "advapi32legacy.dll",
        "api-ms-win-core-registry-l2-1-0.dll",
        "api-ms-win-core-registry-l2-2-0.dll",
        "api-ms-win-core-registry-l2-3-0.dll",
    ]
)
_DLLS_7 = frozenset(
    [
        "advapi32.dll",
        "api-ms-win-downlevel-advapi32-l2-1-0.dll",
        "api-ms-win-downlevel-advapi32-l2-1-1.dll",
        "api-ms-win-service-management-l1-1-0.dll",
        "api-ms-win-service-winsvc-l1-1-0.dll",
        "api-ms-win-service-winsvc-l1-2-0.dll",
        "sechost.dll",
    ]
)
_DLLS_8 = frozenset(
    [
        "api-ms-win-core-processthreads-l1-1-0.dll",
        "api-ms-win-core-processthreads-l1-1-1.dll",
        "api-ms-win-core-processthreads-l1-1-2.dll",
        "api-ms-win-core-processthreads-l1-1-3.dll",
        "api-ms-win-core-processthreads-l1-1-4.dll",
        "api-ms-win-core-processthreads-l1-1-5.dll",
        "api-ms-win-core-processthreads-l1-1-6.dll",
        "api-ms-win-core-processthreads-l1-1-7.dll",
        "api-ms-win-core-processthreads-l1-1-8.dll",
        "api-ms-win-downlevel-kernel32-l1-1-0.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "minkernelbase.dll",
    ]
)
_DLLS_9 = frozenset(["kernel32.dll"])
_DLLS_10 = frozenset(
    [
        "ext-ms-win-appmodel-shellexecute-l1-1-0.dll",
        "ext-ms-win-shell-shell32-l1-1-0.dll",
        "ext-ms-win-shell-shell32-l1-2-0.dll",
        "ext-ms-win-shell-shell32-l1-2-1.dll",
        "ext-ms-win-shell-shell32-l1-2-2.dll",
        "ext-ms-win-shell-shell32-l1-2-3.dll",
        "ext-ms-win-shell-shell32-l1-3-0.dll",
        "shell32.dll",
    ]
)
_DLLS_11 = frozenset(
    [
        "api-ms-win-core-processthreads-l1-1-1.dll",
        "api-ms-win-core-processthreads-l1-1-2.dll",
        "api-ms-win-core-processthreads-l1-1-3.dll",
        "api-ms-win-core-processthreads-l1-1-4.dll",
        "api-ms-win-core-processthreads-l1-1-5.dll",
        "api-ms-win-core-processthreads-l1-1-6.dll",
        "api-ms-win-core-processthreads-l1-1-7.dll",
        "api-ms-win-core-processthreads-l1-1-8.dll",
        "api-ms-win-core-synch-l1-1-0.dll",
        "api-ms-win-downlevel-kernel32-l1-1-0.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "minkernelbase.dll",
    ]
)
_DLLS_12 = frozenset(
    [
        "api-ms-win-core-kernel32-legacy-l1-1-0.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-1.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-2.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-3.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-4.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-5.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-6.dll",
        "api-ms-win-core-libraryloader-l1-2-1.dll",
        "api-ms-win-core-libraryloader-l1-2-2.dll",
        "api-ms-win-core-libraryloader-l1-2-3.dll",
        "api-ms-win-downlevel-kernel32-l2-1-0.dll",
        "kernel32.dll",
        "kernel32legacy.dll",
        "kernelbase.dll",
        "minkernelbase.dll",
    ]
)
_DLLS_13 = frozenset(
    [
        "api-ms-win-core-libraryloader-l1-1-0.dll",
        "api-ms-win-core-libraryloader-l1-1-1.dll",
        "api-ms-win-core-libraryloader-l1-2-0.dll",
        "api-ms-win-core-libraryloader-l1-2-1.dll",
        "api-ms-win-core-libraryloader-l1-2-2.dll",
        "api-ms-win-core-libraryloader-l1-2-3.dll",
        "api-ms-win-downlevel-kernel32-l1-1-0.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "minkernelbase.dll",
    ]
)
_DLLS_14 = frozenset(
    [
        "api-ms-win-core-file-l1-1-0.dll",
        "api-ms-win-core-file-l1-2-0.dll",
        "api-ms-win-core-file-l1-2-1.dll",
        "api-ms-win-core-file-l1-2-2.dll",
        "api-ms-win-core-file-l1-2-3.dll",
        "api-ms-win-core-file-l1-2-4.dll",
        "api-ms-win-core-file-l1-2-5.dll",
        "api-ms-win-downlevel-kernel32-l1-1-0.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "minkernelbase.dll",
    ]
)
_DLLS_15 = frozenset(
    [
        "api-ms-win-core-file-l2-1-2.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-0.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-1.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-2.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-3.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-4.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-5.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-6.dll",
        "api-ms-win-downlevel-kernel32-l2-1-0.dll",
        "kernel32.dll",
        "kernel32legacy.dll",
        "kernelbase.dll",
    ]
)
_DLLS_16 = frozenset(
    [
        "api-ms-win-core-file-l2-1-2.dll",
        "api-ms-win-core-file-l2-1-3.dll",
        "api-ms-win-core-file-l2-1-4.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-0.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-1.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-2.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-3.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-4.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-5.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-6.dll",
        "api-ms-win-downlevel-kernel32-l2-1-0.dll",
        "kernel32.dll",
        "kernel32legacy.dll",
        "kernelbase.dll",
    ]
)
_DLLS_17 = frozenset(
    [
        "api-ms-win-core-kernel32-legacy-l1-1-0.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-1.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-2.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-3.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-4.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-5.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-6.dll",
        "api-ms-win-downlevel-kernel32-l2-1-0.dll",
        "kernel32.dll",
        "kernel32legacy.dll",
    ]
)
_DLLS_18 = frozenset(
    [
        "api-ms-win-core-file-l2-1-0.dll",
        "api-ms-win-core-file-l2-1-1.dll",
        "api-ms-win-core-file-l2-1-2.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-0.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-1.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-2.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-3.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-4.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-5.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-6.dll",
        "api-ms-win-downlevel-kernel32-l1-1-0.dll",
        "api-ms-win-downlevel-kernel32-l2-1-0.dll",
        "kernel32.dll",
        "kernel32legacy.dll",
        "kernelbase.dll",
    ]
)
_DLLS_19 = frozenset(
    [
        "api-ms-win-core-file-l2-1-0.dll",
        "api-ms-win-core-file-l2-1-1.dll",
        "api-ms-win-core-file-l2-1-2.dll",
        "api-ms-win-core-file-l2-1-3.dll",
        "api-ms-win-core-file-l2-1-4.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-0.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-1.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-2.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-3.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-4.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-5.dll",
        "api-ms-win-downlevel-kernel32-l1-1-0.dll",
        "api-ms-win-downlevel-kernel32-l2-1-0.dll",
        "kernel32.dll",
        "kernel32legacy.dll",
        "kernelbase.dll",
    ]
)
_DLLS_20 = frozenset(["wininet.dll"])
_DLLS_21 = frozenset(["urlmon.dll"])
_DLLS_22 = frozenset(["winhttp.dll"])
_DLLS_23 = frozenset(
    [
        "api-ms-win-core-synch-l1-1-0.dll",
        "api-ms-win-core-synch-l1-2-0.dll",
        "api-ms-win-core-synch-l1-2-1.dll",
        "api-ms-win-downlevel-kernel32-l1-1-0.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "minkernelbase.dll",
    ]
)
_DLLS_24 = frozenset(
    [
        "api-ms-win-core-kernel32-legacy-l1-1-2.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-3.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-4.dll",
        "api-ms-win-core-kernel32-legacy-l1-1-5.dll",
        "api-ms-win-core-synch-ansi-l1-1-0.dll",
        "api-ms-win-core-synch-l1-1-0.dll",
        "api-ms-win-core-synch-l1-2-0.dll",
        "api-ms-win-core-synch-l1-2-1.dll",
        "api-ms-win-downlevel-kernel32-l1-1-0.dll",
        "kernel32.dll",
        "kernel32legacy.dll",
        "kernelbase.dll",
        "minkernelbase.dll",
    ]
)
_DLLS_25 = frozenset(
    [
        "api-ms-win-core-memory-l1-1-0.dll",
        "api-ms-win-core-memory-l1-1-1.dll",
        "api-ms-win-core-memory-l1-1-2.dll",
        "api-ms-win-core-memory-l1-1-3.dll",
        "api-ms-win-core-memory-l1-1-4.dll",
        "api-ms-win-core-memory-l1-1-5.dll",
        "api-ms-win-core-memory-l1-1-6.dll",
        "api-ms-win-core-memory-l1-1-7.dll",
        "api-ms-win-core-memory-l1-1-8.dll",
        "api-ms-win-core-memory-l1-1-9.dll",
        "api-ms-win-downlevel-kernel32-l1-1-0.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "minkernelbase.dll",
        "vertdll.dll",
    ]
)
_DLLS_26 = frozenset(
    [
        "api-ms-win-core-memory-l1-1-0.dll",
        "api-ms-win-core-memory-l1-1-1.dll",
        "api-ms-win-core-memory-l1-1-2.dll",
        "api-ms-win-core-memory-l1-1-3.dll",
        "api-ms-win-core-memory-l1-1-4.dll",
        "api-ms-win-core-memory-l1-1-5.dll",
        "api-ms-win-core-memory-l1-1-6.dll",
        "api-ms-win-core-memory-l1-1-7.dll",
        "api-ms-win-core-memory-l1-1-8.dll",
        "api-ms-win-core-memory-l1-1-9.dll",
        "api-ms-win-downlevel-kernel32-l1-1-0.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "minkernelbase.dll",
    ]
)
_DLLS_27 = frozenset(["advapi32.dll", "api-ms-win-security-cryptoapi-l1-1-0.dll", "cryptsp.dll"])
_DLLS_28 = frozenset(["bcrypt.dll", "ksecdd.sys"])

_V4 = (
    Function(
        "RegSetValueExA",
        6,
        "ascii",
        (
            Parameter(0, "hKey", "hkey", None),
            Parameter(1, "lpValueName", "string", None),
            Parameter(3, "dwType", "integer", 32),
        ),
        _DLLS_1,
        _LEARN + "winreg/nf-winreg-regsetvalueexa",
    ),
    Function(
        "RegSetValueExW",
        6,
        "utf-16-le",
        (
            Parameter(0, "hKey", "hkey", None),
            Parameter(1, "lpValueName", "string", None),
            Parameter(3, "dwType", "integer", 32),
        ),
        _DLLS_1,
        _LEARN + "winreg/nf-winreg-regsetvalueexw",
    ),
    Function(
        "RegQueryValueExA",
        6,
        "ascii",
        (
            Parameter(0, "hKey", "hkey", None),
            Parameter(1, "lpValueName", "string", None),
        ),
        _DLLS_2,
        _LEARN + "winreg/nf-winreg-regqueryvalueexa",
    ),
    Function(
        "RegQueryValueExW",
        6,
        "utf-16-le",
        (
            Parameter(0, "hKey", "hkey", None),
            Parameter(1, "lpValueName", "string", None),
        ),
        _DLLS_2,
        _LEARN + "winreg/nf-winreg-regqueryvalueexw",
    ),
    Function(
        "RegDeleteValueA",
        2,
        "ascii",
        (
            Parameter(0, "hKey", "hkey", None),
            Parameter(1, "lpValueName", "string", None),
        ),
        _DLLS_1,
        _LEARN + "winreg/nf-winreg-regdeletevaluea",
    ),
    Function(
        "RegDeleteValueW",
        2,
        "utf-16-le",
        (
            Parameter(0, "hKey", "hkey", None),
            Parameter(1, "lpValueName", "string", None),
        ),
        _DLLS_1,
        _LEARN + "winreg/nf-winreg-regdeletevaluew",
    ),
    Function(
        "RegDeleteKeyA",
        2,
        "ascii",
        (
            Parameter(0, "hKey", "hkey", None),
            Parameter(1, "lpSubKey", "string", None),
        ),
        _DLLS_3,
        _LEARN + "winreg/nf-winreg-regdeletekeya",
    ),
    Function(
        "RegDeleteKeyW",
        2,
        "utf-16-le",
        (
            Parameter(0, "hKey", "hkey", None),
            Parameter(1, "lpSubKey", "string", None),
        ),
        _DLLS_4,
        _LEARN + "winreg/nf-winreg-regdeletekeyw",
    ),
    Function(
        "RegGetValueA",
        7,
        "ascii",
        (
            Parameter(0, "hkey", "hkey", None),
            Parameter(1, "lpSubKey", "string", None),
            Parameter(2, "lpValue", "string", None),
            Parameter(3, "dwFlags", "integer", 32),
        ),
        _DLLS_1,
        _LEARN + "winreg/nf-winreg-reggetvaluea",
    ),
    Function(
        "RegGetValueW",
        7,
        "utf-16-le",
        (
            Parameter(0, "hkey", "hkey", None),
            Parameter(1, "lpSubKey", "string", None),
            Parameter(2, "lpValue", "string", None),
            Parameter(3, "dwFlags", "integer", 32),
        ),
        _DLLS_1,
        _LEARN + "winreg/nf-winreg-reggetvaluew",
    ),
    Function(
        "RegSetKeyValueA",
        6,
        "ascii",
        (
            Parameter(0, "hKey", "hkey", None),
            Parameter(1, "lpSubKey", "string", None),
            Parameter(2, "lpValueName", "string", None),
            Parameter(3, "dwType", "integer", 32),
        ),
        _DLLS_5,
        _LEARN + "winreg/nf-winreg-regsetkeyvaluea",
    ),
    Function(
        "RegSetKeyValueW",
        6,
        "utf-16-le",
        (
            Parameter(0, "hKey", "hkey", None),
            Parameter(1, "lpSubKey", "string", None),
            Parameter(2, "lpValueName", "string", None),
            Parameter(3, "dwType", "integer", 32),
        ),
        _DLLS_5,
        _LEARN + "winreg/nf-winreg-regsetkeyvaluew",
    ),
    Function(
        "RegOpenKeyA",
        3,
        "ascii",
        (
            Parameter(0, "hKey", "hkey", None),
            Parameter(1, "lpSubKey", "string", None),
        ),
        _DLLS_6,
        _LEARN + "winreg/nf-winreg-regopenkeya",
    ),
    Function(
        "RegOpenKeyW",
        3,
        "utf-16-le",
        (
            Parameter(0, "hKey", "hkey", None),
            Parameter(1, "lpSubKey", "string", None),
        ),
        _DLLS_6,
        _LEARN + "winreg/nf-winreg-regopenkeyw",
    ),
    Function(
        "RegCreateKeyA",
        3,
        "ascii",
        (
            Parameter(0, "hKey", "hkey", None),
            Parameter(1, "lpSubKey", "string", None),
        ),
        _DLLS_6,
        _LEARN + "winreg/nf-winreg-regcreatekeya",
    ),
    Function(
        "RegCreateKeyW",
        3,
        "utf-16-le",
        (
            Parameter(0, "hKey", "hkey", None),
            Parameter(1, "lpSubKey", "string", None),
        ),
        _DLLS_6,
        _LEARN + "winreg/nf-winreg-regcreatekeyw",
    ),
    Function(
        "CreateServiceA",
        13,
        "ascii",
        (
            Parameter(1, "lpServiceName", "string", None),
            Parameter(2, "lpDisplayName", "string", None),
            Parameter(3, "dwDesiredAccess", "integer", 32),
            Parameter(4, "dwServiceType", "integer", 32),
            Parameter(5, "dwStartType", "integer", 32),
            Parameter(7, "lpBinaryPathName", "string", None),
        ),
        _DLLS_7,
        _LEARN + "winsvc/nf-winsvc-createservicea",
    ),
    Function(
        "CreateServiceW",
        13,
        "utf-16-le",
        (
            Parameter(1, "lpServiceName", "string", None),
            Parameter(2, "lpDisplayName", "string", None),
            Parameter(3, "dwDesiredAccess", "integer", 32),
            Parameter(4, "dwServiceType", "integer", 32),
            Parameter(5, "dwStartType", "integer", 32),
            Parameter(7, "lpBinaryPathName", "string", None),
        ),
        _DLLS_7,
        _LEARN + "winsvc/nf-winsvc-createservicew",
    ),
    Function(
        "OpenServiceA",
        3,
        "ascii",
        (
            Parameter(1, "lpServiceName", "string", None),
            Parameter(2, "dwDesiredAccess", "integer", 32),
        ),
        _DLLS_7,
        _LEARN + "winsvc/nf-winsvc-openservicea",
    ),
    Function(
        "OpenServiceW",
        3,
        "utf-16-le",
        (
            Parameter(1, "lpServiceName", "string", None),
            Parameter(2, "dwDesiredAccess", "integer", 32),
        ),
        _DLLS_7,
        _LEARN + "winsvc/nf-winsvc-openservicew",
    ),
    Function(
        "CreateProcessA",
        10,
        "ascii",
        (
            Parameter(0, "lpApplicationName", "string", None),
            Parameter(1, "lpCommandLine", "string", None),
            Parameter(5, "dwCreationFlags", "integer", 32),
        ),
        _DLLS_8,
        _LEARN + "processthreadsapi/nf-processthreadsapi-createprocessa",
    ),
    Function(
        "CreateProcessW",
        10,
        "utf-16-le",
        (
            Parameter(0, "lpApplicationName", "string", None),
            Parameter(1, "lpCommandLine", "string", None),
            Parameter(5, "dwCreationFlags", "integer", 32),
        ),
        _DLLS_8,
        _LEARN + "processthreadsapi/nf-processthreadsapi-createprocessw",
    ),
    Function(
        "WinExec",
        2,
        "ascii",
        (
            Parameter(0, "lpCmdLine", "string", None),
            Parameter(1, "uCmdShow", "integer", 32),
        ),
        _DLLS_9,
        _LEARN + "winbase/nf-winbase-winexec",
    ),
    Function(
        "ShellExecuteA",
        6,
        "ascii",
        (
            Parameter(1, "lpOperation", "string", None),
            Parameter(2, "lpFile", "string", None),
            Parameter(3, "lpParameters", "string", None),
            Parameter(4, "lpDirectory", "string", None),
            Parameter(5, "nShowCmd", "integer", 32),
        ),
        _DLLS_10,
        _LEARN + "shellapi/nf-shellapi-shellexecutea",
    ),
    Function(
        "ShellExecuteW",
        6,
        "utf-16-le",
        (
            Parameter(1, "lpOperation", "string", None),
            Parameter(2, "lpFile", "string", None),
            Parameter(3, "lpParameters", "string", None),
            Parameter(4, "lpDirectory", "string", None),
            Parameter(5, "nShowCmd", "integer", 32),
        ),
        _DLLS_10,
        _LEARN + "shellapi/nf-shellapi-shellexecutew",
    ),
    Function(
        "OpenProcess",
        3,
        "ascii",
        (Parameter(0, "dwDesiredAccess", "integer", 32),),
        _DLLS_11,
        _LEARN + "processthreadsapi/nf-processthreadsapi-openprocess",
    ),
    Function(
        "LoadLibraryA",
        1,
        "ascii",
        (Parameter(0, "lpLibFileName", "string", None),),
        _DLLS_12,
        _LEARN + "libloaderapi/nf-libloaderapi-loadlibrarya",
    ),
    Function(
        "LoadLibraryW",
        1,
        "utf-16-le",
        (Parameter(0, "lpLibFileName", "string", None),),
        _DLLS_12,
        _LEARN + "libloaderapi/nf-libloaderapi-loadlibraryw",
    ),
    Function(
        "LoadLibraryExA",
        3,
        "ascii",
        (
            Parameter(0, "lpLibFileName", "string", None),
            Parameter(2, "dwFlags", "integer", 32),
        ),
        _DLLS_13,
        _LEARN + "libloaderapi/nf-libloaderapi-loadlibraryexa",
    ),
    Function(
        "LoadLibraryExW",
        3,
        "utf-16-le",
        (
            Parameter(0, "lpLibFileName", "string", None),
            Parameter(2, "dwFlags", "integer", 32),
        ),
        _DLLS_13,
        _LEARN + "libloaderapi/nf-libloaderapi-loadlibraryexw",
    ),
    Function(
        "GetModuleHandleA",
        1,
        "ascii",
        (Parameter(0, "lpModuleName", "string", None),),
        _DLLS_13,
        _LEARN + "libloaderapi/nf-libloaderapi-getmodulehandlea",
    ),
    Function(
        "GetModuleHandleW",
        1,
        "utf-16-le",
        (Parameter(0, "lpModuleName", "string", None),),
        _DLLS_13,
        _LEARN + "libloaderapi/nf-libloaderapi-getmodulehandlew",
    ),
    Function(
        "CreateFileA",
        7,
        "ascii",
        (
            Parameter(0, "lpFileName", "string", None),
            Parameter(1, "dwDesiredAccess", "integer", 32),
            Parameter(2, "dwShareMode", "integer", 32),
            Parameter(4, "dwCreationDisposition", "integer", 32),
            Parameter(5, "dwFlagsAndAttributes", "integer", 32),
        ),
        _DLLS_14,
        _LEARN + "fileapi/nf-fileapi-createfilea",
    ),
    Function(
        "CreateFileW",
        7,
        "utf-16-le",
        (
            Parameter(0, "lpFileName", "string", None),
            Parameter(1, "dwDesiredAccess", "integer", 32),
            Parameter(2, "dwShareMode", "integer", 32),
            Parameter(4, "dwCreationDisposition", "integer", 32),
            Parameter(5, "dwFlagsAndAttributes", "integer", 32),
        ),
        _DLLS_14,
        _LEARN + "fileapi/nf-fileapi-createfilew",
    ),
    Function(
        "DeleteFileA",
        1,
        "ascii",
        (Parameter(0, "lpFileName", "string", None),),
        _DLLS_14,
        _LEARN + "fileapi/nf-fileapi-deletefilea",
    ),
    Function(
        "DeleteFileW",
        1,
        "utf-16-le",
        (Parameter(0, "lpFileName", "string", None),),
        _DLLS_14,
        _LEARN + "fileapi/nf-fileapi-deletefilew",
    ),
    Function(
        "CopyFileA",
        3,
        "ascii",
        (
            Parameter(0, "lpExistingFileName", "string", None),
            Parameter(1, "lpNewFileName", "string", None),
        ),
        _DLLS_15,
        _LEARN + "winbase/nf-winbase-copyfilea",
    ),
    Function(
        "CopyFileW",
        3,
        "utf-16-le",
        (
            Parameter(0, "lpExistingFileName", "string", None),
            Parameter(1, "lpNewFileName", "string", None),
        ),
        _DLLS_16,
        _LEARN + "winbase/nf-winbase-copyfilew",
    ),
    Function(
        "MoveFileA",
        2,
        "ascii",
        (
            Parameter(0, "lpExistingFileName", "string", None),
            Parameter(1, "lpNewFileName", "string", None),
        ),
        _DLLS_17,
        _LEARN + "winbase/nf-winbase-movefilea",
    ),
    Function(
        "MoveFileW",
        2,
        "utf-16-le",
        (
            Parameter(0, "lpExistingFileName", "string", None),
            Parameter(1, "lpNewFileName", "string", None),
        ),
        _DLLS_17,
        _LEARN + "winbase/nf-winbase-movefilew",
    ),
    Function(
        "MoveFileExA",
        3,
        "ascii",
        (
            Parameter(0, "lpExistingFileName", "string", None),
            Parameter(1, "lpNewFileName", "string", None),
            Parameter(2, "dwFlags", "integer", 32),
        ),
        _DLLS_18,
        _LEARN + "winbase/nf-winbase-movefileexa",
    ),
    Function(
        "MoveFileExW",
        3,
        "utf-16-le",
        (
            Parameter(0, "lpExistingFileName", "string", None),
            Parameter(1, "lpNewFileName", "string", None),
            Parameter(2, "dwFlags", "integer", 32),
        ),
        _DLLS_19,
        _LEARN + "winbase/nf-winbase-movefileexw",
    ),
    Function(
        "CreateDirectoryA",
        2,
        "ascii",
        (Parameter(0, "lpPathName", "string", None),),
        _DLLS_14,
        _LEARN + "fileapi/nf-fileapi-createdirectorya",
    ),
    Function(
        "CreateDirectoryW",
        2,
        "utf-16-le",
        (Parameter(0, "lpPathName", "string", None),),
        _DLLS_14,
        _LEARN + "fileapi/nf-fileapi-createdirectoryw",
    ),
    Function(
        "InternetOpenA",
        5,
        "ascii",
        (
            Parameter(0, "lpszAgent", "string", None),
            Parameter(1, "dwAccessType", "integer", 32),
            Parameter(2, "lpszProxy", "string", None),
            Parameter(3, "lpszProxyBypass", "string", None),
            Parameter(4, "dwFlags", "integer", 32),
        ),
        _DLLS_20,
        _LEARN + "wininet/nf-wininet-internetopena",
    ),
    Function(
        "InternetOpenW",
        5,
        "utf-16-le",
        (
            Parameter(0, "lpszAgent", "string", None),
            Parameter(1, "dwAccessType", "integer", 32),
            Parameter(2, "lpszProxy", "string", None),
            Parameter(3, "lpszProxyBypass", "string", None),
            Parameter(4, "dwFlags", "integer", 32),
        ),
        _DLLS_20,
        _LEARN + "wininet/nf-wininet-internetopenw",
    ),
    Function(
        "InternetOpenUrlA",
        6,
        "ascii",
        (
            Parameter(1, "lpszUrl", "string", None),
            Parameter(2, "lpszHeaders", "string", None),
            Parameter(4, "dwFlags", "integer", 32),
        ),
        _DLLS_20,
        _LEARN + "wininet/nf-wininet-internetopenurla",
    ),
    Function(
        "InternetOpenUrlW",
        6,
        "utf-16-le",
        (
            Parameter(1, "lpszUrl", "string", None),
            Parameter(2, "lpszHeaders", "string", None),
            Parameter(4, "dwFlags", "integer", 32),
        ),
        _DLLS_20,
        _LEARN + "wininet/nf-wininet-internetopenurlw",
    ),
    Function(
        "InternetConnectA",
        8,
        "ascii",
        (
            Parameter(1, "lpszServerName", "string", None),
            Parameter(2, "nServerPort", "integer", 16),
            Parameter(3, "lpszUserName", "string", None),
            Parameter(4, "lpszPassword", "string", None),
            Parameter(5, "dwService", "integer", 32),
            Parameter(6, "dwFlags", "integer", 32),
        ),
        _DLLS_20,
        _LEARN + "wininet/nf-wininet-internetconnecta",
    ),
    Function(
        "InternetConnectW",
        8,
        "utf-16-le",
        (
            Parameter(1, "lpszServerName", "string", None),
            Parameter(2, "nServerPort", "integer", 16),
            Parameter(3, "lpszUserName", "string", None),
            Parameter(4, "lpszPassword", "string", None),
            Parameter(5, "dwService", "integer", 32),
            Parameter(6, "dwFlags", "integer", 32),
        ),
        _DLLS_20,
        _LEARN + "wininet/nf-wininet-internetconnectw",
    ),
    Function(
        "HttpOpenRequestA",
        8,
        "ascii",
        (
            Parameter(1, "lpszVerb", "string", None),
            Parameter(2, "lpszObjectName", "string", None),
            Parameter(3, "lpszVersion", "string", None),
            Parameter(4, "lpszReferrer", "string", None),
            Parameter(6, "dwFlags", "integer", 32),
        ),
        _DLLS_20,
        _LEARN + "wininet/nf-wininet-httpopenrequesta",
    ),
    Function(
        "HttpOpenRequestW",
        8,
        "utf-16-le",
        (
            Parameter(1, "lpszVerb", "string", None),
            Parameter(2, "lpszObjectName", "string", None),
            Parameter(3, "lpszVersion", "string", None),
            Parameter(4, "lpszReferrer", "string", None),
            Parameter(6, "dwFlags", "integer", 32),
        ),
        _DLLS_20,
        _LEARN + "wininet/nf-wininet-httpopenrequestw",
    ),
    Function(
        "URLDownloadToFileA",
        5,
        "ascii",
        (
            Parameter(1, "szURL", "string", None),
            Parameter(2, "szFileName", "string", None),
        ),
        _DLLS_21,
        "https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123(v=vs.85)",
    ),
    Function(
        "URLDownloadToFileW",
        5,
        "utf-16-le",
        (
            Parameter(1, "szURL", "string", None),
            Parameter(2, "szFileName", "string", None),
        ),
        _DLLS_21,
        "https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123(v=vs.85)",
    ),
    Function(
        "WinHttpOpen",
        5,
        "utf-16-le",
        (
            Parameter(0, "pszAgentW", "string", None),
            Parameter(1, "dwAccessType", "integer", 32),
            Parameter(2, "pszProxyW", "string", None),
            Parameter(3, "pszProxyBypassW", "string", None),
            Parameter(4, "dwFlags", "integer", 32),
        ),
        _DLLS_22,
        _LEARN + "winhttp/nf-winhttp-winhttpopen",
    ),
    Function(
        "WinHttpConnect",
        4,
        "utf-16-le",
        (
            Parameter(1, "pswzServerName", "string", None),
            Parameter(2, "nServerPort", "integer", 16),
        ),
        _DLLS_22,
        _LEARN + "winhttp/nf-winhttp-winhttpconnect",
    ),
    Function(
        "WinHttpOpenRequest",
        7,
        "utf-16-le",
        (
            Parameter(1, "pwszVerb", "string", None),
            Parameter(2, "pwszObjectName", "string", None),
            Parameter(3, "pwszVersion", "string", None),
            Parameter(4, "pwszReferrer", "string", None),
            Parameter(6, "dwFlags", "integer", 32),
        ),
        _DLLS_22,
        _LEARN + "winhttp/nf-winhttp-winhttpopenrequest",
    ),
    Function(
        "CreateMutexA",
        3,
        "ascii",
        (Parameter(2, "lpName", "string", None),),
        _DLLS_23,
        _LEARN + "synchapi/nf-synchapi-createmutexa",
    ),
    Function(
        "CreateMutexW",
        3,
        "utf-16-le",
        (Parameter(2, "lpName", "string", None),),
        _DLLS_23,
        _LEARN + "synchapi/nf-synchapi-createmutexw",
    ),
    Function(
        "OpenMutexW",
        3,
        "utf-16-le",
        (
            Parameter(0, "dwDesiredAccess", "integer", 32),
            Parameter(2, "lpName", "string", None),
        ),
        _DLLS_24,
        _LEARN + "synchapi/nf-synchapi-openmutexw",
    ),
    Function(
        "VirtualAlloc",
        4,
        "ascii",
        (
            Parameter(2, "flAllocationType", "integer", 32),
            Parameter(3, "flProtect", "integer", 32),
        ),
        _DLLS_25,
        _LEARN + "memoryapi/nf-memoryapi-virtualalloc",
    ),
    Function(
        "VirtualAllocEx",
        5,
        "ascii",
        (
            Parameter(3, "flAllocationType", "integer", 32),
            Parameter(4, "flProtect", "integer", 32),
        ),
        _DLLS_26,
        _LEARN + "memoryapi/nf-memoryapi-virtualallocex",
    ),
    Function(
        "VirtualProtect",
        4,
        "ascii",
        (Parameter(2, "flNewProtect", "integer", 32),),
        _DLLS_25,
        _LEARN + "memoryapi/nf-memoryapi-virtualprotect",
    ),
    Function(
        "VirtualProtectEx",
        5,
        "ascii",
        (Parameter(3, "flNewProtect", "integer", 32),),
        _DLLS_26,
        _LEARN + "memoryapi/nf-memoryapi-virtualprotectex",
    ),
    Function(
        "CryptAcquireContextA",
        5,
        "ascii",
        (
            Parameter(1, "szContainer", "string", None),
            Parameter(2, "szProvider", "string", None),
            Parameter(3, "dwProvType", "integer", 32),
            Parameter(4, "dwFlags", "integer", 32),
        ),
        _DLLS_27,
        _LEARN + "wincrypt/nf-wincrypt-cryptacquirecontexta",
    ),
    Function(
        "CryptAcquireContextW",
        5,
        "utf-16-le",
        (
            Parameter(1, "szContainer", "string", None),
            Parameter(2, "szProvider", "string", None),
            Parameter(3, "dwProvType", "integer", 32),
            Parameter(4, "dwFlags", "integer", 32),
        ),
        _DLLS_27,
        _LEARN + "wincrypt/nf-wincrypt-cryptacquirecontextw",
    ),
    Function(
        "BCryptOpenAlgorithmProvider",
        4,
        "utf-16-le",
        (
            Parameter(1, "pszAlgId", "string", None),
            Parameter(2, "pszImplementation", "string", None),
            Parameter(3, "dwFlags", "integer", 32),
        ),
        _DLLS_28,
        _LEARN + "bcrypt/nf-bcrypt-bcryptopenalgorithmprovider",
    ),
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
        *_V4,
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
