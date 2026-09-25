import struct

import pytest

from lupabin.evidence import api_catalog, argument_forms
from lupabin.evidence.api_catalog import hkey_name, lookup

PINNED = {
    # v1: RegOpenKeyExA/W (never published)
    "lupabin-api-semantics-v1": "19e41f8f93976c5ebaf5270cdf2ef40812f8199a14ad968038d3b5d3a2bf8abb",
    # v2: + RegCreateKeyExA/W, checked on Microsoft Learn on 2026-09-24
    "lupabin-api-semantics-v2": "238568b92b75a849ffe0d8fdf75ac5877fe4b86d8d1ba9b75022cc4006579420",
    # v3: + GetProcAddress, checked on Microsoft Learn on 2026-09-24
    "lupabin-api-semantics-v3": "7648350dc53ec4234e65902b06bdbde64827df0a0554792f5aa5046d33f82c56",
    # v4: the rest of the catalog (67 entries), checked on 2026-09-24
    "lupabin-api-semantics-v4": "3b6a6839eaeefafb836cf02db429e5af531cbb0b3b38a19f69ee2c5dca7635bc",
}


def test_the_catalog_content_is_pinned_to_its_version():
    # A change needs its Microsoft Learn check again and a new catalog version.
    assert PINNED[api_catalog.CATALOG_ID] == api_catalog.digest()


def test_registry_open_signature_as_published():
    for name, encoding in (("RegOpenKeyExA", "ascii"), ("RegOpenKeyExW", "utf-16-le")):
        entry = api_catalog.FUNCTIONS[name]
        assert entry.arity == 5 and entry.encoding == encoding
        assert [(p.position, p.name, p.type) for p in entry.parameters] == [
            (0, "hKey", "hkey"),
            (1, "lpSubKey", "string"),
            (3, "samDesired", "integer"),
        ]


def test_registry_create_signature_as_published():
    for name, encoding in (("RegCreateKeyExA", "ascii"), ("RegCreateKeyExW", "utf-16-le")):
        entry = api_catalog.FUNCTIONS[name]
        assert entry.arity == 9 and entry.encoding == encoding
        assert [(p.position, p.name, p.type) for p in entry.parameters] == [
            (0, "hKey", "hkey"),
            (1, "lpSubKey", "string"),
            (4, "dwOptions", "integer"),
            (5, "samDesired", "integer"),
        ]
    # unlike RegOpenKeyExA, the page does not list kernel32.dll
    assert lookup(b"kernel32.dll", b"RegCreateKeyExA") is None


def test_get_proc_address_signature_as_published():
    entry = api_catalog.FUNCTIONS["GetProcAddress"]
    assert entry.arity == 2 and entry.encoding == "ascii"  # LPCSTR: never wide
    assert [(p.position, p.name, p.type) for p in entry.parameters] == [(1, "lpProcName", "string")]
    assert lookup(b"KERNEL32.dll", b"GetProcAddress") is not None
    assert lookup(b"api-ms-win-core-libraryloader-l1-2-0.dll", b"GetProcAddress") is not None
    assert lookup(b"advapi32.dll", b"GetProcAddress") is None


def test_every_entry_is_well_formed():
    for name, entry in api_catalog.FUNCTIONS.items():
        positions = [p.position for p in entry.parameters]
        assert positions == sorted(set(positions)) and positions[-1] < entry.arity, name
        assert len({p.name for p in entry.parameters}) == len(entry.parameters), name
        assert entry.dlls and all(dll == dll.lower() for dll in entry.dlls), name
        for parameter in entry.parameters:
            # integers carry their width; keys and strings are pointer-sized
            assert (parameter.type == "integer") == (parameter.bits is not None), name
        if name.endswith("A") and name[:-1] + "W" in api_catalog.FUNCTIONS:
            assert entry.encoding == "ascii", name
        if name.endswith("W") and name[:-1] + "A" in api_catalog.FUNCTIONS:
            assert entry.encoding == "utf-16-le", name


def test_functions_documented_only_in_unicode_read_wide_strings():
    for name in ("WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "OpenMutexW"):
        assert api_catalog.FUNCTIONS[name].encoding == "utf-16-le"
    assert "OpenMutexA" not in api_catalog.FUNCTIONS  # Learn has no page for it
    assert api_catalog.FUNCTIONS["WinExec"].encoding == "ascii"  # LPCSTR only
    port = next(p for p in api_catalog.FUNCTIONS["InternetConnectW"].parameters if p.position == 2)
    assert (port.name, port.bits) == ("nServerPort", 16)  # INTERNET_PORT, a WORD


def test_x64_keys_are_the_sign_extended_constants_only():
    assert hkey_name(0xFFFFFFFF80000001, 64) == "HKEY_CURRENT_USER"
    assert hkey_name(0x80000001, 64) is None  # zero-extended: another pointer
    assert hkey_name(0x80000001, 32) == "HKEY_CURRENT_USER"
    assert hkey_name(0xFFFFFFFF80000001, 32) is None


@pytest.mark.parametrize("value", [0x80000004, 0x80000006, 0x80000007, 0x80000050, 0x7FFFFFFF])
def test_keys_not_listed_for_hkey_abstain(value):
    assert hkey_name(value, 32) is None


def test_lookup_needs_an_exporting_dll():
    assert lookup(b"ADVAPI32.dll", b"RegOpenKeyExW") is not None
    assert lookup(b"api-ms-win-core-registry-l1-1-0.dll", b"RegOpenKeyExW") is not None
    assert lookup(b"kernel32.dll", b"RegOpenKeyExA") is not None  # legacy, ANSI only
    assert lookup(b"kernel32.dll", b"RegOpenKeyExW") is None
    assert lookup(b"evil.dll", b"RegOpenKeyExW") is None
    assert lookup(b"advapi32.dll", b"regopenkeyexw") is None  # names are exact
    assert lookup(b"\xff.dll", b"RegOpenKeyExW") is None


@pytest.mark.parametrize(
    "raw",
    [
        "4831c9",  # xor rcx, rcx: not the 32-bit form
        "31ca",  # xor edx, ecx: two registers
        "498d0510000000",  # lea rax, [rip+..] with REX.B
        "488d0c2510000000",  # lea rcx, [0x10]: SIB, not RIP-relative
        "8d0d10000000",  # lea ecx, [rip+..]: a 32-bit address
        "b801000000",  # mov eax, 1: not an argument register
        "48b90100008000000000",  # movabs rcx, imm64: not a canonical form
    ],
)
def test_non_canonical_x64_settings_abstain(raw):
    assert argument_forms.x64_setting(bytes.fromhex(raw), 0x1000) is None


def test_a_rip_relative_address_below_the_image_abstains():
    raw = b"\x48\x8d\x0d" + struct.pack("<i", -0x2000)
    assert argument_forms.x64_setting(raw, 0x1000) is None


@pytest.mark.parametrize("raw", ["666a05", "6668050000", "50", "ff742404"])
def test_non_constant_or_16_bit_pushes_abstain(raw):
    assert argument_forms.x86_push(bytes.fromhex(raw)) is None


def test_x86_addresses_below_the_image_base_abstain():
    setting = argument_forms.x86_push(b"\x68" + struct.pack("<I", 0x1000))
    assert setting is not None
    assert argument_forms.address_of(setting, 32, 0x400000) is None
    assert argument_forms.address_of(setting, 32, 0) == 0x1000
