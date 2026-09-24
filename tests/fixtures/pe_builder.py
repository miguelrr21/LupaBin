import struct


def build_pe(
    *,
    bits=32,
    imports=True,
    delay=False,
    ordinal=None,
    dll=b"kernel32.dll",
    function=b"ExitProcess",
    more=(),
):
    """`more` adds functions of the same DLL, imported by name: the i-th import's slot is
    0x1140 + i * (4 or 8) and its hint/name entry follows the previous one."""
    data = bytearray(0x1200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    optional_size = 224 if bits == 32 else 240
    struct.pack_into(
        "<HHIIIHH",
        data,
        0x84,
        0x14C if bits == 32 else 0x8664,
        1,
        0,
        0,
        0,
        optional_size,
        0x102 if bits == 32 else 0x22,
    )
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x10B if bits == 32 else 0x20B)
    struct.pack_into("<I", data, opt + 16, 0x1000)
    if bits == 32:
        struct.pack_into("<I", data, opt + 28, 0x400000)
    else:
        struct.pack_into("<Q", data, opt + 24, 0x140000000)
    struct.pack_into("<II", data, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, opt + 56, 0x2000, 0x200)
    struct.pack_into("<H", data, opt + 68, 3)
    count_offset = 92 if bits == 32 else 108
    struct.pack_into("<I", data, opt + count_offset, 16)
    section = opt + optional_size
    data[section : section + 8] = b".idata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x1000, 0x1000, 0x1000, 0x200)
    struct.pack_into("<I", data, section + 36, 0x40000040)
    if imports:
        directory = opt + count_offset + 4 + 8 * (13 if delay else 1)
        struct.pack_into("<II", data, directory, 0x1000, 64 if delay else 40)
        if delay:
            struct.pack_into("<8I", data, 0x200, 1, 0x1100, 0, 0x1140, 0x1120, 0, 0, 0)
        else:
            struct.pack_into("<5I", data, 0x200, 0x1120, 0, 0, 0x1100, 0x1140)
        data[0x300 : 0x300 + len(dll) + 1] = dll + b"\0"
        value = (1 << (bits - 1)) | ordinal if ordinal is not None else 0x1160
        fmt = "<I" if bits == 32 else "<Q"
        struct.pack_into(fmt, data, 0x320, value)
        struct.pack_into(fmt, data, 0x340, value)
        data[0x362 : 0x362 + len(function) + 1] = function + b"\0"
        width, name_rva = bits // 8, 0x1162 + len(function) + 1
        for index, extra in enumerate(more, 1):
            name_rva += name_rva % 2
            for table in (0x320, 0x340):
                struct.pack_into(fmt, data, table + index * width, name_rva)
            data[name_rva - 0xE00 + 2 : name_rva - 0xE00 + 2 + len(extra) + 1] = extra + b"\0"
            name_rva += 2 + len(extra) + 1
        assert name_rva <= 0x1200 and 0x340 + (len(more) + 1) * width <= 0x360
    return bytes(data)


def build_demo(*, bits=32, corrupt=False):
    data = bytearray(build_pe(bits=bits))
    opt = 0x98
    section = opt + (224 if bits == 32 else 240)
    struct.pack_into("<H", data, 0x86, 2)
    struct.pack_into("<I", data, opt + 56, 0x3000)
    struct.pack_into("<I", data, section + 8, 0x400)
    struct.pack_into("<I", data, section + 16, 0x400)
    second = section + 40
    data[second : second + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, second + 8, 0xC00, 0x2000, 0xC00, 0x600)
    struct.pack_into("<I", data, second + 36, 0x40000040)
    struct.pack_into("<II", data, opt + (96 if bits == 32 else 112), 0x2000, 0x100)
    struct.pack_into(
        "<IIHHIIIIIII", data, 0x600, 0, 0, 0, 0, 0x1100, 7, 1, 1, 0x2040, 0x2050, 0x2060
    )
    struct.pack_into("<I", data, 0x640, 0x2300)
    struct.pack_into("<I", data, 0x650, 0x2070)
    struct.pack_into("<H", data, 0x660, 0)
    data[0x670:0x677] = b"Symbol\0"
    message = b"https://training.invalid/sample\0"
    data[0x800 : 0x800 + len(message)] = message
    wide = "DISSECT PRACTICE".encode("utf-16-le") + b"\0\0"
    data[0x900 : 0x900 + len(wide)] = wide
    return bytes(data[:-64] if corrupt else data)


def xor_stream(text, key, encoding="ascii"):
    """NUL + text + NUL, XOR'd as one stream so the decoded run ends at the text."""
    pad = "\0".encode(encoding)
    stream = pad + text.encode(encoding) + pad
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(stream))


# Training texts on the reserved .invalid domain; each XOR'd one contains a crib from
# dissect-xor-cribs-v1 that can verify its key length. Keys use bytes >= 0x80 so the
# ciphertext is never text. None of this comes from, or behaves like, malware.
DECODE_DEMO = (
    ("base64", "https://training.invalid/decode/base64"),
    ("hex", "cmd.exe /c echo dissect-hex"),
    ("xor", "https://training.invalid/decode/xor-1", b"\xa5", "ascii"),
    ("xor", "User-Agent: DissectTraining/1.0", b"\x9e\xc3\x81\xf7", "ascii"),
    ("xor", "kernel32.dll!DissectTraining", b"\xb7\xd2", "utf-16-le"),
    # "http://" is too short to verify a 4-byte key by itself: this one is only
    # recoverable because the User-Agent above established the same key
    ("xor", "http://training.invalid/decode/reuse", b"\x9e\xc3\x81\xf7", "ascii"),
)


def build_decode_demo(*, bits=32):
    import base64

    overlay = bytearray()
    for item in DECODE_DEMO:
        overlay += b"\xcc" * 16
        if item[0] == "base64":
            overlay += b"\0" + base64.b64encode(item[1].encode()) + b"\0"
        elif item[0] == "hex":
            overlay += b"\0" + item[1].encode().hex().encode() + b"\0"
        else:
            overlay += xor_stream(item[1], item[2], item[3])
    return build_pe(bits=bits) + bytes(overlay) + b"\xcc" * 16


# Inert training code: each of the three canonical forms calls the fixture's only
# import (kernel32!ExitProcess, IAT slot 0x1140) once, then returns.
CODE_RVA = 0x2000
THUNK_RVA = 0x2020


def code_demo_bytes(bits=32):
    def rel(source, target, size):
        return struct.pack("<i", target - (source + size))

    slot = 0x1140
    code = bytearray(b"\xcc" * 0x200)
    if bits == 32:
        absolute = struct.pack("<I", 0x400000 + slot)
        body = b"\xff\x15" + absolute  # call [slot]
        body += b"\xe8" + rel(CODE_RVA + len(body), THUNK_RVA, 5)  # call thunk
        body += b"\x8b\x35" + absolute + b"\xff\xd6"  # mov esi, [slot]; call esi
        thunk = b"\xff\x25" + absolute  # jmp [slot]
    else:
        body = b"\x48\xff\x15" + rel(CODE_RVA, slot, 7)  # call [rip+slot]
        body += b"\xe8" + rel(CODE_RVA + len(body), THUNK_RVA, 5)
        body += b"\x48\x8b\x35" + rel(CODE_RVA + len(body), slot, 7) + b"\xff\xd6"
        thunk = b"\xff\x25" + rel(THUNK_RVA, slot, 6)
    body += b"\xc3"
    code[: len(body)] = body
    code[THUNK_RVA - CODE_RVA : THUNK_RVA - CODE_RVA + len(thunk)] = thunk
    return bytes(code)


def build_code_pe(code, *, bits=32, **imports):
    """build_pe plus an executable .text section at CODE_RVA, where the entry point is."""
    size = -(-len(code) // 0x200) * 0x200
    data = bytearray(build_pe(bits=bits, **imports)) + code + b"\xcc" * (size - len(code))
    opt = 0x98
    section = opt + (224 if bits == 32 else 240) + 40
    struct.pack_into("<H", data, 0x86, 2)
    struct.pack_into("<I", data, opt + 16, CODE_RVA)
    struct.pack_into("<I", data, opt + 56, CODE_RVA + -(-size // 0x1000) * 0x1000)
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, size, CODE_RVA, size, 0x1200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    return bytes(data)


def with_load_config(data, *, bits=32, guard=(), seh=(), flags=0x400, size=None, count=None):
    """Add a load configuration directory in .idata listing CFG targets and SafeSEH handlers.

    The directory sits at RVA 0x1400 (file 0x600) and its tables at 0x1500 and 0x1580.
    """
    data = bytearray(data)
    opt = 0x98
    count_offset = 92 if bits == 32 else 108
    base = 0x400000 if bits == 32 else 0x140000000
    table_at, count_at, flags_at = (0x50, 0x54, 0x58) if bits == 32 else (0x80, 0x88, 0x90)
    declared = size if size is not None else flags_at + 4
    struct.pack_into("<II", data, opt + count_offset + 4 + 8 * 10, 0x1400, flags_at + 4)
    struct.pack_into("<I", data, 0x600, declared)
    fmt = "<I" if bits == 32 else "<Q"
    struct.pack_into(fmt, data, 0x600 + table_at, base + 0x1500)
    struct.pack_into(fmt, data, 0x600 + count_at, len(guard) if count is None else count)
    struct.pack_into("<I", data, 0x600 + flags_at, flags)
    stride = 4 + (flags >> 28)
    for index, rva in enumerate(guard):
        struct.pack_into("<I", data, 0x700 + index * stride, rva)
    if bits == 32:
        struct.pack_into("<II", data, 0x640, base + 0x1580, len(seh))
        for index, rva in enumerate(seh):
            struct.pack_into("<I", data, 0x780 + index * 4, rva)
    return bytes(data)


# Inert training call with constant arguments: RegOpenKeyExW(HKEY_CURRENT_USER,
# L"Software\\Dissect\\Training", 0, KEY_READ, &key), set with the canonical forms of
# argument_forms.py. The subkey is a made-up training name; the string lies in the
# read-only .idata section at ARGS_STRING_RVA. Never executed.
ARGS_STRING_RVA = 0x1A00
ARGS_SUBKEY = "Software\\Dissect\\Training"
KEY_READ = 0x20019
HKCU32 = b"\x68\x01\x00\x00\x80"  # push 0x80000001
HKCU64 = b"\x48\xc7\xc1\x01\x00\x00\x80"  # mov rcx, 0xffffffff80000001


def args_demo_bytes(bits=32, hkey=None, before=b""):
    """Code at CODE_RVA that calls the fixture's only import with constant arguments.

    `hkey` replaces the instruction that sets hKey (x64: rcx; x86: the last push);
    `before` goes right before the call."""
    slot = 0x1140
    if bits == 32:
        body = b"\x50"  # push eax: &key, not a constant
        body += b"\x68" + struct.pack("<I", KEY_READ)  # push samDesired
        body += b"\x6a\x00"  # push ulOptions
        body += b"\x68" + struct.pack("<I", 0x400000 + ARGS_STRING_RVA)  # push lpSubKey
        body += (HKCU32 if hkey is None else hkey) + before
        body += b"\xff\x15" + struct.pack("<I", 0x400000 + slot)  # call [slot]
    else:
        # lea rdx, [rip+string]
        body = b"\x48\x8d\x15" + struct.pack("<i", ARGS_STRING_RVA - (CODE_RVA + 7))
        body += HKCU64 if hkey is None else hkey
        body += b"\x41\xb9" + struct.pack("<I", KEY_READ)  # mov r9d, KEY_READ
        body += b"\x45\x33\xc0" + before  # xor r8d, r8d
        body += b"\xff\x15" + struct.pack("<i", slot - (CODE_RVA + len(body) + 6))
    return body + b"\xc3"


def build_args_demo(
    *, bits=32, code=None, writable=False, dll=b"advapi32.dll", function=b"RegOpenKeyExW"
):
    """RegOpenKeyExW with constant arguments; `writable` marks .idata as writable.

    With `code` and `function`, the same layout for another imported function."""
    data = bytearray(
        build_code_pe(
            args_demo_bytes(bits) if code is None else code,
            bits=bits,
            dll=dll,
            function=function,
        )
    )
    text = ARGS_SUBKEY.encode("utf-16-le") + b"\0\0"
    offset = 0x200 + ARGS_STRING_RVA - 0x1000
    data[offset : offset + len(text)] = text
    if writable:
        section = 0x98 + (224 if bits == 32 else 240)
        struct.pack_into("<I", data, section + 36, 0xC0000040)
    return bytes(data)


# Inert training use of GetProcAddress: one call by name (a made-up training export,
# in the read-only .idata) and one by ordinal 5, which is not a name. Never executed.
RESOLVE_NAME = "DissectTrainingProc"


def resolve_demo_bytes(bits=32):
    slot = 0x1140
    if bits == 32:
        absolute = struct.pack("<I", 0x400000 + slot)
        body = bytes.fromhex("68") + struct.pack("<I", 0x400000 + ARGS_STRING_RVA)
        body += bytes.fromhex("56ff15") + absolute  # push esi (hModule); call
        body += bytes.fromhex("6a0556ff15") + absolute  # by ordinal 5
    else:
        body = bytes.fromhex("488d15") + struct.pack("<i", ARGS_STRING_RVA - (CODE_RVA + 7))
        body += bytes.fromhex("488bcbff15")  # mov rcx, rbx (hModule); call
        body += struct.pack("<i", slot - (CODE_RVA + len(body) + 4))
        body += bytes.fromhex("ba05000000488bcbff15")  # mov edx, 5: by ordinal
        body += struct.pack("<i", slot - (CODE_RVA + len(body) + 4))
    return body + bytes.fromhex("c3")


def build_resolve_demo(*, bits=32):
    """GetProcAddress by name and by ordinal, imported from kernel32.dll."""
    data = bytearray(
        build_code_pe(
            resolve_demo_bytes(bits), bits=bits, dll=b"kernel32.dll", function=b"GetProcAddress"
        )
    )
    text = RESOLVE_NAME.encode("ascii") + bytes(1)
    offset = 0x200 + ARGS_STRING_RVA - 0x1000
    data[offset : offset + len(text)] = text
    return bytes(data)


CALL_DLLS = (
    "advapi32.dll",
    "kernel32.dll",
    "shell32.dll",
    "wininet.dll",
    "winhttp.dll",
    "urlmon.dll",
    "bcrypt.dll",
)


def build_call_demo(function, *calls, dll=None):
    """x86 code that calls one catalog function once per entry of `calls`.

    Each call maps a parameter position to a constant: an int is pushed as is, a str
    is written in the function's encoding to the read-only .idata (from ARGS_STRING_RVA)
    and its address is pushed. Other positions push eax, which is not a constant, so
    those arguments stay unknown. Inert training data: never executed."""
    from dissect.evidence.api_catalog import FUNCTIONS

    entry = FUNCTIONS[function]
    if dll is None:
        dll = next((name for name in CALL_DLLS if name in entry.dlls), min(entry.dlls))
    slot = struct.pack("<I", 0x400000 + 0x1140)
    strings, rva, body = {}, ARGS_STRING_RVA, b""
    for call in calls:
        for position in reversed(range(entry.arity)):
            value = call.get(position)
            if isinstance(value, str):
                if value not in strings:
                    strings[value] = rva
                    rva += len(value.encode(entry.encoding)) + 2
                    rva += rva % 2
                value = 0x400000 + strings[value]
            body += b"\x50" if value is None else b"\x68" + struct.pack("<I", value)
        body += b"\xff\x15" + slot  # call [slot]
    assert rva <= 0x2000, "the strings must fit in .idata"
    data = bytearray(build_code_pe(body + b"\xc3", dll=dll.encode(), function=function.encode()))
    for text, at in strings.items():
        raw = text.encode(entry.encoding) + b"\0\0"
        data[0x200 + at - 0x1000 : 0x200 + at - 0x1000 + len(raw)] = raw
    return bytes(data)


# Inert training call for the capabilities demo: RegSetKeyValueW(HKEY_CURRENT_USER,
# the Run key, a made-up value name, REG_SZ, ...). Never executed.
CAPABILITY_VALUE = "DissectTraining"


def build_capability_demo():
    run = r"Software\Microsoft\Windows\CurrentVersion\Run"
    return build_call_demo("RegSetKeyValueW", {0: 0x80000001, 1: run, 2: CAPABILITY_VALUE, 3: 1})


# Inert training code for Phase 5.4: in one x64 function, RegOpenKeyExW(HKEY_CURRENT_USER,
# the Run key, 0, KEY_WRITE, &key), then RegSetValueExW(key, a made-up value name, 0,
# REG_SZ, ...). The .pdata entry that declares the function is at RVA 0x1800, in the
# read-only .idata. Never executed.
SAME_FUNCTION_VALUE = "DissectTraining"
PDATA_RVA = 0x1800


def same_function_code(subkey_rva=0x1A00, value_rva=0x1B00, set_key=None):
    """Code at CODE_RVA; `set_key` replaces the instruction that sets RegSetValueExW's
    hKey (by default a copy of the handle the first call stored at [rsp+0x30])."""

    def rip(prefix, target, body):
        return bytes.fromhex(prefix) + struct.pack("<i", target - (CODE_RVA + len(body) + 7))

    body = b""
    body += rip("488d15", subkey_rva, body)  # lea rdx, subkey
    body += HKCU64  # mov rcx, HKEY_CURRENT_USER
    body += bytes.fromhex("41b906000200")  # mov r9d, KEY_WRITE
    body += bytes.fromhex("4533c0")  # xor r8d, r8d
    body += bytes.fromhex("488d442430")  # lea rax, [rsp+0x30]: &key
    body += bytes.fromhex("4889442420")  # mov [rsp+0x20], rax
    body += bytes.fromhex("ff15") + struct.pack("<i", 0x1140 - (CODE_RVA + len(body) + 6))
    body += set_key if set_key is not None else bytes.fromhex("488b4c2430")  # mov rcx, key
    body += rip("488d15", value_rva, body)  # lea rdx, value name
    body += bytes.fromhex("4533c0")  # xor r8d, r8d
    body += bytes.fromhex("41b901000000")  # mov r9d, REG_SZ
    body += bytes.fromhex("ff15") + struct.pack("<i", 0x1148 - (CODE_RVA + len(body) + 6))
    return body + b"\xc3"


def build_same_function_demo(
    *,
    subkey=r"Software\Microsoft\Windows\CurrentVersion\Run",
    value=SAME_FUNCTION_VALUE,
    pdata=((0, None),),
    set_key=None,
):
    """x64 PE importing RegOpenKeyExW and RegSetValueExW from advapi32.dll.

    `pdata` lists .pdata entries as (begin offset from CODE_RVA, end offset or None for
    the end of the code); an empty tuple leaves the exception directory empty."""
    code = same_function_code(set_key=set_key)
    data = bytearray(
        build_code_pe(
            code,
            bits=64,
            dll=b"advapi32.dll",
            function=b"RegOpenKeyExW",
            more=(b"RegSetValueExW",),
        )
    )
    for rva, text in ((0x1A00, subkey), (0x1B00, value)):
        raw = text.encode("utf-16-le") + b"\0\0"
        data[0x200 + rva - 0x1000 : 0x200 + rva - 0x1000 + len(raw)] = raw
    if pdata:
        directory = 0x98 + 108 + 4 + 8 * 3
        struct.pack_into("<II", data, directory, PDATA_RVA, 12 * len(pdata))
        for index, (begin, end) in enumerate(pdata):
            entry = 0x200 + PDATA_RVA - 0x1000 + 12 * index
            finish = CODE_RVA + (len(code) if end is None else end)
            struct.pack_into("<III", data, entry, CODE_RVA + begin, finish, 0x1880)
    return bytes(data)


def build_code_demo(*, bits=32, **imports):
    """An entry point that calls the import once through each canonical form."""
    return build_code_pe(code_demo_bytes(bits), bits=bits, **imports)


def main():
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Generate inert PE test data; never execute it.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bits", type=int, choices=(32, 64), default=32)
    parser.add_argument(
        "--scenario",
        choices=(
            "basic",
            "demo",
            "corrupt",
            "yara-limited",
            "decode-demo",
            "code-demo",
            "args-demo",
            "capability-demo",
        ),
        default="basic",
    )
    args = parser.parse_args()
    if args.scenario == "code-demo":
        data = build_code_demo(bits=args.bits)
    elif args.scenario == "capability-demo":
        if args.bits != 32:
            parser.error("capability-demo is x86 only")
        data = build_capability_demo()
    elif args.scenario == "args-demo":
        data = build_args_demo(bits=args.bits)
    elif args.scenario == "decode-demo":
        data = build_decode_demo(bits=args.bits)
    elif args.scenario in ("basic", "yara-limited"):
        data = build_pe(bits=args.bits)
    else:
        data = build_demo(bits=args.bits, corrupt=args.scenario == "corrupt")
    if args.scenario == "yara-limited":
        data += b"DISSECT PRACTICE\0" * 20
    with args.output.open("xb") as stream:
        stream.write(data)


if __name__ == "__main__":
    main()
