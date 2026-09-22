import struct


def build_pe(
    *,
    bits=32,
    imports=True,
    delay=False,
    ordinal=None,
    dll=b"kernel32.dll",
    function=b"ExitProcess",
):
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


def main():
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Generate inert PE test data; never execute it.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bits", type=int, choices=(32, 64), default=32)
    parser.add_argument(
        "--scenario", choices=("basic", "demo", "corrupt", "yara-limited"), default="basic"
    )
    args = parser.parse_args()
    data = (
        build_pe(bits=args.bits)
        if args.scenario in ("basic", "yara-limited")
        else build_demo(bits=args.bits, corrupt=args.scenario == "corrupt")
    )
    if args.scenario == "yara-limited":
        data += b"DISSECT PRACTICE\0" * 20
    with args.output.open("xb") as stream:
        stream.write(data)


if __name__ == "__main__":
    main()
