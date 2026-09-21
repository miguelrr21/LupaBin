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


def main():
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Generate inert PE test data; never execute it.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bits", type=int, choices=(32, 64), default=32)
    args = parser.parse_args()
    with args.output.open("xb") as stream:
        stream.write(build_pe(bits=args.bits))


if __name__ == "__main__":
    main()
