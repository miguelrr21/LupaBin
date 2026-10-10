import hashlib
import struct
from dataclasses import replace

import pytest

from lupabin.evidence.pe_triage import Budgets, Span, Triage, read

_BUDGETS = Budgets(
    max_input_bytes=8192,
    max_sections=8,
    max_certificates=8,
    max_debug_entries=8,
    max_path_bytes=128,
    max_hash_bytes=8192,
)
_GUID_BYTES = bytes.fromhex("33221100554477668899aabbccddeeff")


class _PE:
    def __init__(self, bits: int = 32) -> None:
        self.data = bytearray(0x600)
        self.data[:2] = b"MZ"
        struct.pack_into("<I", self.data, 0x3C, 0x80)
        self.data[0x80:0x84] = b"PE\0\0"
        optional_size = 224 if bits == 32 else 240
        struct.pack_into(
            "<HHIIIHH",
            self.data,
            0x84,
            0x14C if bits == 32 else 0x8664,
            1,
            0,
            0,
            0,
            optional_size,
            2,
        )
        self.optional = 0x98
        self.directories = self.optional + (96 if bits == 32 else 112)
        self.section = self.optional + optional_size
        struct.pack_into("<H", self.data, self.optional, 0x10B if bits == 32 else 0x20B)
        struct.pack_into("<II", self.data, self.optional + 32, 0x1000, 0x200)
        struct.pack_into("<II", self.data, self.optional + 56, 0x3000, 0x200)
        struct.pack_into("<I", self.data, self.directories - 4, 16)
        self.data[self.section : self.section + 8] = b".test\0\0\0"
        struct.pack_into("<IIII", self.data, self.section + 8, 0x400, 0x1000, 0x400, 0x200)
        struct.pack_into("<I", self.data, self.section + 36, 0x40000040)

    def directory(self, index: int, address: int, size: int) -> None:
        struct.pack_into("<II", self.data, self.directories + index * 8, address, size)

    def certificate_table(self, table: bytes, before: bytes = b"", after: bytes = b"") -> int:
        at = len(self.data) + len(before)
        self.data.extend(before + table + after)
        self.directory(4, at, len(table))
        return at

    def debug(
        self,
        payload: bytes,
        *,
        pointer: int = 0x400,
        rva: int = 0x1200,
        index: int = 0,
        kind: int = 2,
        flags: int = 0,
    ) -> int:
        if pointer + len(payload) > len(self.data):
            self.data.extend(b"\0" * (pointer + len(payload) - len(self.data)))
        self.data[pointer : pointer + len(payload)] = payload
        at = 0x220 + index * 28
        struct.pack_into(
            "<IIHHIIII", self.data, at, flags, 0xFEDCBA98, 1, 2, kind, len(payload), rva, pointer
        )
        self.directory(6, 0x1020, (index + 1) * 28)
        return at

    def read(self, **budgets: int) -> Triage:
        return read(bytes(self.data), budgets=replace(_BUDGETS, **budgets))


def _certificate(payload: bytes, revision: int = 0x200, kind: int = 2) -> bytes:
    length = 8 + len(payload)
    return struct.pack("<IHH", length, revision, kind) + payload + b"\0" * (-length % 8)


def _rsds(path: bytes = b"private.pdb\0", age: int = 7) -> bytes:
    return b"RSDS" + _GUID_BYTES + struct.pack("<I", age) + path


def _span(offset: int, data: bytes) -> Span:
    return Span(offset, len(data), hashlib.sha256(data).hexdigest())


@pytest.mark.parametrize("bits", [32, 64])
def test_complete_layout_absent_directories_and_no_tail(bits: int) -> None:
    result = _PE(bits).read()
    assert result.layout is not None
    assert result.layout.bits == bits
    assert result.layout.size_of_headers == 0x200
    assert result.layout.tail_offset == 0x600
    assert result.layout_issues == ()
    assert result.certificates.status == result.codeview.status == "absent"
    assert result.overlay.status == "complete"
    assert result.overlay.items == ()


@pytest.mark.parametrize("bits", [32, 64])
def test_directory_count_excludes_unpublished_entries(bits: int) -> None:
    pe = _PE(bits)
    pe.directory(4, 0xFFFFFFFF, 0xFFFFFFFF)
    pe.directory(6, 0xFFFFFFFF, 0xFFFFFFFF)
    struct.pack_into("<I", pe.data, pe.directories - 4, 4)
    result = pe.read()
    assert result.certificates.status == result.codeview.status == "absent"
    assert result.layout is not None
    assert result.layout.security.entry_offset is None


def test_overlay_is_only_tail_not_gaps_inside_sections() -> None:
    pe = _PE()
    pe.data[0x580:0x600] = b"G" * 0x80
    pe.data.extend(b"tail\x00\xff")
    result = pe.read()
    assert result.overlay.status == "complete"
    assert result.overlay.items == (_span(0x600, b"tail\x00\xff"),)


@pytest.mark.parametrize("bits", [32, 64])
def test_security_file_offset_and_two_overlay_spans(bits: int) -> None:
    pe = _PE(bits)
    table = _certificate(b"ABC", kind=0x7777) + _certificate(b"12345678")
    start = pe.certificate_table(table, before=b"lead1234", after=b"trailer")
    result = pe.read()
    assert result.certificates.status == "complete"
    first, second = result.certificates.items
    assert (first.index, first.offset, first.length, first.padding_length) == (0, 0x608, 11, 5)
    assert (first.revision, first.certificate_type) == (0x200, 0x7777)
    assert first.payload == _span(start + 8, b"ABC")
    assert (second.index, second.offset, second.length, second.padding_length) == (1, 0x618, 16, 0)
    assert second.payload == _span(start + 24, b"12345678")
    assert result.overlay.status == "complete"
    assert result.overlay.items == (_span(0x600, b"lead1234"), _span(0x628, b"trailer"))


@pytest.mark.parametrize("before,after", [(b"", b""), (b"", b"end"), (b"12345678", b"")])
def test_overlay_zero_or_one_span_around_certificate(before: bytes, after: bytes) -> None:
    pe = _PE()
    table = _certificate(b"A")
    start = pe.certificate_table(table, before, after)
    result = pe.read()
    expected = tuple(
        _span(offset, raw) for offset, raw in ((0x600, before), (start + len(table), after)) if raw
    )
    assert result.overlay.items == expected
    assert result.overlay.status == "complete"


@pytest.mark.parametrize("payload", [b"", b"1", b"1234567", b"12345678", b"123456789"])
@pytest.mark.parametrize("revision,kind", [(0x100, 1), (0x200, 2), (0xFFFF, 0xFFFF)])
def test_certificate_lengths_revision_and_type_are_raw_declarations(
    payload: bytes, revision: int, kind: int
) -> None:
    pe = _PE()
    pe.certificate_table(_certificate(payload, revision, kind))
    result = pe.read()
    assert result.certificates.status == "complete"
    item = result.certificates.items[0]
    assert item.length == 8 + len(payload)
    assert item.padding_length == (-(8 + len(payload))) % 8
    assert (item.revision, item.certificate_type) == (revision, kind)
    assert item.payload == _span(0x608, payload)


@pytest.mark.parametrize("length", [0, 1, 7, 17, 0xFFFFFFFF])
def test_invalid_certificate_lengths_prevent_overlay(length: int) -> None:
    pe = _PE()
    pe.certificate_table(struct.pack("<IHH", length, 0x200, 2) + b"\0" * 8)
    result = pe.read()
    assert result.certificates.status == "incomplete"
    assert result.certificates.issues[0].code == "certificate_length"
    assert result.certificates.items == ()
    assert result.overlay.status == "unavailable"
    assert result.overlay.items == ()


@pytest.mark.parametrize(
    "table,code",
    [
        (b"1234567", "certificate_header"),
        (struct.pack("<IHH", 9, 0x200, 2) + b"x", "certificate_padding_missing"),
        (struct.pack("<IHH", 9, 0x200, 2) + b"x" + b"z" * 7, "certificate_padding_nonzero"),
        (_certificate(b"12345678") + b"\0", "certificate_header"),
    ],
)
def test_certificate_padding_and_directory_end(table: bytes, code: str) -> None:
    pe = _PE()
    pe.certificate_table(table)
    result = pe.read()
    assert result.certificates.status == "incomplete"
    assert result.certificates.issues[0].code == code
    assert result.overlay.status == "unavailable"


def test_invalid_later_certificate_preserves_only_verified_prefix() -> None:
    pe = _PE()
    pe.certificate_table(_certificate(b"ok") + struct.pack("<IHH", 0, 0x200, 2))
    result = pe.read()
    assert len(result.certificates.items) == 1
    assert result.certificates.items[0].payload == _span(0x608, b"ok")
    assert result.certificates.status == "incomplete"
    assert result.overlay.items == ()


@pytest.mark.parametrize(
    "maximum,published,status", [(0, 0, "incomplete"), (1, 1, "incomplete"), (2, 2, "complete")]
)
def test_certificate_entry_budget_is_explicit(maximum: int, published: int, status: str) -> None:
    pe = _PE()
    pe.certificate_table(_certificate(b"a") + _certificate(b"b"))
    result = pe.read(max_certificates=maximum)
    assert result.certificates.status == status
    assert len(result.certificates.items) == published
    if maximum < 2:
        assert result.certificates.issues[0].kind == "limit"
        assert result.overlay.status == "unavailable"


@pytest.mark.parametrize(
    "address,size,code",
    [
        (0, 8, "security_range"),
        (0x600, 0, "security_range"),
        (0x601, 8, "security_range"),
        (0xFFFFFFF8, 16, "security_range"),
        (0x600, 0xFFFFFFFF, "security_range"),
        (0x80, 8, "security_overlaps_image"),
        (0x300, 8, "security_overlaps_image"),
        (0x5F8, 16, "security_overlaps_image"),
        (0x1400, 8, "security_range"),
    ],
)
def test_invalid_security_directory_never_becomes_overlay(
    address: int, size: int, code: str
) -> None:
    pe = _PE()
    pe.data.extend(b"\0" * 16)
    pe.directory(4, address, size)
    result = pe.read()
    assert result.certificates.status == "incomplete"
    assert result.certificates.issues[0].code == code
    assert result.overlay.status == "unavailable"


@pytest.mark.parametrize("maximum", [0, 2, 3])
def test_hash_budget_is_shared_and_never_silent(maximum: int) -> None:
    pe = _PE()
    pe.certificate_table(_certificate(b"abc"), after=b"tail")
    result = pe.read(max_hash_bytes=maximum)
    if maximum < 3:
        assert result.certificates.status == "incomplete"
        assert result.certificates.issues[0].code == "hash_bytes"
        assert result.overlay.status == "unavailable"
    else:
        assert result.certificates.status == "complete"
        assert result.overlay.status == "incomplete"
        assert result.overlay.issues[0].kind == "limit"
    assert result.overlay.items == ()
    assert pe.read(max_hash_bytes=7).overlay.items == (_span(0x610, b"tail"),)


@pytest.mark.parametrize("bits", [32, 64])
def test_rsds_guid_byte_order_age_and_locations(bits: int) -> None:
    pe = _PE(bits)
    at = pe.debug(_rsds())
    result = pe.read()
    assert result.codeview.status == "complete"
    item = result.codeview.items[0]
    assert item.guid_raw == _GUID_BYTES
    assert item.guid == "00112233-4455-6677-8899-aabbccddeeff"
    assert item.age == 7
    assert item.path_raw == b"private.pdb"
    assert item.path_ascii == "private.pdb"
    assert item.path_offset == 0x418
    assert item.record_length == 36
    assert item.debug.offset == at
    assert item.debug.timestamp == 0xFEDCBA98
    assert (item.debug.major_version, item.debug.minor_version) == (1, 2)
    assert (item.debug.pointer_to_raw_data, item.debug.address_of_raw_data) == (0x400, 0x1200)
    assert result == read(bytes(pe.data), budgets=_BUDGETS)


@pytest.mark.parametrize(
    "path,ascii_text",
    [
        (b"\xff\xfe.pdb", None),
        (b"\xc3\xa9.pdb", None),
        (b"\\\\host\\share\\private.pdb", "\\\\host\\share\\private.pdb"),
        (b"../../private.pdb", "../../private.pdb"),
        (b"<script>\x1b[31m.pdb", "<script>\x1b[31m.pdb"),
    ],
)
def test_path_bytes_are_not_decoded_normalized_or_used(path: bytes, ascii_text: str | None) -> None:
    pe = _PE()
    pe.debug(_rsds(path + b"\0", age=0xFFFFFFFF))
    item = pe.read().codeview.items[0]
    assert item.path_raw == path
    assert item.path_ascii == ascii_text
    assert item.age == 0xFFFFFFFF


def test_debug_file_only_data_with_zero_rva_is_allowed_outside_image() -> None:
    pe = _PE()
    raw = _rsds()
    pe.debug(raw, pointer=0x600, rva=0)
    result = pe.read()
    assert result.codeview.status == "complete"
    assert result.codeview.items[0].path_offset == 0x618
    assert result.overlay.items == (_span(0x600, raw),)


@pytest.mark.parametrize(
    "field,value,code",
    [
        (0, 1, "debug_characteristics_unsupported"),
        (16, 0, "debug_payload_range"),
        (16, 0xFFFFFFFF, "debug_payload_range"),
        (20, 0, "debug_zero_rva_in_image"),
        (20, 0x1201, "debug_pointer_rva_mismatch"),
        (20, 0xFFFFFFFF, "debug_pointer_rva_mismatch"),
        (24, 0, "debug_payload_range"),
        (24, 0x401, "debug_pointer_rva_mismatch"),
        (24, 0xFFFFFFF0, "debug_payload_range"),
    ],
)
def test_debug_contradictions_and_reserved_raw_flags(field: int, value: int, code: str) -> None:
    pe = _PE()
    at = pe.debug(_rsds())
    struct.pack_into("<I", pe.data, at + field, value)
    result = pe.read()
    assert result.codeview.status == "incomplete"
    assert result.codeview.items == ()
    assert result.codeview.issues[0].code == code


@pytest.mark.parametrize("pointer", [0x100, 0x5F0])
def test_zero_rva_cannot_hide_header_or_partial_section_overlap(pointer: int) -> None:
    pe = _PE()
    pe.debug(_rsds(), pointer=pointer, rva=0)
    result = pe.read()
    assert result.codeview.status == "incomplete"
    assert result.codeview.issues[0].code == "debug_zero_rva_in_image"


def test_debug_cannot_reinterpret_certificate_payload() -> None:
    pe = _PE()
    raw = _rsds()
    pe.certificate_table(_certificate(raw))
    pe.debug(raw, pointer=0x608, rva=0)
    result = pe.read()
    assert result.certificates.status == "complete"
    assert result.codeview.items == ()
    assert result.codeview.issues[0].code == "debug_overlaps_security"


@pytest.mark.parametrize(
    "address,size,code",
    [
        (0, 28, "debug_directory_size"),
        (0x1020, 0, "debug_directory_size"),
        (0x1020, 27, "debug_directory_size"),
        (0xFFFFFFFC, 28, "debug_directory_range"),
        (0x13F0, 28, "debug_directory_range"),
        (0x2000, 28, "debug_directory_range"),
    ],
)
def test_debug_directory_range_and_stride(address: int, size: int, code: str) -> None:
    pe = _PE()
    pe.directory(6, address, size)
    result = pe.read()
    assert result.codeview.status == "incomplete"
    assert result.codeview.issues[0].code == code


@pytest.mark.parametrize(
    "payload,maximum,kind,code",
    [
        (b"RSD", 128, "malformed", "codeview_signature_truncated"),
        (b"RSDS" + b"\0" * 19, 128, "malformed", "rsds_truncated"),
        (_rsds(b"abc"), 128, "malformed", "path_not_terminated"),
        (_rsds(b"abcd\0"), 3, "limit", "path_bytes"),
        (_rsds(b"a\0"), 0, "limit", "path_bytes"),
        (b"NB10" + b"\0" * 20, 128, "ignored", "codeview_signature_unsupported"),
        (b"ABCD" + b"\0" * 20, 128, "ignored", "codeview_signature_unsupported"),
    ],
)
def test_unsupported_truncated_and_unterminated_codeview(
    payload: bytes, maximum: int, kind: str, code: str
) -> None:
    pe = _PE()
    pe.debug(payload)
    result = pe.read(max_path_bytes=maximum)
    assert result.codeview.status == "incomplete"
    assert result.codeview.items == ()
    assert (result.codeview.issues[0].kind, result.codeview.issues[0].code) == (kind, code)


@pytest.mark.parametrize("path", [b"a", b"12345"])
def test_path_budget_includes_exact_length_and_one_terminator(path: bytes) -> None:
    pe = _PE()
    pe.debug(_rsds(path + b"\0"))
    result = pe.read(max_path_bytes=len(path))
    assert result.codeview.status == "complete"
    assert result.codeview.items[0].path_raw == path


def test_terminator_outside_debug_payload_is_not_used() -> None:
    pe = _PE()
    pe.debug(_rsds(b"name"))
    assert pe.data[0x41C] == 0
    result = pe.read()
    assert result.codeview.issues[0].code == "path_not_terminated"


def test_debug_ignored_entry_and_later_valid_rsds_are_explicit() -> None:
    pe = _PE()
    pe.debug(b"ignored", kind=16)
    pe.debug(_rsds(b"second\0"), index=1, pointer=0x480, rva=0x1280)
    result = pe.read()
    assert result.codeview.status == "complete"
    assert result.codeview.issues[0].kind == "ignored"
    assert result.codeview.issues[0].code == "debug_type_unsupported"
    assert result.codeview.items[0].debug.index == 1
    assert result.codeview.items[0].path_raw == b"second"


@pytest.mark.parametrize("maximum", [0, 128])
def test_rsds_without_pdb_path_keeps_its_identifier(maximum: int) -> None:
    pe = _PE()
    pe.debug(_rsds(b"\0", age=1))
    result = pe.read(max_path_bytes=maximum)
    assert result.codeview.status == "complete"
    record = result.codeview.items[0]
    assert (record.guid_raw, record.age) == (_GUID_BYTES, 1)
    assert (record.path_raw, record.path_offset, record.record_length) == (b"", 0x418, 25)


def test_only_other_debug_types_is_a_complete_empty_codeview_inventory() -> None:
    pe = _PE()
    pe.debug(b"ignored", kind=13)
    result = pe.read()
    assert result.codeview.status == "complete"
    assert result.codeview.items == ()
    assert [issue.code for issue in result.codeview.issues] == ["debug_type_unsupported"]


def test_unread_codeview_entry_next_to_other_types_stays_incomplete() -> None:
    pe = _PE()
    pe.debug(b"ignored", kind=16)
    pe.debug(b"NB10" + b"\0" * 21, index=1, pointer=0x480, rva=0x1280)
    result = pe.read()
    assert result.codeview.status == "incomplete"
    assert [issue.code for issue in result.codeview.issues] == [
        "debug_type_unsupported",
        "codeview_signature_unsupported",
    ]


@pytest.mark.parametrize("maximum", [0, 1, 2])
def test_debug_entry_budget_does_not_publish_complete_prefix(maximum: int) -> None:
    pe = _PE()
    pe.debug(_rsds())
    pe.debug(_rsds(b"second\0"), index=1, pointer=0x480, rva=0x1280)
    result = pe.read(max_debug_entries=maximum)
    assert len(result.codeview.items) == maximum
    assert result.codeview.status == ("complete" if maximum == 2 else "incomplete")
    if maximum < 2:
        assert result.codeview.issues[-1].code == "debug_entries"


@pytest.mark.parametrize(
    "mutation,code",
    [
        ("raw_truncated", "section_raw_range"),
        ("raw_in_headers", "section_raw_range"),
        ("virtual_in_headers", "section_virtual_range"),
        ("virtual_outside_image", "section_virtual_range"),
        ("raw_overlap", "section_raw_overlap"),
        ("virtual_overlap", "section_virtual_overlap"),
        ("section_table_truncated", "headers_or_section_table"),
        ("headers_truncated", "headers_or_section_table"),
        ("directory_table_truncated", "directory_table"),
        ("extra_directories", "directory_count"),
    ],
)
def test_ambiguous_or_truncated_layout_abstains_everywhere(mutation: str, code: str) -> None:
    pe = _PE()
    if mutation == "raw_truncated":
        struct.pack_into("<I", pe.data, pe.section + 16, 0x500)
    elif mutation == "raw_in_headers":
        struct.pack_into("<I", pe.data, pe.section + 20, 0x100)
    elif mutation == "virtual_in_headers":
        struct.pack_into("<I", pe.data, pe.section + 12, 0x100)
    elif mutation == "virtual_outside_image":
        struct.pack_into("<I", pe.data, pe.section + 12, 0xFFFFFFF0)
    elif mutation in ("raw_overlap", "virtual_overlap"):
        struct.pack_into("<H", pe.data, 0x86, 2)
        at = pe.section + 40
        if mutation == "raw_overlap":
            struct.pack_into("<IIII", pe.data, at + 8, 0x100, 0x2000, 0x100, 0x400)
        else:
            struct.pack_into("<IIII", pe.data, at + 8, 0x100, 0x1100, 0, 0)
    elif mutation == "section_table_truncated":
        struct.pack_into("<H", pe.data, 0x86, 4)
    elif mutation == "headers_truncated":
        struct.pack_into("<I", pe.data, pe.optional + 60, 0x1000)
    elif mutation == "directory_table_truncated":
        struct.pack_into("<H", pe.data, 0x94, 96)
    else:
        struct.pack_into("<I", pe.data, pe.directories - 4, 17)
    result = pe.read()
    assert result.layout is None
    assert result.layout_issues[0].code == code
    for inventory in (result.overlay, result.certificates, result.codeview):
        assert inventory.status == "unavailable"
        assert inventory.items == ()


def test_section_budget_prevents_tail_based_on_only_present_sections() -> None:
    pe = _PE()
    struct.pack_into("<H", pe.data, 0x86, 2)
    struct.pack_into("<IIII", pe.data, pe.section + 48, 0x200, 0x2000, 0x200, 0x600)
    pe.data.extend(b"\0" * 0x200 + b"tail")
    result = pe.read(max_sections=1)
    assert result.layout is None
    assert result.layout_issues[0].kind == "limit"
    assert result.layout_issues[0].code == "sections"
    assert result.overlay.items == ()


def test_virtual_only_section_does_not_extend_file_tail() -> None:
    pe = _PE()
    struct.pack_into("<H", pe.data, 0x86, 2)
    struct.pack_into("<IIII", pe.data, pe.section + 48, 0x200, 0x2000, 0, 0xFFFFFF00)
    pe.data.extend(b"tail")
    result = pe.read()
    assert result.layout is not None
    assert len(result.layout.sections) == 2
    assert result.overlay.items == (_span(0x600, b"tail"),)


def test_section_order_does_not_define_tail() -> None:
    pe = _PE()
    struct.pack_into("<H", pe.data, 0x86, 2)
    struct.pack_into("<IIII", pe.data, pe.section + 8, 0x200, 0x2000, 0x200, 0x400)
    struct.pack_into("<IIII", pe.data, pe.section + 48, 0x200, 0x1000, 0x200, 0x200)
    pe.data.extend(b"tail")
    result = pe.read()
    assert result.overlay.status == "complete"
    assert result.overlay.items == (_span(0x600, b"tail"),)


def test_section_names_remain_raw_bytes() -> None:
    pe = _PE()
    pe.data[pe.section : pe.section + 8] = b"\xff\xfe<>\x1b\0\0\0"
    result = pe.read()
    assert result.layout is not None
    assert result.layout.sections[0].name_raw == b"\xff\xfe<>\x1b\0\0\0"


@pytest.mark.parametrize("data", [b"", b"MZ", b"MZ" + b"\xff" * 62, b"x" * 100])
def test_hostile_headers_are_structured_failures(data: bytes) -> None:
    result = read(data, budgets=_BUDGETS)
    assert result.layout is None
    assert result.layout_issues[0].kind == "malformed"
    assert result.overlay.status == "unavailable"


def test_every_prefix_of_small_fixture_is_bounded() -> None:
    data = bytes(_PE().data)
    for stop in range(len(data)):
        result = read(data[:stop], budgets=_BUDGETS)
        assert result.layout is None
        assert result.overlay.items == ()


def test_input_budget_precedes_header_parsing() -> None:
    result = _PE().read(max_input_bytes=1)
    assert result.layout is None
    assert result.layout_issues[0].code == "input_bytes"
    assert result.layout_issues[0].kind == "limit"


@pytest.mark.parametrize("name", list(Budgets.__dataclass_fields__))
def test_negative_budgets_are_caller_errors(name: str) -> None:
    with pytest.raises(ValueError, match=name):
        replace(_BUDGETS, **{name: -1})


def test_security_in_an_unmapped_gap_does_not_change_the_tail() -> None:
    pe = _PE()
    struct.pack_into("<H", pe.data, 0x86, 2)
    struct.pack_into("<IIII", pe.data, pe.section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<IIII", pe.data, pe.section + 48, 0x200, 0x2000, 0x200, 0x600)
    pe.data.extend(b"\0" * 0x200 + b"tail")
    table = _certificate(b"invented")
    pe.data[0x480 : 0x480 + len(table)] = table
    pe.directory(4, 0x480, len(table))
    result = pe.read()
    assert result.certificates.status == "complete"
    assert result.overlay.items == (_span(0x800, b"tail"),)


def test_hash_limit_does_not_emit_only_one_of_two_overlay_spans() -> None:
    pe = _PE()
    pe.certificate_table(_certificate(b""), b"12345678", b"after")
    result = pe.read(max_hash_bytes=8)
    assert result.certificates.status == "complete"
    assert result.overlay.status == "incomplete"
    assert result.overlay.items == ()
    assert result.overlay.issues[0].code == "hash_bytes"


def test_debug_directory_can_be_mapped_in_headers() -> None:
    pe = _PE()
    at = pe.debug(_rsds())
    pe.data[0x1E0:0x1FC] = pe.data[at : at + 28]
    pe.directory(6, 0x1E0, 28)
    result = pe.read()
    assert result.codeview.status == "complete"
    assert result.codeview.items[0].debug.offset == 0x1E0


def test_debug_payload_cannot_map_virtual_only_section_bytes() -> None:
    pe = _PE()
    struct.pack_into("<I", pe.data, pe.section + 8, 0x800)
    pe.debug(_rsds(), pointer=0x600, rva=0x1400)
    result = pe.read()
    assert result.layout is not None
    assert result.codeview.status == "incomplete"
    assert result.codeview.issues[0].code == "debug_pointer_rva_mismatch"


def test_malformed_debug_entry_does_not_hide_a_later_valid_entry() -> None:
    pe = _PE()
    pe.debug(_rsds(b"no-terminator"))
    pe.debug(_rsds(b"later\0"), pointer=0x480, rva=0x1280, index=1)
    result = pe.read()
    assert result.codeview.status == "incomplete"
    assert result.codeview.issues[0].code == "path_not_terminated"
    assert len(result.codeview.items) == 1
    assert result.codeview.items[0].path_raw == b"later"
    assert result.codeview.items[0].debug.index == 1


def test_bytes_after_first_path_terminator_are_not_part_of_the_name() -> None:
    pe = _PE()
    raw = _rsds(b"name\0uninterpreted")
    pe.debug(raw)
    result = pe.read()
    assert result.codeview.status == "complete"
    item = result.codeview.items[0]
    assert item.path_raw == b"name"
    assert item.record_length == 29
    assert item.debug.size_of_data == len(raw)
