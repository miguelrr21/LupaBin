import inspect
import struct
from dataclasses import fields, replace

import pytest

from lupabin.evidence.pe_resources import (
    Limits,
    Location,
    RawRegion,
    ResourceResult,
    read,
)

TEST_LIMITS = Limits(
    regions=128,
    directories=256,
    entries=4096,
    depth=8,
    name_bytes=4096,
    total_read_bytes=4 * 1024 * 1024,
    version_bytes=65536,
    version_blocks=4096,
    version_depth=8,
    translations=4096,
)
ROOT_RVA = 0x3000
FILE_OFFSET = 0x35
FIXED = bytes.fromhex(
    "bd04effe 00000100 02000100 04000300 06000500 08000700"
    "3f000000 01000000 04000400 01000000 00000000 11223344 55667788"
)
FIXED_ROOT = (
    bytes.fromhex(
        "5c00 3400 0000 560053005f00560045005200530049004f004e005f0049004e0046004f000000 0000"
    )
    + FIXED
)


def _block(
    key: str,
    value: bytes = b"",
    *,
    kind: int = 1,
    children: tuple[bytes, ...] = (),
    value_length: int | None = None,
) -> bytes:
    data = bytearray(b"\0" * 6 + key.encode("utf-16-le") + b"\0\0")
    data.extend(b"\0" * (-len(data) % 4))
    data.extend(value)
    for child in children:
        data.extend(b"\0" * (-len(data) % 4))
        data.extend(child)
    units = len(value) // 2 if kind == 1 else len(value)
    struct.pack_into(
        "<HHH", data, 0, len(data), units if value_length is None else value_length, kind
    )
    return bytes(data)


def _version(*strings: bytes, translations: bytes | None = None) -> bytes:
    children = [_block("StringFileInfo", children=(_block("040904b0", children=strings),))]
    if translations is not None:
        children.append(
            _block("VarFileInfo", children=(_block("Translation", translations, kind=0),))
        )
    return _block("VS_VERSION_INFO", FIXED, kind=0, children=tuple(children))


def _tree(
    *payloads: bytes,
    type_id: int = 16,
    name_id: int = 7,
    languages: tuple[int, ...] = (0x409,),
) -> bytes:
    assert len(payloads) == len(languages)
    leaves = 64 + 8 * len(payloads)
    payload_start = leaves + 16 * len(payloads)
    data = bytearray(payload_start)
    struct.pack_into("<HHII", data, 12, 0, 1, type_id, 0x80000018)
    struct.pack_into("<HHII", data, 36, 0, 1, name_id, 0x80000030)
    struct.pack_into("<HH", data, 60, 0, len(payloads))
    for index, (language, payload) in enumerate(zip(languages, payloads, strict=True)):
        struct.pack_into("<II", data, 64 + index * 8, language, leaves + index * 16)
        struct.pack_into(
            "<4I", data, leaves + index * 16, ROOT_RVA + len(data), len(payload), 1200, 0
        )
        data.extend(payload)
        data.extend(b"\0" * (-len(data) % 4))
    return bytes(data)


def _read(tree: bytes, *, limits: Limits = TEST_LIMITS) -> ResourceResult:
    return read(
        b"\xff" * FILE_OFFSET + tree,
        ROOT_RVA,
        len(tree),
        (RawRegion(ROOT_RVA, FILE_OFFSET, len(tree)),),
        limits=limits,
    )


def _codes(result: ResourceResult) -> set[str]:
    return {omission.code for omission in result.omissions} | {
        omission.code for version in result.versions for omission in version.omissions
    }


def test_absent_empty_and_malformed_are_distinct() -> None:
    assert read(b"", 0, 0, (), limits=TEST_LIMITS).state == "absent"
    empty = _read(b"\0" * 16)
    assert empty.state == "complete"
    assert empty.directories[0].id_entries == 0
    assert not empty.resources
    for rva, size in ((ROOT_RVA, 0), (0, 16), (0xFFFFFFFF, 16), (-1, 16)):
        result = read(b"", rva, size, (), limits=TEST_LIMITS)
        assert result.state == "partial"
        assert _codes(result) == {"invalid_resource_directory"}
    assert _read(b"\0" * 15).state == "partial"


def test_inventory_keeps_type_name_language_and_exact_locations() -> None:
    tree = _tree(b"not parsed", type_id=10, name_id=1)
    result = _read(tree)
    assert result.state == "complete"
    resource = result.resources[0]
    assert tuple(identifier.number for identifier in resource.path) == (10, 1, 0x409)
    assert resource.location == Location(ROOT_RVA + 72, FILE_OFFSET + 72, 16)
    assert resource.data_location == Location(ROOT_RVA + 88, FILE_OFFSET + 88, 10)
    assert resource.codepage == 1200
    assert resource.resource_type == resource.path[0]
    assert resource.resource_name == resource.path[1]
    assert resource.resource_language == resource.path[2]
    assert result.entries[2].location == Location(ROOT_RVA + 64, FILE_OFFSET + 64, 8)
    assert not result.versions


def test_version_type_is_not_resource_name_one() -> None:
    assert not _read(_tree(FIXED_ROOT, type_id=1, name_id=16)).versions
    result = _read(_tree(FIXED_ROOT, type_id=16, name_id=73))
    assert result.state == "complete"
    assert len(result.versions) == 1


def test_fixed_structure_is_thirteen_dwords_not_a_date_or_identity() -> None:
    result = _read(_tree(FIXED_ROOT))
    assert result.state == "complete"
    version = result.versions[0]
    assert len(FIXED_ROOT) == 92
    block = version.blocks[0]
    assert block.location == Location(ROOT_RVA + 88, FILE_OFFSET + 88, 92)
    assert block.value_length == 52
    assert block.value == FIXED
    fixed = version.fixed
    assert fixed is not None
    assert fixed.location == Location(ROOT_RVA + 128, FILE_OFFSET + 128, 52)
    assert fixed.signature == 0xFEEF04BD
    assert fixed.structure_version == 0x10000
    assert (fixed.file_version_ms, fixed.file_version_ls) == (0x10002, 0x30004)
    assert (fixed.product_version_ms, fixed.product_version_ls) == (0x50006, 0x70008)
    assert (fixed.file_flags_mask, fixed.file_flags, fixed.file_os) == (0x3F, 1, 0x40004)
    assert (fixed.file_type, fixed.file_subtype) == (1, 0)
    assert (fixed.file_date_ms, fixed.file_date_ls) == (0x44332211, 0x88776655)


def test_multiple_version_languages_keep_every_leaf() -> None:
    result = _read(_tree(FIXED_ROOT, FIXED_ROOT, languages=(0x409, 0xC0A)))
    assert result.state == "complete"
    assert len(result.versions) == 2
    assert tuple(version.resource_index for version in result.versions) == (0, 1)
    assert [resource.path[2].number for resource in result.resources] == [0x409, 0xC0A]
    assert result.versions[0].blocks[0].location != result.versions[1].blocks[0].location


def test_counted_non_ascii_resource_name_and_original_bytes() -> None:
    tree = bytearray(_tree(b"raw", type_id=10))
    name = "Árbol漢字".encode("utf-16-le")
    name_offset = len(tree)
    tree.extend(struct.pack("<H", len(name) // 2) + name)
    struct.pack_into("<HHI", tree, 36, 1, 0, 0x80000000 | name_offset)
    result = _read(bytes(tree))
    assert result.state == "complete"
    identifier = result.resources[0].path[1]
    assert identifier.number is None
    assert identifier.name is not None
    assert identifier.name.text == "Árbol漢字"
    assert identifier.name.raw == name
    assert identifier.name.location == Location(
        ROOT_RVA + name_offset + 2, FILE_OFFSET + name_offset + 2, len(name)
    )


def test_invalid_resource_surrogate_is_not_replaced() -> None:
    tree = bytearray(_tree(b"raw", type_id=10))
    name_offset = len(tree)
    tree.extend(b"\x01\0\0\xd8")
    struct.pack_into("<HHI", tree, 36, 1, 0, 0x80000000 | name_offset)
    result = _read(bytes(tree))
    assert result.state == "partial"
    value = result.resources[0].path[1].name
    assert value is not None
    assert value.raw == b"\0\xd8"
    assert value.text is None
    assert "invalid_resource_name_utf16" in _codes(result)


def test_resource_name_is_counted_not_nul_terminated() -> None:
    tree = bytearray(_tree(b"raw", type_id=10))
    offset = len(tree)
    tree.extend(b"\x03\0A\0\0\0B\0")
    struct.pack_into("<HHI", tree, 36, 1, 0, 0x80000000 | offset)
    result = _read(bytes(tree))
    assert result.state == "complete"
    name = result.resources[0].path[1].name
    assert name is not None and name.text == "A\0B"


@pytest.mark.parametrize(
    "target, code",
    [
        (0x80000000, "resource_cycle"),
        (0x80000004, "overlapping_ranges"),
        (0x80001000, "metadata_out_of_bounds"),
        (0x80000019, "misaligned_metadata"),
    ],
)
def test_bad_directory_edges_are_explicit(target: int, code: str) -> None:
    tree = bytearray(_tree(b"raw", type_id=10))
    struct.pack_into("<I", tree, 20, target)
    result = _read(bytes(tree))
    assert result.state == "partial"
    assert code in _codes(result)
    assert not result.resources


def test_directory_alias_does_not_repeat_subtree() -> None:
    tree = bytearray(112)
    struct.pack_into("<HH4I", tree, 12, 0, 2, 10, 0x80000020, 16, 0x80000020)
    struct.pack_into("<HHII", tree, 44, 0, 1, 1, 0x80000038)
    struct.pack_into("<HHII", tree, 68, 0, 1, 0x409, 80)
    struct.pack_into("<4I", tree, 80, ROOT_RVA + 96, 1, 0, 0)
    result = _read(bytes(tree))
    assert "directory_alias" in _codes(result)
    assert len(result.resources) == 1


def test_truncated_later_entry_preserves_earlier_leaf() -> None:
    tree = bytearray(_tree(b"raw", type_id=10))
    struct.pack_into("<H", tree, 62, 2)
    result = _read(bytes(tree))
    assert result.state == "partial"
    assert len(result.resources) == 1
    assert "offset_alias" in _codes(result)


def test_payload_alias_is_not_silently_parsed_twice() -> None:
    tree = bytearray(_tree(FIXED_ROOT, FIXED_ROOT, languages=(0x409, 0xC0A)))
    struct.pack_into("<I", tree, 96, struct.unpack_from("<I", tree, 80)[0])
    result = _read(bytes(tree))
    assert len(result.resources) == 2
    assert len(result.versions) == 1
    assert "offset_alias" in _codes(result)


def test_payload_overlaps_metadata() -> None:
    tree = bytearray(_tree(FIXED_ROOT))
    struct.pack_into("<II", tree, 72, ROOT_RVA + 4, 8)
    result = _read(bytes(tree))
    assert len(result.resources) == 1
    assert not result.versions
    assert "overlapping_ranges" in _codes(result)


def test_payload_rva_is_not_relative_to_root_and_can_use_another_region() -> None:
    tree = bytearray(_tree(b"raw", type_id=10))
    struct.pack_into("<II", tree, 72, 0x8000, 3)
    data = bytes(tree[:88]) + b"xyz"
    result = read(
        data,
        ROOT_RVA,
        88,
        (RawRegion(ROOT_RVA, 0, 88), RawRegion(0x8000, 88, 3)),
        limits=TEST_LIMITS,
    )
    assert result.state == "complete"
    assert result.resources[0].data_location == Location(0x8000, 88, 3)


@pytest.mark.parametrize(
    "data_rva, size, code",
    [
        (0xFFFFFFFF, 2, "rva_overflow"),
        (0x7000, 1, "unmapped_rva"),
        (ROOT_RVA + 88, 100, "noncontiguous_rva"),
    ],
)
def test_bad_payload_mapping_preserves_declaration(data_rva: int, size: int, code: str) -> None:
    tree = bytearray(_tree(b"raw", type_id=10))
    struct.pack_into("<II", tree, 72, data_rva, size)
    result = _read(bytes(tree))
    assert result.resources[0].data_location is None
    assert (result.resources[0].data_rva, result.resources[0].data_size) == (data_rva, size)
    assert code in _codes(result)


def test_raw_mapping_rejects_overlap_and_truncation_without_guessing() -> None:
    data = b"\0" * 64
    overlapping = read(
        data,
        ROOT_RVA,
        16,
        (RawRegion(ROOT_RVA, 0, 32), RawRegion(ROOT_RVA + 8, 32, 32)),
        limits=TEST_LIMITS,
    )
    assert _codes(overlapping) == {"ambiguous_rva"}
    shared_raw = read(
        data,
        ROOT_RVA,
        16,
        (RawRegion(ROOT_RVA, 0, 32), RawRegion(0x9000, 8, 32)),
        limits=TEST_LIMITS,
    )
    assert _codes(shared_raw) == {"overlapping_raw_regions"}
    truncated = read(b"\0" * 15, ROOT_RVA, 16, (RawRegion(ROOT_RVA, 0, 16),), limits=TEST_LIMITS)
    assert _codes(truncated) == {"truncated_raw_data"}


def test_directory_declared_size_is_a_bound_even_with_available_bytes() -> None:
    tree = _tree(b"raw", type_id=10)
    result = read(tree, ROOT_RVA, 16, (RawRegion(ROOT_RVA, 0, len(tree)),), limits=TEST_LIMITS)
    assert _codes(result) == {"metadata_out_of_bounds"}


def test_duplicate_unicode_keys_strings_and_translations_keep_provenance() -> None:
    first = _block("Compañía", "uno漢\0".encode("utf-16-le"))
    second = _block("Compañía", "dos\0".encode("utf-16-le"))
    result = _read(
        _tree(_version(first, second, translations=bytes.fromhex("0904b0040904b0040a0ce404")))
    )
    assert result.state == "complete"
    version = result.versions[0]
    assert [value.value.text for value in version.strings] == ["uno漢", "dos"]
    assert [version.blocks[value.block_index].key.text for value in version.strings] == [
        "Compañía",
        "Compañía",
    ]
    assert [(value.language, value.codepage) for value in version.strings] == [(0x409, 1200)] * 2
    assert version.strings[0].value.location != version.strings[1].value.location
    assert [(value.language, value.codepage) for value in version.translations] == [
        (0x409, 1200),
        (0x409, 1200),
        (0xC0A, 1252),
    ]
    assert (
        version.translations[1].location.file_offset - version.translations[0].location.file_offset
        == 4
    )


def test_string_value_length_counts_utf16_words_including_surrogate_pair() -> None:
    value = "A\U00010400\0".encode("utf-16-le")
    result = _read(_tree(_version(_block("K", value))))
    assert result.state == "complete"
    version = result.versions[0]
    string = version.strings[0]
    assert string.value.raw == bytes.fromhex("410001d800dc0000")
    assert version.blocks[string.block_index].value_length == 4
    assert string.value.location.size == 8


def test_alignment_is_relative_to_version_blob_not_file_offset() -> None:
    payload = _version(_block("AB", b"x\0\0\0"), _block("C", b"y\0\0\0"))
    result = _read(_tree(payload))
    assert result.state == "complete"
    version = result.versions[0]
    origin = version.blocks[0].location.file_offset
    assert origin % 4 == 1
    assert all((block.value_location.file_offset - origin) % 4 == 0 for block in version.blocks)
    assert all((block.location.file_offset - origin) % 4 == 0 for block in version.blocks)


@pytest.mark.parametrize(
    "payload, code",
    [
        (b"", "truncated_version_header"),
        (b"\0" * 8, "invalid_version_length"),
        (FIXED_ROOT[:-1], "invalid_version_length"),
        (FIXED_ROOT + b"x", "trailing_version_bytes"),
    ],
)
def test_bad_version_root_is_not_absence(payload: bytes, code: str) -> None:
    result = _read(_tree(payload))
    assert result.state == "partial"
    assert code in _codes(result)


@pytest.mark.parametrize("zeros", [1, 4, 7])
def test_zero_bytes_after_version_root_are_padding(zeros: int) -> None:
    result = _read(_tree(FIXED_ROOT + b"\0" * zeros))
    assert result.state == "complete"
    assert result.versions[0].fixed is not None
    assert not _codes(result)


@pytest.mark.parametrize(
    "position, value, code",
    [
        (0, 0, "invalid_version_length"),
        (2, 53, "version_value_out_of_bounds"),
        (4, 2, "invalid_version_type"),
        (38, 1, "nonzero_version_padding"),
        (40, 0, "fixed_file_info_signature"),
    ],
)
def test_version_header_and_padding_errors(position: int, value: int, code: str) -> None:
    payload = bytearray(FIXED_ROOT)
    struct.pack_into("<H", payload, position, value)
    result = _read(_tree(bytes(payload)))
    assert code in _codes(result)
    assert result.state == "partial"


def test_invalid_fixed_size_preserves_well_formed_children() -> None:
    payload = _block(
        "VS_VERSION_INFO",
        FIXED[:-4],
        kind=0,
        children=(
            _block(
                "StringFileInfo",
                children=(_block("040904b0", children=(_block("K", b"v\0\0\0"),)),),
            ),
        ),
    )
    result = _read(_tree(payload))
    assert "fixed_file_info_size" in _codes(result)
    assert result.versions[0].fixed is None
    assert result.versions[0].strings[0].value.text == "v"


def test_invalid_string_value_does_not_erase_previous_or_following_siblings() -> None:
    payload = _version(
        _block("K", b"a\0\0\0"), _block("K", b"b\0", value_length=50), _block("K", b"c\0\0\0")
    )
    result = _read(_tree(payload))
    assert "version_value_out_of_bounds" in _codes(result)
    assert [string.value.text for string in result.versions[0].strings] == ["a", "c"]


@pytest.mark.parametrize(
    "value, code",
    [
        (b"\0\xd8\0\0", "invalid_version_value_utf16"),
        (b"x\0", "invalid_version_string_terminator"),
        (b"x\0\0\0y\0\0\0", "invalid_version_string_terminator"),
    ],
)
def test_bad_version_text_retains_raw_bytes_without_replacement(value: bytes, code: str) -> None:
    result = _read(_tree(_version(_block("K", value))))
    string = result.versions[0].strings[0]
    assert string.value.raw == value
    assert string.value.text is None
    assert code in _codes(result)


def test_translation_length_is_bytes_and_requires_pairs() -> None:
    result = _read(_tree(_version(translations=b"\x09\x04\xb0")))
    assert "invalid_translation_value" in _codes(result)
    assert not result.versions[0].translations


def test_unknown_blocks_are_retained_but_not_interpreted() -> None:
    payload = _block("VS_VERSION_INFO", FIXED, kind=0, children=(_block("Unknown", b"x\0"),))
    result = _read(_tree(payload))
    assert "unknown_version_block" in _codes(result)
    assert result.versions[0].blocks[1].value == b"x\0"


@pytest.mark.parametrize(
    "limits, code",
    [
        (replace(TEST_LIMITS, regions=0), "regions_limit"),
        (replace(TEST_LIMITS, directories=0), "directories_limit"),
        (replace(TEST_LIMITS, entries=1), "entries_limit"),
        (replace(TEST_LIMITS, depth=1), "resource_depth_limit"),
        (replace(TEST_LIMITS, total_read_bytes=0), "read_bytes_limit"),
        (replace(TEST_LIMITS, version_bytes=1), "version_bytes_limit"),
        (replace(TEST_LIMITS, version_blocks=0), "version_blocks_limit"),
        (replace(TEST_LIMITS, name_bytes=2), "version_key_limit"),
    ],
)
def test_explicit_budgets_are_not_complete_results(limits: Limits, code: str) -> None:
    result = _read(_tree(FIXED_ROOT), limits=limits)
    assert result.state == "partial"
    assert code in _codes(result)
    omissions = (
        *result.omissions,
        *(item for version in result.versions for item in version.omissions),
    )
    assert any(item.code == code and item.kind == "limit" for item in omissions)


def test_version_depth_limit_keeps_fixed_information() -> None:
    result = _read(
        _tree(_version(_block("K", b"v\0\0\0"))), limits=replace(TEST_LIMITS, version_depth=1)
    )
    assert "version_depth_limit" in _codes(result)
    assert result.versions[0].fixed is not None
    assert not result.versions[0].strings


def test_version_block_budget_is_shared_across_resources() -> None:
    result = _read(
        _tree(FIXED_ROOT, FIXED_ROOT, languages=(0x409, 0xC0A)),
        limits=replace(TEST_LIMITS, version_blocks=1),
    )
    assert result.versions[0].state == "complete"
    assert result.versions[1].state == "partial"
    assert "version_blocks_limit" in _codes(result)


def test_other_payloads_are_not_read_even_under_tight_budget() -> None:
    result = _read(
        _tree(b"arbitrary contents" * 100, type_id=10),
        limits=replace(TEST_LIMITS, total_read_bytes=88),
    )
    assert result.state == "complete"
    assert len(result.resources) == 1
    assert not result.versions


def test_name_limit_and_truncation_are_explicit() -> None:
    tree = bytearray(_tree(b"raw", type_id=10))
    offset = len(tree)
    tree.extend(b"\x02\0A\0B\0")
    struct.pack_into("<HHI", tree, 36, 1, 0, 0x80000000 | offset)
    assert "resource_name_limit" in _codes(
        _read(bytes(tree), limits=replace(TEST_LIMITS, name_bytes=2))
    )
    assert "metadata_out_of_bounds" in _codes(_read(bytes(tree[:-2])))


def test_multiple_resource_names_are_not_collapsed_to_name_one() -> None:
    tree = bytearray(136)
    struct.pack_into("<HHII", tree, 12, 0, 1, 16, 0x80000018)
    struct.pack_into("<HH4I", tree, 36, 0, 2, 1, 0x80000038, 7, 0x80000050)
    struct.pack_into("<HHII", tree, 68, 0, 1, 0x409, 104)
    struct.pack_into("<HHII", tree, 92, 0, 1, 0xC0A, 120)
    struct.pack_into("<4I", tree, 104, ROOT_RVA + 136, len(FIXED_ROOT), 0, 0)
    struct.pack_into("<4I", tree, 120, ROOT_RVA + 228, len(FIXED_ROOT), 0, 0)
    tree.extend(FIXED_ROOT + FIXED_ROOT)
    result = _read(bytes(tree))
    assert result.state == "complete"
    assert [resource.path[1].number for resource in result.resources] == [1, 7]
    assert [resource.path[2].number for resource in result.resources] == [0x409, 0xC0A]
    assert len(result.versions) == 2


def test_duplicate_tables_and_distinct_language_codepages_are_preserved() -> None:
    table = _block("040904b0", children=(_block("K", b"a\0\0\0"),))
    spanish = _block("0c0a04e4", children=(_block("K", b"b\0\0\0"),))
    payload = _block(
        "VS_VERSION_INFO",
        kind=0,
        children=(_block("StringFileInfo", children=(table, table, spanish)),),
    )
    result = _read(_tree(payload))
    assert result.state == "complete"
    strings = result.versions[0].strings
    assert [(item.language, item.codepage) for item in strings] == [
        (0x409, 1200),
        (0x409, 1200),
        (0xC0A, 1252),
    ]
    assert len({item.table_index for item in strings}) == 3
    assert result.versions[0].fixed is None


def test_translation_budget_preserves_previous_pairs() -> None:
    payload = _version(translations=bytes.fromhex("0904b0040a0ce404"))
    result = _read(_tree(payload), limits=replace(TEST_LIMITS, translations=1))
    assert "translations_limit" in _codes(result)
    assert len(result.versions[0].translations) == 1
    assert result.versions[0].translations[0].language == 0x409


def test_declared_extent_truncation_does_not_hide_the_root() -> None:
    result = read(b"\0" * 16, ROOT_RVA, 32, (RawRegion(ROOT_RVA, 0, 16),), limits=TEST_LIMITS)
    assert result.state == "partial"
    assert len(result.directories) == 1
    assert _codes(result) == {"noncontiguous_rva"}


def test_zero_size_nonversion_payload_is_an_inventory_entry() -> None:
    result = _read(_tree(b"", type_id=10))
    assert result.state == "complete"
    assert result.resources[0].data_location == Location(ROOT_RVA + 88, FILE_OFFSET + 88, 0)
    assert not result.versions


def test_named_type_is_not_mistaken_for_numeric_rt_version() -> None:
    tree = bytearray(_tree(FIXED_ROOT))
    offset = len(tree)
    name = "16".encode("utf-16-le")
    tree.extend(struct.pack("<H", 2) + name)
    struct.pack_into("<HHI", tree, 12, 1, 0, 0x80000000 | offset)
    result = _read(bytes(tree))
    assert result.state == "complete"
    assert result.resources[0].path[0].number is None
    assert not result.versions


def test_bad_version_key_utf16_keeps_original_key_bytes() -> None:
    string = bytearray(_block("K", b"v\0\0\0"))
    string[6:8] = b"\0\xd8"
    result = _read(_tree(_version(bytes(string))))
    assert "invalid_version_key_utf16" in _codes(result)
    version = result.versions[0]
    key = version.blocks[version.strings[0].block_index].key
    assert key.text is None
    assert key.raw == b"\0\xd8"


def test_unterminated_version_key_and_units_mismatch_are_explicit() -> None:
    missing_nul = bytes.fromhex("0800000001004100")
    result = _read(_tree(missing_nul))
    assert "unterminated_version_key" in _codes(result)
    bad_string = _block("K", b"v\0\0\0", value_length=4)
    assert "version_value_out_of_bounds" in _codes(_read(_tree(_version(bad_string))))


def test_empty_raw_regions_do_not_create_spurious_overlaps() -> None:
    result = read(
        b"\0" * 16,
        ROOT_RVA,
        16,
        (RawRegion(ROOT_RVA, 0, 16), RawRegion(ROOT_RVA + 8, 8, 0)),
        limits=TEST_LIMITS,
    )
    assert result.state == "complete"
    assert not result.omissions


@pytest.mark.parametrize(
    "levels, expected_path", [(1, (16,)), (2, (16, 7)), (4, (16, 7, 0x409, 0x777))]
)
def test_noncanonical_paths_do_not_infer_name_or_language(
    levels: int, expected_path: tuple[int, ...]
) -> None:
    tree = bytearray(_tree(FIXED_ROOT))
    if levels == 1:
        struct.pack_into("<I", tree, 20, 72)
    elif levels == 2:
        struct.pack_into("<I", tree, 44, 72)
    else:
        offset = len(tree)
        tree.extend(b"\0" * 24)
        struct.pack_into("<I", tree, 68, 0x80000000 | offset)
        struct.pack_into("<HHII", tree, offset + 12, 0, 1, 0x777, 72)
    result = _read(bytes(tree))
    resource = result.resources[0]
    assert tuple(item.number for item in resource.path) == expected_path
    assert resource.resource_type == resource.path[0]
    assert resource.resource_name is None
    assert resource.resource_language is None
    assert "noncanonical_resource_levels" in _codes(result)
    assert not result.versions


def test_raw_region_uses_explicit_raw_size_not_a_virtual_extent() -> None:
    region = RawRegion(rva=ROOT_RVA, file_offset=0, raw_size=32)
    assert region.raw_size == 32
    assert not hasattr(region, "size")
    result = read(b"\xff" * 16 + b"\0" * 16, ROOT_RVA + 16, 16, (region,), limits=TEST_LIMITS)
    assert result.state == "complete"
    assert result.directories[0].location == Location(ROOT_RVA + 16, 16, 16)


def test_omission_bases_are_explicit_at_nonzero_payload_offsets() -> None:
    payload = bytearray(FIXED_ROOT)
    payload[38] = 1
    tree = bytearray(_tree(bytes(payload)))
    struct.pack_into("<HH", tree, 12, 1, 0)
    result = _read(bytes(tree))
    resource_issue = next(
        item for item in result.omissions if item.code == "resource_name_partition"
    )
    version_issue = next(
        item for item in result.versions[0].omissions if item.code == "nonzero_version_padding"
    )
    assert resource_issue.base == "resource_directory"
    assert resource_issue.relative_offset == 16
    assert resource_issue.location == Location(ROOT_RVA + 16, FILE_OFFSET + 16, 8)
    assert version_issue.base == "version_payload"
    assert version_issue.relative_offset == 38
    assert version_issue.location == Location(ROOT_RVA + 88 + 38, FILE_OFFSET + 88 + 38, 0)
    limited = _read(bytes(tree), limits=replace(TEST_LIMITS, version_bytes=0))
    omission = limited.versions[0].omissions[0]
    assert omission.base == "version_payload"
    assert omission.relative_offset == 0
    assert omission.location == limited.resources[0].data_location
    invalid = read(b"", ROOT_RVA, 0, (), limits=TEST_LIMITS)
    assert invalid.omissions[0].base == "resource_directory"


@pytest.mark.parametrize("field", [item.name for item in fields(Limits)])
@pytest.mark.parametrize("value", [True, False, 1.0, "1", None, -1])
def test_limits_reject_non_integer_or_negative_values(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        replace(TEST_LIMITS, **{field: value})


def test_limits_require_explicit_values_without_product_defaults() -> None:
    assert inspect.signature(read).parameters["limits"].default is inspect.Parameter.empty
    with pytest.raises(TypeError):
        Limits()


@pytest.mark.parametrize("key", ["", "K", "KK", "KKK"])
@pytest.mark.parametrize("name_bytes", range(8))
def test_version_key_budget_excludes_nul_even_at_odd_limits(key: str, name_bytes: int) -> None:
    raw = key.encode("utf-16-le")
    result = _read(_tree(_block(key, kind=0)), limits=replace(TEST_LIMITS, name_bytes=name_bytes))
    version = result.versions[0]
    if len(raw) <= name_bytes:
        assert len(version.blocks) == 1
        assert version.blocks[0].key.raw == raw
        assert version.blocks[0].key.location.size == len(raw)
        assert "version_key_limit" not in _codes(result)
    else:
        assert not version.blocks
        assert "version_key_limit" in _codes(result)
    assert all(len(block.key.raw) <= name_bytes for block in version.blocks)


@pytest.mark.parametrize("name_bytes", [29, 30, 31, 32])
def test_version_root_key_budget_excludes_terminator(name_bytes: int) -> None:
    result = _read(_tree(FIXED_ROOT), limits=replace(TEST_LIMITS, name_bytes=name_bytes))
    assert (result.state == "complete") == (name_bytes >= 30)
    assert all(len(block.key.raw) <= name_bytes for block in result.versions[0].blocks)


def test_invalid_region_and_negative_configuration() -> None:
    result = read(b"", ROOT_RVA, 16, (RawRegion(ROOT_RVA, -1, 16),), limits=TEST_LIMITS)
    assert _codes(result) == {"invalid_raw_region"}
    with pytest.raises(ValueError, match="resource limit"):
        replace(TEST_LIMITS, entries=-1)
