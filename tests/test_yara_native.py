import pytest

from lupabin.evidence.primitives import YaraLimits
from lupabin.rules.catalog import Catalog, load_catalog
from lupabin.rules.native import scan


@pytest.mark.parametrize(
    "payload,rule",
    [
        (b"This program cannot be run in DOS mode", "lupabin_dos_stub_text"),
        (
            b"VirtualAllocEx WriteProcessMemory CreateRemoteThread",
            "lupabin_process_memory_api_names",
        ),
        (b"RSDS example.pdb", "lupabin_debug_marker_pair"),
        (b"LUPABIN PRACTICE", "lupabin_training_marker"),
        ("LUPABIN PRACTICE".encode("utf-16-le"), "lupabin_training_marker"),
    ],
)
def test_real_native_matches_have_exact_bytes(payload, rule):
    data = b"\0" + payload + b"\0"
    result = scan(data)
    assert result.scan_ok
    assert [match.rule_id for match in result.matches] == [rule]
    assert result.context.package_version == "4.5.4"
    assert result.context.module_version
    for instance in result.matches[0].instances:
        assert (
            bytes.fromhex(instance.raw_hex)
            == data[instance.offset : instance.offset + instance.captured_length]
        )
        assert instance.complete


@pytest.mark.parametrize("payload", [b"benign", b"RSDS", b"example.pdb", b"LUPABIN PRACTIC"])
def test_zero_matches_are_complete_not_failed(payload):
    result = scan(payload)
    assert result.scan_ok
    assert result.matches == ()
    assert result.reason is None


@pytest.mark.parametrize(
    "missing", [b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread"]
)
def test_api_combination_requires_all_names(missing):
    data = b"VirtualAllocEx WriteProcessMemory CreateRemoteThread".replace(missing, b"")
    assert not scan(data).matches


@pytest.mark.parametrize("mode,reason", [("timeout", "yara_timeout"), ("warning", "yara_warning")])
def test_interrupted_scans_discard_matches(monkeypatch, mode, reason):
    import yara

    import lupabin.rules.native as native

    class Rules:
        def __init__(self, original):
            self.original = original

        def __iter__(self):
            return iter(self.original)

        def match(self, **kwargs):
            if mode == "timeout":
                raise yara.TimeoutError("private details")
            kwargs["warnings_callback"](yara.CALLBACK_TOO_MANY_MATCHES, "private details")
            return self.original.match(data=kwargs["data"])

    class Backend:
        __version__ = yara.__version__
        CALLBACK_ABORT = yara.CALLBACK_ABORT
        TimeoutError = yara.TimeoutError

        def set_config(self, **kwargs):
            yara.set_config(**kwargs)

        def compile(self, **kwargs):
            return Rules(yara.compile(**kwargs))

    monkeypatch.setattr(native, "import_module", lambda name: Backend())
    result = native.scan(b"LUPABIN PRACTICE")
    assert result.rules_ok and not result.scan_ok
    assert result.reason == reason
    assert result.matches == ()
    assert "private details" not in result.model_dump_json()


def test_capture_and_occurrence_limits_are_explicit():
    result = scan(b"LUPABIN PRACTICE\0" * 20, YaraLimits(instances=2, capture_bytes=4))
    match = result.matches[0]
    assert result.scan_ok
    assert match.instances_status == "partial"
    assert match.omitted_instances == 18
    assert all(
        i.matched_length == 16 and i.captured_length == 4 and not i.complete
        for i in match.instances
    )


@pytest.mark.parametrize(
    "source,reason",
    [
        ('include "outside.yar"', "yara_compile_error"),
        ("rule invalid { condition: }", "yara_compile_error"),
        (
            'import "console" rule lupabin_training_marker { condition: console.log("untrusted") }',
            "yara_policy_violation",
        ),
        (
            'import "math" rule lupabin_training_marker '
            "{ condition: math.entropy(0, filesize) >= 0 }",
            "yara_policy_violation",
        ),
    ],
)
def test_unapproved_rule_features_are_rejected(source, reason, capsys):
    catalog = load_catalog()
    sources = dict(catalog.sources)
    sources["lupabin_training_marker"] = source
    result = scan(b"LUPABIN PRACTICE", catalog=Catalog(catalog.info, sources))
    assert not result.scan_ok
    assert result.matches == ()
    assert result.reason == reason
    assert "untrusted" not in capsys.readouterr().out
