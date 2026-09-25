import asyncio

import pytest

from lupabin.errors import LupaBinError
from lupabin.evidence.primitives import YaraLimits
from lupabin.rules.catalog import load_catalog
from lupabin.rules.native import scan
from lupabin.rules.process import YaraProcessError, scan_child
from lupabin.transport import Completed


@pytest.mark.parametrize(
    "mode,reason",
    [
        ("exit", "yara_process_failure"),
        ("invalid", "yara_result_invalid"),
        ("timeout", "yara_timeout"),
        ("overflow", "yara_output_limit"),
        ("wrong_input", "yara_result_invalid"),
    ],
)
def test_child_failures_are_sanitized(mode, reason):
    async def execute(executable, args, **kwargs):
        assert "-m" in args and "lupabin.yara_worker" in args
        assert kwargs["timeout"] <= 10
        if mode == "timeout":
            raise LupaBinError("timeout")
        if mode == "overflow":
            raise LupaBinError("output_limit")
        if mode == "exit":
            return Completed(-11, b"", b"private crash details")
        if mode == "wrong_input":
            return Completed(0, scan(b"other").model_dump_json().encode(), b"")
        return Completed(0, b"invalid JSON", b"private parse details")

    with pytest.raises(YaraProcessError) as caught:
        asyncio.run(scan_child(b"LUPABIN PRACTICE", YaraLimits(), load_catalog(), execute=execute))
    assert caught.value.code == reason
    assert "private" not in str(caught.value)


def test_real_child_returns_verified_results():
    result = asyncio.run(scan_child(b"LUPABIN PRACTICE", YaraLimits(), load_catalog()))
    assert result.scan_ok
    assert result.matches[0].instances[0].offset == 0
