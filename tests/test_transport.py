import asyncio
import sys

import pytest

from lupabin.errors import LupaBinError
from lupabin.transport import DockerCLI, read_bounded


def test_reader_rejects_output_over_limit():
    async def run():
        stream = asyncio.StreamReader()
        stream.feed_data(b"12345")
        stream.feed_eof()
        return await read_bounded(stream, 4)

    with pytest.raises(LupaBinError) as caught:
        asyncio.run(run())
    assert caught.value.code == "output_limit"


def test_reader_accepts_exact_limit():
    async def run():
        stream = asyncio.StreamReader()
        stream.feed_data(b"1234")
        stream.feed_eof()
        return await read_bounded(stream, 4)

    assert asyncio.run(run()) == b"1234"


def transport_for_python(monkeypatch):
    monkeypatch.setattr("lupabin.transport.shutil.which", lambda _: sys.executable)
    return DockerCLI()


def test_real_transport_keeps_stdout_and_stderr_separate(monkeypatch):
    transport = transport_for_python(monkeypatch)
    result = asyncio.run(
        transport.run(("-c", "import sys; print('out'); print('err', file=sys.stderr)"))
    )
    assert result.code == 0
    assert result.stdout.strip() == b"out"
    assert result.stderr.strip() == b"err"


def test_real_transport_timeout_terminates_child(monkeypatch):
    transport = transport_for_python(monkeypatch)
    created = []
    original = asyncio.create_subprocess_exec

    async def remember(*args, **kwargs):
        process = await original(*args, **kwargs)
        created.append(process)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", remember)
    with pytest.raises(LupaBinError) as caught:
        asyncio.run(transport.run(("-c", "import time; time.sleep(60)"), timeout=0.1))
    assert caught.value.code == "timeout"
    assert created[0].returncode is not None


def test_real_transport_output_limit(monkeypatch):
    transport = transport_for_python(monkeypatch)
    with pytest.raises(LupaBinError) as caught:
        asyncio.run(transport.run(("-c", "print('x' * 10000)"), limit=100))
    assert caught.value.code == "output_limit"
