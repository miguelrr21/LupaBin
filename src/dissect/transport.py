import asyncio
import shutil
from dataclasses import dataclass
from typing import Protocol

from dissect.errors import DissectError


@dataclass(frozen=True)
class Completed:
    code: int
    stdout: bytes
    stderr: bytes


class Transport(Protocol):
    async def run(
        self, args: tuple[str, ...], *, data: bytes = b"", timeout: float = 10, limit: int = 8192
    ) -> Completed: ...


async def read_bounded(stream: asyncio.StreamReader, limit: int) -> bytes:
    result = bytearray()
    while chunk := await stream.read(min(65536, limit + 1 - len(result))):
        result.extend(chunk)
        if len(result) > limit:
            raise DissectError("output_limit")
    return bytes(result)


class DockerCLI:
    def __init__(self) -> None:
        executable = shutil.which("docker")
        if executable is None:
            raise DissectError("docker_unavailable")
        self.executable = executable

    async def run(
        self, args: tuple[str, ...], *, data: bytes = b"", timeout: float = 10, limit: int = 8192
    ) -> Completed:
        try:
            process = await asyncio.create_subprocess_exec(
                self.executable,
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError:
            raise DissectError("docker_unavailable") from None
        if process.stdin is None or process.stdout is None or process.stderr is None:
            process.kill()
            await process.wait()
            raise DissectError("worker_failure")
        stdin, stdout, stderr = process.stdin, process.stdout, process.stderr

        async def send() -> None:
            try:
                for offset in range(0, len(data), 65536):
                    stdin.write(data[offset : offset + 65536])
                    await stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                stdin.close()

        output = asyncio.create_task(read_bounded(stdout, limit))
        errors = asyncio.create_task(read_bounded(stderr, min(limit, 65536)))
        sender = asyncio.create_task(send())
        waiter = asyncio.create_task(process.wait())
        tasks = (output, errors, sender, waiter)
        try:
            await asyncio.wait_for(asyncio.gather(*tasks), timeout)
            return Completed(waiter.result(), output.result(), errors.result())
        except TimeoutError:
            raise DissectError("timeout") from None
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            await process.wait()
            await asyncio.gather(*tasks, return_exceptions=True)
