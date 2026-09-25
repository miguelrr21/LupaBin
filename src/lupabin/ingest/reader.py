import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from lupabin.errors import LupaBinError
from lupabin.evidence.models import Limits, Sample


@dataclass(frozen=True)
class Blob:
    data: bytes
    sample: Sample


def from_bytes(data: bytes, limits: Limits) -> Blob:
    if not data:
        raise LupaBinError("input_empty")
    if len(data) > limits.input_bytes:
        raise LupaBinError("input_limit")
    return Blob(
        data,
        Sample(
            sha256=hashlib.sha256(data).hexdigest(),
            md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
            size=len(data),
            type="unknown",
        ),
    )


def read_sample(path: Path, limits: Limits) -> Blob:
    flags = os.O_RDONLY
    for flag in ("O_BINARY", "O_NONBLOCK", "O_NOFOLLOW"):
        flags |= getattr(os, flag, 0)
    if path.is_dir():  # Windows reports a directory as a permission error
        raise LupaBinError("input_not_file")
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise LupaBinError("input_not_file")
            if before.st_size > limits.input_bytes:
                raise LupaBinError("input_limit")
            data = stream.read(limits.input_bytes + 1)
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise LupaBinError("input_changed")
            if len(data) != before.st_size and len(data) <= limits.input_bytes:
                raise LupaBinError("input_changed")
    except FileNotFoundError:
        raise LupaBinError("input_not_found") from None
    except PermissionError:
        raise LupaBinError("input_permission") from None
    except OSError:
        raise LupaBinError("invalid_input") from None
    return from_bytes(data, limits)
