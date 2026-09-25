import argparse
import json
import os
import sys
from typing import BinaryIO

from pydantic import ValidationError

from lupabin.analysis import analyze_bytes
from lupabin.errors import LupaBinError
from lupabin.evidence.models import Limits


def write_error(stream: BinaryIO, error: LupaBinError) -> None:
    stream.write(
        (json.dumps({"error": {"code": error.code, "message": str(error)}}) + "\n").encode()
    )


def process(source: BinaryIO, output: BinaryIO, errors: BinaryIO, limits: Limits) -> int:
    try:
        data = source.read(limits.input_bytes + 1)
        report = analyze_bytes(data, limits)
        encoded = (report.model_dump_json() + "\n").encode("utf-8")
        if len(encoded) > limits.output_bytes:
            raise LupaBinError("output_limit")
        output.write(encoded)
        return {"completed": 0, "partial": 3, "failed": 1}[report.analysis.status]
    except LupaBinError as error:
        write_error(errors, error)
    except Exception:
        write_error(errors, LupaBinError("worker_failure"))
    return 1


def main() -> int:
    if sys.platform != "linux":
        write_error(sys.stderr.buffer, LupaBinError("worker_failure"))
        return 1
    if os.getuid() == 0 or os.environ.get("LUPABIN_WORKER") != "1":
        write_error(sys.stderr.buffer, LupaBinError("worker_failure"))
        return 1
    parser = argparse.ArgumentParser()
    parser.add_argument("--limits-json", default=Limits().model_dump_json())
    args = parser.parse_args()
    try:
        limits = Limits.model_validate_json(args.limits_json)
    except ValidationError:
        write_error(sys.stderr.buffer, LupaBinError("worker_failure"))
        return 1
    return process(sys.stdin.buffer, sys.stdout.buffer, sys.stderr.buffer, limits)


if __name__ == "__main__":
    raise SystemExit(main())
