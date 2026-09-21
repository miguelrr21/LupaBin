import argparse
import json
import os
import sys
from typing import BinaryIO

from pydantic import ValidationError

from dissect.analysis import analyze_bytes
from dissect.errors import DissectError
from dissect.evidence.models import Limits


def write_error(stream: BinaryIO, error: DissectError) -> None:
    stream.write(
        (json.dumps({"error": {"code": error.code, "message": str(error)}}) + "\n").encode()
    )


def process(source: BinaryIO, output: BinaryIO, errors: BinaryIO, limits: Limits) -> int:
    try:
        data = source.read(limits.input_bytes + 1)
        report = analyze_bytes(data, limits)
        encoded = (report.model_dump_json() + "\n").encode("utf-8")
        if len(encoded) > limits.output_bytes:
            raise DissectError("output_limit")
        output.write(encoded)
        return {"completed": 0, "partial": 3, "failed": 1}[report.analysis.status]
    except DissectError as error:
        write_error(errors, error)
    except Exception:
        write_error(errors, DissectError("worker_failure"))
    return 1


def main() -> int:
    if sys.platform != "linux":
        write_error(sys.stderr.buffer, DissectError("worker_failure"))
        return 1
    if os.getuid() == 0 or os.environ.get("DISSECT_WORKER") != "1":
        write_error(sys.stderr.buffer, DissectError("worker_failure"))
        return 1
    parser = argparse.ArgumentParser()
    parser.add_argument("--limits-json", default=Limits().model_dump_json())
    args = parser.parse_args()
    try:
        limits = Limits.model_validate_json(args.limits_json)
    except ValidationError:
        write_error(sys.stderr.buffer, DissectError("worker_failure"))
        return 1
    return process(sys.stdin.buffer, sys.stdout.buffer, sys.stderr.buffer, limits)


if __name__ == "__main__":
    raise SystemExit(main())
