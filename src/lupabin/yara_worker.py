import argparse
import sys

from lupabin.evidence.primitives import YaraLimits


def main() -> int:
    from lupabin.rules.native import scan

    parser = argparse.ArgumentParser()
    parser.add_argument("--limits-json", required=True)
    args = parser.parse_args()
    try:
        limits = YaraLimits.model_validate_json(args.limits_json)
        data = sys.stdin.buffer.read(20971520 + 1)
        result = scan(data, limits)
        output = (result.model_dump_json() + "\n").encode("utf-8")
        if len(output) > limits.output_bytes:
            return 1
        sys.stdout.buffer.write(output)
        return 0
    except Exception:
        sys.stderr.buffer.write(b'{"error":"yara_worker_failure"}\n')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
