import argparse
import json
from pathlib import Path

from dissect.evidence.models import Report


def schema_text() -> str:
    return json.dumps(Report.model_json_schema(), indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("docs/evidence-schema.json"))
    args = parser.parse_args()
    expected = schema_text()
    if args.check:
        return int(not args.output.is_file() or args.output.read_text(encoding="utf-8") != expected)
    args.output.write_text(expected, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
