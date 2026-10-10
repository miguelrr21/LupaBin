import argparse
import json
from pathlib import Path
from typing import Any

from lupabin.analysis import analyze_bytes
from lupabin.evidence.models import Limits, Report
from lupabin.explain.engine import explain, validate
from lupabin.ghidra import build_bundle
from lupabin.glossary.catalog import load_glossary
from lupabin.ingest.reader import from_bytes
from lupabin.saved_report import check_against_sample
from lupabin.web import view
from tests.fixtures.pe_builder import build_capability_demo

OUTPUT = Path(__file__).resolve().parents[1] / "src/lupabin/web/static/example.json"
ORIGIN = (
    "EJEMPLO SINTÉTICO: informe preparado offline con el fixture inofensivo capability-demo, "
    "sin ejecutar sus bytes. No procede de un análisis del worker web. "
    "El informe se validó y se contrastó con los bytes del fixture; sus explicaciones "
    "se regeneraron desde las citas. No se subió ningún archivo ni se consultó VirusTotal."
)


def build_example() -> dict[str, Any]:
    data = build_capability_demo()
    limits = Limits()
    report = Report.model_validate_json(analyze_bytes(data, limits).model_dump_json())
    check_against_sample(report, from_bytes(data, limits))
    if report.extractor_errors:
        raise ValueError("The synthetic example has extractor errors")
    glossary = load_glossary()
    explanation = explain(report, glossary)
    items = validate(explanation, report, glossary)
    if items != explanation.items:
        raise ValueError("The synthetic example has invalid explanations")
    if not any(item.rule == "capability.run_key_value@1" for item in items):
        raise ValueError("The synthetic example is missing its expected capability")
    shown = view.build(report, explanation, items, glossary, None, origin=ORIGIN)
    if "html" not in shown["downloads"]:
        raise ValueError("The synthetic example is missing its HTML export")
    view.ghidra_download(shown, build_bundle(report, data))
    shown["example"] = "capability-demo"
    return shown


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the synthetic web example offline.")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    output = parser.parse_args().output
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite {output}")
    shown = build_example()
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(shown, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(output)


if __name__ == "__main__":
    main()
