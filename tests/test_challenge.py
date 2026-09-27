import json
from copy import deepcopy

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from lupabin.analysis import analyze_bytes
from lupabin.challenge.bank import CATALOG, RULES
from lupabin.challenge.engine import BANK_DIGEST, generate, grade, template, validate, web_challenge
from lupabin.challenge.models import Answers, Challenge
from lupabin.cli import app
from lupabin.evidence.models import Report
from lupabin.render.safe import visible
from tests.fixtures.pe_builder import build_code_demo, build_decode_demo, build_demo, build_pe


@pytest.fixture(scope="module")
def reports():
    return {
        "complete": analyze_bytes(build_demo()),
        "partial": analyze_bytes(build_demo(corrupt=True)),
        "code": analyze_bytes(build_code_demo()),
        "decode": analyze_bytes(build_decode_demo()),
    }


def test_bank_is_versioned_and_pinned():
    assert CATALOG == "lupabin-challenges-v1"
    assert BANK_DIGEST == "41e3bec9cf2a8989365306fd558b2ecf0d7ccea846ab3dac3fe7659ae7bc84bf"


def test_correct_options_agree_with_fields_not_just_answer_key(reports):
    seen = set()
    expected = {
        "section": "El tamaño declarado de los datos de la sección en disco.",
        "import": "Una entrada en la tabla de importaciones indicada.",
        "call": (
            "Una transferencia de llamada reconocida en estático hacia la casilla de ese import."
        ),
        "string": "Observación de bytes interpretados con la codificación indicada.",
        "decoded": "Inferencia reproducible al transformar bytes con el método indicado.",
        "coverage": "No permite concluir ausencia: hay operaciones incompletas o bloqueadas.",
    }
    for report in reports.values():
        challenge = generate(report)
        result = grade(report, template(challenge))
        for question, item in zip(challenge.questions, result.items, strict=True):
            seen.add(question.rule)
            actual = next(
                option.text for option in question.options if option.id == item.correct_option
            )
            if question.rule == "header":
                fact = next(f for f in report.evidence if f.kind == "pe_header")
                assert actual == str(fact.data.number_of_sections)
            else:
                assert actual == expected[question.rule]
    assert seen == {rule.id for rule in RULES}


def test_web_projection_contains_regenerated_feedback_without_changing_downloads(reports):
    from lupabin.explain.engine import explain
    from lupabin.explain.engine import validate as validate_explanation
    from lupabin.glossary.catalog import load_glossary
    from lupabin.web.view import build

    report = reports["decode"]
    glossary = load_glossary()
    explanation = explain(report, glossary)
    items = validate_explanation(explanation, report, glossary)
    shown = build(report, explanation, items, glossary, None)
    assert shown["challenge"] == web_challenge(report)
    assert shown["report_digest"] == generate(report).report_digest
    assert shown["report_schema"] == report.schema_version
    assert shown["challenge"]["challenge_id"] == generate(report).id
    assert shown["downloads"]["report"] == report.model_dump_json(indent=2)
    assert "challenge" not in json.loads(shown["downloads"]["report"])


def answered(report, *, correct=True):
    data = template(generate(report)).model_dump(mode="json")
    web = web_challenge(report)
    for answer, question, feedback in zip(
        data["selections"], web["challenge"]["questions"], web["feedback"], strict=True
    ):
        answer["option_id"] = next(
            option["id"]
            for option in question["options"]
            if (option["id"] == feedback["correct_option"]) == correct
        )
    return Answers.model_validate_json(json.dumps(data))


@pytest.mark.parametrize("name", ["complete", "partial", "code", "decode"])
def test_deterministic_round_trip_and_report_preserved(reports, name):
    report = reports[name]
    before = report.model_dump_json()
    challenge = generate(report)
    assert challenge == generate(report)
    assert Challenge.model_validate_json(challenge.model_dump_json()) == challenge
    assert validate(challenge, report) == challenge
    assert challenge.sample_sha256 == report.sample.sha256
    assert challenge.report_schema == "0.11.0"
    assert len(challenge.questions) <= 7
    assert len({q.id for q in challenge.questions}) == len(challenge.questions)
    facts = {f.id: f for f in report.evidence}
    for question in challenge.questions:
        assert len({o.text for o in question.options}) == 3
        assert question.citations
        for citation in question.citations:
            source = facts[citation.evidence_id] if citation.evidence_id else report
            value = source.model_dump(mode="json")
            for key in citation.path.replace("[", ".").replace("]", "").split("."):
                value = value[int(key)] if isinstance(value, list) else value[key]
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
            assert citation.value == visible(text)
    result = grade(report, answered(report))
    assert result.correct == result.total == len(challenge.questions)
    assert all(item.explanation and item.not_proven and item.citations for item in result.items)
    wrong = grade(report, answered(report, correct=False))
    assert wrong.correct == 0 and wrong.answered == wrong.total
    skipped = grade(report, template(challenge))
    assert skipped.correct == skipped.answered == 0
    assert all(item.outcome == "unanswered" for item in skipped.items)
    assert report.model_dump_json() == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("sample_sha256", "0" * 64),
        ("challenge_id", "0" * 64),
        ("report_schema", "0.1.0"),
        ("catalog", "other"),
    ],
)
def test_answers_reject_wrong_identity(reports, field, value):
    raw = template(generate(reports["code"])).model_dump(mode="json")
    raw[field] = value
    with pytest.raises((ValueError, ValidationError)):
        grade(reports["code"], Answers.model_validate_json(json.dumps(raw)))


@pytest.mark.parametrize("mutation", ["question", "option", "duplicate", "extra", "score"])
def test_answers_reject_unknown_or_duplicate_selections(reports, mutation):
    raw = template(generate(reports["code"])).model_dump(mode="json")
    if mutation == "duplicate":
        raw["selections"].append(raw["selections"][0])
    elif mutation == "extra":
        raw["selections"][0]["correct"] = True
    elif mutation == "score":
        raw["correct"] = True
    else:
        raw["selections"][0]["question_id" if mutation == "question" else "option_id"] = "unknown"
    with pytest.raises((ValueError, ValidationError)):
        grade(reports["code"], Answers.model_validate_json(json.dumps(raw)))


@pytest.mark.parametrize(
    "mutation", ["option", "citation", "prompt", "hash", "duplicate-option", "duplicate-question"]
)
def test_question_export_is_not_authority(reports, mutation):
    report = reports["code"]
    raw = generate(report).model_dump(mode="json")
    if mutation == "option":
        raw["questions"][0]["options"][0]["text"] = "Inventado"
    elif mutation == "citation":
        raw["questions"][0]["citations"][0]["evidence_id"] = "E99999"
    elif mutation == "prompt":
        raw["questions"][0]["prompt"] = "Inventado"
    elif mutation == "duplicate-option":
        raw["questions"][0]["options"][1] = raw["questions"][0]["options"][0]
    elif mutation == "duplicate-question":
        raw["questions"][1] = raw["questions"][0]
    else:
        raw["sample_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        validate(Challenge.model_validate_json(json.dumps(raw)), report)


def test_anchors_ignore_times_but_not_coverage_or_facts(reports):
    report = reports["complete"]
    raw = report.model_dump(mode="json")
    raw["analysis"]["started_at"] = "2020-01-01T00:00:00Z"
    raw["analysis"]["finished_at"] = "2020-01-01T00:00:01Z"
    assert generate(Report.model_validate_json(json.dumps(raw))) == generate(report)
    raw["evidence"][0]["data"]["timestamp_raw"] += 1
    changed = Report.model_validate_json(json.dumps(raw))
    with pytest.raises(ValueError):
        grade(changed, template(generate(report)))


def test_changed_generation_invalidates_old_answers(reports, monkeypatch):
    from lupabin.challenge import engine

    report = reports["complete"]
    original = generate(report)
    candidates = engine._candidates

    def changed_candidates(report):
        selected = candidates(report)
        selected.pop("section")
        return selected

    monkeypatch.setattr(engine, "_candidates", changed_candidates)
    changed = generate(report)
    assert changed.report_digest == original.report_digest
    assert changed.id != original.id
    with pytest.raises(ValueError):
        grade(report, template(original))


def test_multiple_sections_and_strings_are_scoped_to_one_citation(reports):
    report = reports["decode"]
    challenge = generate(report)
    for question in challenge.questions:
        if question.rule in ("section", "string"):
            assert question.citations[0].evidence_id in question.prompt
    assert "decoded" in {q.rule for q in challenge.questions}
    decoded = next(q for q in challenge.questions if q.rule == "decoded")
    assert decoded.level == "inferred"


def test_failed_report_can_teach_coverage_without_inventing_facts():
    raw = analyze_bytes(b"\x00" * 32).model_dump(mode="json")
    raw["extractor_runs"] = [r for r in raw["extractor_runs"] if r["source"] == "pe"]
    raw["extractor_errors"] = [e for e in raw["extractor_errors"] if e["source"] == "pe"]
    raw["limitations"] = [e for e in raw["limitations"] if e["source"] == "pe"]
    raw["yara_context"] = None
    raw["analysis"]["status"] = "failed"
    report = Report.model_validate_json(json.dumps(raw))
    challenge = generate(report)
    assert [q.rule for q in challenge.questions] == ["coverage"]
    assert challenge.questions[0].level == "general"
    assert grade(report, answered(report)).correct == 1


def test_no_questions_without_supported_evidence():
    raw = analyze_bytes(b"\x00" * 32).model_dump(mode="json")
    raw["extractor_runs"] = [r for r in raw["extractor_runs"] if r["source"] == "strings"]
    raw["extractor_errors"] = []
    raw["limitations"] = []
    raw["yara_context"] = None
    raw["analysis"]["status"] = "completed"
    report = Report.model_validate_json(json.dumps(raw))
    challenge = generate(report)
    assert not challenge.questions and challenge.empty_reason
    result = grade(report, template(challenge))
    assert result.total == 0 and "Sin preguntas" in result.summary


def test_hostile_sample_text_is_inert():
    report = analyze_bytes(build_pe(dll=b"evil\x1b[31m.dll", function=b"<script>alert(1)</script>"))
    shown = generate(report).model_dump_json()
    assert "evil" in shown and "U+001B" in shown
    assert "\\u001b" not in shown
    assert grade(report, answered(report)).correct > 0


@pytest.mark.parametrize(
    "content",
    [b"{", b"x" * 65537, b"[]", b'{"correct": true}'],
    ids=("malformed", "oversized", "array", "answer-key"),
)
def test_cli_rejects_malformed_or_large_answers(tmp_path, reports, content):
    path = tmp_path / "report.json"
    path.write_text(reports["code"].model_dump_json(), encoding="utf-8")
    answers = tmp_path / "answers.json"
    answers.write_bytes(content)
    output = CliRunner().invoke(app, ["challenge", str(path), "--answers", str(answers)])
    assert output.exit_code == 2 and "Respuestas inválidas" in output.output


@pytest.mark.parametrize("duplicate", ["identity", "selection"])
def test_cli_rejects_duplicate_json_keys(tmp_path, reports, duplicate):
    report = reports["code"]
    path = tmp_path / "report.json"
    path.write_text(report.model_dump_json(), encoding="utf-8")
    answers = template(generate(report)).model_dump_json()
    if duplicate == "identity":
        answers = '{"challenge_id":"' + "0" * 64 + '",' + answers[1:]
    else:
        answers = answers.replace('"option_id":null', '"option_id":"A","option_id":null', 1)
    answer_path = tmp_path / "answers.json"
    answer_path.write_text(answers, encoding="utf-8")
    output = CliRunner().invoke(app, ["challenge", str(path), "--answers", str(answer_path)])
    assert output.exit_code == 2 and "Respuestas inválidas" in output.output


def test_cli_reports_verification_and_invalid_report_without_network(tmp_path, reports):
    runner = CliRunner()
    path = tmp_path / "report.json"
    path.write_text(reports["code"].model_dump_json(), encoding="utf-8")
    sample = tmp_path / "synthetic.bin"
    sample.write_bytes(build_code_demo())
    checked = runner.invoke(app, ["challenge", str(path), "--sample", str(sample), "--json"])
    assert checked.exit_code == 0, checked.output
    assert "y contrastado con la muestra" in json.loads(checked.stdout)["origin"]
    assert runner.invoke(app, ["challenge", str(path), "--practice", "--json"]).exit_code == 2
    sample.write_bytes(build_pe())
    mismatch = runner.invoke(app, ["challenge", str(path), "--sample", str(sample)])
    assert mismatch.exit_code == 1
    assert json.loads(mismatch.stderr)["error"]["code"] == "report_mismatch"
    path.write_text("{}", encoding="utf-8")
    invalid = runner.invoke(app, ["challenge", str(path)])
    assert invalid.exit_code == 1
    assert json.loads(invalid.stderr)["error"]["code"] == "invalid_report"


def test_revalidation_rejects_a_forged_report_instance(reports):
    report = reports["code"]
    forged = report.model_copy(update={"evidence": report.evidence[1:]})
    with pytest.raises(ValueError):
        generate(forged)


def test_cli_generates_template_and_grades_without_loading_questions(tmp_path, reports):
    runner = CliRunner()
    report = reports["code"]
    path = tmp_path / "report.json"
    path.write_text(report.model_dump_json(), encoding="utf-8")
    before = path.read_bytes()
    output = runner.invoke(app, ["challenge", str(path), "--json"])
    assert output.exit_code == 0, output.output
    document = json.loads(output.stdout)
    assert "sin contrastarlo" in document["origin"]
    assert document["answers_template"]["challenge_id"] == document["challenge"]["id"]
    answers = tmp_path / "answers.json"
    answers.write_text(answered(report).model_dump_json(), encoding="utf-8")
    scored = runner.invoke(app, ["challenge", str(path), "--answers", str(answers), "--json"])
    assert scored.exit_code == 0, scored.output
    assert json.loads(scored.stdout)["result"]["correct"] == len(generate(report).questions)
    practice = runner.invoke(app, ["challenge", str(path), "--practice"], input="\n" * 7)
    assert practice.exit_code == 0, practice.output
    assert "Sin responder" in practice.output and "Citas" in practice.output
    assert path.read_bytes() == before
    invalid = deepcopy(document["answers_template"])
    invalid["selections"][0]["option_id"] = "unknown"
    answers.write_text(json.dumps(invalid), encoding="utf-8")
    assert runner.invoke(app, ["challenge", str(path), "--answers", str(answers)]).exit_code == 2
