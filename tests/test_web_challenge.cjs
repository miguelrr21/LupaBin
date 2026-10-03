"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../src/lupabin/web/static/app.js"), "utf8");

function page() {
  const nodes = new Map();
  const element = () => ({
    textContent: "", children: [], hidden: false, events: {},
    append(...children) { for (const child of children) { child.parent = this; this.children.push(child); } },
    get firstChild() { return this.children[0]; },
    remove() { this.parent.children.splice(this.parent.children.indexOf(this), 1); },
    setAttribute(key, value) { this[key] = value; },
    addEventListener(name, fn) { this.events[name] = fn; },
    scrollIntoView() {},
  });
  const get = (id) => { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); };
  const payload = {
    sample: { sha256: "a".repeat(64) }, report_digest: "c".repeat(64), report_schema: "0.13.0",
    challenge: {
      challenge_id: "b".repeat(64),
      challenge: {
        id: "b".repeat(64), sample_sha256: "a".repeat(64), report_digest: "c".repeat(64),
        schema_version: "0.1.0", report_schema: "0.13.0", catalog: "lupabin-challenges-v1",
        notice: "Práctica, no examen protegido.", empty_reason: null,
        questions: [{ id: "Q1", rule: "string", level: "observed", prompt: "<script>hostile</script>",
          citations: [{ evidence_id: "E1", path: "data.text", value: "<img src=x>" }],
          options: [{ id: "A", text: "Una" }, { id: "B", text: "Otra" }, { id: "C", text: "Tercera" }] }],
      },
      feedback: [{ question_id: "Q1", correct_option: "B", explanation: "Texto literal.",
        not_proven: "No prueba uso.", citations: [{ evidence_id: "E1", path: "data.text", value: "<img src=x>" }] }],
    },
  };
  const ready = [];
  const context = vm.createContext({
    document: { getElementById: get, addEventListener(name, fn) { ready.push(fn); }, createElement: element,
      querySelector: get, querySelectorAll: () => [],
      createTextNode(text) { return { ...element(), textContent: text }; } },
    window: { scrollTo() {} }, clearTimeout() {}, clearInterval() {},
    atob: (value) => Buffer.from(value, "base64").toString("binary"),
    payload,
  });
  vm.runInContext(source, context);
  return { get, context, payload, ready };
}
const text = (node) => [node.textContent, ...node.children.map(text)].join(" ");
const descendants = (node) => [node, ...node.children.flatMap(descendants)];

for (const [selection, correct, unanswered] of [["B", 1, 0], ["A", 0, 0], [null, 0, 1]]) {
  test(`local grading ${selection} keeps evidence and original report`, () => {
    const { context, payload } = page();
    const before = JSON.stringify(payload);
    context.selection = selection;
    const result = JSON.parse(vm.runInContext("JSON.stringify(challenge_grade(payload, { Q1: selection }))", context));
    assert.equal(result.correct, correct);
    assert.equal(result.unanswered, unanswered);
    assert.match(result.items[0].explanation, /literal/);
    assert.equal(JSON.stringify(payload), before);
  });
}

test("identity, questions and options are checked before local grading", () => {
  for (const mutation of ["hash", "question", "option", "feedback"]) {
    const { context, payload } = page();
    context.answers = { Q1: "B" };
    if (mutation === "hash") payload.sample.sha256 = "different";
    if (mutation === "question") context.answers = { unknown: "B" };
    if (mutation === "option") context.answers.Q1 = "unknown";
    if (mutation === "feedback") payload.challenge.feedback[0].question_id = "unknown";
    assert.throws(() => vm.runInContext("challenge_grade(payload, answers)", context));
  }
});

test("practice renders inert text, reveals feedback only after grading and resets", () => {
  const { context, get } = page();
  vm.runInContext("challenge_render(payload)", context);
  let shown = text(get("challenge-content"));
  assert.match(shown, /<script>hostile/);
  assert.doesNotMatch(shown, /Texto literal/);
  const button = descendants(get("challenge-content")).find((node) => node.textContent === "Corregir respuestas");
  button.events.click();
  shown = text(get("challenge-content"));
  assert.match(shown, /Texto literal/);
  assert.match(shown, /E1/);
  assert.match(shown, /Sin responder/);
  vm.runInContext("challenge_render(payload)", context);
  assert.doesNotMatch(text(get("challenge-content")), /Texto literal/);
});

test("radio changes clear stale grades, regrading is deterministic and new reports reset", () => {
  const { context, get, payload } = page();
  const before = JSON.stringify(payload);
  vm.runInContext("challenge_render(payload)", context);
  const nodes = descendants(get("challenge-content"));
  const correct = nodes.find((node) => node.textContent === "Corregir respuestas");
  nodes.find((node) => node.type === "radio" && node.value === "B").events.change();
  correct.events.click();
  const passed = text(get("challenge-content"));
  assert.match(passed, /1\/1 correctas/);
  correct.events.click();
  assert.equal(text(get("challenge-content")), passed);
  nodes.find((node) => node.type === "radio" && node.value === "A").events.change();
  assert.doesNotMatch(text(get("challenge-content")), /1\/1 correctas/);
  assert.match(text(get("challenge-content")), /vuelve a corregir/);
  correct.events.click();
  assert.match(text(get("challenge-content")), /Incorrecta/);
  assert.match(text(get("challenge-content")), /Repasa: string/);
  vm.runInContext("challenge_reset()", context);
  assert.equal(get("challenge-content").children.length, 0);
  assert.equal(get("challenge-panel").hidden, true);
  assert.equal(get("challenge-open")["aria-expanded"], "false");
  assert.equal(JSON.stringify(payload), before);
});

test("malformed identities and duplicate question or option IDs do not render a grade", () => {
  for (const mutation of ["catalog", "schema", "duplicate", "options", "extra-option", "invalid-option", "digest", "feedback-identity", "invalid-id", "version"]) {
    const { context, get, payload } = page();
    const challenge = payload.challenge.challenge;
    if (mutation === "catalog") challenge.catalog = "other";
    if (mutation === "schema") challenge.report_schema = "other";
    if (mutation === "duplicate") challenge.questions.push(challenge.questions[0]);
    if (mutation === "options") challenge.questions[0].options[0].id = "B";
    if (mutation === "extra-option") challenge.questions[0].options.push(challenge.questions[0].options[0]);
    if (mutation === "invalid-option") challenge.questions[0].options[0].id = "unknown";
    if (mutation === "digest") payload.report_digest = "d".repeat(64);
    if (mutation === "feedback-identity") payload.challenge.challenge_id = "d".repeat(64);
    if (mutation === "invalid-id") challenge.id = "invalid";
    if (mutation === "version") challenge.schema_version = "other";
    vm.runInContext("challenge_render(payload)", context);
    assert.match(text(get("challenge-content")), /No se puede validar/);
    assert.doesNotMatch(text(get("challenge-content")), /Corregir respuestas/);
  }
});

test("trailing newlines are not valid digest or question identifiers", () => {
  for (const target of ["digest", "question"]) {
    const { context, get, payload } = page();
    if (target === "digest") {
      payload.challenge.challenge.id += "\n";
      payload.challenge.challenge_id = payload.challenge.challenge.id;
    } else {
      payload.challenge.challenge.questions[0].id += "\n";
      payload.challenge.feedback[0].question_id = payload.challenge.challenge.questions[0].id;
    }
    vm.runInContext("challenge_render(payload)", context);
    assert.match(text(get("challenge-content")), /No se puede validar/);
  }
});

test("a changed report for the same sample cannot reuse displayed answers or grade", () => {
  const { context, get, payload } = page();
  vm.runInContext("challenge_render(payload)", context);
  const nodes = descendants(get("challenge-content"));
  nodes.find((node) => node.type === "radio" && node.value === "B").events.change();
  const grade = nodes.find((node) => node.textContent === "Corregir respuestas");
  grade.events.click();
  assert.match(text(get("challenge-content")), /1\/1 correctas/);
  payload.report_digest = "d".repeat(64);
  payload.challenge.challenge.report_digest = payload.report_digest;
  payload.challenge.challenge.id = "e".repeat(64);
  payload.challenge.challenge_id = payload.challenge.challenge.id;
  grade.events.click();
  assert.match(text(get("challenge-content")), /No se pudo corregir/);
  assert.doesNotMatch(text(get("challenge-content")), /1\/1 correctas/);
});

test("closing practice or leaving the report clears the grade immediately", () => {
  const { context, get, ready } = page();
  vm.runInContext("loadConfig = () => {}; lastResult = { data: payload }; challenge_reset()", context);
  ready[0]();
  get("challenge-open").events.click();
  descendants(get("challenge-content")).find((node) => node.textContent === "Corregir respuestas").events.click();
  assert.match(text(get("challenge-content")), /0\/1 correctas/);
  get("challenge-open").events.click();
  assert.equal(get("challenge-content").children.length, 0);
  get("challenge-open").events.click();
  get("again").events.click();
  assert.equal(get("challenge-content").children.length, 0);
  assert.equal(get("challenge-panel").hidden, true);
  assert.equal(vm.runInContext("lastResult", context), null);
});

test("practice and all three downloads coexist and never reuse a previous report", () => {
  const { context, get, payload, ready } = page();
  const archive = Buffer.from([0x50, 0x4b, 0xff, 0, 0x80]);
  payload.downloads = { ghidra: archive.toString("base64"), report: '{"facts":true}', markdown: "# Informe" };
  context.captures = [];
  const before = JSON.stringify(payload);
  vm.runInContext(`
    loadConfig = () => {};
    renderSummary = renderItems = showVirusTotalStatus = select = () => {};
    download = (data, name, type) => captures.push({ data, name, type });
    lastResult = { data: payload };
    render(payload, "first.exe");
  `, context);
  ready[0]();
  get("challenge-open").events.click();
  descendants(get("challenge-content")).find((node) => node.textContent === "Corregir respuestas").events.click();
  get("ghidra-download").events.click();
  get("download-json").events.click();
  get("download-md").events.click();
  assert.deepEqual(Buffer.from(context.captures[0].data), archive);
  assert.equal(context.captures[1].data, payload.downloads.report);
  assert.equal(context.captures[2].data, payload.downloads.markdown);
  assert.equal(JSON.stringify(payload), before);
  assert.match(text(get("challenge-content")), /0\/1 correctas/);
  get("again").events.click();
  get("ghidra-download").events.click();
  get("download-json").events.click();
  get("download-md").events.click();
  assert.equal(context.captures.length, 3);
  context.next = JSON.parse(before);
  context.next.downloads = { report: "new report", markdown: "new markdown", ghidra_error: "Exportación no disponible" };
  context.next.sample.sha256 = "f".repeat(64);
  context.next.challenge.challenge.sample_sha256 = context.next.sample.sha256;
  vm.runInContext('lastResult = { data: next }; render(next, "second.exe");', context);
  assert.equal(get("challenge-content").children.length, 0);
  assert.equal(get("challenge-panel").hidden, true);
  assert.equal(get("ghidra-download").disabled, true);
  assert.equal(get("ghidra-download").title, context.next.downloads.ghidra_error);
  get("ghidra-download").events.click();
  get("download-json").events.click();
  assert.equal(context.captures.length, 4);
  assert.equal(context.captures[3].data, "new report");
  assert.equal(context.captures[3].name, `${"f".repeat(64)}.lupabin.json`);
  get("challenge-open").events.click();
  assert.doesNotMatch(text(get("challenge-content")), /0\/1 correctas/);
});

test("empty challenge abstains and does not offer a correction button", () => {
  const { context, get, payload } = page();
  payload.challenge.challenge.questions = [];
  payload.challenge.challenge.empty_reason = "Sin preguntas sustentadas.";
  payload.challenge.feedback = [];
  vm.runInContext("challenge_render(payload)", context);
  assert.match(text(get("challenge-content")), /Sin preguntas/);
  assert.doesNotMatch(text(get("challenge-content")), /Corregir respuestas/);
});

test("practice shows how many questions are answered and what each one is answered with", () => {
  const { context, get, ready } = page();
  vm.runInContext("loadConfig = () => {}; lastResult = { data: payload }; challenge_reset()", context);
  ready[0]();
  get("go-practice").events.click();
  assert.equal(get("challenge-panel").hidden, false);
  assert.equal(get("step-practice").className, "done");
  const shown = text(get("challenge-content"));
  assert.match(shown, /Respondidas: 0 de 1\./);
  assert.match(shown, /Q1\. <script>hostile<\/script>\s+Hecho/);
  descendants(get("challenge-content")).find((node) => node.value === "B").events.change();
  assert.match(text(get("challenge-content")), /Respondidas: 1 de 1\./);
  get("go-practice").events.click(); // already open: it stays open, with the answers
  assert.equal(get("challenge-panel").hidden, false);
  assert.match(text(get("challenge-content")), /Respondidas: 1 de 1\./);
});

test("a download closes the downloads menu", () => {
  const { context, get, ready } = page();
  vm.runInContext("loadConfig = () => {}; lastResult = null", context);
  ready[0]();
  get("downloads").open = true;
  get("download-md").events.click();
  assert.equal(get("downloads").open, false);
});
