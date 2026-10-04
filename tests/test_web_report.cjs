"use strict";
// The report by questions: every item lands under its topic, and the search and the
// level filter hide items without changing them.

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../src/lupabin/web/static/app.js"), "utf8");

const QUESTIONS = [
  { id: "identity", title: "¿Qué es?", intro: "Formato.", topics: [{ id: "format", title: "Formato y cabecera" }] },
  { id: "code", title: "¿Qué contiene su código?", intro: "Llamadas.", topics: [
    { id: "capabilities", title: "Capacidades reconocidas" }, { id: "calls", title: "Recorrido y llamadas del código" }] },
  { id: "content", title: "¿Qué textos y datos lleva?", intro: "Textos.", topics: [{ id: "strings", title: "Cadenas de texto" }] },
];

function entry(id, topic, level, statement, values = []) {
  return { id, rule: `${topic}.rule@1`, topic, level, statement, not_proven: "No prueba ejecución.",
    extras: values.length ? [{ label: "Llamadas", values }] : [], evidence: ["E1"], glossary: ["pe.format"] };
}

const many = Array.from({ length: 12 }, (_, index) => `kernel32.dll!Sleep (${index})`);
const ITEMS = [
  entry("X1", "format", "observed", "El archivo es PE32+."),
  entry("X2", "calls", "inferred", "El código llama a funciones importadas.", [...many, "kernel32.dll!CreateProcessW"]),
  entry("X3", "capabilities", "inferred", "Escribe en una clave de arranque automático."),
  entry("X4", "strings", "observed", "<img src=x onerror=1> Contiene 3 cadenas de texto."),
];

function page() {
  const nodes = new Map();
  const element = () => ({
    textContent: "", children: [], hidden: false, events: {}, value: "",
    append(...children) {
      for (const given of children) {
        const child = typeof given === "string" ? { ...element(), textContent: given } : given;
        child.parent = this;
        this.children.push(child);
      }
    },
    get firstChild() { return this.children[0]; },
    remove() { this.parent.children.splice(this.parent.children.indexOf(this), 1); },
    setAttribute(key, value) { this[key] = key === "hidden" ? true : value; },
    getAttribute(key) { return this[key]; },
    addEventListener(name, fn) { this.events[name] = fn; },
    scrollIntoView() { this.scrolled = true; },
    focus() {},
  });
  const get = (id) => { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); };
  const tabs = ["summary", ...QUESTIONS.map((question) => question.id)].map((id) => {
    const tab = get(`tab-${id}`);
    tab.id = `tab-${id}`;
    tab["aria-controls"] = `pane-${id}`;
    return tab;
  });
  const context = vm.createContext({
    document: { getElementById: get, addEventListener() {}, createElement: element,
      querySelector: get, querySelectorAll: () => tabs,
      createTextNode(text) { return { ...element(), textContent: text }; } },
    window: { scrollTo() {} }, clearTimeout() {}, clearInterval() {},
    payload: { items: ITEMS, questions: QUESTIONS, notes: [], omitted: 0, status: "completed",
      sample: { sha256: "a".repeat(64), md5: "b".repeat(32), size: 10, type: "pe" },
      summary: { groups: [], warnings: [] }, downloads: {}, virustotal: null, absence: "" },
  });
  vm.runInContext(source, context);
  vm.runInContext("lastResult = { data: payload, vt: null }; renderItems(payload);", context);
  return { get, context };
}

const text = (node) => [node.textContent, ...node.children.map(text)].join(" ");
const visible = (node) => (node.hidden ? "" : [node.textContent, ...node.children.map(visible)].join(" "));
const run = (context, code) => vm.runInContext(code, context);

test("each question shows its own items, grouped by topic and with their level", () => {
  const { get, context } = page();
  assert.equal(get("count-identity").textContent, "1");
  assert.equal(get("count-code").textContent, "2");
  assert.equal(get("count-content").textContent, "1");
  assert.equal(get("intro-code").textContent, "Llamadas.");
  assert.equal(get("q-code").children.length, 0); // a pane is built when it is opened
  run(context, 'paint("pane-code")');
  const shown = text(get("q-code"));
  assert.match(shown, /Capacidades reconocidas[\s\S]*X3[\s\S]*Recorrido y llamadas del código[\s\S]*X2/);
  assert.match(shown, /Inferencia/);
  assert.doesNotMatch(shown, /X1|X4/);
  assert.match(get("filter-count").textContent, /^4 afirmaciones/);
  assert.equal(get("filter-reset").hidden, true);
});

test("the search hides what does not match, ignoring case and accents", () => {
  const { get, context } = page();
  for (const question of QUESTIONS) run(context, `paint("pane-${question.id}")`);
  run(context, 'setFilter("  CODIGO llama ", "all")');
  assert.equal(get("count-code").textContent, "1/2");
  assert.equal(get("count-identity").textContent, "0/1");
  assert.match(visible(get("q-code")), /X2/);
  assert.doesNotMatch(visible(get("q-code")), /X3|Capacidades reconocidas/);
  assert.equal(get("empty-identity").hidden, false);
  assert.equal(get("empty-code").hidden, true);
  assert.match(get("filter-count").textContent, /^1 de 4 afirmaciones/);
  assert.equal(get("filter-reset").hidden, false);
});

test("a value found by the search is shown even beyond the first eight", () => {
  const { get, context } = page();
  run(context, 'paint("pane-code")');
  assert.doesNotMatch(visible(get("q-code")), /CreateProcessW/);
  run(context, 'setFilter("createprocessw", "all")');
  assert.match(visible(get("q-code")), /CreateProcessW/);
  assert.doesNotMatch(visible(get("q-code")), /Sleep \(11\)/);
});

test("the level filter keeps only facts or only inferences", () => {
  const { get, context } = page();
  for (const question of QUESTIONS) run(context, `paint("pane-${question.id}")`);
  run(context, 'setFilter("", "observed")');
  assert.equal(get("count-code").textContent, "0/2");
  assert.equal(get("count-identity").textContent, "1/1");
  assert.equal(get("level-observed")["aria-pressed"], "true");
  assert.equal(get("level-all")["aria-pressed"], "false");
  run(context, "resetFilter()");
  assert.equal(get("count-code").textContent, "2");
  assert.equal(get("level-all")["aria-pressed"], "true");
  assert.match(visible(get("q-code")), /X3[\s\S]*X2/);
});

test("opening an item from the summary clears a filter that hides it", () => {
  const { get, context } = page();
  run(context, 'setFilter("no-such-text", "all")');
  run(context, 'openItem("X3")');
  assert.equal(get("search").value, "");
  assert.equal(get("tab-code")["aria-selected"], "true");
  assert.equal(get("pane-code").hidden, false);
  assert.match(visible(get("q-code")), /X3/);
});

test("text of the sample stays text in the report and in the search", () => {
  const { get, context } = page();
  run(context, 'paint("pane-content")');
  run(context, 'setFilter("<img", "all")');
  assert.match(visible(get("q-content")), /<img src=x onerror=1>/);
  assert.doesNotMatch(source, /\.innerHTML|insertAdjacentHTML|document\.write\(/);
});

test("the guide marks the sections already opened and starts again with each report", () => {
  const { get, context } = page();
  run(context, 'render(payload, "a.exe")');
  assert.equal(get("step-code").className, "");
  assert.equal(get("step-vt").hidden, true); // no VirusTotal tab, no step for it
  run(context, 'select("tab-code")');
  assert.equal(get("step-code").className, "done");
  assert.equal(get("step-identity").className, "");
  run(context, 'render(payload, "b.exe")');
  assert.equal(get("step-code").className, "");
});
