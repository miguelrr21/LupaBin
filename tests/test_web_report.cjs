"use strict";
// The report by questions: every item lands under its topic, and the search and the
// level filter hide items without changing them.

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const source = fs.readFileSync(path.join(__dirname, "../src/lupabin/web/static/app.js"), "utf8");
const html = fs.readFileSync(path.join(__dirname, "../src/lupabin/web/static/index.html"), "utf8");
const css = fs.readFileSync(path.join(__dirname, "../src/lupabin/web/static/app.css"), "utf8");
const favicon = fs.readFileSync(path.join(__dirname, "../src/lupabin/web/static/favicon.svg"), "utf8");

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
  const documentEvents = {};
  let active = null;
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
    focus() { active = this; },
    contains(node) { return node === this || this.children.some((child) => child.contains(node)); },
    querySelector(selector) { return this.children.find((child) => child.tagName === selector); },
  });
  const get = (id) => { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); };
  const tabs = ["summary", ...QUESTIONS.map((question) => question.id)].map((id) => {
    const tab = get(`tab-${id}`);
    tab.id = `tab-${id}`;
    tab["aria-controls"] = `pane-${id}`;
    return tab;
  });
  const context = vm.createContext({
    document: { getElementById: get, addEventListener(name, fn) { documentEvents[name] = fn; },
      createElement(tagName) { return { ...element(), tagName }; },
      querySelector: get, querySelectorAll: () => tabs,
      createTextNode(text) { return { ...element(), textContent: text }; } },
    window: { scrollTo() {} }, clearTimeout() {}, clearInterval() {},
    payload: { items: ITEMS, questions: QUESTIONS, notes: [], omitted: 0, status: "completed",
      sample: { sha256: "a".repeat(64), md5: "b".repeat(32), size: 10, type: "pe" },
      summary: { groups: [], warnings: [] }, downloads: {}, virustotal: null, absence: "" },
  });
  vm.runInContext(source, context);
  vm.runInContext("lastResult = { data: payload, vt: null }; renderItems(payload);", context);
  return { get, context, documentEvents, active: () => active,
    wire() {
      run(context, 'loadConfig = () => {};');
      get("downloads").append({ ...element(), tagName: "summary" }, get("download-json"));
      documentEvents.DOMContentLoaded();
    } };
}

const text = (node) => [node.textContent, ...node.children.map(text)].join(" ");
const visible = (node) => (node.hidden ? "" : [node.textContent, ...node.children.map(visible)].join(" "));
const run = (context, code) => vm.runInContext(code, context);
const descendants = (node) => node.children.flatMap((child) => [child, ...descendants(child)]);

test("the reading guide is a vertical list in DOM order on every viewport", () => {
  const guide = html.match(/<ol class="steps">([\s\S]*?)<\/ol>/)[1];
  assert.deepEqual([...guide.matchAll(/<li id="step-([a-z]+)"/g)].map((match) => match[1]),
    ["identity", "code", "content", "vt", "coverage", "practice"]);
  assert.match(guide, /<li id="step-vt" hidden>/);
  assert.doesNotMatch(guide, /\bvalue=|\bstart=|\breversed\b/);
  const rules = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)]
    .filter((match) => match[1].split(",").some((selector) => selector.trim() === ".steps"));
  assert.equal(rules.length, 1);
  assert.match(rules[0][2], /display:\s*block\s*;/);
  assert.doesNotMatch(rules[0][2], /grid|columns|column-count|column-width|flex/);
  for (const rule of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    if (/\.steps|#step-/.test(rule[1])) assert.doesNotMatch(rule[2], /\border\s*:|grid-area|grid-row|grid-column/);
  }
});

test("both themes keep AA text contrast and distinct control and focus boundaries", () => {
  const themes = [...css.matchAll(/:root\s*\{([^}]+)\}/g)].map((match) =>
    Object.fromEntries([...match[1].matchAll(/--([a-z-]+):\s*(#[a-f0-9]{6})\s*;/g)].map((value) => [value[1], value[2]])));
  assert.equal(themes.length, 2);
  const luminance = (color) => [0.2126, 0.7152, 0.0722].reduce((sum, weight, index) => {
    const value = parseInt(color.slice(1 + 2 * index, 3 + 2 * index), 16) / 255;
    return sum + weight * (value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
  }, 0);
  for (const [index, theme] of themes.entries()) {
    const results = {};
    for (const [fg, bg, minimum] of [["text", "panel", 4.5], ["muted", "panel", 4.5],
      ["muted", "bg", 4.5], ["blue", "panel", 4.5], ["blue", "blue-soft", 4.5],
      ["violet", "violet-soft", 4.5], ["on-accent", "blue", 4.5], ["on-accent", "blue-hover", 4.5],
      ["amber", "amber-soft", 4.5], ["red", "red-soft", 4.5],
      ["border-strong", "bg", 3], ["border-strong", "panel", 3], ["focus", "panel", 3]]) {
      const a = luminance(theme[fg]), b = luminance(theme[bg]);
      const ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
      assert.ok(ratio >= minimum, `${index ? "dark" : "light"} ${fg}/${bg}: ${ratio}`);
      results[`${fg}/${bg}`] = Number(ratio.toFixed(2));
    }
    console.log(`${index ? "dark" : "light"} contrast: ${JSON.stringify(results)}`);
  }
});

test("the brand and favicon share an inert geometric lens instead of the old D", () => {
  const mark = html.match(/<svg class="brand-mark"[^>]*>([\s\S]*?)<\/svg>/)[1];
  assert.match(html, /class="brand"[^>]*aria-label="LupaBin, inicio"/);
  assert.match(html, /class="brand-mark"[^>]*aria-hidden="true"/);
  assert.match(mark, /<circle/);
  assert.match(mark, /<rect/);
  for (const shape of mark.matchAll(/<(?:circle|path|rect)\b[^>]*\/>/g)) assert.ok(favicon.includes(shape[0]));
  assert.doesNotMatch(mark + favicon, /<script|<image|<foreignObject|\bon[a-z]+=|\bhref=/i);
  assert.doesNotMatch(mark, /M4 3h7|M8 8h3/);
});

test("Escape closes Downloads and restores focus to its summary only while open", () => {
  const pageView = page();
  const { get, documentEvents, wire, active } = pageView;
  wire();
  get("downloads").open = true;
  get("download-json").focus();
  let prevented = false;
  documentEvents.keydown({ key: "Escape", preventDefault() { prevented = true; } });
  assert.equal(get("downloads").open, false);
  assert.equal(active(), get("downloads").querySelector("summary"));
  assert.equal(prevented, true);
  get("search").focus();
  documentEvents.keydown({ key: "Escape", preventDefault() { assert.fail("closed menu"); } });
  assert.equal(active(), get("search"));
});

test("outside click closes Downloads without stealing focus; inside click keeps it open", () => {
  const { get, documentEvents, wire, active } = page();
  wire();
  get("downloads").open = true;
  documentEvents.click({ target: get("downloads").querySelector("summary") });
  assert.equal(get("downloads").open, true);
  documentEvents.keydown({ key: "Enter", preventDefault() { assert.fail("not Escape"); } });
  assert.equal(get("downloads").open, true);
  get("search").focus();
  documentEvents.click({ target: get("search") });
  assert.equal(get("downloads").open, false);
  assert.equal(active(), get("search"));
});

test("opening Ghidra help closes Downloads without moving focus away from the disclosure", () => {
  const { get, documentEvents, wire, active } = page();
  wire();
  get("downloads").open = true;
  get("ghidra-help-toggle").focus();
  documentEvents.click({ target: get("ghidra-help-toggle") });
  assert.equal(get("downloads").open, false);
  assert.equal(active(), get("ghidra-help-toggle"));
});

test("the guide has five visible steps without VT and six when its section is available", () => {
  const { get, context } = page();
  const names = ["identity", "code", "content", "vt", "coverage", "practice"];
  run(context, 'render(payload, "sample.exe")');
  assert.deepEqual(names.filter((id) => !get(`step-${id}`).hidden), ["identity", "code", "content", "coverage", "practice"]);
  run(context, 'payload.virustotal = { status: "not_found" }; render(payload, "sample.exe")');
  assert.deepEqual(names.filter((id) => !get(`step-${id}`).hidden), names);
});

test("structured header citations navigate to the exact item, not sample-shaped references", () => {
  const { get, context, active } = page();
  run(context, `payload.texts = 'Texto hostil (X999) (X4)';
    payload.header = { texts: [{ text: 'Texto hostil (X999) ' }, { text: '(X4)', item_id: 'X4' }] };
    renderHead(payload, 'sample.exe'); setFilter('nothing', 'inferred');`);
  const links = descendants(get("hashes")).filter((node) => node.className === "header-ref");
  assert.equal(links.length, 1);
  assert.equal(links[0].textContent, "(X4)");
  assert.match(text(get("hashes")), /Texto hostil \(X999\)/);
  links[0].events.click();
  assert.equal(get("tab-content")["aria-selected"], "true");
  assert.equal(get("search").value, "");
  assert.equal(active().id, "item-X4");
  assert.match(text(active()), /<img src=x onerror=1>/);
});

test("legacy headers stay plain and a missing structured target never becomes a link", () => {
  const { get, context } = page();
  run(context, `payload.texts = 'Legacy (X999)'; renderHead(payload, 'old.exe');`);
  assert.match(text(get("hashes")), /Legacy \(X999\)/);
  assert.equal(descendants(get("hashes")).filter((node) => node.className === "header-ref").length, 0);
  run(context, `payload.header = { texts: [{ text: '(X999)', item_id: 'X999' }] };
    renderHead(payload, 'old.exe');`);
  assert.equal(descendants(get("hashes")).filter((node) => node.className === "header-ref").length, 0);
});

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
