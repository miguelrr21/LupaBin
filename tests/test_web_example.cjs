"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const staticPath = path.join(__dirname, "../src/lupabin/web/static");
const source = fs.readFileSync(path.join(staticPath, "app.js"), "utf8");
const markup = fs.readFileSync(path.join(staticPath, "index.html"), "utf8");
const run = (context, code) => vm.runInContext(code, context);
const text = (node) => [node.textContent, ...node.children.map(text)].join(" ");
const response = (data) => ({ ok: true, status: 200, json: async () => data });

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function payload() {
  return {
    example: "capability-demo", report_schema: "0.14.0", report_digest: "c".repeat(64),
    sample: { sha256: "a".repeat(64), md5: "b".repeat(32), size: 100, type: "PE32" },
    status: "completed", summary: { groups: [], warnings: [] },
    questions: [{ id: "identity", intro: "Formato", topics: [{ id: "format", title: "Formato" }] }],
    items: [{ id: "X1", topic: "format", rule: "pe.header@1", level: "observed",
      statement: "Texto de prueba", extras: [], not_proven: "No prueba ejecución.", evidence: ["E1"], glossary: [] }],
    notes: [], omitted: 0, glossary: [], absence: "Un ejemplo no es un veredicto.", virustotal: null,
    downloads: { report: "{\"mock\":true}", markdown: "# EJEMPLO SINTÉTICO",
      html: "<!doctype html><html lang=\"es\"><body>EJEMPLO SINTÉTICO</body></html>" },
    challenge: { challenge_id: "d".repeat(64), feedback: [], challenge: {
      id: "d".repeat(64), sample_sha256: "a".repeat(64), report_digest: "c".repeat(64),
      report_schema: "0.14.0", schema_version: "0.1.0", catalog: "lupabin-challenges-v1",
      questions: [], notice: "Práctica de prueba", empty_reason: "Sin preguntas en el mock.",
    } },
  };
}

function page(route = async () => response(payload())) {
  const nodes = new Map();
  const calls = [];
  const timers = new Map();
  let timerId = 0;
  let ready;
  const element = () => ({
    textContent: "", children: [], hidden: false, events: {}, value: "", className: "",
    classList: { add() {}, remove() {} },
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
  const get = (id) => {
    if (!nodes.has(id)) nodes.set(id, element());
    return nodes.get(id);
  };
  const tabs = ["summary", "identity", "code", "content", "vt", "coverage", "glossary"].map((id) => {
    const tab = get(`tab-${id}`);
    tab.id = `tab-${id}`;
    tab["aria-controls"] = `pane-${id}`;
    return tab;
  });
  const settings = { max_bytes: 20 * 1024 * 1024, virustotal: true, upload: true };
  const context = vm.createContext({
    document: { getElementById: get, addEventListener(name, callback) { ready = callback; },
      createElement: element, querySelector: get, querySelectorAll: () => tabs,
      createTextNode(value) { return { ...element(), textContent: value }; } },
    window: { scrollTo() {} }, AbortController, console,
    setInterval(callback) { const id = ++timerId; timers.set(id, callback); return id; },
    setTimeout(callback) { const id = ++timerId; timers.set(id, callback); return id; },
    clearInterval(id) { timers.delete(id); }, clearTimeout(id) { timers.delete(id); },
    fetch: async (url, options = {}) => {
      if (url === "/api/config") return response(settings);
      calls.push({ url, options });
      return route(url, options);
    },
    settings,
    testFile: { name: "normal.bin", size: 5, arrayBuffer: async () => new Uint8Array([1, 2, 3]).buffer },
    event: { preventDefault() {} },
    downloads: [],
  });
  vm.runInContext(source, context);
  ready();
  run(context, "config = settings; download = (...args) => downloads.push(args);");
  get("vt").checked = true;
  return { get, context, calls, timers };
}

test("the start button opens the synthetic report without reading or uploading the selected file", async () => {
  const { get, context, calls } = page();
  context.testFile.arrayBuffer = async () => { throw new Error("must not read selected file"); };
  run(context, "choose(testFile)");
  await get("example-open").events.click();
  assert.match(markup, /id="example-open"[^>]*>Ver informe de ejemplo/);
  assert.deepEqual(calls.map((call) => call.url), ["/static/example.json"]);
  assert.equal(calls[0].options.method, undefined);
  assert.equal(calls[0].options.body, undefined);
  assert.equal(get("result").hidden, false);
  assert.equal(get("example-notice").hidden, false);
  assert.match(get("result-name").textContent, /EJEMPLO SINTÉTICO/);
  assert.equal(get("vt").checked, true);
  assert.equal(get("vt-status").hidden, true);
  assert.equal(get("tab-vt").hidden, true);
  assert.equal(run(context, "chosen"), null);
  assert.equal(run(context, "lastResult.file"), null);
  await run(context, "askVirusTotal(true)");
  assert.equal(calls.length, 1);
});

test("the example shares filters, citations, practice and original downloads", async () => {
  const { get, context } = page();
  await get("example-open").events.click();
  run(context, 'paint("pane-identity"); setFilter("no-match", "all")');
  assert.equal(get("count-identity").textContent, "0/1");
  run(context, 'openItem("X1")');
  assert.equal(get("count-identity").textContent, "1");
  assert.match(text(get("q-identity")), /E1/);
  get("challenge-open").events.click();
  assert.equal(get("challenge-panel").hidden, false);
  assert.match(text(get("challenge-content")), /Práctica de prueba/);
  get("download-json").events.click();
  get("download-md").events.click();
  assert.equal(get("download-html").disabled, false);
  get("download-html").events.click();
  assert.equal(context.downloads[0][0], payload().downloads.report);
  assert.equal(context.downloads[1][0], payload().downloads.markdown);
  assert.equal(context.downloads[2][0], payload().downloads.html);
  assert.match(context.downloads[2][1], /^ejemplo-sintetico-.*\.html$/);
  assert.equal(context.downloads[2][2], "text/html;charset=utf-8");
  assert.match(context.downloads[0][1], /^ejemplo-sintetico-.*\.json$/);
  assert.equal(get("downloads").open, false);
});

test("an oversized HTML export does not disable the other downloads or the report", async () => {
  const data = payload();
  delete data.downloads.html;
  data.downloads.html_error = "La exportación HTML supera el límite.";
  const { get, context } = page(async () => response(data));
  await get("example-open").events.click();
  assert.equal(get("result").hidden, false);
  assert.equal(get("download-html").disabled, true);
  assert.equal(get("download-html").title, data.downloads.html_error);
  get("download-html").events.click();
  assert.equal(context.downloads.length, 0);
  get("download-json").events.click();
  get("download-md").events.click();
  assert.equal(context.downloads.length, 2);
});

test("returning from the example restores normal analysis and its VirusTotal option", async () => {
  const normal = payload();
  delete normal.example;
  const { get, context, calls } = page(async (url) => {
    if (url === "/static/example.json") return response(payload());
    if (url === "/api/analyze") return response(normal);
    return response({ status: "not_found", sha256: normal.sample.sha256 });
  });
  await get("example-open").events.click();
  get("challenge-open").events.click();
  get("again").events.click();
  assert.equal(get("upload").hidden, false);
  assert.equal(get("challenge-panel").hidden, true);
  assert.equal(get("example-notice").hidden, true);
  assert.equal(run(context, "lastResult"), null);
  run(context, "choose(testFile)");
  await get("form").events.submit(context.event);
  await Promise.resolve();
  assert.equal(get("result-name").textContent, "normal.bin");
  assert.equal(get("example-notice").hidden, true);
  assert.deepEqual(calls.map((call) => call.url), ["/static/example.json", "/api/analyze", "/api/virustotal?upload=1"]);
  assert.equal(calls[1].options.method, "POST");
  assert.equal(calls[2].options.method, "POST");
});

test("an old analysis cannot replace the example or start a VirusTotal upload", async () => {
  const pending = deferred();
  const started = deferred();
  const { get, context, calls, timers } = page(async (url) => {
    if (url === "/api/analyze") {
      started.resolve();
      return pending.promise;
    }
    return response(payload());
  });
  run(context, "choose(testFile)");
  const analysis = get("form").events.submit(context.event);
  await started.promise;
  const original = calls[0];
  await get("example-open").events.click();
  assert.equal(original.options.signal.aborted, true);
  assert.equal(timers.size, 0);
  pending.resolve(response(payload()));
  await analysis;
  assert.equal(run(context, "lastResult.example"), true);
  assert.match(get("result-name").textContent, /EJEMPLO SINTÉTICO/);
  assert.equal(calls.some((call) => call.url.startsWith("/api/virustotal")), false);
});

test("leaving a pending example ignores its late response and restores a clean start", async () => {
  const pending = deferred();
  const { get, context, calls } = page(async () => pending.promise);
  const loading = get("example-open").events.click();
  get("progress-back").events.click();
  assert.equal(calls[0].options.signal.aborted, true);
  pending.resolve(response(payload()));
  await loading;
  assert.equal(get("upload").hidden, false);
  assert.equal(run(context, "lastResult"), null);
});

test("a late example JSON body cannot replace a newer normal report", async () => {
  const body = deferred();
  const reading = deferred();
  const normal = payload();
  delete normal.example;
  const { get, context } = page(async (url) => url === "/static/example.json"
    ? { ok: true, json: () => { reading.resolve(); return body.promise; } } : response(normal));
  get("vt").checked = false;
  const loading = get("example-open").events.click();
  await reading.promise;
  run(context, "choose(testFile)");
  await get("form").events.submit(context.event);
  body.resolve(payload());
  await loading;
  assert.equal(get("result-name").textContent, "normal.bin");
  assert.equal(get("example-notice").hidden, true);
});

test("old VirusTotal results and practice state cannot leak into the example", async () => {
  const { get, context, timers } = page();
  context.oldData = payload();
  context.oldResult = null;
  run(context, 'lastResult = { data: oldData, file: testFile, vt: { state: "following" } }; oldResult = lastResult; vtTimer = setTimeout(() => {}, 1); vtClock = setInterval(() => {}, 1); render(oldData, "old.bin"); challenge_toggle(true); setFilter("old", "observed");');
  await get("example-open").events.click();
  run(context, 'applyVirusTotal(oldResult, { status: "found", stats: {} })');
  assert.equal(timers.size, 0);
  assert.equal(run(context, "lastResult.data.virustotal"), null);
  assert.equal(get("challenge-panel").hidden, true);
  assert.equal(get("challenge-content").children.length, 0);
  assert.equal(get("search").value, "");
  assert.equal(get("level-all")["aria-pressed"], "true");
  assert.equal(get("step-practice").className, "");
});

test("switching to the example stops a VirusTotal request still reading its old file", async () => {
  const pending = deferred();
  const { get, context, calls } = page();
  context.oldData = payload();
  context.testFile.arrayBuffer = () => pending.promise;
  run(context, 'startReport(); lastResult = { data: oldData, file: testFile, vt: { state: "loading" } }');
  const lookup = run(context, "askVirusTotal(true)");
  await get("example-open").events.click();
  pending.resolve(new ArrayBuffer(1));
  await lookup;
  assert.deepEqual(calls.map((call) => call.url), ["/static/example.json"]);
});

test("switching to the example aborts an in-flight VirusTotal POST and ignores its late result", async () => {
  const pending = deferred();
  const started = deferred();
  const normal = payload();
  delete normal.example;
  let aborted = false;
  const { get, context, calls, timers } = page(async (url, options) => {
    if (url.startsWith("/api/virustotal")) {
      options.signal.addEventListener("abort", () => { aborted = true; });
      started.resolve();
      return pending.promise;
    }
    return response(url === "/api/analyze" ? normal : payload());
  });
  get("vt").checked = false;
  run(context, "choose(testFile)");
  await get("form").events.submit(context.event);
  const lookup = run(context, "askVirusTotal(true)");
  await started.promise;
  const original = calls.find((call) => call.url === "/api/virustotal?upload=1");
  assert.equal(original.options.method, "POST");
  assert.equal(original.options.signal.aborted, false);
  await get("example-open").events.click();
  assert.equal(original.options.signal.aborted, true);
  assert.equal(aborted, true);
  pending.resolve(response({ status: "queued", sha256: normal.sample.sha256, analysis: "old-analysis" }));
  await lookup;
  assert.equal(run(context, "lastResult.example"), true);
  assert.equal(run(context, "lastResult.data.virustotal"), null);
  assert.equal(run(context, "lastResult.vt"), null);
  assert.equal(get("result").hidden, false);
  assert.equal(get("error").hidden, true);
  assert.match(get("result-name").textContent, /EJEMPLO SINTÉTICO/);
  assert.equal(get("vt-status").hidden, true);
  assert.equal(get("tab-vt").hidden, true);
  assert.equal(timers.size, 0);
  assert.match(markup, /Cambiar de informe no revierte los envíos ya iniciados ni garantiza su cancelación en el servidor\./);
});

for (const [name, route] of [
  ["HTTP error", async () => ({ ok: false, status: 404 })],
  ["network failure", async () => { throw new Error("offline"); }],
  ["invalid JSON", async () => ({ ok: true, json: async () => { throw new Error("invalid JSON"); } })],
  ["wrong artifact", async () => response({ ...payload(), example: "unknown" })],
  ["unexpected VirusTotal data", async () => response({ ...payload(), virustotal: { status: "found" } })],
]) {
  test(`an example ${name} gives a clear error and a way back`, async () => {
    const { get, context } = page(route);
    await get("example-open").events.click();
    assert.equal(get("error").hidden, false);
    assert.match(get("error-title").textContent, /ejemplo/);
    assert.equal(get("error-text").textContent, "No se pudo cargar el informe de ejemplo. Vuelve a intentarlo o analiza tu propio archivo.");
    assert.equal(run(context, "lastResult"), null);
    get("error-back").events.click();
    assert.equal(get("upload").hidden, false);
  });
}

test("a failed obsolete example request does not hide a newer report", async () => {
  const pending = deferred();
  let count = 0;
  const { get } = page(async () => ++count === 1 ? pending.promise : response(payload()));
  const first = get("example-open").events.click();
  await get("example-open").events.click();
  pending.reject(new Error("obsolete"));
  await first;
  assert.equal(get("result").hidden, false);
  assert.equal(get("error").hidden, true);
});

test("the generated artifact renders and preserves the report identity and supported practice", async () => {
  const data = JSON.parse(fs.readFileSync(path.join(staticPath, "example.json"), "utf8"));
  const report = JSON.parse(data.downloads.report);
  assert.equal(data.example, "capability-demo");
  assert.equal(data.virustotal, null);
  assert.equal(data.sample.sha256, report.sample.sha256);
  assert.equal(data.report_schema, report.schema_version);
  assert.equal(data.omitted, 0);
  assert.ok(data.items.some((item) => item.rule === "capability.run_key_value@1"));
  assert.match(data.downloads.markdown, /EJEMPLO SINTÉTICO/);
  assert.doesNotMatch(data.downloads.markdown, /Informe producido ahora por el worker aislado/);
  assert.match(data.downloads.html, /^<!doctype html>/);
  assert.match(data.downloads.html, /EJEMPLO SINTÉTICO/);
  assert.ok(data.downloads.html.includes(report.sample.sha256));
  assert.doesNotMatch(data.downloads.html, /Informe producido ahora por el worker aislado/);
  assert.equal(Buffer.from(data.downloads.ghidra, "base64").subarray(0, 2).toString(), "PK");
  const { get, context, calls } = page(async () => response(data));
  await get("example-open").events.click();
  assert.equal(get("result").hidden, false);
  for (const question of data.questions) run(context, `paint("pane-${question.id}")`);
  get("challenge-open").events.click();
  assert.doesNotMatch(text(get("challenge-content")), /No se puede validar/);
  assert.ok(run(context, "challenge_grade(lastResult.data, {}).total") > 0);
  assert.deepEqual(calls.map((call) => call.url), ["/static/example.json"]);
});
