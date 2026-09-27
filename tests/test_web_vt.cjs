"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "../src/lupabin/web/static/app.js"), "utf8");
const complete = {
  malicious: 2, suspicious: 1, undetected: 60, harmless: 0,
  timeout: 0, "confirmed-timeout": 0, "type-unsupported": 0, failure: 0,
};

function page(stats) {
  const nodes = new Map();
  const element = () => ({
    textContent: "", hidden: false, className: "", title: "", children: [],
    append(...children) { this.children.push(...children); },
    setAttribute(key, value) { this[key] = value; },
  });
  const get = (id) => {
    if (!nodes.has(id)) nodes.set(id, element());
    return nodes.get(id);
  };
  const context = vm.createContext({
    document: {
      getElementById: get, addEventListener() {}, createElement: element,
      createTextNode(text) { return { ...element(), textContent: text }; },
    },
    payload: { status: "found", stats, rows: [], behaviour: [] },
  });
  vm.runInContext(source, context);
  vm.runInContext("renderScore(payload); lastResult = { vt: { state: 'done' }, data: { virustotal: payload } }; showVirusTotalStatus();", context);
  return { get, context };
}

for (const key of Object.keys(complete)) {
  test(`missing ${key} never creates a score or total`, () => {
    const stats = { ...complete };
    delete stats[key];
    const { get } = page(stats);
    assert.equal(get("vt-score").hidden, true);
    assert.match(get("vt-status-text").textContent, /recuento.*no está completo/);
    assert.equal(get("vt-status").className, "vt-status ");
  });
}

for (const value of [null, true, -1, 2.5, "2", NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
  test(`invalid malicious counter ${String(value)} is not zero`, () => {
    const { get } = page({ ...complete, malicious: value });
    assert.equal(get("vt-score").hidden, true);
    assert.match(get("vt-status-text").textContent, /recuento.*no está completo/);
    assert.equal(get("vt-status").className, "vt-status ");
  });
}

for (const stats of [null, {}, { ...complete, unknown: 1 }, { ...complete, harmless: Number.MAX_SAFE_INTEGER }]) {
  test(`unusable statistics ${JSON.stringify(stats)} do not become complete`, () => {
    const { get } = page(stats);
    assert.equal(get("vt-score").hidden, true);
    assert.match(get("vt-status-text").textContent, /recuento.*no está completo/);
  });
}

test("statistic cards abstain instead of displaying rounded large integers", () => {
  const { get, context } = page({ ...complete, malicious: Number.MAX_SAFE_INTEGER + 1 });
  vm.runInContext("renderVirusTotal({ virustotal: payload })", context);
  const text = (node) => [node.textContent, ...node.children.map(text)].join(" ");
  const shown = text(get("vt-report"));
  assert.match(shown, /no disponible/);
  assert.doesNotMatch(shown, /9007199254740992/);
});

test("technique comparisons use exact IDs and matching report hashes", () => {
  const { context } = page(complete);
  context.data = {
    sample: { sha256: "a" },
    vt_local_context: { sha256: "a", techniques: { "T1547.001": { status: "static_match", evidence: ["E1"], statement: "local" } } },
    virustotal: { sha256: "a", context: { comparisons: [
      { id: "T1547.001", status: "no_local_report", evidence: [] },
      { id: "T1547", status: "no_local_report", evidence: [] },
      { id: "T1547.001x", status: "invalid_id", evidence: [] },
    ], messages: { unsupported: "unsupported", identity_mismatch: "mismatch" } } },
  };
  const run = () => JSON.parse(vm.runInContext("JSON.stringify(contrastRows(data))", context));
  assert.deepEqual(run().map((row) => row.status), ["static_match", "unsupported", "invalid_id"]);
  assert.deepEqual(run()[0].evidence, ["E1"]);
  context.data.virustotal.sha256 = "b";
  assert.ok(run().every((row) => row.status === "identity_mismatch" && row.evidence.length === 0));
});

test("complete statistics keep the real total", () => {
  const { get } = page(complete);
  assert.equal(get("vt-score").hidden, false);
  assert.equal(get("vt-score").textContent, "VirusTotal 2/63");
  assert.match(get("vt-status-text").textContent, /2 de 63 motores/);
});

test("an explicit zero is different from a missing counter", () => {
  const { get } = page({ ...complete, malicious: 0 });
  assert.equal(get("vt-score").hidden, false);
  assert.equal(get("vt-score").textContent, "VirusTotal 0/61");
});

test("an empty but complete scan does not show a zero-denominator score", () => {
  const { get } = page(Object.fromEntries(Object.keys(complete).map((key) => [key, 0])));
  assert.equal(get("vt-score").hidden, true);
  assert.match(get("vt-status-text").textContent, /no tiene resultados de motores/);
});

test("an incomplete update clears a previous score", () => {
  const { get, context } = page(complete);
  context.payload = { status: "found", stats: { undetected: 60 } };
  vm.runInContext("renderScore(payload)", context);
  assert.equal(get("vt-score").hidden, true);
  assert.equal(get("vt-score").textContent, "");
  assert.equal(get("vt-score").title, "");
});
