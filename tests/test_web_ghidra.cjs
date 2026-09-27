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
    textContent: "", hidden: false, disabled: false, children: [],
    append(...children) { this.children.push(...children); },
    setAttribute(key, value) { this[key] = value; },
    addEventListener() {},
  });
  const get = (id) => {
    if (!nodes.has(id)) nodes.set(id, element());
    return nodes.get(id);
  };
  const captures = [];
  const context = vm.createContext({
    document: {
      getElementById: get, addEventListener() {}, createElement: element,
      createTextNode(text) { return { ...element(), textContent: text }; },
    },
    atob: (value) => Buffer.from(value, "base64").toString("binary"),
    captures,
  });
  vm.runInContext(source, context);
  vm.runInContext("download = (data, name, type) => captures.push({ data, name, type });", context);
  return { context, captures, get };
}

test("Ghidra ZIP download preserves every binary byte and uses only the sample hash", () => {
  const { context, captures } = page();
  const bytes = Buffer.from([0x50, 0x4b, 0, 0xff, 0x80, 0x1b]);
  context.payload = { sample: { sha256: "a".repeat(64) }, downloads: { ghidra: bytes.toString("base64") } };
  vm.runInContext("lastResult = { data: payload }; ghidra_download();", context);
  assert.equal(captures.length, 1);
  assert.deepEqual(Buffer.from(captures[0].data), bytes);
  assert.equal(captures[0].name, `${"a".repeat(64)}.lupabin-ghidra.zip`);
  assert.equal(captures[0].type, "application/zip");
});

test("no download is fabricated when the package is unavailable", () => {
  const { context, captures } = page();
  vm.runInContext("ghidra_download(); lastResult = { data: { downloads: {} } }; ghidra_download();", context);
  assert.equal(captures.length, 0);
});

test("a failed export disables its button without hiding the local report", () => {
  const { context, get } = page();
  context.payload = {
    sample: { sha256: "a".repeat(64), md5: "b".repeat(32), size: 1024, type: "PE32" },
    status: "partial", virustotal: null,
    downloads: { ghidra_error: "No se pudo crear una exportación Ghidra válida." },
  };
  vm.runInContext("renderHead(payload, 'sample.exe');", context);
  assert.equal(get("ghidra-download").disabled, true);
  assert.equal(get("ghidra-download").title, context.payload.downloads.ghidra_error);
  assert.equal(get("result-name").textContent, "sample.exe");
});
