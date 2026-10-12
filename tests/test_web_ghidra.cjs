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

test("Ghidra help is a native disclosure beside Downloads with the actual ZIP workflow", () => {
  const html = fs.readFileSync(path.join(__dirname, "../src/lupabin/web/static/index.html"), "utf8");
  const help = html.match(/<details class="ghidra-help" id="ghidra-help">([\s\S]*?)<\/details>/);
  assert.ok(help);
  assert.match(help[1], /<summary[^>]*id="ghidra-help-toggle"[^>]*>Cómo usar el ZIP en Ghidra<\/summary>/);
  assert.ok(html.indexOf('id="downloads"') < help.index && help.index < html.indexOf('id="again"'));
  const steps = [...help[1].matchAll(/<li>([\s\S]*?)<\/li>/g)].map((match) => match[1]);
  assert.equal(steps.length, 5);
  assert.match(steps[0], /Descarga[\s\S]*extrae[\s\S]*lupabin-ghidra\.json[\s\S]*ImportLupaBin\.java/);
  assert.match(steps[1], /mismo PE original[\s\S]*sin ejecutarlo/);
  assert.match(steps[2], /Window[\s\S]*Script Manager[\s\S]*Script Directories[\s\S]*ImportLupaBin\.java/);
  assert.match(steps[3], /solo[\s\S]*ImportLupaBin\.java[\s\S]*lupabin-ghidra\.json/);
  assert.match(steps[4], /archivo nuevo[\s\S]*lee[\s\S]*confirma[\s\S]*guarda el programa/);
  assert.match(help[1], /ZIP no contiene el PE/);
  assert.match(help[1], /SHA-256[\s\S]*no desactives/);
  assert.match(help[1], /ejemplo[\s\S]*otro ejecutable/);
  assert.match(help[1], /conserva[\s\S]*anotaciones existentes/);
  assert.match(help[1], /no[\s\S]*veredicto/);
  assert.doesNotMatch(help[1], /\bhidden\b|\bautofocus\b|<script/);
  const exporter = fs.readFileSync(path.join(__dirname, "../src/lupabin/ghidra/__init__.py"), "utf8");
  const importer = fs.readFileSync(path.join(__dirname, "../src/lupabin/ghidra/ImportLupaBin.java"), "utf8");
  for (const name of ["lupabin-ghidra.json", "ImportLupaBin.java"]) assert.ok(exporter.includes(`("${name}",`));
  assert.match(importer, /askFile\("Selecciona lupabin-ghidra\.json"/);
  assert.match(importer, /askFile\("Guardar revisión previa \(archivo NUEVO\)"/);
});

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
