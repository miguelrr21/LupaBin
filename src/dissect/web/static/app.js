"use strict";
// Dissect web page. Every string from the server goes into the page with textContent;
// nothing here builds markup from data (a test forbids the HTML-parsing sinks).

const $ = (id) => document.getElementById(id);
const VALUES_SHOWN = 8;
const STATUS = { completed: "Análisis completo", partial: "Análisis parcial", failed: "Análisis fallido" };

let config = { max_bytes: 20 * 1024 * 1024, virustotal: false, upload: false };
let chosen = null;
let lastResult = null;
let painted = new Set(); // panes already built for the current result (built when opened)
let vtTimer = null; // the next check of an uploaded file's analysis at VirusTotal
let vtClock = null; // updates the elapsed time shown while VirusTotal analyses
const VT_FOLLOW_MS = 20000; // the public API allows 4 requests per minute
const VT_FOLLOW_LIMIT_MS = 15 * 60 * 1000;

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "className") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

function clear(node) {
  while (node.firstChild) node.firstChild.remove();
}

function bytes(size) {
  if (size < 1024) return `${size} bytes`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1).replace(".", ",")} KiB`;
  return `${(size / 1024 / 1024).toFixed(1).replace(".", ",")} MiB`;
}

function show(section) {
  for (const id of ["upload", "progress", "error", "result"]) $(id).hidden = id !== section;
  window.scrollTo({ top: 0 });
}

// --- upload ----------------------------------------------------------------------------

function choose(file) {
  chosen = file || null;
  $("drop-file").hidden = !chosen;
  $("drop-text").hidden = !!chosen;
  $("drop-file").textContent = chosen ? `${chosen.name} · ${bytes(chosen.size)}` : "";
  const tooBig = chosen && chosen.size > config.max_bytes;
  $("submit").disabled = !chosen || tooBig || chosen.size === 0;
  $("limits-note").textContent = tooBig
    ? `Este archivo supera el máximo de ${bytes(config.max_bytes)}.`
    : chosen && chosen.size === 0 ? "El archivo está vacío." : "";
}

async function loadConfig() {
  try {
    const response = await fetch("/api/config");
    if (response.ok) config = await response.json();
  } catch (_) {
    /* the defaults are enough to show the page */
  }
  $("max-size").textContent = bytes(config.max_bytes);
  $("vt-options").hidden = !config.virustotal;
  $("upload-notice").hidden = !config.upload;
  $("vt-label").textContent = config.upload
    ? "Analizar también en VirusTotal"
    : "Consultar VirusTotal por el SHA-256 del archivo";
}

async function submit(event) {
  event.preventDefault();
  if (!chosen) return;
  const vt = config.virustotal && $("vt").checked;
  const upload = vt && config.upload;
  show("progress");
  $("progress-text").textContent = "Enviando el archivo…";
  const started = Date.now();
  const timer = setInterval(() => {
    const seconds = Math.round((Date.now() - started) / 1000);
    $("progress-time").textContent = `${seconds} s`;
    if (seconds >= 1) $("progress-text").textContent = "Analizando en un contenedor aislado, sin red…";
  }, 500);
  let response;
  let data = null;
  try {
    const body = await chosen.arrayBuffer();
    response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body,
    });
    data = await response.json().catch(() => null);
  } catch (_) {
    fail("No se pudo contactar con el servidor. Comprueba la conexión y vuelve a intentarlo.");
    return;
  } finally {
    clearInterval(timer);
    $("progress-time").textContent = "";
  }
  if (!response.ok || !data || data.error) {
    fail(data && data.message ? data.message : `El servidor respondió con el código ${response.status}.`);
    return;
  }
  try {
    lastResult = { data, name: chosen.name, file: chosen, vt: vt ? { state: "loading", upload } : null };
    render(data, chosen.name); // uses lastResult to paint panes when they open
    show("result");
    if (vt) askVirusTotal(upload);
  } catch (error) {
    console.error(error);
    fail("El análisis terminó, pero la página no pudo mostrarlo. Recarga la página y vuelve a intentarlo.");
  }
}

function fail(message) {
  $("error-text").textContent = message;
  show("error");
}

// --- result ----------------------------------------------------------------------------

function copyButton(text) {
  return el("button", {
    type: "button", className: "copy", text: "Copiar",
    onclick: async (event) => {
      try {
        await navigator.clipboard.writeText(text);
        event.target.textContent = "Copiado";
        setTimeout(() => { event.target.textContent = "Copiar"; }, 1200);
      } catch (_) { /* clipboard not available */ }
    },
  });
}

function renderHead(data, name) {
  $("result-name").textContent = name;
  const badge = $("result-status");
  badge.textContent = STATUS[data.status] || data.status;
  badge.className = `badge ${data.status}`;
  const hashes = $("hashes");
  clear(hashes);
  const rows = [
    ["SHA-256", data.sample.sha256, true],
    ["MD5", data.sample.md5, true],
    ["Tamaño", bytes(data.sample.size), false],
    ["Tipo", data.sample.type, false],
  ];
  for (const [label, value, copy] of rows) {
    hashes.append(el("dt", { text: label }), el("dd", {}, el("span", { text: value }), copy ? copyButton(value) : null));
  }
  renderScore(data.virustotal);
}

function renderScore(vt) {
  const score = $("vt-score");
  const stats = vt && vt.stats;
  const total = stats ? Object.values(stats).reduce((a, b) => a + b, 0) : 0;
  score.hidden = !total;
  if (total) {
    const hits = (stats.malicious || 0);
    score.textContent = `VirusTotal ${hits}/${total}`;
    score.className = `score ${hits ? "hit" : "clean"}`;
    score.title = `${hits} de ${total} motores lo marcan como malicioso (fuente externa)`;
  }
}

function glossaryChip(ref) {
  return el("button", { type: "button", className: "chip plain", text: ref, onclick: () => openEntry(ref) });
}

function values(list) {
  const ul = el("ul", { className: "values" });
  list.forEach((value, index) => {
    ul.append(el("li", { text: String(value), hidden: index >= VALUES_SHOWN }));
  });
  if (list.length <= VALUES_SHOWN) return ul;
  const more = el("button", {
    type: "button", className: "more", text: `Mostrar los ${list.length}`,
    onclick: () => {
      for (const li of ul.children) li.hidden = false;
      more.remove();
    },
  });
  return el("div", {}, ul, more);
}

function item(entry) {
  const node = el("li", { className: "item", id: `item-${entry.id}` },
    el("div", { className: "item-head" },
      el("span", { className: "item-id", text: entry.id }),
      el("span", { className: "item-rule", text: entry.rule })),
    el("p", { className: "statement", text: entry.statement }));
  for (const extra of entry.extras) {
    node.append(el("div", { className: "extra" },
      el("span", { className: "extra-label", text: `${extra.label}:` }), values(extra.values)));
  }
  node.append(el("p", { className: "limit" }, el("strong", { text: "Límite: " }), entry.not_proven));
  const refs = el("div", { className: "refs" }, "Evidencia:");
  const evidence = entry.evidence.length > 12 ? [...entry.evidence.slice(0, 12), `y ${entry.evidence.length - 12} más`] : entry.evidence;
  for (const ref of evidence) refs.append(el("span", { className: "chip plain", text: ref }));
  refs.append(" Glosario:");
  for (const ref of entry.glossary) refs.append(glossaryChip(ref));
  node.append(refs);
  return node;
}

function renderSummary(data) {
  const box = $("summary");
  clear(box);
  if (!data.summary.groups.length) {
    box.append(el("p", { className: "empty", text: "No se reconoció ninguna capacidad." }));
  }
  for (const group of data.summary.groups) {
    const section = el("div", { className: "tactic" }, el("h4", { text: group.tactic }));
    for (const capability of group.items) {
      const block = el("div", { className: "capability" },
        el("p", {}, el("a", { href: `#item-${capability.id}`, className: "item-id", text: capability.id, onclick: (event) => { event.preventDefault(); openItem(capability.id); } }), " ", capability.statement));
      if (capability.techniques.length) {
        const chips = el("div", { className: "chips" });
        for (const technique of capability.techniques) chips.append(el("span", { className: "chip", text: technique }));
        block.append(chips);
      }
      section.append(block);
    }
    box.append(section);
  }
  const warnings = $("warnings");
  clear(warnings);
  for (const warning of data.summary.warnings) {
    warnings.append(el("li", { text: warning.id ? `${warning.id}: ${warning.text}` : warning.text }));
  }
}

function renderLevel(data, level) {
  const list = $(level);
  clear(list);
  const chosenItems = data.items.filter((entry) => entry.level === level);
  if (!chosenItems.length) list.append(el("li", { className: "empty", text: "(ninguno)" }));
  for (const entry of chosenItems) list.append(item(entry));
}

function renderItems(data) {
  for (const level of ["observed", "inferred"]) {
    clear($(level));
    $(`count-${level}`).textContent = String(data.items.filter((entry) => entry.level === level).length);
  }
  const notes = $("notes");
  clear(notes);
  for (const note of data.notes) notes.append(el("li", { text: note }));
  $("omitted").textContent = data.omitted
    ? `${data.omitted} explicaciones se omitieron porque no superaron la validación.`
    : "";
}

function renderVirusTotal(data) {
  const vt = data.virustotal;
  const box = $("vt-report");
  clear(box);
  const state = lastResult && lastResult.vt;
  if (!vt) {
    if (state && state.state === "loading") {
      box.append(el("p", { className: "muted", text: state.upload
        ? "Consultando VirusTotal por el SHA-256. Si no conoce el archivo, se subirá y se seguirá su análisis…"
        : "Consultando VirusTotal por el SHA-256…" }));
    } else if (state && state.state === "error") {
      box.append(el("p", { text: `VirusTotal: ${state.message}` }));
    }
    return;
  }
  box.append(el("h3", { text: vt.title }), el("p", { className: "notice", text: vt.disclaimer }));
  if (vt.note) box.append(el("p", { text: vt.note }));
  const stats = Object.entries(vt.stats || {});
  if (stats.length) {
    const names = { malicious: "maliciosos", suspicious: "sospechosos", undetected: "sin detección", harmless: "inofensivos", timeout: "sin tiempo", "type-unsupported": "tipo no admitido", failure: "fallos", "confirmed-timeout": "tiempo agotado" };
    const row = el("div", { className: "vt-stats" });
    for (const [key, count] of stats) {
      row.append(el("div", { className: `vt-stat ${key}${count ? " hit" : ""}` }, el("b", { text: String(count) }), names[key] || key));
    }
    box.append(row);
  }
  if (vt.rows.length) {
    const table = el("table", { className: "vt-table" });
    for (const entry of vt.rows) table.append(el("tr", {}, el("th", { text: entry.label }), el("td", { text: entry.value })));
    box.append(table);
  }
  if (vt.behaviour.length) {
    box.append(el("h4", { text: "Comportamiento observado en los sandboxes de VirusTotal" }));
    for (const section of vt.behaviour) {
      box.append(el("div", { className: "extra" }, el("span", { className: "extra-label", text: `${section.label} (${section.values.length}):` }), values(section.values)));
    }
    if (vt.omitted) box.append(el("p", { className: "muted small", text: `${vt.omitted} entradas omitidas por formato o límite.` }));
  }
  if (vt.permalink) {
    box.append(el("p", {}, el("a", { href: vt.permalink, target: "_blank", rel: "noopener noreferrer", text: "Ver la ficha en VirusTotal" })));
  }
}

// --- VirusTotal, asked apart so the report never waits for it ------------------------------

function minutes(ms) {
  const seconds = Math.floor(ms / 1000);
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
}

function status(kind, text, detail) {
  const box = $("vt-status");
  box.hidden = false;
  box.className = `vt-status ${kind}`;
  $("vt-status-text").textContent = text;
  $("vt-status-open").hidden = !detail;
}

function showVirusTotalStatus() {
  const state = lastResult && lastResult.vt;
  if (!state) {
    $("vt-status").hidden = true;
    return;
  }
  const vt = lastResult.data.virustotal;
  if (state.state === "loading") {
    status("busy", "VirusTotal: consultando…", false);
  } else if (state.state === "error") {
    status("", `VirusTotal: ${state.message}`, false);
  } else if (state.state === "following") {
    status("busy", `VirusTotal: archivo subido, lo está analizando (${minutes(Date.now() - state.since)}). El resultado aparecerá aquí en cuanto termine.`, true);
  } else if (state.state === "late") {
    status("", "VirusTotal sigue analizándolo después de 15 minutos. Consulta su ficha más tarde.", true);
  } else if (vt && vt.status === "found") {
    const stats = vt.stats || {};
    const total = Object.values(stats).reduce((a, b) => a + b, 0);
    const hits = stats.malicious || 0;
    const text = total
      ? `VirusTotal: ${hits} de ${total} motores lo marcan como malicioso${vt.uploaded ? " (análisis de la subida de ahora)" : ""}.`
      : "VirusTotal conoce el archivo, pero aún no tiene resultados de motores.";
    status(total ? (hits ? "hit" : "clean") : "", text, true);
  } else if (vt && vt.status === "not_found") {
    status("", "VirusTotal no conoce este archivo (no se subió).", true);
  } else if (vt) {
    status("", `VirusTotal: ${vt.note || "no disponible."}`, true);
  }
}

function refreshVirusTotal() {
  renderScore(lastResult.data.virustotal);
  painted.delete("pane-vt");
  if ($("tab-vt").getAttribute("aria-selected") === "true") paint("pane-vt");
  showVirusTotalStatus();
}

function stopFollowing() {
  clearTimeout(vtTimer);
  clearInterval(vtClock);
  vtTimer = vtClock = null;
}

function virusTotalFailed(result, message) {
  if (result !== lastResult) return;
  stopFollowing();
  result.vt = { state: "error", message };
  refreshVirusTotal();
}

function applyVirusTotal(result, vt) {
  if (result !== lastResult) return; // the user moved on to another file
  result.data.virustotal = vt;
  if (vt.status === "queued" && vt.analysis) {
    if (!result.vt || result.vt.state !== "following") {
      result.vt = { state: "following", since: Date.now(), analysis: vt.analysis };
      clearInterval(vtClock);
      vtClock = setInterval(showVirusTotalStatus, 1000);
    }
    if (Date.now() - result.vt.since > VT_FOLLOW_LIMIT_MS) {
      stopFollowing();
      result.vt = { state: "late" };
    } else {
      clearTimeout(vtTimer);
      vtTimer = setTimeout(() => follow(result, vt.sha256, vt.analysis), VT_FOLLOW_MS);
    }
  } else {
    stopFollowing();
    result.vt = { state: "done" };
  }
  refreshVirusTotal();
}

async function askVirusTotal(upload) {
  const result = lastResult;
  try {
    const response = await fetch(`/api/virustotal?upload=${upload ? "1" : "0"}`, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: await result.file.arrayBuffer(),
    });
    const vt = await response.json().catch(() => null);
    if (!response.ok || !vt || vt.error) {
      virusTotalFailed(result, vt && vt.message ? vt.message : "no se pudo consultar.");
      return;
    }
    applyVirusTotal(result, vt);
  } catch (_) {
    virusTotalFailed(result, "no se pudo contactar con el servidor.");
  }
}

async function follow(result, sha256, analysis) {
  if (result !== lastResult) return;
  try {
    const response = await fetch(`/api/virustotal/${sha256}?analysis=${encodeURIComponent(analysis)}`);
    const vt = await response.json().catch(() => null);
    if (!response.ok || !vt || vt.error) {
      virusTotalFailed(result, vt && vt.message ? vt.message : "no se pudo seguir el análisis.");
      return;
    }
    applyVirusTotal(result, vt);
  } catch (_) {
    // a network hiccup: try again at the next interval
    if (result === lastResult) vtTimer = setTimeout(() => follow(result, sha256, analysis), VT_FOLLOW_MS);
  }
}

function renderGlossary(data) {
  const box = $("glossary");
  clear(box);
  for (const entry of data.glossary) {
    const node = el("article", { className: "entry", id: `entry-${entry.id}` },
      el("h3", { text: entry.title }),
      el("p", { className: "item-rule", text: entry.id }),
      el("p", { text: entry.summary }));
    if (entry.not_proven) node.append(el("p", { className: "limit" }, el("strong", { text: "Límite: " }), entry.not_proven));
    const sources = el("ul", { className: "sources" });
    for (const source of entry.sources) {
      const label = `${source.title} (${source.publisher})`;
      sources.append(el("li", {}, source.url
        ? el("a", { href: source.url, target: "_blank", rel: "noopener noreferrer", text: label })
        : `${label}: ${source.document}`));
    }
    node.append(sources);
    box.append(node);
  }
}

const PAINTERS = {
  "pane-observed": (data) => renderLevel(data, "observed"),
  "pane-inferred": (data) => renderLevel(data, "inferred"),
  "pane-vt": renderVirusTotal,
  "pane-glossary": renderGlossary,
};

function paint(pane) {
  if (!lastResult || painted.has(pane) || !PAINTERS[pane]) return;
  painted.add(pane);
  PAINTERS[pane](lastResult.data);
}

function render(data, name) {
  painted = new Set();
  renderHead(data, name);
  renderSummary(data);
  renderItems(data);
  $("tab-vt").hidden = !(data.virustotal || (lastResult && lastResult.vt));
  showVirusTotalStatus();
  $("absence").textContent = data.absence;
  select("tab-summary");
}

// --- tabs ------------------------------------------------------------------------------

function tabs() {
  return [...document.querySelectorAll('[role="tab"]')].filter((tab) => !tab.hidden);
}

function select(id, focus) {
  for (const tab of document.querySelectorAll('[role="tab"]')) {
    const on = tab.id === id;
    tab.setAttribute("aria-selected", on ? "true" : "false");
    tab.tabIndex = on ? 0 : -1;
    $(tab.getAttribute("aria-controls")).hidden = !on;
    if (on) paint(tab.getAttribute("aria-controls"));
    if (on && focus) tab.focus();
  }
}

function openItem(id) {
  paint("pane-observed");
  paint("pane-inferred");
  const target = $(`item-${id}`);
  if (!target) return;
  const pane = target.closest('[role="tabpanel"]');
  select(pane.getAttribute("aria-labelledby"));
  target.scrollIntoView({ block: "start" });
}

function openEntry(ref) {
  paint("pane-glossary");
  const target = $(`entry-${ref}`);
  if (!target) return;
  select("tab-glossary");
  target.scrollIntoView({ block: "start" });
  target.classList.add("flash");
  setTimeout(() => target.classList.remove("flash"), 1300);
}

function download(text, name, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = el("a", { href: url, download: name });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// --- wiring ----------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  loadConfig();
  const drop = $("drop");
  $("file").addEventListener("change", (event) => choose(event.target.files[0]));
  for (const name of ["dragenter", "dragover"]) {
    drop.addEventListener(name, (event) => { event.preventDefault(); drop.classList.add("over"); });
  }
  for (const name of ["dragleave", "drop"]) {
    drop.addEventListener(name, () => drop.classList.remove("over"));
  }
  drop.addEventListener("drop", (event) => {
    event.preventDefault();
    if (event.dataTransfer.files.length) choose(event.dataTransfer.files[0]);
  });
  $("vt").addEventListener("change", () => {
    $("upload-notice").hidden = !config.upload || !$("vt").checked;
  });
  $("vt-status-open").addEventListener("click", () => {
    select("tab-vt");
    $("tab-vt").scrollIntoView({ block: "start" });
  });
  $("form").addEventListener("submit", submit);
  $("error-back").addEventListener("click", () => show("upload"));
  $("again").addEventListener("click", () => {
    stopFollowing();
    lastResult = null;
    $("vt-status").hidden = true;
    $("file").value = "";
    choose(null);
    show("upload");
  });
  $("download-json").addEventListener("click", () => {
    if (lastResult) download(lastResult.data.downloads.report, `${lastResult.data.sample.sha256}.dissect.json`, "application/json");
  });
  $("download-md").addEventListener("click", () => {
    if (lastResult) download(lastResult.data.downloads.markdown, `${lastResult.data.sample.sha256}.dissect.md`, "text/markdown");
  });
  document.querySelector('[role="tablist"]').addEventListener("click", (event) => {
    const tab = event.target.closest('[role="tab"]');
    if (tab) select(tab.id);
  });
  document.querySelector('[role="tablist"]').addEventListener("keydown", (event) => {
    const list = tabs();
    const index = list.findIndex((tab) => tab.getAttribute("aria-selected") === "true");
    let next = null;
    if (event.key === "ArrowRight") next = list[(index + 1) % list.length];
    if (event.key === "ArrowLeft") next = list[(index - 1 + list.length) % list.length];
    if (event.key === "Home") next = list[0];
    if (event.key === "End") next = list[list.length - 1];
    if (next) {
      event.preventDefault();
      select(next.id, true);
    }
  });
});
