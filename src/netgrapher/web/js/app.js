// netgrapher UI entry point: loads the project, wires toolbar, panels, graph and shortcuts.

import { api, itemPath, startSession } from "./api.js";
import { h } from "./dom.js";
import { screenshot } from "./exporting.js";
import {
  TYPES, applyVisibility, buildElements, edgeData, getFilter, labelOf, nodeData, parentOf,
  parseCidr, placeNewNodes, runLayout, setFilter, stylesheet, visibleLeaves,
} from "./graph.js";
import { History, invert } from "./history.js";
import { renderDetails, renderHiddenList } from "./panels.js";

const $ = (id) => document.getElementById(id);
const state = { doc: null, annotations: {}, view: {}, selected: null };
let cy = null;

cytoscape.use(cytoscapeFcose);
cytoscape.use(cytoscapeDagre);

// -- status ---------------------------------------------------------------------------------

function message(text, isError = false) {
  const el = $("st-msg");
  el.textContent = text;
  el.style.color = isError ? "var(--danger)" : "";
  if (text && !isError) setTimeout(() => { if (el.textContent === text) el.textContent = ""; }, 4000);
}

function setDirty(dirty) {
  state.doc.dirty = dirty;
  $("st-dirty").hidden = !dirty;
  document.title = `${dirty ? "● " : ""}${state.doc.name} — netgrapher`;
}

function updateStatus() {
  $("st-name").textContent = state.doc.path || state.doc.name;
  const total = Object.keys(state.doc.entities).length;
  const shown = cy ? cy.nodes().filter((n) => !n.hasClass("gone")).length : total;
  $("st-counts").textContent = `${shown} of ${total} entities shown`;
  const run = state.doc.runs.at(-1);
  $("st-run").textContent = run ? `${run.mode} · ${run.source} · stopped: ${run.stop_reason}` : "";
  $("btn-save").disabled = !state.doc.can_save;
  setDirty(state.doc.dirty);
}

// -- editing --------------------------------------------------------------------------------

async function applyPatches(items) {
  const result = await api("POST", "/api/annotations:batch", items);
  for (const [id, annotation] of Object.entries(result.annotations)) {
    if (Object.keys(annotation).length) state.annotations[id] = annotation;
    else delete state.annotations[id];
    const el = cy.getElementById(id);
    if (el.nonempty()) {
      el.data("label", labelOf(state, id));
      if (el.isNode() && annotation.position && !el.grabbed()) el.position({ ...annotation.position });
    }
  }
  setDirty(true);
  refresh();
}

const history = new History(() => {
  $("btn-undo").disabled = !history.canUndo;
  $("btn-redo").disabled = !history.canRedo;
});

async function edit(items) {
  const inverse = items.map(({ id, patch }) => ({ id, patch: invert(state.annotations[id] || {}, patch) }));
  try {
    await history.push({
      items, inverse,
      redo: () => applyPatches(items),
      undo: () => applyPatches(inverse),
    });
  } catch (err) {
    message(err.message, true);
  }
}

// Create / delete graph elements. The server broadcasts a user_graph event that updates the
// view (see applyUserGraph); these commands only drive the API and the undo stack.
async function addEntity(spec) {
  let id = null;
  try {
    await history.push({
      redo: async () => { id = (await api("POST", "/api/entities", spec)).id; },
      undo: async () => { await api("DELETE", `/api/entities/${itemPath(id)}`); },
    });
    if (id) select(id);
  } catch (err) {
    message(err.message, true);
    throw err;
  }
}

async function addLink(spec) {
  let id = null;
  try {
    await history.push({
      redo: async () => { id = (await api("POST", "/api/links", spec)).id; },
      undo: async () => { await api("DELETE", `/api/links/${itemPath(id)}`); },
    });
  } catch (err) {
    message(err.message, true);
  }
}

async function remove(id) {
  const kind = state.doc.entities[id] ? "entities" : "links";
  let removed = [];
  try {
    await history.push({
      redo: async () => { removed = (await api("DELETE", `/api/${kind}/${itemPath(id)}`)).deleted; },
      undo: async () => { await api("POST", "/api/restore", { ids: removed }); },
    });
    if (state.selected === id) select(null);
  } catch (err) {
    message(err.message, true);
  }
}

let viewTimer = null;
function saveView() {
  clearTimeout(viewTimer);
  viewTimer = setTimeout(async () => {
    try {
      const view = { ...state.view, zoom: cy.zoom(), pan: cy.pan() };
      state.view = await api("PUT", "/api/view", view);
      setDirty(true);
    } catch (err) {
      message(err.message, true);
    }
  }, 400);
}

function refresh() {
  applyVisibility(cy, state);
  renderHiddenList($("hidden-list"), $("hidden-count"), ctx);
  renderDetails($("details"), ctx, state.selected);
  updateStatus();
}

function select(id) {
  state.selected = id;
  cy.elements().unselect();
  const el = id ? cy.getElementById(id) : null;
  if (el && el.nonempty()) {
    el.select();
    if (!el.hasClass("gone")) cy.animate({ center: { eles: el }, duration: 200 });
  }
  renderDetails($("details"), ctx, id);
}

function toggleCollapse(id) {
  const collapsed = new Set(state.view.collapsed || []);
  if (collapsed.has(id)) collapsed.delete(id); else collapsed.add(id);
  state.view.collapsed = [...collapsed];
  refresh();
  saveView();
}

const ctx = { state, edit, select, toggleCollapse, remove };

// -- graph ----------------------------------------------------------------------------------

function render({ relayout = false, positions = null } = {}) {
  const viewport = cy && positions ? { zoom: cy.zoom(), pan: cy.pan() } : null;
  if (cy) cy.destroy();
  cy = cytoscape({
    container: $("cy"),
    elements: buildElements(state, positions || {}),
    style: stylesheet(),
    boxSelectionEnabled: false,
    selectionType: "single",
  });
  applyVisibility(cy, state);
  if (positions) {
    // Resync during a live run: keep what is on screen, place only what is new.
    const unplaced = cy.nodes().filter((n) => !n.isParent() && !positions[n.id()] && !state.annotations[n.id()]?.position);
    placeNewNodes(cy, state, unplaced.map((n) => n.id()));
    cy.zoom(viewport.zoom);
    cy.pan(viewport.pan);
  } else {
    runLayout(cy, state, { relayout });
    if (!relayout && state.view.zoom && state.view.pan) {
      cy.zoom(state.view.zoom);
      cy.pan(state.view.pan);
    }
  }
  cy.on("tap", "node, edge", (e) => {
    if (linkMode && e.target.isNode()) onLinkPick(e.target.id());
    else select(e.target.id());
  });
  cy.on("tap", (e) => { if (e.target === cy) { if (linkMode) setLinkMode(false); else select(null); } });
  cy.on("dbltap", 'node[type = "subnet"]', (e) => toggleCollapse(e.target.id()));
  cy.on("dragfree", "node", (e) => {
    const node = e.target;
    const moved = node.isParent() ? node.descendants().filter((n) => !n.isParent()) : node;
    edit(moved.map((n) => ({ id: n.id(), patch: { position: { ...n.position() }, pinned: true } })));
  });
  cy.on("zoom pan", () => { state.view.zoom = cy.zoom(); state.view.pan = cy.pan(); });
  refresh();
}

function loadDoc(doc, { positions = null } = {}) {
  state.doc = doc;
  state.annotations = doc.annotations || {};
  state.view = { layout: "fcose", filters: [], collapsed: [], show_hidden: false, ...(doc.view || {}) };
  if (!positions) {
    state.selected = null;
    history.clear();
  }
  syncFilterControls();
  render({ positions });
  showLive(doc.live);
}

// -- live updates (FR-UI-16) ----------------------------------------------------------------

let socket = null;
let paused = false;
let pending = [];

function currentPositions() {
  return cy ? Object.fromEntries(cy.nodes().map((n) => [n.id(), { ...n.position() }])) : {};
}

async function resync() {
  try {
    loadDoc(await api("GET", "/api/project"), { positions: currentPositions() });
  } catch (err) {
    message(`Lost sync with the server: ${err.message}`, true);
  }
}

function connectEvents() {
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/events`);
  socket = ws;
  ws.addEventListener("message", (m) => onEvent(JSON.parse(m.data)));
  ws.addEventListener("close", () => {
    if (socket !== ws) return;
    setTimeout(() => { connectEvents(); }, 2000);
  });
}

function onEvent(ev) {
  switch (ev.type) {
    case "hello":
      if (ev.seq !== state.doc.seq) resync();
      break;
    case "graph":
      if (ev.seq <= state.doc.seq) break; // already in the snapshot
      if (paused) {
        pending.push(ev);
        updatePauseButton();
      } else if (ev.seq !== state.doc.seq + 1) {
        resync();
      } else {
        applyGraph(ev);
      }
      break;
    case "run_stats":
      showLive({ ...ev, running: true });
      break;
    case "run_ended":
      paused = false; // the run is over: apply everything that is still queued
      flushPending();
      refreshMeta();
      break;
    case "annotations":
      applyRemoteAnnotations(ev.annotations);
      break;
    case "user_graph":
      applyUserGraph(ev);
      break;
    case "resync":
      resync();
      break;
    default:
      break;
  }
}

function applyGraph(ev) {
  const doc = state.doc;
  const placedBefore = cy.nodes().filter((n) => !n.isParent()).length;
  const fresh = [];
  if (Object.keys(ev.aliases || {}).length) {
    for (const [oldId, newId] of Object.entries(ev.aliases)) {
      delete state.annotations[oldId];
      if (state.selected === oldId) state.selected = newId;
    }
    for (const [id, annotation] of Object.entries(ev.annotations || {})) {
      if (Object.keys(annotation).length) state.annotations[id] = annotation;
      else delete state.annotations[id];
    }
    history.renameIds(ev.aliases);
    (ev.conflicts || []).forEach((c) => message(c));
  }
  cy.batch(() => {
    for (const id of ev.links_removed) {
      delete doc.links[id];
      cy.getElementById(id).remove();
    }
    for (const id of ev.removed) {
      delete doc.entities[id];
      const node = cy.getElementById(id);
      node.children().move({ parent: null });
      node.remove();
    }
    const entries = Object.entries(ev.entities)
      .sort(([, a], [, b]) => Number(b.type === "subnet") - Number(a.type === "subnet"));
    for (const [id, entity] of entries) doc.entities[id] = entity;
    for (const [id, entity] of entries) {
      const parent = parentOf(state, entity);
      const node = cy.getElementById(id);
      if (node.empty()) {
        cy.add({ group: "nodes", data: { ...nodeData(state, id, entity), ...(parent ? { parent } : {}) } });
        fresh.push(id);
      } else {
        node.data(nodeData(state, id, entity));
        if ((node.parent().nonempty() ? node.parent().id() : null) !== parent) node.move({ parent });
      }
    }
    for (const [id, link] of Object.entries(ev.links)) {
      if (link.type === "member") continue;
      doc.links[id] = link;
      if (!doc.entities[link.a] || !doc.entities[link.b]) continue;
      const edge = cy.getElementById(id);
      if (edge.empty()) cy.add({ group: "edges", data: edgeData(state, id, link) });
      else edge.data(edgeData(state, id, link));
    }
  });
  doc.seq = ev.seq;
  applyVisibility(cy, state);
  if (placedBefore === 0 && fresh.length) {
    runLayout(cy, state, { relayout: true }); // nothing on screen to keep stable yet
  } else {
    placeNewNodes(cy, state, fresh);
  }
  const freshNodes = cy.collection(fresh.map((id) => cy.getElementById(id)));
  freshNodes.addClass("fresh");
  setTimeout(() => freshNodes.removeClass("fresh"), 5000);
  refresh();
}

// A user_graph event carries the full composed entity/link set (discovered + user − deleted).
// Reconcile the view to it: add new, remove gone, update the rest; keep existing positions.
function applyUserGraph(ev) {
  const doc = state.doc;
  const nextEntities = ev.entities;
  const nextLinks = ev.links;
  const fresh = [];
  cy.batch(() => {
    for (const id of Object.keys(doc.links)) {
      if (!(id in nextLinks)) { delete doc.links[id]; cy.getElementById(id).remove(); }
    }
    for (const id of Object.keys(doc.entities)) {
      if (!(id in nextEntities)) {
        delete doc.entities[id];
        const node = cy.getElementById(id);
        node.children().move({ parent: null });
        node.remove();
      }
    }
    const entries = Object.entries(nextEntities)
      .sort(([, a], [, b]) => Number(b.type === "subnet") - Number(a.type === "subnet"));
    for (const [id, entity] of entries) {
      const existed = id in doc.entities;
      doc.entities[id] = entity;
      const parent = parentOf(state, entity);
      const node = cy.getElementById(id);
      if (node.empty()) {
        cy.add({ group: "nodes", data: { ...nodeData(state, id, entity), ...(parent ? { parent } : {}) } });
        fresh.push(id);
      } else {
        node.data(nodeData(state, id, entity));
        if ((node.parent().nonempty() ? node.parent().id() : null) !== parent) node.move({ parent });
      }
    }
    for (const [id, link] of Object.entries(nextLinks)) {
      if (link.type === "member") continue;
      doc.links[id] = link;
      if (!doc.entities[link.a] || !doc.entities[link.b]) continue;
      const edge = cy.getElementById(id);
      if (edge.empty()) cy.add({ group: "edges", data: edgeData(state, id, link) });
      else edge.data(edgeData(state, id, link));
    }
  });
  doc.seq = ev.seq;
  applyVisibility(cy, state);
  if (cy.nodes(":childless").length === fresh.length && fresh.length) runLayout(cy, state, { relayout: true });
  else placeNewNodes(cy, state, fresh);
  setDirty(true);
  refresh();
}

function applyRemoteAnnotations(changes) {
  let changed = false;
  for (const [id, annotation] of Object.entries(changes)) {
    if (JSON.stringify(state.annotations[id] || {}) === JSON.stringify(annotation)) continue;
    if (Object.keys(annotation).length) state.annotations[id] = annotation;
    else delete state.annotations[id];
    const el = cy.getElementById(id);
    if (el.nonempty()) el.data("label", labelOf(state, id));
    changed = true;
  }
  if (changed) {
    setDirty(true);
    refresh();
  }
}

function flushPending() {
  const events = pending;
  pending = [];
  updatePauseButton();
  for (const ev of events) onEvent(ev);
}

function updatePauseButton() {
  $("btn-pause").textContent = paused
    ? `Resume updates${pending.length ? ` (${pending.length})` : ""}`
    : "Pause updates";
}

function clock(seconds) {
  const s = Math.floor(seconds || 0);
  return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}

function showLive(live) {
  const el = $("st-live");
  const running = Boolean(live?.running);
  el.hidden = !live;
  $("btn-pause").hidden = !running;
  if (!live) return;
  el.textContent = running
    ? `● live ${clock(live.elapsed)} · ${(live.packets || 0).toLocaleString()} packets · ${live.entities ?? 0} entities${live.stopping ? ` · stopping (${live.stopping})` : ""}`
    : "capture finished";
}

async function refreshMeta() {
  try {
    const doc = await api("GET", "/api/project");
    for (const key of ["path", "name", "can_save", "dirty", "runs", "live", "seq"]) state.doc[key] = doc[key];
    showLive(doc.live);
    updateStatus();
    message(`Capture finished; saved to ${doc.path}.`);
  } catch (err) {
    message(err.message, true);
  }
}

// -- filters --------------------------------------------------------------------------------

function buildTypeFilters() {
  const root = $("type-filters");
  for (const [type, label] of TYPES) {
    const box = h("input", { type: "checkbox", value: type });
    box.addEventListener("change", () => {
      const checked = [...root.querySelectorAll("input:checked")].map((b) => b.value);
      setFilter(state.view, "entity_types", checked.length === TYPES.length ? null : checked);
      refresh();
      saveView();
    });
    root.append(h("label", {}, box, label));
  }
}

function syncFilterControls() {
  const types = getFilter(state.view, "entity_types", null);
  for (const box of $("type-filters").querySelectorAll("input")) {
    box.checked = !types || types.includes(box.value);
  }
  $("hide-unconfirmed").checked = Boolean(getFilter(state.view, "hide_unconfirmed", false));
  $("prov-filter").value = getFilter(state.view, "provenance_required", "") || "";
  $("hide-cidr").value = getFilter(state.view, "hide_cidr", "") || "";
  $("show-hidden").checked = Boolean(state.view.show_hidden);
  $("sel-layout").value = state.view.layout || "fcose";
}

function wireFilters() {
  buildTypeFilters();
  $("hide-unconfirmed").addEventListener("change", (e) => {
    setFilter(state.view, "hide_unconfirmed", e.target.checked ? true : null);
    refresh();
    saveView();
  });
  $("prov-filter").addEventListener("change", (e) => {
    setFilter(state.view, "provenance_required", e.target.value || null);
    refresh();
    saveView();
  });
  $("hide-cidr").addEventListener("change", (e) => {
    const text = e.target.value.trim();
    if (text && !parseCidr(text)) {
      message(`Not an IPv4 range: ${text}`, true);
      return;
    }
    setFilter(state.view, "hide_cidr", text || null);
    refresh();
    saveView();
  });
  $("show-hidden").addEventListener("change", (e) => {
    state.view.show_hidden = e.target.checked;
    refresh();
    saveView();
  });
}

// -- search ---------------------------------------------------------------------------------

let matches = [];
let matchIndex = -1;

function searchText(id) {
  const e = state.doc.entities[id];
  const parts = [id, labelOf(state, id)];
  if (e) {
    parts.push(e.ip, e.prefix, ...(e.names || []).map((n) => n.name));
    (e.interfaces || []).forEach((i) => parts.push(i.ip));
    if (e.type === "external") parts.push(...(e.addresses || []));
  }
  return parts.filter(Boolean).join(" ").toLowerCase();
}

function wireSearch() {
  const input = $("search");
  input.addEventListener("input", () => {
    const q = input.value.trim().toLowerCase();
    cy.elements().removeClass("match");
    matches = q ? cy.nodes().filter((n) => !n.hasClass("gone") && searchText(n.id()).includes(q)) : [];
    if (q) matches.addClass("match");
    matchIndex = -1;
    message(q ? `${matches.length} match${matches.length === 1 ? "" : "es"}` : "");
  });
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && matches.length) {
      matchIndex = (matchIndex + 1) % matches.length;
      select(matches[matchIndex].id());
    } else if (e.key === "Escape") {
      input.value = "";
      input.dispatchEvent(new Event("input"));
    }
  });
}

// -- project actions ------------------------------------------------------------------------

async function save() {
  if (!state.doc.can_save) {
    message("This project has no file yet; use Save as.", true);
    return;
  }
  try {
    // Store the current layout so the graph reopens exactly as it looks now.
    const items = visibleLeaves(cy)
      .filter((n) => {
        const p = state.annotations[n.id()]?.position;
        return !p || p.x !== n.position().x || p.y !== n.position().y;
      })
      .map((n) => ({ id: n.id(), patch: { position: { ...n.position() } } }));
    if (items.length) await applyPatches(items);
    await api("PUT", "/api/view", { ...state.view, zoom: cy.zoom(), pan: cy.pan() });
    await api("POST", "/api/project/save");
    setDirty(false);
    message("Saved.");
  } catch (err) {
    message(`Save failed: ${err.message}`, true);
  }
}

function confirmDiscard() {
  return !state.doc?.dirty || confirm("Discard unsaved changes to this project?");
}

async function openUpload(file) {
  if (!file || !confirmDiscard()) return;
  try {
    loadDoc(await api("POST", "/api/project/open", await file.arrayBuffer()));
    message(`Opened ${file.name}. Use Save as to keep changes.`);
  } catch (err) {
    message(`Cannot open: ${err.message}`, true);
  }
}

async function refreshRecent() {
  const select = $("sel-recent");
  while (select.options.length > 1) select.remove(1);
  try {
    for (const entry of await api("GET", "/api/project/recent")) {
      select.append(h("option", { value: entry.path }, entry.path));
    }
  } catch (_) {
    // the list is optional
  }
}

// -- creating entities and links ------------------------------------------------------------

const ADD_TITLES = { subnet: "Add network", router: "Add router", host: "Add host", node: "Add node" };
const ADD_FIELD = {
  subnet: ["Prefix", "e.g. 10.0.0.0/24"],
  router: ["IP address", "e.g. 10.0.0.1"],
  host: ["IP address", "e.g. 10.0.0.42"],
  node: null, // label only
};

function openAddDialog(type) {
  const dialog = $("dlg-add");
  $("add-title").textContent = ADD_TITLES[type];
  const field = ADD_FIELD[type];
  $("add-addr-row").hidden = !field;
  if (field) {
    $("add-addr-label").textContent = field[0];
    $("add-addr").placeholder = field[1];
  }
  $("add-addr").value = "";
  $("add-label").value = "";
  $("add-error").hidden = true;
  dialog.returnValue = "";
  dialog.showModal();
  dialog.dataset.type = type;
}

async function submitAddDialog() {
  const dialog = $("dlg-add");
  if (dialog.returnValue !== "ok") return;
  const type = dialog.dataset.type;
  const addr = $("add-addr").value.trim();
  const label = $("add-label").value.trim();
  const spec = { type };
  if (type === "subnet") spec.prefix = addr;
  else if (type === "router" || type === "host") spec.ip = addr;
  if (label) spec.label = label;
  try {
    await addEntity(spec);
  } catch (err) {
    // Re-open with the error so the user can correct it.
    openAddDialog(type);
    $("add-addr").value = addr;
    $("add-label").value = label;
    $("add-error").textContent = err.message;
    $("add-error").hidden = false;
  }
}

let linkMode = false;
let linkSource = null;

function setLinkMode(on) {
  linkMode = on;
  linkSource = null;
  $("btn-link").classList.toggle("primary", on);
  document.body.classList.toggle("linking", on);
  cy.elements().unselect();
  message(on ? "Link mode: click the first node, then the second (Esc to cancel)." : "");
}

async function onLinkPick(id) {
  if (!linkSource) {
    linkSource = id;
    cy.getElementById(id).select();
    message(`Linking from ${labelOf(state, id)}… click the second node.`);
    return;
  }
  if (id === linkSource) return;
  const a = linkSource;
  setLinkMode(false);
  await addLink({ type: "inferred-path", a, b: id });
}

function wireToolbar() {
  $("btn-open").addEventListener("click", () => $("file-open").click());
  $("file-open").addEventListener("change", (e) => {
    openUpload(e.target.files[0]);
    e.target.value = "";
  });
  $("sel-recent").addEventListener("focus", refreshRecent);
  $("sel-recent").addEventListener("change", async (e) => {
    const path = e.target.value;
    e.target.value = "";
    if (!path || !confirmDiscard()) return;
    try {
      loadDoc(await api("POST", "/api/project/open", { path }));
      message(`Opened ${path}.`);
    } catch (err) {
      message(`Cannot open: ${err.message}`, true);
    }
  });
  $("btn-save").addEventListener("click", save);
  $("sel-export").addEventListener("change", (e) => {
    const format = e.target.value;
    e.target.value = "";
    if (!format) return;
    const a = h("a", { href: `/api/export?format=${format}`, download: "" });
    document.body.append(a);
    a.click();
    a.remove();
  });
  $("btn-shot").addEventListener("click", () => $("dlg-shot").showModal());
  $("dlg-shot").addEventListener("close", () => {
    const dialog = $("dlg-shot");
    if (dialog.returnValue !== "ok") return;
    const form = dialog.querySelector("form");
    const opts = Object.fromEntries(new FormData(form).entries());
    opts.anonymize = form.anonymize.checked;
    opts.keep = form.keep.checked;
    try {
      screenshot(cy, state, opts);
    } catch (err) {
      message(`Screenshot failed: ${err.message}`, true);
    }
  });
  $("btn-undo").addEventListener("click", () => history.undo().catch((e) => message(e.message, true)));
  $("btn-redo").addEventListener("click", () => history.redo().catch((e) => message(e.message, true)));
  $("sel-layout").addEventListener("change", (e) => {
    state.view.layout = e.target.value;
    render({ relayout: true });
    saveView();
  });
  $("btn-relayout").addEventListener("click", () => render({ relayout: true }));
  $("btn-fit").addEventListener("click", () => cy.fit(cy.elements(":visible"), 30));
  $("sel-add").addEventListener("change", (e) => {
    const type = e.target.value;
    e.target.value = "";
    if (type) openAddDialog(type);
  });
  $("dlg-add").addEventListener("close", submitAddDialog);
  $("btn-link").addEventListener("click", () => setLinkMode(!linkMode));
  $("btn-pause").addEventListener("click", () => {
    paused = !paused;
    updatePauseButton();
    if (!paused) flushPending();
  });
  $("btn-report").addEventListener("click", async () => {
    try {
      $("report-text").textContent = (await api("GET", "/api/report")).text;
      $("dlg-report").showModal();
    } catch (err) {
      message(err.message, true);
    }
  });
}

function wireKeys() {
  document.addEventListener("keydown", (e) => {
    const typing = ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName);
    const mod = e.ctrlKey || e.metaKey;
    if (mod && e.key.toLowerCase() === "s") {
      e.preventDefault();
      save();
    } else if (!typing && mod && e.key.toLowerCase() === "z") {
      e.preventDefault();
      (e.shiftKey ? history.redo() : history.undo()).catch((err) => message(err.message, true));
    } else if (!typing && mod && e.key.toLowerCase() === "y") {
      e.preventDefault();
      history.redo().catch((err) => message(err.message, true));
    } else if (!typing && (e.key === "Delete" || e.key === "Backspace") && state.selected) {
      e.preventDefault();
      remove(state.selected);
    } else if (e.key === "Escape" && linkMode) {
      e.preventDefault();
      setLinkMode(false);
    } else if (!typing && e.key === "F2" && state.selected) {
      e.preventDefault();
      document.querySelector(".label-edit")?.focus();
    } else if (!typing && e.key === "/") {
      e.preventDefault();
      $("search").focus();
    }
  });
  window.addEventListener("beforeunload", (e) => {
    if (state.doc?.dirty) {
      e.preventDefault();
      e.returnValue = "";
    }
  });
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (cy) cy.style(stylesheet());
  });
}

async function main() {
  try {
    await startSession();
    wireFilters();
    wireSearch();
    wireToolbar();
    wireKeys();
    loadDoc(await api("GET", "/api/project"));
    connectEvents();
    window.netgrapher = { cy: () => cy, state, paused: () => paused, pending: () => pending.length };
  } catch (err) {
    message(err.status === 401
      ? "Not authenticated: open the link printed by `netgrapher ui`."
      : `Cannot load the project: ${err.message}`, true);
  }
}

main();
