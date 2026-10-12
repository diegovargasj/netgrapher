// Cytoscape elements, style, visibility (hiding, filters, collapsed subnets) and layout.

export const TYPES = [
  ["subnet", "Subnets"],
  ["router", "Routers"],
  ["unknown_router", "Unknown routers"],
  ["host", "Hosts"],
  ["external", "Internet"],
];

export function defaultLabel(id, entity) {
  switch (entity.type) {
    case "subnet": return entity.prefix;
    case "host": return entity.ip;
    case "router": return id.replace(/^rtr:/, "");
    case "external": return "Internet";
    default: return "?";
  }
}

export function linkDefaultLabel(link) {
  if (link.type === "interface") return link.ip || "";
  if (link.type === "inferred-path") return link.hops != null ? `~${link.hops} hop${link.hops === 1 ? "" : "s"}` : "path";
  return "";
}

export function labelOf(state, id) {
  const custom = state.annotations[id]?.label;
  if (custom) return custom;
  const entity = state.doc.entities[id];
  if (entity) return defaultLabel(id, entity);
  const link = state.doc.links[id];
  return link ? linkDefaultLabel(link) : id;
}

export function parentOf(state, entity) {
  return entity.type === "host" && state.doc.entities[entity.subnet_id] ? entity.subnet_id : null;
}

export function nodeData(state, id, e) {
  const label = labelOf(state, id);
  return {
    id, type: e.type, label, displayLabel: label, conf: e.confidence,
    kind: e.kind || "", self: e.is_self ? 1 : 0,
  };
}

export function edgeData(state, id, l) {
  const label = labelOf(state, id);
  return { id, source: l.a, target: l.b, type: l.type, label, displayLabel: label, conf: l.confidence };
}

/** positions: optional {id: {x, y}} that wins over saved positions (used when resyncing live). */
export function buildElements(state, positions = {}) {
  const elements = [];
  for (const [id, e] of Object.entries(state.doc.entities)) {
    const data = nodeData(state, id, e);
    const parent = parentOf(state, e);
    if (parent) data.parent = parent;
    const element = { group: "nodes", data };
    const pos = positions[id] || state.annotations[id]?.position;
    if (pos) element.position = { x: pos.x, y: pos.y };
    elements.push(element);
  }
  for (const [id, l] of Object.entries(state.doc.links)) {
    if (l.type === "member") continue; // drawn as containment
    if (!state.doc.entities[l.a] || !state.doc.entities[l.b]) continue;
    elements.push({ group: "edges", data: edgeData(state, id, l) });
  }
  return elements;
}

/**
 * Give new nodes a position next to what they relate to, without moving existing nodes:
 * hosts beside their siblings, other nodes beside their neighbours, the rest to the right.
 */
const GRID_COLS = 6; // hosts per row inside a subnet container
const GRID_STEP_X = 92; // wide enough that IP labels below each host do not overlap
const GRID_STEP_Y = 44;

const isPinned = (state, id) => Boolean(state.annotations[id]?.pinned);

/** Lay a subnet's (unpinned) host children out as a centred grid, so they never form a strip. */
export function gridSubnetChildren(cy, state, parent) {
  const leaves = parent.children().filter((c) => !c.isParent());
  const movable = leaves.filter((c) => !isPinned(state, c.id())).sort((a, b) =>
    a.id() < b.id() ? -1 : a.id() > b.id() ? 1 : 0);
  if (movable.length === 0) return;
  const cols = Math.min(GRID_COLS, movable.length);
  // Anchor at the children's current top-left so the grid grows down and right as hosts arrive,
  // instead of expanding in all directions over neighbouring nodes.
  const positions = leaves.map((n) => n.position());
  const x0 = Math.min(...positions.map((p) => p.x));
  const y0 = Math.min(...positions.map((p) => p.y));
  movable.forEach((n, i) => {
    n.position({ x: x0 + (i % cols) * GRID_STEP_X, y: y0 + Math.floor(i / cols) * GRID_STEP_Y });
  });
}

export function gridAllSubnets(cy, state) {
  cy.nodes('node[type = "subnet"]').forEach((subnet) => gridSubnetChildren(cy, state, subnet));
}

/** Place freshly added nodes without moving the rest; subnets with new hosts are re-gridded. */
export function placeNewNodes(cy, state, newIds) {
  const pending = new Set(newIds);
  const isPlaced = (n) => !pending.has(n.id());
  const jitter = () => (Math.random() - 0.5) * 30;
  const fresh = cy.collection(newIds.map((id) => cy.getElementById(id)).filter((n) => n.nonempty()));

  // Non-subnet leaves with no parent (routers, external, unknown): anchor near a placed neighbour.
  let fallbackRow = 0;
  fresh.filter((n) => !n.isParent() && n.parent().empty()).forEach((n) => {
    const around = n.neighborhood("node").filter(isPlaced);
    let anchor = null;
    if (around.nonempty()) {
      const bb = around.boundingBox();
      anchor = { x: (bb.x1 + bb.x2) / 2 + 90, y: (bb.y1 + bb.y2) / 2 + 40 };
    } else {
      const placed = cy.nodes().filter((m) => isPlaced(m) && !m.isParent() && m.parent().empty());
      const bb = placed.nonempty() ? placed.boundingBox() : { x2: 0, y1: 0 };
      anchor = { x: bb.x2 + 120, y: bb.y1 + 70 * fallbackRow++ };
    }
    n.position({ x: anchor.x + jitter(), y: anchor.y + jitter() });
    pending.delete(n.id());
  });

  // Each subnet that gained a host (or is itself new): re-grid its children as a block.
  const touched = new Set();
  fresh.forEach((n) => {
    const parent = n.isParent() ? n : n.parent();
    if (parent.nonempty() && parent.data("type") === "subnet") touched.add(parent.id());
  });
  touched.forEach((id) => {
    const subnet = cy.getElementById(id);
    // A brand-new subnet with children needs a starting anchor before its grid is centred.
    const unplacedParent = pending.has(id);
    if (unplacedParent) {
      const around = subnet.neighborhood("node").filter(isPlaced);
      const seed = around.nonempty()
        ? (() => { const b = around.boundingBox(); return { x: (b.x1 + b.x2) / 2, y: b.y2 + 120 }; })()
        : { x: 0, y: 0 };
      subnet.children(":childless").forEach((c, i) => c.position({ x: seed.x + i, y: seed.y }));
    }
    gridSubnetChildren(cy, state, subnet);
  });
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export function stylesheet() {
  const c = (n) => cssVar(n);
  const opacity = "mapData(conf, 0, 1, 0.35, 1)";
  return [
    { selector: "node", style: {
      label: "data(displayLabel)", color: c("--text"), "font-size": 10,
      "text-valign": "bottom", "text-margin-y": 3, "text-wrap": "ellipsis", "text-max-width": 140,
      "background-color": c("--node-host"), width: 14, height: 14, opacity,
    } },
    { selector: 'node[type = "subnet"]', style: {
      shape: "round-rectangle", "background-color": c("--node-subnet-bg"),
      "border-color": c("--node-subnet-border"), "border-width": 1.5,
      "text-valign": "top", "text-margin-y": -4, "font-weight": "bold", "font-size": 11,
      width: 70, height: 36, padding: 14,
    } },
    { selector: 'node[type = "subnet"][kind = "remote"]', style: { "border-style": "dashed" } },
    { selector: 'node[type = "router"]', style: {
      shape: "round-rectangle", "background-color": c("--node-router"), width: 30, height: 22,
      "font-weight": "bold",
    } },
    { selector: 'node[type = "unknown_router"]', style: {
      shape: "octagon", "background-color": c("--node-unknown"), width: 24, height: 24,
      "border-width": 2, "border-style": "dashed", "border-color": c("--text"),
    } },
    { selector: 'node[type = "external"]', style: {
      shape: "barrel", "background-color": c("--node-external"), width: 46, height: 30,
    } },
    { selector: "node[self = 1]", style: {
      "background-color": c("--node-self"), "border-width": 3, "border-color": c("--node-self"),
      "border-opacity": 0.4, width: 18, height: 18,
    } },
    { selector: "node.collapsed", style: { width: 90, height: 40 } },
    { selector: "edge", style: {
      width: 1.5, "line-color": c("--edge"), "curve-style": "bezier", opacity,
      label: "data(displayLabel)", "font-size": 9, color: c("--muted"),
      "text-background-color": c("--bg"), "text-background-opacity": 0.8,
      "text-background-padding": 1, "text-rotation": "autorotate",
    } },
    { selector: 'edge[type = "inferred-path"]', style: { "line-style": "dashed" } },
    { selector: 'edge[type = "uplink"]', style: { width: 2.5 } },
    { selector: ".ghost", style: { opacity: 0.18 } },
    { selector: ".gone", style: { display: "none" } },
    { selector: ".fresh", style: { "overlay-color": c("--node-self"), "overlay-opacity": 0.45, "overlay-padding": 7 } },
    { selector: ".match", style: { "overlay-color": c("--match"), "overlay-opacity": 0.35, "overlay-padding": 4 } },
    { selector: ":selected", style: { "overlay-color": c("--accent"), "overlay-opacity": 0.25, "overlay-padding": 5 } },
  ];
}

// -- filters --------------------------------------------------------------------------------

export function getFilter(view, type, fallback) {
  const f = (view.filters || []).find((x) => x.type === type);
  return f ? f.value : fallback;
}

export function setFilter(view, type, value) {
  view.filters = (view.filters || []).filter((x) => x.type !== type);
  if (value !== null && value !== undefined && value !== "") view.filters.push({ type, value });
}

function ipToInt(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => !(p >= 0 && p <= 255))) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function parseCidr(text) {
  const m = (text || "").trim().match(/^(\d+\.\d+\.\d+\.\d+)(?:\/(\d{1,2}))?$/);
  if (!m) return null;
  const base = ipToInt(m[1]);
  const len = m[2] === undefined ? 32 : Number(m[2]);
  if (base === null || len > 32) return null;
  const mask = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0;
  return { net: (base & mask) >>> 0, mask };
}

function inCidr(cidr, address) {
  const ip = ipToInt((address || "").split("/")[0]);
  return ip !== null && ((ip & cidr.mask) >>> 0) === cidr.net;
}

function filteredOut(entity, id, view) {
  const types = getFilter(view, "entity_types", null);
  if (types && !types.includes(entity.type)) return true;
  if (entity.confidence < getFilter(view, "confidence_below", 0)) return true;
  const prov = getFilter(view, "provenance_required", null);
  if (prov && !(entity.provenance || []).includes(prov)) return true;
  const cidr = parseCidr(getFilter(view, "hide_cidr", ""));
  if (cidr) {
    const address = entity.ip || entity.prefix || (entity.type === "router" ? id.slice(4) : null);
    if (address && inCidr(cidr, address)) return true;
  }
  return false;
}

// -- visibility -----------------------------------------------------------------------------

export function isManuallyHidden(state, id) {
  return Boolean(state.annotations[id]?.hidden);
}

/** Apply hiding (with cascade), filters and collapsed subnets as CSS classes. */
export function applyVisibility(cy, state) {
  const { doc, view } = state;
  const showHidden = Boolean(view.show_hidden);
  const collapsed = new Set(view.collapsed || []);
  const status = {}; // id -> "shown" | "ghost" | "gone"

  for (const [id, e] of Object.entries(doc.entities)) {
    let s = "shown";
    const parent = e.type === "host" ? e.subnet_id : null;
    if (filteredOut(e, id, view) || (parent && doc.entities[parent] && filteredOut(doc.entities[parent], parent, view))) {
      s = "gone";
    } else if (isManuallyHidden(state, id) || (parent && isManuallyHidden(state, parent))) {
      s = showHidden ? "ghost" : "gone";
    }
    if (parent && collapsed.has(parent)) s = "gone";
    status[id] = s;
  }
  cy.batch(() => {
    cy.nodes().forEach((n) => {
      const s = status[n.id()] || "shown";
      n.toggleClass("gone", s === "gone");
      n.toggleClass("ghost", s === "ghost");
      const isCollapsed = n.data("type") === "subnet" && collapsed.has(n.id());
      n.toggleClass("collapsed", isCollapsed);
      const count = isCollapsed ? hostCount(doc, n.id()) : 0;
      n.data("displayLabel", isCollapsed ? `${n.data("label")} (${count} hosts)` : n.data("label"));
    });
    cy.edges().forEach((edge) => {
      const ends = [status[edge.data("source")], status[edge.data("target")]];
      let s = "shown";
      if (ends.includes("gone")) s = "gone";
      else if (isManuallyHidden(state, edge.id())) s = showHidden ? "ghost" : "gone";
      else if (ends.includes("ghost")) s = "ghost";
      edge.toggleClass("gone", s === "gone");
      edge.toggleClass("ghost", s === "ghost");
      edge.data("displayLabel", edge.data("label"));
    });
  });
}

function hostCount(doc, subnetId) {
  return Object.values(doc.entities).filter((e) => e.type === "host" && e.subnet_id === subnetId).length;
}

// -- layout ---------------------------------------------------------------------------------

export function visibleLeaves(cy) {
  return cy.nodes().filter((n) => !n.hasClass("gone") && n.children().filter((c) => !c.hasClass("gone")).length === 0);
}

/** Use saved positions when every visible node has one; otherwise compute a layout. */
export function runLayout(cy, state, { relayout = false } = {}) {
  const annotations = state.annotations;
  const leaves = visibleLeaves(cy);
  const placed = leaves.every((n) => annotations[n.id()]?.position);
  if (!relayout && placed && leaves.length) {
    leaves.forEach((n) => n.position({ ...annotations[n.id()].position }));
    cy.fit(cy.elements(":visible"), 30);
    return;
  }
  const eles = cy.elements().not(".gone");
  const pinned = leaves.filter((n) => annotations[n.id()]?.pinned && annotations[n.id()]?.position);
  if ((state.view.layout || "fcose") === "dagre") {
    eles.layout({ name: "dagre", rankDir: "TB", nodeSep: 25, rankSep: 70, animate: false,
                  nodeDimensionsIncludeLabels: true }).run();
    pinned.forEach((n) => n.position({ ...annotations[n.id()].position }));
  } else {
    const fixed = pinned.map((n) => ({ nodeId: n.id(), position: { ...annotations[n.id()].position } }));
    eles.layout({
      name: "fcose", quality: "default", randomize: true, animate: false,
      nodeDimensionsIncludeLabels: true, packComponents: true, nodeRepulsion: 6000,
      idealEdgeLength: 70, fixedNodeConstraint: fixed.length ? fixed : undefined,
    }).run();
  }
  // The general-purpose layout clusters subnet children; lay them out as a tidy grid instead.
  gridAllSubnets(cy, state);
  cy.fit(cy.elements(":visible"), 30);
}
