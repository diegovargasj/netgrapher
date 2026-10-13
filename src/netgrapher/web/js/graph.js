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
    id, type: e.type, label, displayLabel: label,
    confirmed: e.confirmed === false ? 0 : 1,
    kind: e.kind || "", self: e.is_self ? 1 : 0,
  };
}

export function edgeData(state, id, l) {
  const label = labelOf(state, id);
  return { id, source: l.a, target: l.b, type: l.type, label, displayLabel: label,
           confirmed: l.confirmed === false ? 0 : 1 };
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

// Numeric sort key for a host, so hosts order by IP (192.168.1.2 before 192.168.1.10) rather
// than lexically. IPv4 -> a single number; anything else falls back to the id string.
function hostSortKey(state, id) {
  const ip = state.doc.entities[id]?.ip || id.replace(/^host:/, "");
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (!m) return [1, id];
  return [0, ((+m[1] * 256 + +m[2]) * 256 + +m[3]) * 256 + +m[4]];
}

function compareHosts(state, a, b) {
  const [ka, va] = hostSortKey(state, a.id());
  const [kb, vb] = hostSortKey(state, b.id());
  if (ka !== kb) return ka - kb;
  return va < vb ? -1 : va > vb ? 1 : 0;
}

/**
 * Lay a subnet's host children out as a grid in strict IP order (fixed GRID_COLS columns). Every
 * host's cell is determined solely by its index, so the grid is stable as hosts arrive.
 *
 * Pinned hosts (the user dragged the subnet or a host) are never moved; instead the grid origin is
 * inferred from a pinned host and its cell, so new (unpinned) hosts append into the SAME grid the
 * user moved — rather than starting a second grid elsewhere.
 */
export function gridSubnetChildren(cy, state, parent) {
  const all = parent.children().filter((c) => !c.isParent())
    .sort((a, b) => compareHosts(state, a, b));
  if (all.length === 0) return;
  const cell = (i) => ({ col: i % GRID_COLS, row: Math.floor(i / GRID_COLS) });

  // Origin = position of cell 0. Prefer a pinned host (keeps the grid where the user put it);
  // otherwise anchor on the lowest-IP host so existing hosts keep their cells.
  const pinnedIndex = all.findIndex((n) => isPinned(state, n.id()));
  let origin;
  if (pinnedIndex >= 0) {
    const c = cell(pinnedIndex);
    const p = all[pinnedIndex].position();
    origin = { x: p.x - c.col * GRID_STEP_X, y: p.y - c.row * GRID_STEP_Y };
  } else {
    origin = { ...all[0].position() };
  }

  all.forEach((n, i) => {
    if (isPinned(state, n.id())) return; // leave pinned hosts exactly where they are
    const c = cell(i);
    n.position({ x: origin.x + c.col * GRID_STEP_X, y: origin.y + c.row * GRID_STEP_Y });
  });
}

export function gridAllSubnets(cy, state) {
  cy.nodes('node[type = "subnet"]').forEach((subnet) => gridSubnetChildren(cy, state, subnet));
}

/** Place freshly added nodes without moving the rest; subnets with new hosts are re-gridded. */
const PLACE_PAD = 36; // keep this much clear space around a newly placed element

function rectsOverlap(a, b, pad) {
  return !(a.x2 + pad <= b.x1 || b.x2 + pad <= a.x1 || a.y2 + pad <= b.y1 || b.y2 + pad <= a.y1);
}

function unionBox(rects) {
  return {
    x1: Math.min(...rects.map((r) => r.x1)), y1: Math.min(...rects.map((r) => r.y1)),
    x2: Math.max(...rects.map((r) => r.x2)), y2: Math.max(...rects.map((r) => r.y2)),
  };
}

/** A centre for a w×h box near (cx, cy) that overlaps nothing in `occupied`; spirals outward. */
function freeSpot(occupied, w, h, cx, cy) {
  const step = Math.max(w, h) / 2 + PLACE_PAD;
  const fits = (x, y) => {
    const rect = { x1: x - w / 2, y1: y - h / 2, x2: x + w / 2, y2: y + h / 2 };
    return !occupied.some((o) => rectsOverlap(rect, o, PLACE_PAD));
  };
  if (fits(cx, cy)) return { x: cx, y: cy };
  for (let ring = 1; ring <= 40; ring++) {
    for (let dx = -ring; dx <= ring; dx++) {
      for (let dy = -ring; dy <= ring; dy++) {
        if (Math.max(Math.abs(dx), Math.abs(dy)) !== ring) continue; // perimeter only
        const x = cx + dx * step;
        const y = cy + dy * step;
        if (fits(x, y)) return { x, y };
      }
    }
  }
  return { x: cx, y: cy };
}

/** Bounding boxes (with labels) of already-placed, visible top-level nodes — the graph footprint. */
function footprint(cy, pending) {
  const rects = [];
  cy.nodes().forEach((n) => {
    if (n.hasClass("gone") || n.parent().nonempty() || pending.has(n.id())) return;
    rects.push(n.boundingBox({ includeLabels: true, includeOverlays: false }));
  });
  return rects;
}

function translateNode(n, dx, dy) {
  if (dx === 0 && dy === 0) return;
  if (n.isParent()) {
    n.children(":childless").forEach((c) => {
      const p = c.position();
      c.position({ x: p.x + dx, y: p.y + dy });
    });
  } else {
    const p = n.position();
    n.position({ x: p.x + dx, y: p.y + dy });
  }
}

/**
 * Push overlapping top-level nodes apart. Nodes in `anchored` (grown/just-placed) and pinned nodes
 * stay put; movable neighbours are nudged out along the axis of least overlap until nothing
 * overlaps (or a few iterations pass).
 */
function resolveOverlaps(cy, state, anchored) {
  const fixed = new Set(anchored);
  const pinned = (id) => Boolean(state.annotations[id]?.pinned);
  const tops = cy.nodes().filter((n) => !n.hasClass("gone") && n.parent().empty());
  if (tops.length < 2) return;
  const box = (n) => n.boundingBox({ includeLabels: true, includeOverlays: false });
  for (let iter = 0; iter < 16; iter++) {
    const items = tops.map((n) => ({ n, id: n.id(), box: box(n) }));
    let moved = false;
    for (let i = 0; i < items.length; i++) {
      for (let j = i + 1; j < items.length; j++) {
        const a = items[i];
        const b = items[j];
        if (!rectsOverlap(a.box, b.box, PLACE_PAD)) continue;
        const aMov = !fixed.has(a.id) && !pinned(a.id);
        const bMov = !fixed.has(b.id) && !pinned(b.id);
        if (!aMov && !bMov) continue; // both anchored: cannot separate them
        const overlapX = Math.min(a.box.x2, b.box.x2) - Math.max(a.box.x1, b.box.x1) + PLACE_PAD;
        const overlapY = Math.min(a.box.y2, b.box.y2) - Math.max(a.box.y1, b.box.y1) + PLACE_PAD;
        const aLeft = (a.box.x1 + a.box.x2) <= (b.box.x1 + b.box.x2);
        const aAbove = (a.box.y1 + a.box.y2) <= (b.box.y1 + b.box.y2);
        let dx = 0;
        let dy = 0;
        if (overlapX < overlapY) dx = aLeft ? -overlapX : overlapX;
        else dy = aAbove ? -overlapY : overlapY;
        const share = aMov && bMov ? 0.5 : 1;
        if (aMov) translateNode(a.n, dx * share, dy * share);
        if (bMov) translateNode(b.n, -dx * share, -dy * share);
        a.box = box(a.n);
        b.box = box(b.n);
        moved = true;
      }
    }
    if (!moved) break;
  }
}

function moveSubnetTo(subnet, cx, cy) {
  const bb = subnet.boundingBox({ includeLabels: true, includeOverlays: false });
  const dx = cx - (bb.x1 + bb.x2) / 2;
  const dy = cy - (bb.y1 + bb.y2) / 2;
  subnet.children(":childless").forEach((c) => {
    const p = c.position();
    c.position({ x: p.x + dx, y: p.y + dy });
  });
}

export function placeNewNodes(cy, state, newIds) {
  const pending = new Set(newIds);
  const isPlaced = (n) => !pending.has(n.id());
  const fresh = cy.collection(newIds.map((id) => cy.getElementById(id)).filter((n) => n.nonempty()));

  // 1. Existing subnets that merely gained a host: re-grid their children in place (no relocation).
  const grownSubnets = new Set();
  fresh.forEach((n) => {
    const parent = n.parent();
    if (!n.isParent() && parent.nonempty() && parent.data("type") === "subnet"
        && isPlaced(parent)) {
      grownSubnets.add(parent.id());
    }
  });
  grownSubnets.forEach((id) => gridSubnetChildren(cy, state, cy.getElementById(id)));
  const anchored = new Set(grownSubnets);

  // 2. Build the current footprint; new elements claim free space and extend it as we go.
  const occupied = footprint(cy, pending);
  const preferredCentre = (node, w, h) => {
    const neigh = node.neighborhood("node").filter((m) => isPlaced(m) && !m.hasClass("gone"));
    if (neigh.nonempty()) {
      const bb = neigh.boundingBox();
      return { x: (bb.x1 + bb.x2) / 2, y: (bb.y1 + bb.y2) / 2 };
    }
    if (occupied.length) {
      const g = unionBox(occupied);
      return { x: g.x2 + w / 2 + PLACE_PAD, y: (g.y1 + g.y2) / 2 };
    }
    return { x: 0, y: 0 };
  };

  // 3. New subnets: grid their children, measure, then drop the whole box into free space.
  fresh.filter((n) => n.isParent() && pending.has(n.id())).forEach((subnet) => {
    subnet.children(":childless").forEach((c, i) => c.position({ x: i * GRID_STEP_X, y: 0 }));
    gridSubnetChildren(cy, state, subnet);
    const bb = subnet.boundingBox({ includeLabels: true, includeOverlays: false });
    const pref = preferredCentre(subnet, bb.w, bb.h);
    const spot = freeSpot(occupied, bb.w, bb.h, pref.x, pref.y);
    moveSubnetTo(subnet, spot.x, spot.y);
    occupied.push(subnet.boundingBox({ includeLabels: true, includeOverlays: false }));
    anchored.add(subnet.id());
    pending.delete(subnet.id());
  });

  // 4. New standalone nodes (routers, external, unknown): drop each into free space near neighbours.
  fresh.filter((n) => !n.isParent() && n.parent().empty() && pending.has(n.id())).forEach((n) => {
    const bb = n.boundingBox({ includeLabels: true, includeOverlays: false });
    const pref = preferredCentre(n, bb.w, bb.h);
    const spot = freeSpot(occupied, bb.w, bb.h, pref.x, pref.y);
    n.position(spot);
    occupied.push(n.boundingBox({ includeLabels: true, includeOverlays: false }));
    anchored.add(n.id());
    pending.delete(n.id());
  });

  // 5. A grown subnet may now overlap its neighbours: nudge the movable ones aside.
  if (grownSubnets.size || anchored.size) resolveOverlaps(cy, state, anchored);
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export function stylesheet() {
  const c = (n) => cssVar(n);
  return [
    { selector: "node", style: {
      label: "data(displayLabel)", color: c("--text"), "font-size": 10,
      "text-valign": "bottom", "text-margin-y": 3, "text-wrap": "ellipsis", "text-max-width": 140,
      "background-color": c("--node-host"), width: 14, height: 14,
    } },
    { selector: "node[confirmed = 0]", style: {
      opacity: 0.55, "border-width": 1.5, "border-style": "dashed", "border-color": c("--muted"),
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
      width: 1.5, "line-color": c("--edge"), "curve-style": "bezier",
      label: "data(displayLabel)", "font-size": 9, color: c("--muted"),
      "text-background-color": c("--bg"), "text-background-opacity": 0.8,
      "text-background-padding": 1, "text-rotation": "autorotate",
    } },
    { selector: 'edge[type = "inferred-path"]', style: { "line-style": "dashed" } },
    { selector: "edge[confirmed = 0]", style: { opacity: 0.5, "line-style": "dashed" } },
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
  if (getFilter(view, "hide_unconfirmed", false) && entity.confirmed === false) return true;
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
