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

export function buildElements(state) {
  const elements = [];
  for (const [id, e] of Object.entries(state.doc.entities)) {
    const data = {
      id, type: e.type, label: labelOf(state, id), conf: e.confidence,
      kind: e.kind || "", self: e.is_self ? 1 : 0,
    };
    if (e.type === "host" && state.doc.entities[e.subnet_id]) data.parent = e.subnet_id;
    data.displayLabel = data.label;
    const element = { group: "nodes", data };
    const pos = state.annotations[id]?.position;
    if (pos) element.position = { x: pos.x, y: pos.y };
    elements.push(element);
  }
  for (const [id, l] of Object.entries(state.doc.links)) {
    if (l.type === "member") continue; // drawn as containment
    if (!state.doc.entities[l.a] || !state.doc.entities[l.b]) continue;
    elements.push({
      group: "edges",
      data: { id, source: l.a, target: l.b, type: l.type, label: labelOf(state, id),
              displayLabel: labelOf(state, id), conf: l.confidence },
    });
  }
  return elements;
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
  cy.fit(cy.elements(":visible"), 30);
}
