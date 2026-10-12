// Minimal SVG serializer for the visible graph. netgrapher does not use cytoscape-svg
// (GPL-3.0); this covers the shapes and styles netgrapher's stylesheet uses.

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const num = (v) => (Number.isFinite(v) ? Math.round(v * 100) / 100 : 0);

function polygon(cx, cy, w, h, points) {
  return points.map(([x, y]) => `${num(cx + (x * w) / 2)},${num(cy + (y * h) / 2)}`).join(" ");
}

const OCTAGON = [[-0.41, -1], [0.41, -1], [1, -0.41], [1, 0.41], [0.41, 1], [-0.41, 1], [-1, 0.41], [-1, -0.41]];

function dash(style, width) {
  if (style === "dashed") return ` stroke-dasharray="${num(width * 4)} ${num(width * 3)}"`;
  if (style === "dotted") return ` stroke-dasharray="${num(width)} ${num(width * 2)}"`;
  return "";
}

function nodeShape(node) {
  const p = node.position();
  const w = node.width();
  const h = node.height();
  const fill = node.style("background-color");
  const op = Number(node.style("opacity")) * Number(node.style("background-opacity"));
  const bw = parseFloat(node.style("border-width")) || 0;
  const stroke = bw ? ` stroke="${esc(node.style("border-color"))}" stroke-width="${num(bw)}"${dash(node.style("border-style"), bw)}` : "";
  const common = `fill="${esc(fill)}" fill-opacity="${num(op)}"${stroke}`;
  if (node.isParent()) {
    const bb = node.boundingBox({ includeLabels: false, includeOverlays: false });
    return `<rect x="${num(bb.x1)}" y="${num(bb.y1)}" width="${num(bb.w)}" height="${num(bb.h)}" rx="8" ${common}/>`;
  }
  switch (node.style("shape")) {
    case "ellipse":
      return `<ellipse cx="${num(p.x)}" cy="${num(p.y)}" rx="${num(w / 2)}" ry="${num(h / 2)}" ${common}/>`;
    case "octagon":
      return `<polygon points="${polygon(p.x, p.y, w, h, OCTAGON)}" ${common}/>`;
    case "barrel":
      return `<rect x="${num(p.x - w / 2)}" y="${num(p.y - h / 2)}" width="${num(w)}" height="${num(h)}" rx="${num(w / 4)}" ${common}/>`;
    default:
      return `<rect x="${num(p.x - w / 2)}" y="${num(p.y - h / 2)}" width="${num(w)}" height="${num(h)}" rx="4" ${common}/>`;
  }
}

function nodeLabel(node) {
  const text = node.data("displayLabel");
  if (!text) return "";
  const size = parseFloat(node.style("font-size")) || 10;
  const color = node.style("color");
  const weight = node.style("font-weight");
  let x = node.position().x;
  let y;
  if (node.isParent()) {
    const bb = node.boundingBox({ includeLabels: false, includeOverlays: false });
    x = (bb.x1 + bb.x2) / 2;
    y = bb.y1 - 4;
  } else {
    y = node.position().y + node.height() / 2 + 3 + size;
  }
  return `<text x="${num(x)}" y="${num(y)}" font-size="${num(size)}" font-weight="${esc(weight)}" fill="${esc(color)}" text-anchor="middle">${esc(text)}</text>`;
}

function edgeShape(edge) {
  const s = edge.sourceEndpoint();
  const t = edge.targetEndpoint();
  const width = parseFloat(edge.style("width")) || 1;
  const cps = edge.controlPoints() || [];
  let d = `M ${num(s.x)} ${num(s.y)} `;
  if (cps.length === 1) d += `Q ${num(cps[0].x)} ${num(cps[0].y)} ${num(t.x)} ${num(t.y)}`;
  else if (cps.length === 2) d += `C ${num(cps[0].x)} ${num(cps[0].y)} ${num(cps[1].x)} ${num(cps[1].y)} ${num(t.x)} ${num(t.y)}`;
  else d += `L ${num(t.x)} ${num(t.y)}`;
  const out = [`<path d="${d}" fill="none" stroke="${esc(edge.style("line-color"))}" stroke-width="${num(width)}" stroke-opacity="${num(Number(edge.style("opacity")))}"${dash(edge.style("line-style"), width)}/>`];
  const text = edge.data("displayLabel");
  if (text) {
    const m = edge.midpoint();
    const size = parseFloat(edge.style("font-size")) || 9;
    out.push(`<text x="${num(m.x)}" y="${num(m.y - 2)}" font-size="${num(size)}" fill="${esc(edge.style("color"))}" text-anchor="middle">${esc(text)}</text>`);
  }
  return out.join("");
}

/**
 * @param cy cytoscape instance
 * @param options {full: boolean, scale: number, background: string|null}
 */
export function toSvg(cy, { full = true, scale = 1, background = null } = {}) {
  const visible = cy.elements(":visible");
  const bb = full ? visible.boundingBox({ includeLabels: true }) : cy.extent();
  const pad = 10;
  const x = bb.x1 - pad;
  const y = bb.y1 - pad;
  const w = bb.w + 2 * pad;
  const h = bb.h + 2 * pad;
  const parts = [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${num(w * scale)}" height="${num(h * scale)}" viewBox="${num(x)} ${num(y)} ${num(w)} ${num(h)}" font-family="system-ui, sans-serif">`,
  ];
  if (background) parts.push(`<rect x="${num(x)}" y="${num(y)}" width="${num(w)}" height="${num(h)}" fill="${esc(background)}"/>`);
  const nodes = visible.nodes();
  const parents = nodes.filter((n) => n.isParent()).sort((a, b) => a.ancestors().length - b.ancestors().length);
  parents.forEach((n) => parts.push(nodeShape(n)));
  visible.edges().forEach((e) => parts.push(edgeShape(e)));
  nodes.filter((n) => !n.isParent()).forEach((n) => parts.push(nodeShape(n)));
  nodes.forEach((n) => parts.push(nodeLabel(n)));
  parts.push("</svg>");
  return parts.join("\n");
}
