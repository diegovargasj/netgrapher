// Screenshots (PNG via cytoscape, SVG via svg.js) with optional anonymization (FR-UI-9/10).

import { stylesheet } from "./graph.js";
import { toSvg } from "./svg.js";

const PREFIX = { subnet: "NET", router: "RTR", host: "HOST", unknown_router: "UNK" };

// The live graph follows the OS light/dark theme, but a screenshot can be drawn on a chosen
// background. On a white background the dark-theme palette (near-white text, near-black subnet
// fills) is unreadable, so force the light palette for the export and restore it afterwards.
// Values mirror the :root light defaults in css/app.css.
const LIGHT_PALETTE = {
  "--text": "#1d2330",
  "--muted": "#6b7280",
  "--edge": "#8b95a5",
  "--node-router": "#2563eb",
  "--node-host": "#64748b",
  "--node-self": "#059669",
  "--node-subnet-bg": "#eef2f7",
  "--node-subnet-border": "#94a3b8",
  "--node-external": "#7c3aed",
  "--node-unknown": "#9ca3af",
  "--bg": "#ffffff",
};

/** Run `fn` with CSS variables overridden on :root and the cytoscape style rebuilt, then restore. */
function withPalette(cy, overrides, fn) {
  if (!overrides) return fn();
  const root = document.documentElement;
  const previous = Object.keys(overrides).map((k) => [k, root.style.getPropertyValue(k)]);
  for (const [k, v] of Object.entries(overrides)) root.style.setProperty(k, v);
  cy.style(stylesheet());
  try {
    return fn();
  } finally {
    for (const [k, v] of previous) {
      if (v) root.style.setProperty(k, v);
      else root.style.removeProperty(k);
    }
    cy.style(stylesheet());
  }
}

/** Replace labels with consistent placeholders; returns a function that restores them. */
export function anonymize(cy, state, keepCustom) {
  const counters = {};
  const saved = [];
  const sorted = cy.nodes().sort((a, b) => (a.id() < b.id() ? -1 : a.id() > b.id() ? 1 : 0));
  const placeholder = {};
  sorted.forEach((n) => {
    const type = n.data("type");
    if (type === "external") {
      placeholder[n.id()] = "Internet";
      return;
    }
    counters[type] = (counters[type] || 0) + 1;
    const width = type === "host" ? 3 : 2;
    placeholder[n.id()] = `${PREFIX[type] || "N"}-${String(counters[type]).padStart(width, "0")}`;
  });
  cy.batch(() => {
    cy.elements().forEach((el) => {
      saved.push([el, el.data("displayLabel")]);
      const custom = state.annotations[el.id()]?.label;
      if (keepCustom && custom) return;
      if (el.isNode()) {
        const text = el.data("displayLabel") || "";
        const suffix = text.match(/ \(\d+ hosts\)$/);
        el.data("displayLabel", placeholder[el.id()] + (suffix ? suffix[0] : ""));
      } else if (el.data("type") !== "inferred-path") {
        el.data("displayLabel", "");
      }
    });
  });
  return () => cy.batch(() => saved.forEach(([el, text]) => el.data("displayLabel", text)));
}

function download(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function screenshot(cy, state, opts) {
  // "white" is a fixed light background; force the light palette so text/fills stay legible.
  // "theme" and "transparent" keep the live palette (they already match it).
  const palette = opts.bg === "white" ? LIGHT_PALETTE : null;
  const stem = (state.doc.name || "netgrapher").replace(/\.ngraph$/, "");
  withPalette(cy, palette, () => {
    const background = opts.bg === "transparent" ? null
      : getComputedStyle(document.documentElement).getPropertyValue("--bg").trim();
    const restore = opts.anonymize ? anonymize(cy, state, opts.keep) : () => {};
    try {
      if (opts.format === "svg") {
        const svg = toSvg(cy, { full: opts.scope === "full", scale: Number(opts.scale),
                                background });
        download(new Blob([svg], { type: "image/svg+xml" }), `${stem}.svg`);
      } else {
        const blob = cy.png({ output: "blob", full: opts.scope === "full",
                              scale: Number(opts.scale), bg: background || undefined });
        download(blob, `${stem}.png`);
      }
    } finally {
      restore();
    }
  });
}
