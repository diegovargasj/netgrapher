// Screenshots (PNG via cytoscape, SVG via svg.js) with optional anonymization (FR-UI-9/10).

import { toSvg } from "./svg.js";

const PREFIX = { subnet: "NET", router: "RTR", host: "HOST", unknown_router: "UNK" };

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
  const background = opts.bg === "transparent" ? null
    : opts.bg === "theme" ? getComputedStyle(document.documentElement).getPropertyValue("--bg").trim()
    : "#ffffff";
  const restore = opts.anonymize ? anonymize(cy, state, opts.keep) : () => {};
  const stem = (state.doc.name || "netgrapher").replace(/\.ngraph$/, "");
  try {
    if (opts.format === "svg") {
      const svg = toSvg(cy, { full: opts.scope === "full", scale: Number(opts.scale), background });
      download(new Blob([svg], { type: "image/svg+xml" }), `${stem}.svg`);
    } else {
      const blob = cy.png({ output: "blob", full: opts.scope === "full", scale: Number(opts.scale),
                            bg: background || undefined });
      download(blob, `${stem}.png`);
    }
  } finally {
    restore();
  }
}
