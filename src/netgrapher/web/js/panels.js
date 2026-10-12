// Details panel (attributes, evidence, rename, note, hide) and hidden-items list.

import { api, itemPath } from "./api.js";
import { clear, h } from "./dom.js";
import { defaultLabel, linkDefaultLabel, labelOf } from "./graph.js";

const pct = (v) => (v == null ? "?" : `${Math.round(v * 100)}%`);
const time = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "");
const list = (items) => (items && items.length ? items.join(", ") : "—");
const names = (n) => list((n || []).map((x) => `${x.name} (${x.source})`));

function attrs(rows) {
  return h("dl", { className: "attrs" },
    rows.filter(([, v]) => v !== undefined && v !== null && v !== "")
      .flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
}

function entityRows(id, e, ctx) {
  const go = (target) => h("a", { className: "link", onclick: () => ctx.select(target) }, labelOf(ctx.state, target));
  switch (e.type) {
    case "subnet":
      return attrs([
        ["Prefix", e.prefix], ["Kind", e.kind], ["Prefix confidence", pct(e.prefix_confidence)],
        ["Gateways", e.gateway_ids?.length ? h("span", {}, ...e.gateway_ids.flatMap((g, i) => [i ? ", " : "", go(g)])) : "—"],
        ["DHCP servers", list(e.dhcp_servers)],
      ]);
    case "router":
      return h("div", {},
        attrs([
          ["Names", names(e.names)], ["Roles", list(e.roles)], ["Protocols", list(e.protocols)],
          ["Router IDs", list(e.router_ids)], ["Hop distance", e.hop_distance],
          ["MACs (evidence)", list(e.l2_evidence?.macs)],
        ]),
        h("table", { className: "small" },
          h("tr", {}, h("th", {}, "Interface"), h("th", {}, "Subnet"), h("th", {}, "Conf.")),
          ...(e.interfaces || []).map((i) => h("tr", {},
            h("td", {}, i.ip + (i.virtual ? " (virtual)" : "")),
            h("td", {}, i.subnet ? go(i.subnet) : "—"),
            h("td", {}, pct(i.confidence))))));
    case "host":
      return attrs([
        ["IP", e.ip], ["Subnet", e.subnet_id ? go(e.subnet_id) : "—"], ["Names", names(e.names)],
        ["Roles", list(e.roles)], ["This machine", e.is_self ? "yes" : ""],
        ["Hop distance", e.hop_distance], ["OS family (TTL)", e.os_family_guess],
        ["First seen", time(e.first_seen)], ["Last seen", time(e.last_seen)],
        ["MACs (evidence)", list(e.l2_evidence?.macs)],
      ]);
    case "external":
      return attrs([
        ["Addresses", e.host_count],
        ["Sample", list((e.addresses || []).slice(0, 30))],
        ["ASN", e.asn],
      ]);
    default:
      return attrs([["Reason", e.reason], ["MACs (evidence)", list(e.l2_evidence?.macs)]]);
  }
}

function evidenceSection(id) {
  const ul = h("ul", { className: "plain evidence" }, h("li", { className: "muted" }, "Loading…"));
  api("GET", `/api/entity/${itemPath(id)}/evidence`).then((items) => {
    clear(ul);
    if (!items.length) ul.append(h("li", { className: "muted" }, "No evidence recorded."));
    for (const ev of items) {
      ul.append(h("li", {},
        h("div", {}, h("span", { className: "rule" }, ev.rule), ` · weight ${ev.weight} · ${ev.provenance}`),
        h("div", {}, ev.summary),
        ev.frames?.length ? h("div", { className: "muted" }, `frames ${ev.frames.join(", ")}`) : null));
    }
  }).catch((err) => { clear(ul).append(h("li", { className: "muted" }, err.message)); });
  return ul;
}

/**
 * ctx: { state, edit(items), select(id), toggleCollapse(id) }
 */
export function renderDetails(root, ctx, id) {
  clear(root);
  const { state } = ctx;
  if (!id) {
    root.append(h("p", { className: "muted" }, "Select a node or link to see its details."));
    return;
  }
  const entity = state.doc.entities[id];
  const link = state.doc.links[id];
  if (!entity && !link) return;
  const ann = state.annotations[id] || {};
  const fallback = entity ? defaultLabel(id, entity) : linkDefaultLabel(link);

  const input = h("input", {
    className: "label-edit", value: ann.label || "", placeholder: fallback || "(no label)",
    "aria-label": "Label", maxlength: 200,
  });
  const commitLabel = () => {
    const value = input.value.trim();
    if (value !== (ann.label || "")) ctx.edit([{ id, patch: { label: value || null } }]);
  };
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") input.blur(); });
  input.addEventListener("blur", commitLabel);

  const note = h("textarea", { "aria-label": "Note", maxlength: 10000, placeholder: "Notes…" });
  note.value = ann.note || "";
  note.addEventListener("blur", () => {
    if (note.value !== (ann.note || "")) ctx.edit([{ id, patch: { note: note.value || null } }]);
  });

  const conf = entity ? entity.confidence : link.confidence;
  root.append(
    input,
    h("div", { className: "muted" }, `${entity ? entity.type.replace("_", " ") : `${link.type} link`} · ${id} · confidence ${pct(conf)}`),
    h("div", { className: "actions" },
      h("button", { onclick: () => ctx.edit([{ id, patch: { hidden: ann.hidden ? null : true } }]) },
        ann.hidden ? "Unhide" : "Hide"),
      ann.pinned ? h("button", { onclick: () => ctx.edit([{ id, patch: { pinned: null } }]) }, "Unpin") : null,
      entity?.type === "subnet" ? h("button", { onclick: () => ctx.toggleCollapse(id) },
        (state.view.collapsed || []).includes(id) ? "Expand hosts" : "Collapse hosts") : null),
  );
  if (entity) {
    root.append(entityRows(id, entity, ctx));
    if (entity.provenance?.length) root.append(h("div", { className: "muted" }, `Provenance: ${entity.provenance.join(", ")}`));
  } else {
    const go = (target) => h("a", { className: "link", onclick: () => ctx.select(target) }, labelOf(state, target));
    root.append(attrs([
      ["From", go(link.a)], ["To", go(link.b)], ["Interface IP", link.ip],
      ["Virtual", link.virtual ? "yes" : ""], ["Hops", link.hops], ["Basis", list(link.basis)],
    ]));
  }
  root.append(h("h2", {}, "Note"), note, h("h2", {}, "Evidence"), evidenceSection(id));
}

export function renderHiddenList(root, countEl, ctx) {
  clear(root);
  const hidden = Object.entries(ctx.state.annotations).filter(([, a]) => a.hidden).map(([id]) => id);
  countEl.textContent = hidden.length ? `(${hidden.length})` : "";
  if (!hidden.length) {
    root.append(h("li", { className: "muted" }, "Nothing hidden."));
    return;
  }
  hidden.sort().forEach((id) => {
    root.append(h("li", {},
      h("span", { title: id }, labelOf(ctx.state, id)),
      h("button", { onclick: () => ctx.edit([{ id, patch: { hidden: null } }]) }, "Restore")));
  });
}
