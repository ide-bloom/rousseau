// MCP inventory: servers, tools, pin status, drift diffs, findings.
import { get, post } from "../api.js";
import { state } from "../app.js";
import { ago, diffBlock, el, kv, mount, pre, sevBadge, toast } from "../util.js";
import { showEvent } from "./detail.js";

export async function render(main, [name]) {
  const list = el("div", { class: "list", "aria-label": "MCP servers" });
  const detail = el("div", {}, el("div", { class: "empty", text: "Select a server." }));
  mount(main, el("h1", { text: "MCP inventory" }), el("div", { class: "split" }, list, detail));
  const servers = await get("/servers");
  if (!servers.length) {
    mount(list, el("div", { class: "empty", text: "No MCP servers seen yet. Run `rousseau protect` so your clients launch servers through `rousseau wrap`." }));
    return;
  }
  mount(list, servers.map((s) => el("div", { class: `item${s.name === name ? " sel" : ""}`, tabindex: "0", onclick: () => { location.hash = `#/mcp/${encodeURIComponent(s.name)}`; } },
    el("div", { class: "row" }, el("strong", { text: s.name }), s.pending ? el("span", { class: "badge sev-high", text: `${s.pending} pending` }) : null, s.findings ? sevBadge(s.max_finding) : null),
    el("div", { class: "muted", text: `${s.tools} tool(s) · ${s.findings} finding(s) · ${s.record?.transport || "?"} · seen ${ago(s.record?.last_seen)}` }))));
  if (name) await showServer(detail, name);
}

async function showServer(container, name) {
  const d = await get(`/servers/${encodeURIComponent(name)}`);
  const act = async (verb, tool) => {
    try {
      await post(`/pins/${verb}`, { server: name, tool });
      toast(`${verb === "approve" ? "Approved" : "Denied"} ${tool}`);
      await showServer(container, name);
    } catch (e) { toast(e.message); }
  };
  const pinRows = d.pins.map((p) => {
    const def = (() => { try { return JSON.parse(p.current_def); } catch { return {}; } })();
    const drift = p.status === "pending" && p.approved_def && p.approved_def !== p.current_def;
    const tr = el("tr", {},
      el("td", { class: "mono", text: p.tool }),
      el("td", {}, el("span", { class: `badge ${p.status === "approved" ? "sev-info" : p.status === "removed" ? "faint" : "sev-high"}`, text: p.status })),
      el("td", { class: "wrap", text: def.description || "" }),
      el("td", { class: "mono faint", text: p.current_hash.slice(0, 12) }),
      el("td", {}, el("div", { class: "row" },
        p.status !== "approved" && p.status !== "removed" ? el("button", { class: "btn primary", disabled: state.replay, onclick: (ev) => { ev.stopPropagation(); act("approve", p.tool); } , text: "Approve" }) : null,
        p.status === "pending" ? el("button", { class: "btn danger", disabled: state.replay, onclick: (ev) => { ev.stopPropagation(); act("deny", p.tool); }, text: "Deny" }) : null)));
    tr.addEventListener("click", () => {
      import("../app.js").then(({ openDrawer }) => openDrawer(`${name}.${p.tool}`,
        kv([["Status", p.status], ["Current hash", p.current_hash], ["Approved hash", p.approved_hash], ["First seen", new Date(p.first_seen).toLocaleString()]]),
        drift ? el("h2", { text: "Change since approval" }) : null,
        drift ? diffBlock(lineDiff(pretty(p.approved_def), pretty(p.current_def))) : null,
        el("h2", { text: "Current definition (canonical)" }), pre(def)));
    });
    return tr;
  });
  const rec = d.record || {};
  mount(container,
    el("div", { class: "card" }, kv([["Server", name], ["Transport", rec.transport], ["Command / upstream", rec.target], ["Server info", rec.info?.serverInfo ? `${rec.info.serverInfo.name} ${rec.info.serverInfo.version || ""}` : null], ["Protocol", rec.info?.protocolVersion], ["First seen", rec.first_seen ? new Date(rec.first_seen).toLocaleString() : null]])),
    el("h2", { text: "Tools and pins" }),
    d.pins.length ? el("table", {}, el("thead", {}, el("tr", {}, ["Tool", "Pin", "Description", "Hash", ""].map((h) => el("th", { text: h })))), el("tbody", {}, pinRows)) : el("p", { class: "muted", text: "No tools listed yet." }),
    el("h2", { text: "Drift history" }),
    d.drift.length ? el("table", {}, el("tbody", {}, d.drift.map((e) => el("tr", { onclick: () => showEvent(e) }, el("td", { class: "mono", text: new Date(e.ts).toLocaleString() }), el("td", { class: "mono", text: e.drift?.tool }), el("td", { text: e.drift?.change }))))) : el("p", { class: "muted", text: "No drift detected." }),
    el("h2", { text: "Inspector findings" }),
    d.findings.length ? el("table", {}, el("tbody", {}, d.findings.map((e) => el("tr", { onclick: () => showEvent(e) }, el("td", {}, sevBadge(e.finding?.severity)), el("td", { class: "mono", text: e.finding?.code }), el("td", { class: "wrap", text: e.finding?.location }), el("td", { class: "wrap", text: e.finding?.decoded ? `decoded: ${e.finding.decoded}` : e.finding?.detail }))))) : el("p", { class: "muted", text: "No findings." }));
}

function pretty(canon) {
  try { return JSON.stringify(sortKeys(JSON.parse(canon)), null, 2); } catch { return canon || ""; }
}
function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]));
  return v;
}
/** LCS line diff, same output format as rousseau-mcp canonical::line_diff. */
function lineDiff(a, b) {
  const x = a.split("\n"), y = b.split("\n");
  const t = Array.from({ length: x.length + 1 }, () => new Array(y.length + 1).fill(0));
  for (let i = x.length - 1; i >= 0; i--) for (let j = y.length - 1; j >= 0; j--) t[i][j] = x[i] === y[j] ? t[i + 1][j + 1] + 1 : Math.max(t[i + 1][j], t[i][j + 1]);
  const out = []; let i = 0, j = 0;
  while (i < x.length && j < y.length) {
    if (x[i] === y[j]) { out.push("  " + x[i]); i++; j++; } else if (t[i + 1][j] >= t[i][j + 1]) out.push("- " + x[i++]); else out.push("+ " + y[j++]);
  }
  while (i < x.length) out.push("- " + x[i++]);
  while (j < y.length) out.push("+ " + y[j++]);
  return out.join("\n");
}
