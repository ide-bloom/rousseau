// Live timeline: newest first, filterable, fed by the WebSocket.
import { get, query } from "../api.js";
import { onLive } from "../app.js";
import { attrBadge, el, mount, sevBadge, sevRank, sparkline, summarize, time } from "../util.js";
import { showEvent } from "./detail.js";

const MAX_ROWS = 1000;
let unsub = null;
let timer = null;

export function unmount() { unsub?.(); unsub = null; clearInterval(timer); }

export async function render(main) {
  const f = { session: "", agent: "", server: "", kind: "", min_severity: "", text: "" };
  const inputs = {
    session: el("input", { placeholder: "session", "aria-label": "Filter by session" }),
    agent: el("input", { placeholder: "agent", "aria-label": "Filter by agent" }),
    server: el("input", { placeholder: "MCP server", "aria-label": "Filter by MCP server" }),
    kind: el("select", { "aria-label": "Event kind" }, ["", "process.", "file.", "net.", "dns.", "registry.", "mcp.", "mcp.call", "mcp.finding", "mcp.drift", "mcp.blocked", "transcript.", "session.", "sensor."].map((k) => el("option", { value: k, text: k || "all kinds" }))),
    min_severity: el("select", { "aria-label": "Minimum severity" }, ["", "low", "medium", "high", "critical"].map((s) => el("option", { value: s, text: s ? `≥ ${s}` : "any severity" }))),
    text: el("input", { placeholder: "search text (/)", "aria-label": "Search" }),
  };
  const paused = el("input", { type: "checkbox", id: "pause" });
  const tbody = el("tbody");
  const counts = new Array(60).fill(0);
  const canvas = el("canvas", { class: "spark", "aria-label": "Events per second, last minute" });
  const rate = el("div", { class: "v", text: "0" });
  const total = el("div", { class: "v", text: "0" });
  let rows = [];

  const matches = (e) => {
    if (f.session && e.session !== f.session) return false;
    if (f.agent && e.lineage?.agent !== f.agent) return false;
    if (f.server && (e.mcp?.server || e.lineage?.mcp_server || e.finding?.server || e.drift?.server) !== f.server) return false;
    if (f.kind && !e.kind.startsWith(f.kind)) return false;
    if (f.min_severity && sevRank(e.severity) < sevRank(f.min_severity)) return false;
    if (f.text && !JSON.stringify(e).toLowerCase().includes(f.text.toLowerCase())) return false;
    return true;
  };
  const row = (e) => el("tr", { onclick: () => showEvent(e), tabindex: "0" },
    el("td", { class: "mono", text: time(e.ts) }),
    el("td", {}, sevBadge(e.severity)),
    el("td", { class: "kind", text: e.kind }),
    el("td", { class: "mono", text: e.lineage?.agent || e.mcp?.server || "" }),
    el("td", {}, attrBadge(e.attribution)),
    el("td", { class: "mono wrap", text: summarize(e) }));
  const redraw = () => {
    mount(tbody, rows.filter(matches).slice(0, MAX_ROWS).map(row));
    total.textContent = String(rows.length);
  };
  const load = async () => {
    const server = { ...f };
    delete server.text;
    rows = await get(`/events${query({ ...server, limit: 500 })}`);
    redraw();
  };
  for (const [k, input] of Object.entries(inputs)) {
    input.addEventListener(input.tagName === "SELECT" ? "change" : "input", () => {
      f[k] = input.value.trim();
      if (k === "text") redraw(); else load().catch(() => {});
    });
  }
  unsub = onLive((m) => {
    if (m.type === "lagged") { load().catch(() => {}); return; }
    if (m.type !== "event") return;
    counts[59]++;
    if (paused.checked) return;
    rows.unshift(m.event);
    if (rows.length > MAX_ROWS * 2) rows.length = MAX_ROWS * 2;
    if (matches(m.event)) {
      tbody.prepend(row(m.event));
      while (tbody.children.length > MAX_ROWS) tbody.lastChild.remove();
    }
    total.textContent = String(rows.length);
  });
  timer = setInterval(() => {
    rate.textContent = String(counts[59]);
    counts.shift(); counts.push(0);
    sparkline(canvas, counts);
  }, 1000);

  mount(main,
    el("h1", { text: "Live timeline" }),
    el("div", { class: "grid" },
      el("div", { class: "card" }, el("div", { class: "k", text: "Events / s" }), rate),
      el("div", { class: "card" }, el("div", { class: "k", text: "Loaded" }), total),
      el("div", { class: "card span2" }, el("div", { class: "k", text: "Last 60 s" }), canvas)),
    el("div", { class: "toolbar" }, ...Object.values(inputs), el("label", { class: "row muted" }, paused, "pause")),
    el("table", {}, el("thead", {}, el("tr", {}, ["Time", "Sev", "Kind", "Agent / server", "Attributed to", "Summary"].map((h) => el("th", { text: h })))), tbody));
  await load();
}
