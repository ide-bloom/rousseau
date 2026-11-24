// Sessions list and causal tree (intent → processes → effects).
import { get, query } from "../api.js";
import { attrBadge, dateTime, el, kv, mount, sevBadge } from "../util.js";
import { showEvent } from "./detail.js";
import { showIncident } from "./alerts.js";

export async function render(main, [id]) {
  const list = el("div", { class: "list", role: "listbox", "aria-label": "Sessions" });
  const detail = el("div", {}, el("div", { class: "empty", text: "Select a session." }));
  mount(main, el("h1", { text: "Sessions" }), el("div", { class: "split" }, list, detail));
  const sessions = await get(`/sessions${query({ limit: 300 })}`);
  if (!sessions.length) {
    mount(list, el("div", { class: "empty", text: "No agent sessions yet. Start an AI agent, or run the demo scenario (examples/scenarios)." }));
    return;
  }
  mount(list, sessions.map((s) => el("div", {
    class: `item${s.id === id ? " sel" : ""}`, role: "option", tabindex: "0",
    onclick: () => { location.hash = `#/sessions/${encodeURIComponent(s.id)}`; },
  },
  el("div", { class: "row" }, el("strong", { text: s.agent }), s.ended ? el("span", { class: "faint", text: "ended" }) : el("span", { class: "badge badge-info", text: "live" }), s.incidents ? sevBadge(s.max_severity) : null, s.incidents ? el("span", { class: "muted", text: `${s.incidents} incident(s)` }) : null),
  el("div", { class: "mono muted", text: s.project || s.cwd || s.command_line || "" }),
  el("div", { class: "faint", text: `${dateTime(s.started)} · pid ${s.root_pid}` }))));
  if (id) await showSession(detail, id);
}

function nodeView(n, depth = 0) {
  const kids = n.children || [];
  const li = el("li");
  const toggle = el("span", { class: "tw", text: kids.length ? (depth < 2 ? "▾" : "▸") : "" });
  const childList = kids.length ? el("ul", { hidden: depth >= 2 }, kids.map((c) => nodeView(c, depth + 1))) : null;
  const label = el("div", {
    class: `node ${n.kind}`, tabindex: "0",
    title: n.detail || "",
    onclick: async (ev) => {
      ev.stopPropagation();
      if (childList && ev.target === toggle) { childList.hidden = !childList.hidden; toggle.textContent = childList.hidden ? "▸" : "▾"; return; }
      if (n.event_id) showEvent(await get(`/events/${n.event_id}`));
      else if (childList) { childList.hidden = !childList.hidden; toggle.textContent = childList.hidden ? "▸" : "▾"; }
    },
    onkeydown: (ev) => { if (ev.key === "ArrowRight" && childList) { childList.hidden = false; toggle.textContent = "▾"; } if (ev.key === "ArrowLeft" && childList) { childList.hidden = true; toggle.textContent = "▸"; } },
  }, toggle, n.severity ? sevBadge(n.severity) : null, n.kind === "intent" ? attrBadge({ kind: n.detail, tool: n.detail }) : null, el("span", { class: "lbl", text: n.label }));
  li.append(label);
  if (childList) li.append(childList);
  return li;
}

async function showSession(container, id) {
  mount(container, el("div", { class: "muted", text: "Loading session…" }));
  const d = await get(`/sessions/${encodeURIComponent(id)}`);
  const s = d.session;
  const incidents = d.incidents.length
    ? el("table", {}, el("tbody", {}, d.incidents.map((i) => el("tr", { onclick: () => showIncident(i.id) }, el("td", {}, sevBadge(i.severity)), el("td", { class: "mono", text: i.rule_id }), el("td", { text: i.title }), el("td", { class: "muted", text: `×${i.count}` })))))
    : el("p", { class: "muted", text: "No incidents in this session." });
  mount(container,
    el("div", { class: "card" }, kv([["Session", s.id], ["Agent", s.agent], ["Root process", `${s.image || ""} (pid ${s.root_pid})`], ["Command line", s.command_line], ["Working dir", s.cwd], ["Project", s.project], ["Started", dateTime(s.started)], ["Ended", s.ended ? dateTime(s.ended) : "running"], ["Events", d.event_count]])),
    el("h2", { text: "Incidents" }), incidents,
    el("h2", { text: "Causal timeline: intent → action → effects" }),
    el("p", { class: "muted" }, "Each top-level node is a tool call (MCP or a built-in tool recovered from the agent transcript). Processes it spawned and their file, network and registry effects sit underneath. ",
      el("span", { class: "attr-unexplained", text: "Unexplained" }), " groups activity no tool call accounts for."),
    d.tree.length ? el("div", { class: "tree card" }, el("ul", {}, d.tree.map((n) => nodeView(n)))) : el("div", { class: "empty", text: "No activity recorded." }));
}
