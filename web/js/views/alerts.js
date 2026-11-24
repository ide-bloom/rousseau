// Alerts: grouped incidents with the rule's explanation and evidence chain.
import { get, post, query } from "../api.js";
import { onLive, openDrawer, state } from "../app.js";
import { attrBadge, dateTime, el, kv, mount, sevBadge, summarize, time, toast } from "../util.js";
import { showEvent } from "./detail.js";

let unsub = null;
export function unmount() { unsub?.(); unsub = null; }

export async function render(main) {
  const status = el("select", { "aria-label": "Status filter" }, ["open", "acknowledged", "closed", ""].map((s) => el("option", { value: s, text: s || "all" })));
  const tbody = el("tbody");
  let incidents = [];
  const draw = () => mount(tbody, incidents.filter((i) => !status.value || i.status === status.value).map((i) =>
    el("tr", { onclick: () => showIncident(i.id), tabindex: "0" },
      el("td", {}, sevBadge(i.severity)),
      el("td", { class: "mono", text: i.rule_id }),
      el("td", { text: i.title }),
      el("td", { class: "mono", text: i.agent || "" }),
      el("td", { class: "muted", text: `×${i.count}` }),
      el("td", { class: "mono", text: i.mode }),
      el("td", { class: "muted", text: i.actions.join(", ") }),
      el("td", { class: "mono", text: dateTime(i.last_ts) }),
      el("td", { text: i.status }))));
  status.addEventListener("change", draw);
  const load = async () => { incidents = await get(`/incidents${query({ limit: 500 })}`); draw(); };
  unsub = onLive((m) => { if (m.type === "incident") load().catch(() => {}); });
  mount(main, el("h1", { text: "Alerts" }), el("div", { class: "toolbar" }, status),
    el("table", {}, el("thead", {}, el("tr", {}, ["Sev", "Rule", "Title", "Agent", "Count", "Mode", "Actions", "Last seen", "Status"].map((h) => el("th", { text: h })))), tbody));
  await load();
}

export async function showIncident(id) {
  const d = await get(`/incidents/${id}`);
  const i = d.incident;
  const setStatus = async (s) => {
    try { await post(`/incidents/${id}/status`, { status: s }); toast(`Incident ${s}`); showIncident(id); } catch (e) { toast(e.message); }
  };
  openDrawer(`${i.rule_id}: ${i.title}`,
    el("p", {}, sevBadge(i.severity), " ", el("span", { class: "muted", text: `${i.count} match(es) · mode ${i.mode} · ${i.status}` })),
    el("div", { class: "row" }, ["acknowledged", "closed", "open"].filter((s) => s !== i.status).map((s) => el("button", { class: "btn", disabled: state.replay, onclick: () => setStatus(s), text: s === "open" ? "Reopen" : s[0].toUpperCase() + s.slice(1) }))),
    el("h2", { text: "Why this matters" }), el("p", { text: i.explanation }),
    kv([["Session", i.session ? el("a", { href: `#/sessions/${encodeURIComponent(i.session)}`, text: i.session }) : null], ["Agent", i.agent], ["OWASP Agentic", i.owasp.join(", ")], ["MITRE ATT&CK", i.mitre.join(", ")], ["First seen", dateTime(i.first_ts)], ["Last seen", dateTime(i.last_ts)], ["Response actions", i.actions.join(", ") || "none"]]),
    d.rule?.falsepositives?.length ? el("div", {}, el("h2", { text: "Possible false positives" }), el("ul", {}, d.rule.falsepositives.map((f) => el("li", { text: f })))) : null,
    el("h2", { text: "Evidence chain" }),
    el("table", {}, el("tbody", {}, d.evidence.map((e) => el("tr", { onclick: () => showEvent(e) },
      el("td", { class: "mono", text: time(e.ts) }), el("td", { class: "kind", text: e.kind }), el("td", {}, attrBadge(e.attribution)), el("td", { class: "mono wrap", text: summarize(e) }))))),
    d.rule?.references?.length ? el("div", {}, el("h2", { text: "References" }), el("ul", {}, d.rule.references.map((r) => el("li", {}, el("a", { href: r, target: "_blank", rel: "noopener noreferrer", text: r }))))) : null);
}
