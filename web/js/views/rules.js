// Rules: enable/disable, per-rule response mode, reload.
import { get, post } from "../api.js";
import { openDrawer, state } from "../app.js";
import { el, kv, mount, pre, sevBadge, toast } from "../util.js";

export async function render(main) {
  const filter = el("input", { placeholder: "filter rules (/)", "aria-label": "Filter rules" });
  const tbody = el("tbody");
  let rules = [];
  const change = async (id, body) => {
    try { await post(`/rules/${encodeURIComponent(id)}`, body); toast(`Updated ${id}`); await load(); } catch (e) { toast(e.message); }
  };
  const draw = () => {
    const q = filter.value.toLowerCase();
    mount(tbody, rules.filter((r) => !q || `${r.id} ${r.title} ${r.owasp.join(" ")} ${r.mitre.join(" ")}`.toLowerCase().includes(q)).map((r) => {
      const enabled = el("input", { type: "checkbox", "aria-label": `Enable ${r.id}`, disabled: state.replay, onclick: (e) => e.stopPropagation(), onchange: (e) => change(r.id, { enabled: e.target.checked }) });
      enabled.checked = r.enabled;
      const mode = el("select", { "aria-label": `Mode for ${r.id}`, disabled: state.replay, onclick: (e) => e.stopPropagation(), onchange: (e) => change(r.id, { mode: e.target.value }) },
        ["inherit", "observe", "alert", "enforce"].map((m) => el("option", { value: m, text: m === "inherit" ? `inherit (${state.mode})` : m })));
      mode.value = r.mode || "inherit";
      return el("tr", { tabindex: "0", onclick: () => openDrawer(`${r.id}: ${r.title}`, el("p", { text: r.description }), kv([["Severity", r.severity], ["Type", r.detection_type], ["OWASP Agentic", r.owasp.join(", ")], ["MITRE ATT&CK", r.mitre.join(", ")], ["Effective mode", r.effective_mode]]), el("h2", { text: "False positives" }), el("ul", {}, r.falsepositives.map((f) => el("li", { text: f }))), el("h2", { text: "Source" }), pre(r.source)) },
        el("td", {}, enabled), el("td", { class: "mono", text: r.id }), el("td", {}, sevBadge(r.severity)), el("td", { text: r.title }),
        el("td", { class: "kind", text: r.detection_type }), el("td", { class: "mono", text: r.owasp.join(" ") }), el("td", { class: "mono", text: r.mitre.join(" ") }), el("td", {}, mode));
    }));
  };
  const load = async () => { rules = await get("/rules"); draw(); };
  filter.addEventListener("input", draw);
  mount(main, el("h1", { text: "Detection rules" }),
    el("div", { class: "toolbar" }, filter, el("button", { class: "btn", disabled: state.replay, onclick: async () => { try { await post("/rules/reload"); toast("Rules reloaded"); await load(); } catch (e) { toast(e.message); } }, text: "Reload rules" })),
    el("table", {}, el("thead", {}, el("tr", {}, ["On", "Id", "Sev", "Title", "Type", "OWASP", "ATT&CK", "Mode"].map((h) => el("th", { text: h })))), tbody));
  await load();
}
