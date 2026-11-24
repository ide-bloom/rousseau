// App shell: routing, header status, theme, keyboard navigation, drawer.
import { get, live, token } from "./api.js";
import { el, mount, toast } from "./util.js";
import * as timeline from "./views/timeline.js";
import * as sessions from "./views/sessions.js";
import * as mcp from "./views/mcp.js";
import * as alerts from "./views/alerts.js";
import * as rules from "./views/rules.js";
import * as settings from "./views/settings.js";

const views = { timeline, sessions, mcp, alerts, rules, settings };
const listeners = new Set();
let current = null;

/** Subscribe to live messages; returns an unsubscribe function. */
export function onLive(fn) { listeners.add(fn); return () => listeners.delete(fn); }

export const state = { replay: false, mode: "observe" };

function route() {
  const hash = location.hash.replace(/^#\/?/, "") || "timeline";
  const [name, ...rest] = hash.split("/");
  const view = views[name] ? name : "timeline";
  document.querySelectorAll(".tabs a").forEach((a) => a.classList.toggle("active", a.dataset.view === view));
  if (current?.unmount) current.unmount();
  closeDrawer();
  const main = document.getElementById("main");
  mount(main, el("div", { class: "muted", text: "Loading…" }));
  current = views[view];
  Promise.resolve(current.render(main, rest.map(decodeURIComponent))).catch((e) => mount(main, el("div", { class: "empty", text: String(e.message || e) })));
}

export function openDrawer(title, ...content) {
  document.getElementById("drawer-title").textContent = title;
  mount(document.getElementById("drawer-body"), ...content);
  const d = document.getElementById("drawer");
  d.hidden = false;
  document.getElementById("drawer-close").focus();
}

export function closeDrawer() { document.getElementById("drawer").hidden = true; }

async function refreshStatus() {
  try {
    const o = await get("/overview");
    state.replay = o.replay; state.mode = o.mode;
    document.getElementById("replay-badge").hidden = !o.replay;
    const pill = document.getElementById("mode-pill");
    pill.textContent = o.mode; pill.className = `pill mode-${o.mode}`;
    const health = o.health || [];
    const worst = health.some((h) => h.status === "down") ? "down" : health.some((h) => h.status === "degraded") ? "degraded" : health.length ? "ok" : "";
    const hEl = document.getElementById("health");
    hEl.className = `health ${worst}`;
    document.getElementById("health-text").textContent = health.map((h) => `${h.sensor} ${h.status}`).join(" · ") || "no sensor data";
    hEl.title = health.map((h) => `${h.sensor}: ${h.status} — ${h.message}`).join("\n");
    const c = document.getElementById("alert-count");
    c.hidden = !o.stats.open_incidents; c.textContent = o.stats.open_incidents;
  } catch (e) { toast(e.message); }
}

function setupTheme() {
  let theme = "dark";
  try { theme = localStorage.getItem("rousseau.theme") || "dark"; } catch { /* default */ }
  document.documentElement.dataset.theme = theme;
  const toggle = () => {
    theme = theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("rousseau.theme", theme); } catch { /* ignore */ }
  };
  document.getElementById("theme").addEventListener("click", toggle);
  return toggle;
}

function setupKeys(toggleTheme) {
  let g = false;
  const go = { t: "timeline", s: "sessions", m: "mcp", a: "alerts", r: "rules", ",": "settings" };
  document.addEventListener("keydown", (e) => {
    const typing = ["INPUT", "SELECT", "TEXTAREA"].includes(document.activeElement?.tagName);
    if (e.key === "Escape") { closeDrawer(); if (typing) document.activeElement.blur(); return; }
    if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
    if (g && go[e.key]) { location.hash = `#/${go[e.key]}`; g = false; e.preventDefault(); return; }
    g = e.key === "g";
    if (e.key === "/") { const f = document.querySelector("main input"); if (f) { f.focus(); e.preventDefault(); } }
    else if (e.key === "t") toggleTheme();
    else if (e.key === "j" || e.key === "k") moveSelection(e.key === "j" ? 1 : -1);
    else if (e.key === "Enter") document.querySelector("main .sel")?.click();
    else if (e.key === "?") toast("Keys: g t/s/m/a/r/, switch view · j/k move · Enter open · / filter · t theme · Esc close");
  });
}

function moveSelection(delta) {
  const rows = [...document.querySelectorAll("main tbody tr, main .list .item")];
  if (!rows.length) return;
  let i = rows.findIndex((r) => r.classList.contains("sel"));
  rows.forEach((r) => r.classList.remove("sel"));
  i = Math.max(0, Math.min(rows.length - 1, i + delta));
  rows[i].classList.add("sel");
  rows[i].scrollIntoView({ block: "nearest" });
}

function start() {
  if (!token) {
    mount(document.getElementById("main"), el("div", { class: "empty", text: "No access token. Open the dashboard with the link printed by `rousseau ui` or `rousseau run`." }));
    return;
  }
  const toggle = setupTheme();
  setupKeys(toggle);
  document.getElementById("drawer-close").addEventListener("click", closeDrawer);
  window.addEventListener("hashchange", route);
  live((m) => {
    for (const fn of listeners) fn(m);
    if (m.type === "incident") refreshStatus();
  }, (on) => document.getElementById("live").classList.toggle("on", on));
  refreshStatus();
  setInterval(refreshStatus, 15000);
  route();
}

start();
