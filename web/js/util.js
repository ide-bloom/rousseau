// DOM and formatting helpers. All text goes through textContent: tool
// descriptions, arguments and results are attacker-controlled.

/** Creates an element. `attrs` may hold `class`, `text`, `title`, `on*` handlers and plain attributes. */
export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = String(v);
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat()) {
    if (c === undefined || c === null || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

/** Replaces the children of `node`. */
export function mount(node, ...children) {
  node.replaceChildren(...children.flat().filter((c) => c !== null && c !== undefined && c !== false));
}

const SEV = ["info", "low", "medium", "high", "critical"];
export const sevRank = (s) => Math.max(0, SEV.indexOf(s || "info"));

export function sevBadge(sev) {
  if (!sev) return el("span", { class: "faint", text: "–" });
  return el("span", { class: `badge sev-${sev}`, text: sev });
}

export function time(ms) {
  if (!ms) return "–";
  const d = new Date(ms);
  return d.toLocaleTimeString(undefined, { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

export function dateTime(ms) {
  if (!ms) return "–";
  const d = new Date(ms);
  return d.toLocaleDateString() + " " + d.toLocaleTimeString(undefined, { hour12: false });
}

export function ago(ms) {
  if (!ms) return "–";
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function truncate(s, n = 160) {
  s = String(s ?? "");
  return s.length > n ? s.slice(0, n) + "…" : s;
}

/** One-line summary of an event (mirrors rousseau-server tree::summarize). */
export function summarize(e) {
  const p = e.process || {};
  const f = e.file, n = e.net, m = e.mcp;
  switch (e.kind) {
    case "process.start": return `${p.name || "?"} (pid ${p.pid}) ${truncate(p.command_line || p.image || "", 200)}`;
    case "process.stop": return `${p.name || "?"} (pid ${p.pid}) exited${p.exit_code != null ? " " + p.exit_code : ""}`;
    case "net.connect": case "net.accept": case "net.close":
      return `${n?.protocol || ""} ${n?.remote || ""} (${n?.remote_scope || ""})` + (n?.bytes_sent != null ? ` ${n.bytes_sent} B out / ${n.bytes_recv ?? 0} B in` : "");
    case "dns.query": return e.dns?.query || "";
    case "registry.set": case "registry.delete": return `${e.registry?.key}\\${e.registry?.value ?? ""} = ${truncate(e.registry?.data ?? "", 100)}`;
    case "mcp.call": return `${m?.server}.${m?.tool}(${truncate(JSON.stringify(m?.arguments ?? {}), 140)})`;
    case "mcp.result": return `${m?.server}.${m?.tool} → ${m?.is_error ? "error" : "ok"} in ${m?.duration_ms ?? "?"} ms`;
    case "mcp.blocked": return `BLOCKED ${m?.server}.${m?.tool}: ${m?.blocked_reason || ""}`;
    case "mcp.finding": return `${e.finding?.title}: ${truncate(e.finding?.detail, 160)}`;
    case "mcp.drift": return `${e.drift?.server}.${e.drift?.tool} ${e.drift?.change}`;
    case "mcp.tools": return `${m?.server}: ${(m?.result?.tools || []).length} tools listed`;
    case "mcp.initialize": return `${m?.server}: ${m?.result?.serverInfo?.name || ""} ${m?.result?.serverInfo?.version || ""} (protocol ${m?.result?.protocolVersion || "?"})`;
    case "mcp.server_start": return `${m?.server} started (${truncate(m?.command || m?.upstream || "", 120)})`;
    case "mcp.message": return `${m?.server} ${m?.direction === "server_to_client" ? "←" : "→"} ${m?.method || ""}`;
    case "transcript.tool_use": return `${e.transcript?.tool} ${truncate(e.transcript?.command || JSON.stringify(e.transcript?.input ?? ""), 180)}`;
    case "session.start": return `${e.session_info?.agent} session started (${e.session_info?.cwd || "?"})`;
    case "session.end": return `${e.session_info?.agent} session ended`;
    case "sensor.health": return `${e.sensor?.sensor}: ${e.sensor?.status} — ${e.sensor?.message}`;
    default:
      if (f) return f.path + (f.new_path ? ` → ${f.new_path}` : "");
      return e.kind;
  }
}

export function attrBadge(a) {
  if (!a) return el("span", { class: "faint", text: "–" });
  const label = a.kind === "unexplained" ? "unexplained" : (a.tool || a.kind);
  return el("span", { class: `attr-${a.kind} mono`, title: `${a.kind} ${a.tool_call || ""} (${a.method || ""})`, text: label });
}

/** Key/value list from [label, value] pairs (skips empty values). */
export function kv(pairs) {
  const dl = el("dl", { class: "kv" });
  for (const [k, v] of pairs) {
    if (v === undefined || v === null || v === "") continue;
    dl.append(el("dt", { text: k }), el("dd", {}, v instanceof Node ? v : String(v)));
  }
  return dl;
}

export function pre(obj, cls = "") {
  return el("pre", { class: cls, text: typeof obj === "string" ? obj : JSON.stringify(obj, null, 2) });
}

/** Renders a +/- line diff with colours. */
export function diffBlock(text) {
  const p = el("pre", { class: "diff" });
  for (const line of String(text || "").split("\n")) {
    const cls = line.startsWith("+ ") ? "add" : line.startsWith("- ") ? "del" : "";
    p.append(el("span", { class: cls, text: line + "\n" }));
  }
  return p;
}

let toastTimer;
export function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 3000);
}

/** Tiny dependency-free sparkline on a canvas. */
export function sparkline(canvas, values) {
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || 160, h = canvas.clientHeight || 42;
  canvas.width = w * dpr; canvas.height = h * dpr;
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);
  const max = Math.max(1, ...values);
  const color = getComputedStyle(document.documentElement).getPropertyValue("--accent").trim() || "#38bdf8";
  ctx.strokeStyle = color; ctx.lineWidth = 1.5; ctx.beginPath();
  values.forEach((v, i) => {
    const x = (i / Math.max(1, values.length - 1)) * (w - 2) + 1;
    const y = h - 2 - (v / max) * (h - 4);
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.stroke();
}
