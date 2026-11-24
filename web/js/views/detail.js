// Event detail drawer shared by all views.
import { openDrawer } from "../app.js";
import { attrBadge, dateTime, diffBlock, el, kv, pre, sevBadge, summarize } from "../util.js";

export function showEvent(e) {
  const p = e.process || {}, l = e.lineage || {}, a = e.attribution;
  const parts = [
    el("p", {}, sevBadge(e.severity), " ", el("span", { class: "kind", text: e.kind }), " ", el("span", { text: summarize(e) })),
    kv([
      ["Event id", e.id], ["Time", dateTime(e.ts)], ["Session", e.session],
      ["Agent", l.agent], ["Lineage", l.ancestors?.length ? [p.name, ...l.ancestors].filter(Boolean).join(" ← ") : null],
      ["MCP server subtree", l.mcp_server], ["Attribution", a ? attrBadge(a) : null],
      ["Tool call", a?.tool_call], ["Attribution method", a?.method],
      ["Process", p.pid ? `${p.name || ""} (pid ${p.pid}, ppid ${p.ppid ?? "?"})` : null],
      ["Image", p.image], ["Command line", p.command_line], ["Working dir", p.cwd], ["Signer", p.signer],
    ]),
  ];
  if (e.file) parts.push(el("h2", { text: "File" }), kv([["Path", e.file.path], ["New path", e.file.new_path]]));
  if (e.net) parts.push(el("h2", { text: "Network" }), kv([["Protocol", e.net.protocol], ["Direction", e.net.direction], ["Remote", e.net.remote], ["Scope", e.net.remote_scope], ["Local", e.net.local_addr ? `${e.net.local_addr}:${e.net.local_port}` : null], ["Bytes sent", e.net.bytes_sent], ["Bytes received", e.net.bytes_recv]]));
  if (e.dns) parts.push(el("h2", { text: "DNS" }), kv([["Query", e.dns.query], ["Type", e.dns.query_type], ["Longest label", e.dns.longest_label], ["Subdomain entropy", e.dns.subdomain_entropy]]));
  if (e.registry) parts.push(el("h2", { text: "Registry" }), kv([["Key", e.registry.key], ["Value", e.registry.value], ["Data", e.registry.data]]));
  if (e.finding) {
    const f = e.finding;
    parts.push(el("h2", { text: "Inspector finding" }), kv([["Inspector", f.inspector], ["Code", f.code], ["Title", f.title], ["Detail", f.detail], ["Location", f.location], ["Server", f.server], ["Tool", f.tool]]));
    if (f.decoded) parts.push(el("h2", { text: "Decoded hidden content" }), pre(f.decoded, "decoded"));
  }
  if (e.drift) parts.push(el("h2", { text: `Tool ${e.drift.change}` }), kv([["Server", e.drift.server], ["Tool", e.drift.tool], ["Previous hash", e.drift.previous_hash], ["Current hash", e.drift.current_hash]]), diffBlock(e.drift.diff));
  if (e.transcript) parts.push(el("h2", { text: "Transcript tool use" }), kv([["Adapter", e.transcript.adapter], ["Tool", e.transcript.tool], ["Command", e.transcript.command], ["Agent session", e.transcript.agent_session], ["cwd", e.transcript.cwd]]), e.transcript.input ? pre(e.transcript.input) : null);
  if (e.mcp) {
    const m = e.mcp;
    parts.push(el("h2", { text: "MCP" }), kv([["Server", m.server], ["Transport", m.transport], ["Method", m.method], ["Tool", m.tool], ["Call id", m.call_id], ["Duration", m.duration_ms != null ? `${m.duration_ms} ms` : null], ["Blocked", m.blocked_reason], ["Server pid", m.server_pid], ["Proxy pid", m.proxy_pid], ["Command", m.command], ["Upstream", m.upstream], ["MCP session", m.session_id]]));
    for (const [k, v] of [["Arguments", m.arguments], ["Params", m.params], ["Result", m.result], ["Error", m.error]]) if (v !== undefined && v !== null) parts.push(el("h2", { text: k }), pre(v));
  }
  if (e.sensor) parts.push(el("h2", { text: "Sensor" }), kv([["Sensor", e.sensor.sensor], ["Status", e.sensor.status], ["Message", e.sensor.message], ["Lost", e.sensor.events_lost], ["Dropped", e.sensor.events_dropped]]));
  parts.push(el("details", {}, el("summary", { text: "Raw event JSON" }), pre(e)));
  openDrawer(`Event ${e.id}`, ...parts);
}
