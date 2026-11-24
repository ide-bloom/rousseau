// Settings: response mode, transcript adapters (opt-in), retention, alerts.
import { get, put } from "../api.js";
import { state } from "../app.js";
import { el, mount, toast } from "../util.js";

export async function render(main) {
  const s = await get("/settings");
  const select = (value, options) => { const e = el("select", { disabled: state.replay }, options.map((o) => el("option", { value: o, text: o }))); e.value = value; return e; };
  const check = (value) => { const e = el("input", { type: "checkbox", disabled: state.replay }); e.checked = !!value; return e; };
  const f = {
    mode: select(s.response.mode, ["observe", "alert", "enforce"]),
    allow_suspend: check(s.response.allow_suspend),
    strict_pinning: check(s.pinning.strict),
    transcripts_claude_code: check(s.transcripts.claude_code),
    transcripts_codex: check(s.transcripts.codex),
    retention_days: el("input", { type: "number", min: "1", max: "3650", value: s.retention_days, disabled: state.replay }),
    alert_min_severity: select(s.alerts.min_severity, ["info", "low", "medium", "high", "critical"]),
    toast: check(s.alerts.toast),
    eventlog: check(s.alerts.eventlog),
  };
  const row = (label, input, hint) => [el("label", { text: label }), input, hint ? el("div", { class: "hint", text: hint }) : null];
  const save = el("button", { class: "btn primary", disabled: state.replay, text: "Save", onclick: async () => {
    try {
      await put("/settings", {
        mode: f.mode.value, allow_suspend: f.allow_suspend.checked, strict_pinning: f.strict_pinning.checked,
        transcripts_claude_code: f.transcripts_claude_code.checked, transcripts_codex: f.transcripts_codex.checked,
        retention_days: Number(f.retention_days.value), alert_min_severity: f.alert_min_severity.value,
        toast: f.toast.checked, eventlog: f.eventlog.checked,
      });
      toast("Settings saved; the sensor reloaded them.");
    } catch (e) { toast(e.message); }
  } });
  const channels = ["discord_webhook", "slack_webhook", "webhook_url"].filter((k) => s.alerts[k]).join(", ") || "none";
  mount(main, el("h1", { text: "Settings" }),
    el("div", { class: "form" },
      ...row("Response mode", f.mode, "observe: record only · alert: notify · enforce: also block MCP tool calls (drifted/unapproved tools, high-severity argument findings)."),
      ...row("Allow process-tree suspension", f.allow_suspend, "Enforce-mode rules marked suspend_tree may suspend the agent's process tree. Critical system processes are never suspended. Resume with `rousseau resume <pid>`."),
      ...row("Strict tool pinning", f.strict_pinning, "New servers' tools start as pending and need approval (default: trust on first use)."),
      ...row("Read Claude Code transcripts", f.transcripts_claude_code, "Opt-in. Reads ~/.claude/projects/*.jsonl read-only and stores only tool-use metadata, to attribute built-in Bash/Read/Edit tool activity."),
      ...row("Read Codex transcripts", f.transcripts_codex, "Opt-in. Reads ~/.codex/sessions rollout files read-only."),
      ...row("Retention (days)", f.retention_days),
      ...row("Alert severity floor", f.alert_min_severity),
      ...row("Windows toast", f.toast),
      ...row("Windows Event Log", f.eventlog, "Application log, source Rousseau (event ids in docs/architecture.md)."),
      el("label", { text: "Webhook channels" }), el("div", { class: "mono", text: channels }),
      el("div", { class: "hint", text: "Discord, Slack and HMAC-signed webhook URLs are set in rousseau.toml ([alerts]) so secrets never pass through the browser." }),
      el("span"), el("div", {}, save)));
}
