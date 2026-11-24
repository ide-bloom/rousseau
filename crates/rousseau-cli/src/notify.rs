//! Local alert channels: Windows Event Log and toast notifications.
//!
//! Event Log entries are written to the Application log under the source
//! `Rousseau` (registered by `rousseau install`). Event IDs:
//!
//! | ID   | Meaning                          | Type        |
//! |------|----------------------------------|-------------|
//! | 1000 | sensor started                   | Information |
//! | 1001 | sensor stopped                   | Information |
//! | 2000 | incident, severity info          | Information |
//! | 2001 | incident, severity low           | Information |
//! | 2002 | incident, severity medium        | Warning     |
//! | 2003 | incident, severity high          | Error       |
//! | 2004 | incident, severity critical      | Error       |
//! | 3000 | sensor health degraded or down   | Warning     |
//!
//! Toasts need an interactive session, so they are only used by
//! `rousseau run` and `rousseau ui`, never by the LocalSystem service.

use rousseau_core::event::Severity;
use rousseau_core::incident::Incident;
use rousseau_server::alerts::LocalNotifier;
use windows::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, REPORT_EVENT_TYPE, RegisterEventSourceW,
    ReportEventW,
};
use windows::core::{HSTRING, PCWSTR};

/// Event Log source name.
pub const EVENT_SOURCE: &str = "Rousseau";
/// AppUserModelID used for toasts.
pub const AUMID: &str = "Rousseau.EDR";

pub const EVENT_STARTED: u32 = 1000;
pub const EVENT_STOPPED: u32 = 1001;
pub const EVENT_HEALTH: u32 = 3000;

/// Writes one entry to the Application log.
pub fn report(event_id: u32, severity: Severity, message: &str) {
    let ty: REPORT_EVENT_TYPE = match severity {
        Severity::Info | Severity::Low => EVENTLOG_INFORMATION_TYPE,
        Severity::Medium => EVENTLOG_WARNING_TYPE,
        Severity::High | Severity::Critical => EVENTLOG_ERROR_TYPE,
    };
    let source = HSTRING::from(EVENT_SOURCE);
    let msg = HSTRING::from(message);
    // SAFETY: `source` and `msg` are NUL-terminated wide strings that live
    // for the duration of the calls; the event source handle is released.
    unsafe {
        let Ok(h) = RegisterEventSourceW(PCWSTR::null(), &source) else { return };
        let strings = [PCWSTR(msg.as_ptr())];
        let _ = ReportEventW(h, ty, 0, event_id, None, 0, Some(&strings), None);
        let _ = DeregisterEventSource(h);
    }
}

/// Event Log notifier.
pub struct EventLog;

impl LocalNotifier for EventLog {
    fn name(&self) -> &'static str {
        "eventlog"
    }
    fn notify(&self, i: &Incident) {
        let msg = format!(
            "{} ({})\r\nSeverity: {}\r\nSession: {}\r\nMode: {}\r\nOWASP: {}\r\nATT&CK: {}\r\n\r\n{}\r\n\r\nEvidence events: {:?}",
            i.title,
            i.rule_id,
            i.severity.as_str(),
            i.session.as_deref().unwrap_or("-"),
            i.mode.as_str(),
            i.owasp.join(", "),
            i.mitre.join(", "),
            i.explanation,
            i.evidence
        );
        report(2000 + i.severity.rank() as u32, i.severity, &msg);
    }
}

/// Registers the toast AppUserModelID for the current user (no shortcut
/// needed for unpackaged apps that set a DisplayName).
pub fn register_toast_app() {
    let key = format!(r"HKCU\Software\Classes\AppUserModelId\{AUMID}");
    let _ = std::process::Command::new("reg.exe")
        .args(["add", &key, "/v", "DisplayName", "/t", "REG_SZ", "/d", "Rousseau", "/f"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// Shows a toast. Errors are ignored (notifications may be disabled).
pub fn toast(title: &str, body: &str) {
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
    let xml = format!(
        "<toast><visual><binding template=\"ToastGeneric\"><text>{}</text><text>{}</text></binding></visual></toast>",
        xml_escape(title),
        xml_escape(body)
    );
    let result = (|| -> windows::core::Result<()> {
        let doc = XmlDocument::new()?;
        doc.LoadXml(&HSTRING::from(xml))?;
        let notification = ToastNotification::CreateToastNotification(&doc)?;
        ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(AUMID))?.Show(&notification)
    })();
    if let Err(e) = result {
        tracing::debug!(error = %e, "toast failed");
    }
}

/// Toast notifier.
pub struct Toast;

impl LocalNotifier for Toast {
    fn name(&self) -> &'static str {
        "toast"
    }
    fn notify(&self, i: &Incident) {
        toast(
            &format!("Rousseau: {} [{}]", i.title, i.severity.as_str()),
            &format!("{} · {}", i.rule_id, i.agent.as_deref().unwrap_or("agent")),
        );
    }
}
