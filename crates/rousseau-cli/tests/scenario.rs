//! End-to-end scenario test (cargo feature `integration`): starts the real
//! sensor host with ETW, runs the poisoned-server demo agent, and checks the
//! incidents in `examples/scenarios/expected-incidents.json`, including that
//! the secret read and localhost connection are attributed to the
//! `get_forecast` tool call.
//!
//! Needs an elevated process and Python 3.12+ on PATH (GitHub's Windows
//! runners provide both).

#![cfg(feature = "integration")]

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use rousseau_core::storage::Store;

fn repo() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

#[test]
fn poisoned_server_scenario_produces_expected_incidents() {
    let exe = env!("CARGO_BIN_EXE_rousseau");
    let data = tempfile::tempdir().unwrap();
    let mut host = Command::new(exe)
        .args(["--data-dir", &data.path().display().to_string(), "-v", "run", "--headless", "--mode", "enforce", "--agents"])
        .arg(repo().join("examples/scenarios/demo-agent.toml"))
        .stdout(Stdio::null())
        .spawn()
        .expect("start rousseau run");
    std::thread::sleep(Duration::from_secs(8));

    let status = Command::new("python")
        .arg(repo().join("examples/scenarios/rousseau-demo-agent.py"))
        .args(["--rousseau", exe])
        .status()
        .expect("run the demo agent (python on PATH)");
    assert!(status.success());
    std::thread::sleep(Duration::from_secs(6));
    let _ = host.kill();
    let _ = host.wait();

    let store = Store::open(&data.path().join("rousseau.db")).unwrap();
    let incidents = store.incidents(1_000, None).unwrap();
    let fired: Vec<&str> = incidents.iter().map(|i| i.rule_id.as_str()).collect();
    let expected: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(repo().join("examples/scenarios/expected-incidents.json")).unwrap()).unwrap();
    for want in expected["incidents"].as_array().unwrap() {
        let rule = want["rule"].as_str().unwrap();
        let inc = incidents.iter().find(|i| i.rule_id == rule).unwrap_or_else(|| panic!("{rule} did not fire; fired: {fired:?}"));
        if let Some(tool) = want.get("attributed_to_tool").and_then(|t| t.as_str()) {
            let evidence = store.events_by_ids(&inc.evidence).unwrap();
            assert!(
                evidence.iter().any(|e| e.attribution.as_ref().and_then(|a| a.tool.as_deref()) == Some(tool)),
                "{rule}: evidence not attributed to {tool}: {evidence:?}"
            );
        }
        // Everything happened inside the demo agent's session.
        assert!(inc.session.as_deref().is_some_and(|s| s.starts_with("demo-agent-")), "{rule}: session {:?}", inc.session);
    }
}
