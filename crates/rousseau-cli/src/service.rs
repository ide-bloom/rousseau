//! The `Rousseau` Windows service (LocalSystem) and its installer.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result};
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::host::{Host, HostOptions};
use crate::paths::Paths;

/// Service name.
pub const SERVICE_NAME: &str = "Rousseau";
const DISPLAY_NAME: &str = "Rousseau EDR sensor";
const DESCRIPTION: &str = "Endpoint detection and response for AI coding agents: ETW sensors, MCP correlation and detection rules.";

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Entry point used by the SCM (`rousseau service`).
pub fn run_dispatcher(data_dir: PathBuf) -> Result<()> {
    let _ = DATA_DIR.set(data_dir);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).context("not started by the Service Control Manager")
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!(error = %e, "service failed");
    }
}

fn run_service() -> Result<()> {
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(SERVICE_NAME, handler)?;
    let set = |state: ServiceState, accept: ServiceControlAccept| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })
    };
    set(ServiceState::StartPending, ServiceControlAccept::empty())?;
    let paths = Paths::resolve(DATA_DIR.get().cloned());
    let rt = tokio::runtime::Runtime::new()?;
    let host = rt.block_on(Host::start(&paths, HostOptions { toast: false, extra_agents: Vec::new(), mode: None }));
    let host = match host {
        Ok(h) => h,
        Err(e) => {
            set(ServiceState::Stopped, ServiceControlAccept::empty())?;
            return Err(e);
        }
    };
    set(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN)?;
    let _ = stop_rx.recv();
    set(ServiceState::StopPending, ServiceControlAccept::empty())?;
    drop(host);
    rt.shutdown_timeout(Duration::from_secs(5));
    set(ServiceState::Stopped, ServiceControlAccept::empty())?;
    Ok(())
}

/// Registers and starts the service. `exe` must be in an admin-only
/// directory (the service runs it as LocalSystem).
pub fn install(exe: &Path, data_dir: &Path) -> Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.to_path_buf(),
        launch_arguments: vec!["--data-dir".into(), data_dir.as_os_str().to_owned(), "service".into()],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let svc = match mgr.open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS) {
        Ok(s) => {
            s.change_config(&info)?;
            s
        }
        Err(_) => mgr.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS)?,
    };
    svc.set_description(DESCRIPTION)?;
    if svc.query_status()?.current_state != ServiceState::Running {
        svc.start::<&str>(&[])?;
    }
    Ok(())
}

/// Stops and deletes the service.
pub fn uninstall() -> Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let svc = mgr.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS)?;
    if svc.query_status()?.current_state != ServiceState::Stopped {
        let _ = svc.stop();
        for _ in 0..20 {
            if svc.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    svc.delete()?;
    Ok(())
}

/// `Some(state)` if the service is installed.
pub fn status() -> Option<String> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    let svc = mgr.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS).ok()?;
    Some(format!("{:?}", svc.query_status().ok()?.current_state))
}
