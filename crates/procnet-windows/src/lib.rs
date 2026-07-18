//! Windows platform boundary for `ProcNet Recorder`.
//!
//! ETW, TDH, IP Helper and native handle implementations are intentionally deferred to V0.

#![deny(unsafe_code)]

mod etw;
mod process_icon;
#[allow(unsafe_code)]
mod raw;
mod system_snapshot;

pub use etw::{
    CleanupPreparation, CleanupResult, EtwCleanupError, EtwProbeError, EtwProbeErrorKind,
    EtwProbeSummary, EtwSessionStatistics, Ipv4Aggregate, Ipv6Aggregate, NetworkDirection,
    NetworkProtocol, PreparedEtwCleanup, cleanup_target, run_tcp_ip_probe,
    run_tcp_ip_probe_with_sink, run_tcp_ip_probe_with_sink_until,
};
pub use process_icon::ProcessIconCache;
pub use system_snapshot::{SystemSnapshotError, capture_system_snapshot};

/// The single fixed ETW Session owned by `ProcNet` Recorder.
pub const PROJECT_ETW_SESSION_NAME: &str = "ProcNetRecorder-V0-TcpIp-Probe";

/// Starts a new copy of the GUI through the standard Windows `runas` elevation path.
///
/// # Errors
///
/// Returns a clear error when the executable path cannot be resolved, UAC is cancelled, or
/// Windows rejects the elevated launch.
pub fn restart_elevated() -> Result<(), String> {
    let executable =
        std::env::current_exe().map_err(|error| format!("无法确定当前程序路径：{error}"))?;
    let working_directory = executable
        .parent()
        .ok_or_else(|| "当前程序路径没有父目录".to_owned())?;
    raw::elevation::restart_elevated(&executable, working_directory, "--elevated-handoff")
}

/// Starts a new copy through the normal Explorer shell, providing an explicit path out of an
/// elevated GUI process.
///
/// # Errors
///
/// Returns a clear error if the executable path cannot be resolved or Explorer rejects launch.
pub fn restart_unelevated() -> Result<(), String> {
    let executable =
        std::env::current_exe().map_err(|error| format!("无法确定当前程序路径：{error}"))?;
    let working_directory = executable
        .parent()
        .ok_or_else(|| "当前程序路径没有父目录".to_owned())?;
    raw::elevation::restart_unelevated(&executable, working_directory)
}

/// Installs Ctrl+C ignore behavior for the current V0 validation driver process.
///
/// # Errors
///
/// Returns an error if Windows rejects the console handler change.
pub fn ignore_ctrl_c_for_validation() -> Result<impl Drop, String> {
    raw::console_control::IgnoreCtrlCGuard::install()
}

/// Broadcasts a real Ctrl+C event to the current console for V0 validation.
///
/// # Errors
///
/// Returns an error if Windows rejects the console control event.
pub fn generate_ctrl_c_for_validation() -> Result<(), String> {
    raw::console_control::generate_ctrl_c()
}

/// Detaches the V0 validation driver from its parent and allocates a private console.
///
/// # Errors
///
/// Returns an error if Windows cannot allocate the private console.
pub fn create_isolated_console_for_validation() -> Result<(), String> {
    raw::console_control::create_isolated_console()
}

/// Returns the product name without exposing a platform type to the core crate.
#[must_use]
pub const fn project_name() -> &'static str {
    procnet_core::PROJECT_NAME
}

#[cfg(test)]
mod tests {
    use super::project_name;

    #[test]
    fn platform_layer_depends_inward_on_core() {
        assert_eq!(project_name(), "ProcNet Recorder");
    }
}
