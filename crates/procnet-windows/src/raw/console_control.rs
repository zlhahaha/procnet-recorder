use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Foundation::{BOOL, FALSE, TRUE};
use windows::Win32::System::Console::{
    AllocConsole, CTRL_BREAK_EVENT, CTRL_C_EVENT, FreeConsole, GenerateConsoleCtrlEvent,
    SetConsoleCtrlHandler,
};

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Installed project console handler. Dropping it unregisters only this handler.
pub(crate) struct ConsoleCtrlHandler;

impl ConsoleCtrlHandler {
    pub(crate) fn install() -> Result<Self, String> {
        STOP_REQUESTED.store(false, Ordering::SeqCst);
        // SAFETY: `None, FALSE` restores Ctrl+C delivery for this process. The callback has the
        // required system ABI, uses only a static atomic, and remains valid for the process lifetime.
        unsafe {
            SetConsoleCtrlHandler(None, FALSE)
                .and_then(|()| SetConsoleCtrlHandler(Some(control_handler), TRUE))
        }
        .map_err(|error| format!("cannot install Windows console Ctrl+C handler: {error}"))?;
        Ok(Self)
    }

    pub(crate) fn stop_requested() -> bool {
        STOP_REQUESTED.load(Ordering::SeqCst)
    }
}

impl Drop for ConsoleCtrlHandler {
    fn drop(&mut self) {
        // SAFETY: The same static callback registered by `install` is removed for this process.
        let _ = unsafe { SetConsoleCtrlHandler(Some(control_handler), FALSE) };
    }
}

/// Temporarily makes the current validation driver ignore broadcast Ctrl+C events.
pub struct IgnoreCtrlCGuard;

impl IgnoreCtrlCGuard {
    pub(crate) fn install() -> Result<Self, String> {
        // SAFETY: A null handler with TRUE is the documented per-process Ctrl+C ignore setting.
        unsafe { SetConsoleCtrlHandler(None, TRUE) }
            .map_err(|error| format!("cannot ignore Ctrl+C in validation driver: {error}"))?;
        Ok(Self)
    }
}

impl Drop for IgnoreCtrlCGuard {
    fn drop(&mut self) {
        // SAFETY: A null handler with FALSE restores normal Ctrl+C handling for this process.
        let _ = unsafe { SetConsoleCtrlHandler(None, FALSE) };
    }
}

pub(crate) fn generate_ctrl_c() -> Result<(), String> {
    // SAFETY: Group id zero broadcasts CTRL_C_EVENT only to processes sharing this console. The
    // validation driver has installed `IgnoreCtrlCGuard`; its child installs the project handler.
    unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) }
        .map_err(|error| format!("cannot generate console Ctrl+C event: {error}"))
}

pub(crate) fn create_isolated_console() -> Result<(), String> {
    // SAFETY: These calls affect only the current validation driver process. `FreeConsole` may
    // legitimately fail when no console is attached, so only the subsequent allocation is required.
    let _ = unsafe { FreeConsole() };
    // SAFETY: `AllocConsole` attaches one new console to the current process, which currently has
    // none after the best-effort `FreeConsole` call.
    unsafe { AllocConsole() }
        .map_err(|error| format!("cannot allocate isolated validation console: {error}"))
}

unsafe extern "system" fn control_handler(control_type: u32) -> BOOL {
    if matches!(control_type, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
        STOP_REQUESTED.store(true, Ordering::SeqCst);
        TRUE
    } else {
        FALSE
    }
}
