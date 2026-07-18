use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::Win32::Foundation::GetLastError;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::PCWSTR;

pub(crate) fn restart_elevated(
    executable: &Path,
    working_directory: &Path,
    parameters: &str,
) -> Result<(), String> {
    let operation = wide("runas");
    let executable = wide(executable.as_os_str());
    let parameters = wide(parameters);
    let working_directory = wide(working_directory.as_os_str());
    // SAFETY: All strings are owned, NUL-terminated UTF-16 buffers that remain live for the call.
    // No window handle is supplied, and ShellExecuteW does not retain these pointers after
    // returning.
    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(operation.as_ptr()),
            PCWSTR(executable.as_ptr()),
            PCWSTR(parameters.as_ptr()),
            PCWSTR(working_directory.as_ptr()),
            SW_SHOWNORMAL,
        )
    };
    if result.0 > 32 {
        return Ok(());
    }
    // SAFETY: GetLastError has no pointer preconditions and is read immediately after the failed
    // ShellExecuteW call on the same thread.
    let error = unsafe { GetLastError() };
    if error.0 == 1223 {
        return Err("管理员授权已取消；当前窗口仍保持受限模式".to_owned());
    }
    Err(format!(
        "无法以管理员身份重新启动（ShellExecuteW={}，Win32={}）",
        result.0, error.0
    ))
}

pub(crate) fn restart_unelevated(
    executable: &Path,
    working_directory: &Path,
) -> Result<(), String> {
    let operation = wide("open");
    let explorer = wide("explorer.exe");
    let parameters = wide(format!("\"{}\"", executable.display()));
    let working_directory = wide(working_directory.as_os_str());
    // SAFETY: All input strings are owned NUL-terminated UTF-16 buffers and remain live for the
    // duration of ShellExecuteW. Explorer receives the executable as a quoted argument and the
    // API does not retain any pointer after returning.
    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(operation.as_ptr()),
            PCWSTR(explorer.as_ptr()),
            PCWSTR(parameters.as_ptr()),
            PCWSTR(working_directory.as_ptr()),
            SW_SHOWNORMAL,
        )
    };
    if result.0 > 32 {
        Ok(())
    } else {
        // SAFETY: GetLastError has no pointer preconditions and is read immediately after the
        // failed ShellExecuteW call on the same thread.
        let error = unsafe { GetLastError() };
        Err(format!(
            "无法通过 Windows Shell 以普通权限重新启动（ShellExecuteW={}，Win32={}）",
            result.0, error.0
        ))
    }
}

fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}
