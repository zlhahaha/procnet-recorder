use std::ffi::c_void;
use std::mem::{size_of, size_of_val};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use windows::Win32::Foundation::{
    BOOL, CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_FILES, ERROR_SUCCESS, FILETIME,
    GetLastError, HANDLE,
};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

const FILETIME_UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;
const MAX_PROCESS_IMAGE_NAME_CHARS: usize = 32_768;
const MAX_TABLE_QUERY_ATTEMPTS: usize = 4;

#[derive(Debug)]
pub(crate) struct NativeProcess {
    pub pid: u32,
    pub started_at_unix_nanos: Option<u64>,
    pub name: String,
    pub image_path: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum NativeProtocol {
    Tcp,
    Udp,
}

#[derive(Debug)]
pub(crate) struct NativeConnection {
    pub protocol: NativeProtocol,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub tcp_state: Option<u32>,
    pub pid: u32,
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: The handle was returned by a successful Win32 open/snapshot call and is owned
        // exclusively by this guard. CloseHandle is called exactly once here.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub(crate) fn capture_processes() -> Result<Vec<NativeProcess>, String> {
    // SAFETY: The flags and PID are valid for a system-wide process snapshot. The returned handle
    // is immediately placed in an exclusive RAII guard.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map(OwnedHandle)
        .map_err(|error| format!("CreateToolhelp32Snapshot failed: {error}"))?;
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(size_of::<PROCESSENTRY32W>())
            .map_err(|_| "PROCESSENTRY32W size does not fit u32".to_owned())?,
        ..PROCESSENTRY32W::default()
    };
    // SAFETY: entry points to a fully initialized PROCESSENTRY32W with dwSize set as required;
    // snapshot is a live process snapshot handle.
    unsafe { Process32FirstW(snapshot.0, &raw mut entry) }
        .map_err(|error| format!("Process32FirstW failed: {error}"))?;

    let mut processes = Vec::new();
    loop {
        let identity = query_process_identity(entry.th32ProcessID);
        processes.push(NativeProcess {
            pid: entry.th32ProcessID,
            started_at_unix_nanos: identity.as_ref().map(|value| value.0),
            name: utf16_z(&entry.szExeFile),
            image_path: identity.and_then(|value| value.1),
        });
        // SAFETY: entry remains a valid writable PROCESSENTRY32W with dwSize unchanged, and the
        // snapshot handle remains live for the duration of the loop.
        if unsafe { Process32NextW(snapshot.0, &raw mut entry) }.is_err() {
            // SAFETY: GetLastError has no pointer preconditions and is called immediately after
            // the failed Process32NextW on this thread.
            let error = unsafe { GetLastError() };
            if error == ERROR_NO_MORE_FILES {
                break;
            }
            return Err(format!(
                "Process32NextW failed with Win32 error {}",
                error.0
            ));
        }
    }
    processes.sort_unstable_by_key(|process| (process.pid, process.started_at_unix_nanos));
    Ok(processes)
}

fn query_process_identity(pid: u32) -> Option<(u64, Option<String>)> {
    // SAFETY: OpenProcess is called with query-only access for the supplied PID; a successful
    // handle is transferred immediately into an exclusive RAII guard.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .ok()
        .map(OwnedHandle)?;
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: All FILETIME pointers are valid and writable, and process is a live query handle.
    unsafe {
        GetProcessTimes(
            process.0,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    }
    .ok()?;
    Some((
        filetime_to_unix_nanos(creation),
        query_image_path(process.0),
    ))
}

fn query_image_path(process: HANDLE) -> Option<String> {
    let mut buffer = vec![0u16; MAX_PROCESS_IMAGE_NAME_CHARS];
    let mut length = u32::try_from(buffer.len()).ok()?;
    // SAFETY: buffer is contiguous writable UTF-16 storage of `length` elements; process is a
    // live query handle and QueryFullProcessImageNameW updates length to the initialized count.
    unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_FORMAT::default(),
            PWSTR(buffer.as_mut_ptr()),
            &raw mut length,
        )
    }
    .ok()?;
    buffer.truncate(usize::try_from(length).ok()?);
    Some(String::from_utf16_lossy(&buffer))
}

pub(crate) fn capture_connections() -> Result<Vec<NativeConnection>, String> {
    let mut connections = Vec::new();
    capture_tcp4(&mut connections)?;
    capture_tcp6(&mut connections)?;
    capture_udp4(&mut connections)?;
    capture_udp6(&mut connections)?;
    connections.sort_unstable_by_key(|connection| {
        (
            connection.pid,
            match connection.protocol {
                NativeProtocol::Tcp => 0,
                NativeProtocol::Udp => 1,
            },
            connection.local,
            connection.remote,
        )
    });
    Ok(connections)
}

fn capture_tcp4(output: &mut Vec<NativeConnection>) -> Result<(), String> {
    let buffer = query_table(|pointer, size| {
        // SAFETY: query_table supplies either a null sizing pointer or aligned writable storage of
        // *size bytes. Remaining arguments select the documented owner-PID IPv4 TCP table.
        unsafe {
            GetExtendedTcpTable(
                pointer,
                size,
                BOOL(0),
                u32::from(AF_INET.0),
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        }
    })?;
    // SAFETY: query_table returned an aligned buffer initialized by GetExtendedTcpTable for the
    // exact MIB_TCPTABLE_OWNER_PID layout. Each row lies within the API-reported allocation.
    unsafe {
        let table = &*(buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>());
        for row in rows(&buffer, &table.table, table.dwNumEntries)? {
            output.push(tcp4_connection(row));
        }
    }
    Ok(())
}

fn capture_tcp6(output: &mut Vec<NativeConnection>) -> Result<(), String> {
    let buffer = query_table(|pointer, size| {
        // SAFETY: query_table supplies valid sizing or writable storage arguments. Remaining
        // arguments select the documented owner-PID IPv6 TCP table.
        unsafe {
            GetExtendedTcpTable(
                pointer,
                size,
                BOOL(0),
                u32::from(AF_INET6.0),
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        }
    })?;
    // SAFETY: The aligned buffer contains the MIB_TCP6TABLE_OWNER_PID layout returned by the API.
    unsafe {
        let table = &*(buffer.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>());
        for row in rows(&buffer, &table.table, table.dwNumEntries)? {
            output.push(tcp6_connection(row));
        }
    }
    Ok(())
}

fn capture_udp4(output: &mut Vec<NativeConnection>) -> Result<(), String> {
    let buffer = query_table(|pointer, size| {
        // SAFETY: query_table supplies valid sizing or writable storage arguments. Remaining
        // arguments select the documented owner-PID IPv4 UDP table.
        unsafe {
            GetExtendedUdpTable(
                pointer,
                size,
                BOOL(0),
                u32::from(AF_INET.0),
                UDP_TABLE_OWNER_PID,
                0,
            )
        }
    })?;
    // SAFETY: The aligned buffer contains the MIB_UDPTABLE_OWNER_PID layout returned by the API.
    unsafe {
        let table = &*(buffer.as_ptr().cast::<MIB_UDPTABLE_OWNER_PID>());
        for row in rows(&buffer, &table.table, table.dwNumEntries)? {
            output.push(udp4_connection(row));
        }
    }
    Ok(())
}

fn capture_udp6(output: &mut Vec<NativeConnection>) -> Result<(), String> {
    let buffer = query_table(|pointer, size| {
        // SAFETY: query_table supplies valid sizing or writable storage arguments. Remaining
        // arguments select the documented owner-PID IPv6 UDP table.
        unsafe {
            GetExtendedUdpTable(
                pointer,
                size,
                BOOL(0),
                u32::from(AF_INET6.0),
                UDP_TABLE_OWNER_PID,
                0,
            )
        }
    })?;
    // SAFETY: The aligned buffer contains the MIB_UDP6TABLE_OWNER_PID layout returned by the API.
    unsafe {
        let table = &*(buffer.as_ptr().cast::<MIB_UDP6TABLE_OWNER_PID>());
        for row in rows(&buffer, &table.table, table.dwNumEntries)? {
            output.push(udp6_connection(row));
        }
    }
    Ok(())
}

fn query_table(
    mut query: impl FnMut(Option<*mut c_void>, *mut u32) -> u32,
) -> Result<Vec<usize>, String> {
    let mut byte_count = 0u32;
    let first = query(None, &raw mut byte_count);
    if first != ERROR_INSUFFICIENT_BUFFER.0 && first != ERROR_SUCCESS.0 {
        return Err(format!(
            "IP Helper table sizing failed with Win32 error {first}"
        ));
    }
    for _ in 0..MAX_TABLE_QUERY_ATTEMPTS {
        let requested = usize::try_from(byte_count)
            .map_err(|_| "IP Helper table size does not fit usize".to_owned())?;
        let words = requested.div_ceil(size_of::<usize>()).max(1);
        let mut buffer = vec![0usize; words];
        let mut supplied = u32::try_from(size_of_val(buffer.as_slice()))
            .map_err(|_| "IP Helper table allocation does not fit u32".to_owned())?;
        let status = query(Some(buffer.as_mut_ptr().cast()), &raw mut supplied);
        if status == ERROR_SUCCESS.0 {
            return Ok(buffer);
        }
        if status != ERROR_INSUFFICIENT_BUFFER.0 {
            return Err(format!(
                "IP Helper table query failed with Win32 error {status}"
            ));
        }
        byte_count = supplied;
    }
    Err("IP Helper table kept growing across bounded query retries".to_owned())
}

unsafe fn rows<'a, T>(
    buffer: &'a [usize],
    first: &'a [T; 1],
    count: u32,
) -> Result<&'a [T], String> {
    let count =
        usize::try_from(count).map_err(|_| "table row count does not fit usize".to_owned())?;
    let row_offset = first
        .as_ptr()
        .addr()
        .checked_sub(buffer.as_ptr().addr())
        .ok_or_else(|| "IP Helper row pointer precedes its allocation".to_owned())?;
    let row_bytes = count
        .checked_mul(size_of::<T>())
        .ok_or_else(|| "IP Helper row byte count overflowed".to_owned())?;
    let required = row_offset
        .checked_add(row_bytes)
        .ok_or_else(|| "IP Helper table byte count overflowed".to_owned())?;
    if required > size_of_val(buffer) {
        return Err("IP Helper row count exceeds the returned allocation".to_owned());
    }
    // SAFETY: The caller verified that `first` belongs to the variable-length table returned by
    // IP Helper, and checked byte arithmetic proves count rows fit the allocation.
    Ok(unsafe { std::slice::from_raw_parts(first.as_ptr(), count) })
}

fn tcp4_connection(row: &MIB_TCPROW_OWNER_PID) -> NativeConnection {
    NativeConnection {
        protocol: NativeProtocol::Tcp,
        local: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
            port(row.dwLocalPort),
        ),
        remote: Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes())),
            port(row.dwRemotePort),
        )),
        tcp_state: Some(row.dwState),
        pid: row.dwOwningPid,
    }
}

fn tcp6_connection(row: &MIB_TCP6ROW_OWNER_PID) -> NativeConnection {
    NativeConnection {
        protocol: NativeProtocol::Tcp,
        local: SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
            port(row.dwLocalPort),
        ),
        remote: Some(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)),
            port(row.dwRemotePort),
        )),
        tcp_state: Some(row.dwState),
        pid: row.dwOwningPid,
    }
}

fn udp4_connection(row: &MIB_UDPROW_OWNER_PID) -> NativeConnection {
    NativeConnection {
        protocol: NativeProtocol::Udp,
        local: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
            port(row.dwLocalPort),
        ),
        remote: None,
        tcp_state: None,
        pid: row.dwOwningPid,
    }
}

fn udp6_connection(row: &MIB_UDP6ROW_OWNER_PID) -> NativeConnection {
    NativeConnection {
        protocol: NativeProtocol::Udp,
        local: SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
            port(row.dwLocalPort),
        ),
        remote: None,
        tcp_state: None,
        pid: row.dwOwningPid,
    }
}

fn port(raw: u32) -> u16 {
    u16::try_from(raw & u32::from(u16::MAX)).map_or(0, u16::from_be)
}

fn filetime_to_unix_nanos(value: FILETIME) -> u64 {
    let ticks = (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime);
    ticks
        .saturating_sub(FILETIME_UNIX_EPOCH_TICKS)
        .saturating_mul(100)
}

fn utf16_z(value: &[u16]) -> String {
    let length = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..length])
}
