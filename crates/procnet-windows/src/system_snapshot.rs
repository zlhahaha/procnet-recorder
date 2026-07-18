use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use procnet_core::{
    ConnectionSnapshot, ProcessKey, ProcessSnapshot, SystemSnapshot, TcpConnectionState,
    TransportProtocol,
};

use crate::raw::system_snapshot::{
    NativeConnection, NativeProcess, NativeProtocol, capture_connections, capture_processes,
};

/// Safe platform snapshot failure with no native pointers or handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemSnapshotError(String);

impl fmt::Display for SystemSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for SystemSnapshotError {}

/// Captures processes and TCP/UDP IPv4/IPv6 ownership, then joins only by a real `ProcessKey`.
///
/// # Errors
///
/// Returns an error when process enumeration or an IP Helper table query fails.
pub fn capture_system_snapshot() -> Result<SystemSnapshot, SystemSnapshotError> {
    let processes = capture_processes().map_err(SystemSnapshotError)?;
    let connections = capture_connections().map_err(SystemSnapshotError)?;
    Ok(join_snapshot(current_unix_nanos(), processes, connections))
}

fn join_snapshot(
    captured_at_unix_nanos: u64,
    processes: Vec<NativeProcess>,
    connections: Vec<NativeConnection>,
) -> SystemSnapshot {
    let process_keys = processes
        .iter()
        .filter_map(|process| {
            process.started_at_unix_nanos.map(|started_at_unix_nanos| {
                (
                    process.pid,
                    ProcessKey {
                        pid: process.pid,
                        started_at_unix_nanos,
                    },
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    let process_names = processes
        .iter()
        .map(|process| (process.pid, process.name.clone()))
        .collect::<BTreeMap<_, _>>();
    let processes = processes
        .into_iter()
        .filter(|process| process.started_at_unix_nanos.is_some())
        .map(|process| ProcessSnapshot {
            key: process_keys[&process.pid],
            name: process.name,
            image_path: process.image_path,
            icon: procnet_core::ProcessIconState::NotLoaded,
        })
        .collect();
    let connections = connections
        .into_iter()
        .map(|connection| ConnectionSnapshot {
            protocol: match connection.protocol {
                NativeProtocol::Tcp => TransportProtocol::Tcp,
                NativeProtocol::Udp => TransportProtocol::Udp,
            },
            local: connection.local,
            remote: connection.remote,
            tcp_state: connection.tcp_state.map(tcp_state),
            pid: connection.pid,
            process_key: process_keys.get(&connection.pid).copied(),
            owner_name: process_names.get(&connection.pid).cloned(),
        })
        .collect();
    SystemSnapshot {
        captured_at_unix_nanos,
        process_names: process_names.into_iter().collect(),
        processes,
        connections,
    }
}

const fn tcp_state(state: u32) -> TcpConnectionState {
    match state {
        1 => TcpConnectionState::Closed,
        2 => TcpConnectionState::Listen,
        3 => TcpConnectionState::SynSent,
        4 => TcpConnectionState::SynReceived,
        5 => TcpConnectionState::Established,
        6 => TcpConnectionState::FinWait1,
        7 => TcpConnectionState::FinWait2,
        8 => TcpConnectionState::CloseWait,
        9 => TcpConnectionState::Closing,
        10 => TcpConnectionState::LastAck,
        11 => TcpConnectionState::TimeWait,
        12 => TcpConnectionState::DeleteTcb,
        unknown => TcpConnectionState::Unknown(unknown),
    }
}

fn current_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use procnet_core::{TcpConnectionState, TransportProtocol};

    use super::{join_snapshot, tcp_state};
    use crate::raw::system_snapshot::{NativeConnection, NativeProcess, NativeProtocol};

    #[test]
    fn joins_connections_only_to_real_process_start_times() {
        let snapshot = join_snapshot(
            999,
            vec![
                NativeProcess {
                    pid: 7,
                    started_at_unix_nanos: Some(123),
                    name: "fixture.exe".to_owned(),
                    image_path: Some("C:\\fixture.exe".to_owned()),
                },
                NativeProcess {
                    pid: 8,
                    started_at_unix_nanos: None,
                    name: "protected.exe".to_owned(),
                    image_path: None,
                },
            ],
            vec![
                NativeConnection {
                    protocol: NativeProtocol::Tcp,
                    local: "127.0.0.1:39001".parse::<SocketAddr>().unwrap(),
                    remote: Some("127.0.0.1:40000".parse().unwrap()),
                    tcp_state: Some(5),
                    pid: 7,
                },
                NativeConnection {
                    protocol: NativeProtocol::Udp,
                    local: "127.0.0.1:39002".parse().unwrap(),
                    remote: None,
                    tcp_state: None,
                    pid: 8,
                },
            ],
        );
        assert_eq!(snapshot.captured_at_unix_nanos, 999);
        assert_eq!(snapshot.processes[0].key.started_at_unix_nanos, 123);
        assert_eq!(snapshot.connections[0].protocol, TransportProtocol::Tcp);
        assert_eq!(
            snapshot.connections[0].tcp_state,
            Some(TcpConnectionState::Established)
        );
        assert_eq!(
            snapshot.connections[0].process_key,
            Some(snapshot.processes[0].key)
        );
        assert_eq!(snapshot.connections[1].process_key, None);
        assert_eq!(
            snapshot.connections[1].owner_name.as_deref(),
            Some("protected.exe")
        );
        assert_eq!(snapshot.processes.len(), 1);
        assert!(
            snapshot
                .process_names
                .contains(&(8, "protected.exe".to_owned()))
        );
    }

    #[test]
    fn preserves_unknown_tcp_states() {
        assert_eq!(tcp_state(77), TcpConnectionState::Unknown(77));
    }
}
