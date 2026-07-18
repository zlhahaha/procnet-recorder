use std::fmt::{self, Write};

use procnet_core::{ProcessIconState, TcpConnectionState, TrafficDirection, TransportProtocol};

use crate::{ApplicationSnapshot, CaptureRestriction, CaptureStatus};

/// Renders a complete deterministic JSON snapshot.
///
/// # Errors
///
/// Returns a formatting error if writing into the in-memory string fails.
#[allow(clippy::too_many_lines)]
pub fn render_snapshot_json(snapshot: &ApplicationSnapshot) -> Result<String, fmt::Error> {
    let mut output = String::new();
    let (capture_status, restriction) = capture_labels(snapshot.capture_status);
    write!(
        output,
        "{{\n  \"running\": {},\n  \"capture_status\": ",
        snapshot.running
    )?;
    json_string(&mut output, capture_status)?;
    write!(output, ",\n  \"capture_restriction\": ")?;
    json_string(&mut output, restriction)?;
    write!(
        output,
        ",\n  \"events\": {{\"received\": {}, \"accepted\": {}, \"processed\": {}, \
         \"dropped_full\": {}, \"dropped_stopped\": {}}},\n  \"curve\": {{\n    \
         \"bucket_width_nanos\": {}, \"maximum_buckets\": {}, \"events_received\": {}, \
         \"events_accepted\": {}, \"events_late_dropped\": {}, \"bytes_received\": {}, \
         \"bytes_accepted\": {}, \"bytes_late_dropped\": {},\n    \"buckets\": [",
        snapshot.events_received,
        snapshot.events_accepted,
        snapshot.events_processed,
        snapshot.events_dropped_full,
        snapshot.events_dropped_stopped,
        snapshot.curve.bucket_width_nanos,
        snapshot.curve.maximum_buckets,
        snapshot.curve.events_received,
        snapshot.curve.events_accepted,
        snapshot.curve.events_late_dropped,
        snapshot.curve.bytes_received,
        snapshot.curve.bytes_accepted,
        snapshot.curve.bytes_late_dropped,
    )?;
    for (index, bucket) in snapshot.curve.buckets.iter().enumerate() {
        separator(&mut output, index)?;
        write!(
            output,
            "{{\"start_unix_nanos\":{},\"send_bytes\":{},\"receive_bytes\":{}}}",
            bucket.start_unix_nanos, bucket.send_bytes, bucket.receive_bytes
        )?;
    }
    write!(
        output,
        "]\n  }},\n  \"network_rate\": {{\"sampled_at_unix_nanos\":{},\"interval_nanos\":{},\"send_bytes_per_second\":{},\"receive_bytes_per_second\":{}}},\n  \"recent_60_seconds\": [",
        snapshot.network_rate.sampled_at_unix_nanos,
        snapshot.network_rate.interval_nanos,
        snapshot.network_rate.send_bytes_per_second,
        snapshot.network_rate.receive_bytes_per_second,
    )?;
    for (index, bucket) in snapshot.recent_60_seconds.buckets.iter().enumerate() {
        separator(&mut output, index)?;
        write!(
            output,
            "{{\"start_unix_nanos\":{},\"send_bytes\":{},\"receive_bytes\":{}}}",
            bucket.start_unix_nanos, bucket.send_bytes, bucket.receive_bytes
        )?;
    }
    write!(output, "],\n  \"process_traffic\": [")?;
    for (index, process) in snapshot.process_traffic.iter().enumerate() {
        separator(&mut output, index)?;
        write!(
            output,
            "{{\"pid\":{},\"process_started_at_unix_nanos\":{},\"name\":",
            process.pid,
            process
                .process_key
                .map_or(0, |key| key.started_at_unix_nanos)
        )?;
        json_optional_string(&mut output, process.name.as_deref())?;
        write!(output, ",\"image_path\":")?;
        json_optional_string(&mut output, process.image_path.as_deref())?;
        write!(output, ",\"icon_status\":")?;
        json_string(&mut output, icon_status(&process.icon))?;
        write!(
            output,
            ",\"send_bytes_total\":{},\"receive_bytes_total\":{},\"send_bytes_per_second\":{},\"receive_bytes_per_second\":{},\"connection_count\":{},\"last_timestamp_unix_nanos\":{}}}",
            process.send_bytes_total,
            process.receive_bytes_total,
            process.send_bytes_per_second,
            process.receive_bytes_per_second,
            process.connection_count,
            process.last_timestamp_unix_nanos,
        )?;
    }
    write!(output, "],\n  \"flows\": [")?;
    let mut flows = snapshot.flows.iter().collect::<Vec<_>>();
    flows.sort_unstable_by_key(|flow| &flow.key);
    for (index, flow) in flows.into_iter().enumerate() {
        separator(&mut output, index)?;
        write!(
            output,
            "{{\"pid\":{},\"process_started_at_unix_nanos\":{},\"protocol\":",
            flow.key.pid,
            flow.process_key.map_or(0, |key| key.started_at_unix_nanos)
        )?;
        json_string(&mut output, protocol(flow.key.protocol))?;
        write!(output, ",\"direction\":")?;
        json_string(&mut output, direction(flow.key.direction))?;
        write!(output, ",\"source\":")?;
        json_string(&mut output, &flow.key.source.to_string())?;
        write!(output, ",\"destination\":")?;
        json_string(&mut output, &flow.key.destination.to_string())?;
        write!(
            output,
            ",\"events\":{},\"bytes\":{},\"first_timestamp_unix_nanos\":{},\"last_timestamp_unix_nanos\":{}}}",
            flow.events,
            flow.bytes,
            flow.first_timestamp_unix_nanos,
            flow.last_timestamp_unix_nanos
        )?;
    }
    write!(output, "],\n  \"system\": ")?;
    if let Some(system) = &snapshot.system {
        write!(
            output,
            "{{\"captured_at_unix_nanos\":{},\"processes\":[",
            system.captured_at_unix_nanos
        )?;
        let mut processes = system.processes.iter().collect::<Vec<_>>();
        processes.sort_unstable_by_key(|process| process.key);
        for (index, process) in processes.into_iter().enumerate() {
            separator(&mut output, index)?;
            write!(
                output,
                "{{\"pid\":{},\"started_at_unix_nanos\":{},\"name\":",
                process.key.pid, process.key.started_at_unix_nanos
            )?;
            json_string(&mut output, &process.name)?;
            write!(output, ",\"image_path\":")?;
            json_optional_string(&mut output, process.image_path.as_deref())?;
            write!(output, ",\"icon_status\":")?;
            json_string(&mut output, icon_status(&process.icon))?;
            write!(output, "}}")?;
        }
        write!(output, "],\"connections\":[")?;
        let mut connections = system.connections.iter().collect::<Vec<_>>();
        connections.sort_unstable_by_key(|connection| {
            (
                connection.pid,
                connection.protocol,
                connection.local,
                connection.remote,
            )
        });
        for (index, connection) in connections.into_iter().enumerate() {
            separator(&mut output, index)?;
            write!(
                output,
                "{{\"pid\":{},\"process_started_at_unix_nanos\":{},\"protocol\":",
                connection.pid,
                connection
                    .process_key
                    .map_or(0, |key| key.started_at_unix_nanos)
            )?;
            json_string(&mut output, protocol(connection.protocol))?;
            write!(output, ",\"local\":")?;
            json_string(&mut output, &connection.local.to_string())?;
            write!(output, ",\"remote\":")?;
            json_optional_string(
                &mut output,
                connection.remote.map(|value| value.to_string()).as_deref(),
            )?;
            write!(output, ",\"tcp_state\":")?;
            json_optional_string(&mut output, connection.tcp_state.map(tcp_state).as_deref())?;
            let detail = snapshot
                .connection_details
                .iter()
                .find(|detail| &detail.connection == connection);
            write!(output, ",\"process_name\":")?;
            json_optional_string(
                &mut output,
                detail.and_then(|detail| detail.process_name.as_deref()),
            )?;
            write!(output, ",\"process_image_path\":")?;
            json_optional_string(
                &mut output,
                detail.and_then(|detail| detail.process_image_path.as_deref()),
            )?;
            write!(output, "}}")?;
        }
        write!(output, "]}}")?;
    } else {
        write!(output, "null")?;
    }
    write!(output, "\n}}\n")?;
    Ok(output)
}

/// Renders deterministic CSV records for flows, curve buckets, processes, and connections.
///
/// # Errors
///
/// Returns a formatting error if writing into the in-memory string fails.
#[allow(clippy::too_many_lines)]
pub fn render_snapshot_csv(snapshot: &ApplicationSnapshot) -> Result<String, fmt::Error> {
    let mut output = String::from(
        "record_type,pid,process_started_at_unix_nanos,protocol,direction,local,remote,state,name,image_path,start_unix_nanos,send_bytes,receive_bytes,events,bytes\r\n",
    );
    let mut flows = snapshot.flows.iter().collect::<Vec<_>>();
    flows.sort_unstable_by_key(|flow| &flow.key);
    for flow in flows {
        csv_row(
            &mut output,
            &[
                "flow",
                &flow.key.pid.to_string(),
                &flow
                    .process_key
                    .map_or(0, |key| key.started_at_unix_nanos)
                    .to_string(),
                protocol(flow.key.protocol),
                direction(flow.key.direction),
                &flow.key.source.to_string(),
                &flow.key.destination.to_string(),
                "",
                "",
                "",
                "",
                "",
                "",
                &flow.events.to_string(),
                &flow.bytes.to_string(),
            ],
        );
    }
    for bucket in &snapshot.curve.buckets {
        csv_row(
            &mut output,
            &[
                "curve",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                &bucket.start_unix_nanos.to_string(),
                &bucket.send_bytes.to_string(),
                &bucket.receive_bytes.to_string(),
                "",
                "",
            ],
        );
    }
    csv_row(
        &mut output,
        &[
            "network_rate",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            &snapshot.network_rate.sampled_at_unix_nanos.to_string(),
            &snapshot.network_rate.send_bytes_per_second.to_string(),
            &snapshot.network_rate.receive_bytes_per_second.to_string(),
            "",
            &snapshot.network_rate.interval_nanos.to_string(),
        ],
    );
    for bucket in &snapshot.recent_60_seconds.buckets {
        csv_row(
            &mut output,
            &[
                "recent_curve",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                &bucket.start_unix_nanos.to_string(),
                &bucket.send_bytes.to_string(),
                &bucket.receive_bytes.to_string(),
                "",
                "",
            ],
        );
    }
    for process in &snapshot.process_traffic {
        csv_row(
            &mut output,
            &[
                "process_traffic",
                &process.pid.to_string(),
                &process
                    .process_key
                    .map_or(0, |key| key.started_at_unix_nanos)
                    .to_string(),
                "",
                "",
                "",
                "",
                icon_status(&process.icon),
                process.name.as_deref().unwrap_or(""),
                process.image_path.as_deref().unwrap_or(""),
                &process.last_timestamp_unix_nanos.to_string(),
                &process.send_bytes_per_second.to_string(),
                &process.receive_bytes_per_second.to_string(),
                &process.send_bytes_total.to_string(),
                &process.receive_bytes_total.to_string(),
            ],
        );
    }
    if let Some(system) = &snapshot.system {
        let mut processes = system.processes.iter().collect::<Vec<_>>();
        processes.sort_unstable_by_key(|process| process.key);
        for process in processes {
            csv_row(
                &mut output,
                &[
                    "process",
                    &process.key.pid.to_string(),
                    &process.key.started_at_unix_nanos.to_string(),
                    "",
                    "",
                    "",
                    "",
                    icon_status(&process.icon),
                    &process.name,
                    process.image_path.as_deref().unwrap_or(""),
                    "",
                    "",
                    "",
                    "",
                    "",
                ],
            );
        }
        let mut connections = system.connections.iter().collect::<Vec<_>>();
        connections.sort_unstable_by_key(|connection| {
            (
                connection.pid,
                connection.protocol,
                connection.local,
                connection.remote,
            )
        });
        for connection in connections {
            let detail = snapshot
                .connection_details
                .iter()
                .find(|detail| detail.connection == *connection);
            csv_row(
                &mut output,
                &[
                    "connection",
                    &connection.pid.to_string(),
                    &connection
                        .process_key
                        .map_or(0, |key| key.started_at_unix_nanos)
                        .to_string(),
                    protocol(connection.protocol),
                    "",
                    &connection.local.to_string(),
                    &connection
                        .remote
                        .map_or_else(String::new, |value| value.to_string()),
                    &connection.tcp_state.map_or_else(String::new, tcp_state),
                    detail
                        .and_then(|detail| detail.process_name.as_deref())
                        .unwrap_or(""),
                    detail
                        .and_then(|detail| detail.process_image_path.as_deref())
                        .unwrap_or(""),
                    "",
                    "",
                    "",
                    "",
                    "",
                ],
            );
        }
    }
    Ok(output)
}

fn json_string(output: &mut String, value: &str) -> fmt::Result {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            control if control <= '\u{1f}' => write!(output, "\\u{:04x}", u32::from(control))?,
            other => output.push(other),
        }
    }
    output.push('"');
    Ok(())
}

fn json_optional_string(output: &mut String, value: Option<&str>) -> fmt::Result {
    match value {
        Some(value) => json_string(output, value),
        None => write!(output, "null"),
    }
}

fn csv_row(output: &mut String, fields: &[&str]) {
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push('"');
        output.push_str(&field.replace('"', "\"\""));
        output.push('"');
    }
    output.push_str("\r\n");
}

fn separator(output: &mut String, index: usize) -> fmt::Result {
    if index == 0 {
        Ok(())
    } else {
        write!(output, ",")
    }
}
const fn protocol(value: TransportProtocol) -> &'static str {
    match value {
        TransportProtocol::Tcp => "tcp",
        TransportProtocol::Udp => "udp",
    }
}
const fn direction(value: TrafficDirection) -> &'static str {
    match value {
        TrafficDirection::Send => "send",
        TrafficDirection::Receive => "receive",
    }
}
fn tcp_state(value: TcpConnectionState) -> String {
    format!("{value:?}")
}
const fn icon_status(value: &ProcessIconState) -> &'static str {
    match value {
        ProcessIconState::NotLoaded => "not_loaded",
        ProcessIconState::Unavailable => "unavailable",
        ProcessIconState::Available(_) => "available",
    }
}
const fn capture_labels(value: CaptureStatus) -> (&'static str, &'static str) {
    match value {
        CaptureStatus::Available => ("available", "none"),
        CaptureStatus::Restricted(CaptureRestriction::PermissionRequired) => {
            ("restricted", "permission_required")
        }
        CaptureStatus::Restricted(CaptureRestriction::SessionAlreadyExists) => {
            ("restricted", "session_already_exists")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::{SystemTime, UNIX_EPOCH};

    use procnet_core::{
        ConnectionSnapshot, NetworkEvent, ProcessKey, ProcessSnapshot, SystemSnapshot,
        TcpConnectionState, TrafficDirection, TransportProtocol,
    };

    use super::{render_snapshot_csv, render_snapshot_json};
    use crate::{ApplicationRuntime, SubmitOutcome};

    fn exported_snapshot() -> crate::ApplicationSnapshot {
        let runtime = ApplicationRuntime::start(4).unwrap();
        let event_time = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        )
        .unwrap();
        let key = ProcessKey {
            pid: 7,
            started_at_unix_nanos: event_time - 1,
        };
        runtime
            .publish_system_snapshot(SystemSnapshot {
                captured_at_unix_nanos: event_time + 1,
                process_names: vec![(7, "fixture.exe".to_owned())],
                processes: vec![ProcessSnapshot {
                    key,
                    name: "quoted,\"进程\n.exe".to_owned(),
                    image_path: Some("C:\\测试\\app.exe".to_owned()),
                    icon: procnet_core::ProcessIconState::NotLoaded,
                }],
                connections: vec![ConnectionSnapshot {
                    protocol: TransportProtocol::Tcp,
                    local: "127.0.0.1:39001".parse::<SocketAddr>().unwrap(),
                    remote: None,
                    tcp_state: Some(TcpConnectionState::Listen),
                    pid: 7,
                    process_key: Some(key),
                    owner_name: Some("fixture.exe".to_owned()),
                }],
            })
            .unwrap();
        assert_eq!(
            runtime.ingress().try_submit(NetworkEvent {
                timestamp_unix_nanos: event_time,
                pid: 7,
                protocol: TransportProtocol::Tcp,
                direction: TrafficDirection::Send,
                source: "127.0.0.1:40000".parse().unwrap(),
                destination: "127.0.0.1:39001".parse().unwrap(),
                bytes: 123,
            }),
            SubmitOutcome::Accepted
        );
        runtime.stop().unwrap()
    }

    #[test]
    fn json_and_csv_are_deterministic_and_escape_text() {
        let snapshot = exported_snapshot();
        let json = render_snapshot_json(&snapshot).unwrap();
        assert_eq!(json, render_snapshot_json(&snapshot).unwrap());
        assert!(json.contains("quoted,\\\"进程\\n.exe"));
        assert!(json.contains("C:\\\\测试\\\\app.exe"));
        assert!(json.contains("\"bytes\":123"));
        assert!(json.contains("\"process_traffic\""));
        assert!(json.contains("\"send_bytes_total\":123"));
        assert!(json.contains("\"recent_60_seconds\""));
        assert!(json.contains("\"network_rate\""));
        assert!(json.contains("\"process_name\":\"quoted,"));

        let csv = render_snapshot_csv(&snapshot).unwrap();
        assert_eq!(csv, render_snapshot_csv(&snapshot).unwrap());
        assert!(csv.contains("\"quoted,\"\"进程\n.exe\""));
        assert!(csv.contains("\"flow\""));
        assert!(csv.contains("\"curve\""));
        assert!(csv.contains("\"process\""));
        assert!(csv.contains("\"connection\""));
        assert!(csv.contains("\"process_traffic\""));
        assert!(csv.contains("\"recent_curve\""));
        assert!(csv.contains("\"network_rate\""));
    }
}
