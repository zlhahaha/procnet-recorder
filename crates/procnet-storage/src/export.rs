use procnet_core::SessionDetail;

#[must_use]
#[allow(clippy::format_push_string)]
pub fn render_session_json(detail: &SessionDetail) -> String {
    let mut output = format!(
        "{{\n  \"schema_version\": 1,\n  \"session\": {{\"id\": {}, \"name\": \"{}\", \"notes\": \"{}\", \"status\": \"{}\", \"started_at_ns\": {}, \"ended_at_ns\": {}, \"send_bytes\": {}, \"receive_bytes\": {}, \"event_count\": {}}},\n  \"buckets\": [",
        detail.session.id.0,
        json_escape(&detail.session.name),
        json_escape(&detail.session.notes),
        detail.session.status.as_str(),
        detail.session.started_at_unix_nanos,
        detail
            .session
            .ended_at_unix_nanos
            .map_or_else(|| "null".to_owned(), |value| value.to_string()),
        detail.session.send_bytes,
        detail.session.receive_bytes,
        detail.session.event_count,
    );
    for (index, bucket) in detail.buckets.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&format!("\n    {{\"start_ns\": {}, \"send_bytes\": {}, \"receive_bytes\": {}, \"event_count\": {}}}", bucket.start_unix_nanos, bucket.send_bytes, bucket.receive_bytes, bucket.event_count));
    }
    output.push_str("\n  ],\n  \"processes\": [");
    for (index, process) in detail.processes.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&format!("\n    {{\"pid\": {}, \"started_at_ns\": {}, \"name\": \"{}\", \"image_path\": {}, \"send_bytes\": {}, \"receive_bytes\": {}, \"connection_count\": {}}}", process.pid, process.started_at_unix_nanos, json_escape(&process.name), process.image_path.as_ref().map_or_else(|| "null".to_owned(), |value| format!("\"{}\"", json_escape(value))), process.send_bytes, process.receive_bytes, process.connection_count));
    }
    output.push_str("\n  ],\n  \"endpoints\": [");
    for (index, endpoint) in detail.endpoints.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&format!("\n    {{\"protocol\": \"{}\", \"remote_address\": \"{}\", \"process_name\": \"{}\", \"first_seen_ns\": {}, \"last_seen_ns\": {}, \"connection_count\": {}}}", json_escape(&endpoint.protocol), json_escape(&endpoint.remote_address), json_escape(&endpoint.process_name), endpoint.first_seen_unix_nanos, endpoint.last_seen_unix_nanos, endpoint.connection_count));
    }
    output.push_str("\n  ],\n  \"alerts\": [");
    for (index, alert) in detail.alerts.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&format!("\n    {{\"id\": {}, \"occurred_at_ns\": {}, \"kind\": \"{}\", \"title\": \"{}\", \"detail\": \"{}\", \"process_name\": {}, \"remote_address\": {}}}", alert.id, alert.occurred_at_unix_nanos, alert.kind.as_str(), json_escape(&alert.title), json_escape(&alert.detail), json_option(alert.process_name.as_deref()), json_option(alert.remote_address.as_deref())));
    }
    output.push_str("\n  ]\n}\n");
    output
}

#[must_use]
#[allow(clippy::format_push_string)]
pub fn render_session_csv(detail: &SessionDetail) -> String {
    let mut output = "section,start_ns,pid,name,protocol,remote_address,send_bytes,receive_bytes,event_count,connection_count,detail\r\n".to_owned();
    output.push_str(&format!(
        "session,{},,{},{},,{},{},{},,{}\r\n",
        detail.session.started_at_unix_nanos,
        csv_escape(&detail.session.name),
        detail.session.status.as_str(),
        detail.session.send_bytes,
        detail.session.receive_bytes,
        detail.session.event_count,
        csv_escape(&format!(
            "ended_at_ns={:?}; notes={}",
            detail.session.ended_at_unix_nanos, detail.session.notes
        ))
    ));
    for bucket in &detail.buckets {
        output.push_str(&format!(
            "bucket,{},,,,,{},{},{},,\r\n",
            bucket.start_unix_nanos, bucket.send_bytes, bucket.receive_bytes, bucket.event_count
        ));
    }
    for process in &detail.processes {
        output.push_str(&format!(
            "process,,{},{},,,{},{},,{},{}\r\n",
            process.pid,
            csv_escape(&process.name),
            process.send_bytes,
            process.receive_bytes,
            process.connection_count,
            csv_escape(&format!(
                "started_at_ns={}; image_path={}",
                process.started_at_unix_nanos,
                process.image_path.as_deref().unwrap_or("")
            ))
        ));
    }
    for endpoint in &detail.endpoints {
        output.push_str(&format!(
            "endpoint,,,{},{},{},,,,{},{}\r\n",
            csv_escape(&endpoint.process_name),
            csv_escape(&endpoint.protocol),
            csv_escape(&endpoint.remote_address),
            endpoint.connection_count,
            csv_escape(&format!(
                "first_seen_ns={}; last_seen_ns={}",
                endpoint.first_seen_unix_nanos, endpoint.last_seen_unix_nanos
            ))
        ));
    }
    for alert in &detail.alerts {
        output.push_str(&format!(
            "alert,{},,,{},,,,,,{}\r\n",
            alert.occurred_at_unix_nanos,
            alert.kind.as_str(),
            csv_escape(&format!(
                "{}: {}; process={}; remote={}",
                alert.title,
                alert.detail,
                alert.process_name.as_deref().unwrap_or(""),
                alert.remote_address.as_deref().unwrap_or("")
            ))
        ));
    }
    output
}

#[must_use]
#[allow(clippy::format_push_string)]
pub fn render_session_markdown(detail: &SessionDetail) -> String {
    let session = &detail.session;
    let mut output = format!(
        "# ProcNet Recorder 会话报告\n\n- 会话：{}\n- 备注：{}\n- 状态：{}\n- 开始：{} ns\n- 结束：{}\n- 上传：{} B\n- 下载：{} B\n- 事件：{}\n- 进程：{}\n- 远程端点：{}\n- 提醒：{}\n\n## 进程排行\n\n| 进程 | PID | 上传 | 下载 | 连接 |\n|---|---:|---:|---:|---:|\n",
        markdown_escape(&session.name),
        markdown_escape(&session.notes),
        session.status.as_str(),
        session.started_at_unix_nanos,
        session
            .ended_at_unix_nanos
            .map_or_else(|| "—".to_owned(), |value| format!("{value} ns")),
        session.send_bytes,
        session.receive_bytes,
        session.event_count,
        detail.processes.len(),
        detail.endpoints.len(),
        detail.alerts.len()
    );
    for process in &detail.processes {
        output.push_str(&format!(
            "| {} | {} | {} B | {} B | {} |\n",
            markdown_escape(&process.name),
            process.pid,
            process.send_bytes,
            process.receive_bytes,
            process.connection_count
        ));
    }
    output.push_str("\n## 远程端点\n\n| 协议 | 地址 | 进程 | 连接 |\n|---|---|---|---:|\n");
    for endpoint in &detail.endpoints {
        output.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            markdown_escape(&endpoint.protocol),
            markdown_escape(&endpoint.remote_address),
            markdown_escape(&endpoint.process_name),
            endpoint.connection_count
        ));
    }
    output.push_str("\n## 提醒\n\n");
    if detail.alerts.is_empty() {
        output.push_str("无。\n");
    } else {
        for alert in &detail.alerts {
            output.push_str(&format!(
                "- **{}**：{}\n",
                markdown_escape(&alert.title),
                markdown_escape(&alert.detail)
            ));
        }
    }
    output
}

fn json_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect(),
            '\n' => "\\n".chars().collect(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            value if value.is_control() => format!("\\u{:04x}", u32::from(value)).chars().collect(),
            value => vec![value],
        })
        .collect()
}
fn csv_escape(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
fn json_option(value: Option<&str>) -> String {
    value.map_or_else(
        || "null".to_owned(),
        |value| format!("\"{}\"", json_escape(value)),
    )
}
fn markdown_escape(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use procnet_core::{SessionId, SessionRecord, SessionStatus};

    fn detail() -> SessionDetail {
        SessionDetail {
            session: SessionRecord {
                id: SessionId(1),
                name: "demo \"x\"".to_owned(),
                notes: String::new(),
                started_at_unix_nanos: 1,
                ended_at_unix_nanos: Some(2),
                status: SessionStatus::Completed,
                send_bytes: 3,
                receive_bytes: 4,
                event_count: 5,
            },
            buckets: vec![],
            processes: vec![],
            endpoints: vec![],
            alerts: vec![],
        }
    }
    #[test]
    fn complete_exports_include_schema_and_sections() {
        let value = detail();
        assert!(render_session_json(&value).contains("\\\"x\\\""));
        assert!(render_session_csv(&value).starts_with("section,"));
        assert!(render_session_markdown(&value).contains("进程排行"));
    }
}
