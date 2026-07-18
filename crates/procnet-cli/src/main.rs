//! V0 command-line entry point for bounded ETW feasibility experiments.

#![forbid(unsafe_code)]

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use std::time::Instant;

const DEFAULT_PROBE_SECONDS: u64 = 5;
const MAX_PROBE_SECONDS: u64 = 300;
const MAX_RUNTIME_SECONDS: u64 = 3600;
const RUNTIME_SAMPLE_INTERVAL: Duration = Duration::from_secs(5);
const EXIT_PERMISSION_REQUIRED: u8 = 5;
const EXIT_SESSION_ALREADY_EXISTS: u8 = 183;

struct CommandError {
    message: String,
    exit_code: u8,
}

impl CommandError {
    fn from_probe(error: &procnet_windows::EtwProbeError) -> Self {
        let message = match error.kind() {
            procnet_windows::EtwProbeErrorKind::AccessDenied => format!(
                "network capture unavailable: administrator privileges or membership in the \
                     Performance Log Users group is required ({error})"
            ),
            procnet_windows::EtwProbeErrorKind::SessionAlreadyExists => format!(
                "network capture unavailable: ETW Session \
                     'ProcNetRecorder-V0-TcpIp-Probe' already exists; run the exact cleanup-etw \
                     command before retrying ({error})"
            ),
            procnet_windows::EtwProbeErrorKind::Other => error.to_string(),
        };
        Self {
            message,
            exit_code: probe_exit_code(error.kind()),
        }
    }

    fn from_cleanup(error: &procnet_windows::EtwCleanupError) -> Self {
        let exit_code = if matches!(error, procnet_windows::EtwCleanupError::AccessDenied { .. }) {
            EXIT_PERMISSION_REQUIRED
        } else {
            1
        };
        Self {
            message: error.to_string(),
            exit_code,
        }
    }
}

const fn probe_exit_code(kind: procnet_windows::EtwProbeErrorKind) -> u8 {
    match kind {
        procnet_windows::EtwProbeErrorKind::AccessDenied => EXIT_PERMISSION_REQUIRED,
        procnet_windows::EtwProbeErrorKind::SessionAlreadyExists => EXIT_SESSION_ALREADY_EXISTS,
        procnet_windows::EtwProbeErrorKind::Other => 1,
    }
}

impl From<String> for CommandError {
    fn from(message: String) -> Self {
        Self {
            message,
            exit_code: 1,
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERROR: {}", error.message);
            ExitCode::from(error.exit_code)
        }
    }
}

fn run() -> Result<(), CommandError> {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("v0-probe") => {
            let arguments = arguments.collect::<Vec<_>>();
            run_v0_probe(&arguments)
        }
        Some("v1-runtime-probe") => {
            let arguments = arguments.collect::<Vec<_>>();
            run_v1_runtime_probe(&arguments)
        }
        Some("cleanup-etw") => {
            let arguments = arguments.collect::<Vec<_>>();
            run_cleanup_etw(&arguments)
        }
        Some("system-snapshot") => {
            let arguments = arguments.collect::<Vec<_>>();
            run_system_snapshot(&arguments)
        }
        Some("export-snapshot") => {
            let arguments = arguments.collect::<Vec<_>>();
            run_export_snapshot(&arguments)
        }
        Some("v0-ctrl-c-test") => run_ctrl_c_validation().map_err(Into::into),
        Some("--help" | "-h") | None => {
            print_help();
            Ok(())
        }
        Some(command) => Err(format!("unknown command: {command}").into()),
    }
}

fn run_cleanup_etw(arguments: &[String]) -> Result<(), CommandError> {
    let session_name = parse_cleanup_session(arguments)?;
    match procnet_windows::cleanup_target(session_name)
        .map_err(|error| CommandError::from_cleanup(&error))?
    {
        procnet_windows::CleanupPreparation::AlreadyAbsent => {
            println!("ETW Session already absent: {session_name}");
            Ok(())
        }
        procnet_windows::CleanupPreparation::Ready(target) => {
            println!("Stopping exact ETW Session: {}", target.session_name());
            let result = target
                .stop()
                .map_err(|error| CommandError::from_cleanup(&error))?;
            match result {
                procnet_windows::CleanupResult::Stopped => {
                    println!("ETW Session stopped and absence verified: {session_name}");
                }
                procnet_windows::CleanupResult::StoppedAfterMoreData => {
                    println!(
                        "ETW stop returned ERROR_MORE_DATA; follow-up query confirmed absence: {session_name}"
                    );
                }
                procnet_windows::CleanupResult::AlreadyAbsent => {
                    println!("ETW Session became absent before stop: {session_name}");
                }
            }
            Ok(())
        }
    }
}

fn parse_cleanup_session(arguments: &[String]) -> Result<&str, String> {
    match arguments {
        [flag, session_name] if flag == "--session" => Ok(session_name),
        _ => Err("usage: procnet-cli cleanup-etw --session <exact-session-name>".to_owned()),
    }
}

fn run_v0_probe(arguments: &[String]) -> Result<(), CommandError> {
    let (seconds, fixture_ports, quiet) = parse_probe_options(arguments)?;
    eprintln!(
        "[INFO] starting ETW TCP/IP probe for {seconds}s; this may require administrator privileges"
    );
    let summary =
        procnet_windows::run_tcp_ip_probe(Duration::from_secs(seconds), fixture_ports, !quiet)
            .map_err(|error| CommandError::from_probe(&error))?;
    print_ipv4_aggregates(&summary);
    print_ipv6_aggregates(&summary);
    print_probe_summary(&summary);
    Ok(())
}

fn run_v1_runtime_probe(arguments: &[String]) -> Result<(), CommandError> {
    let options = parse_runtime_options(arguments)?;
    let RuntimeOptions {
        seconds,
        ports,
        queue_capacity,
        allow_restricted,
        export_json,
        export_csv,
    } = options;
    let ports_label = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    eprintln!(
        "[INFO] starting V1 bounded runtime probe for {seconds}s on fixture ports {ports_label}; \
         queue_capacity={queue_capacity}"
    );
    let runtime = procnet_application::ApplicationRuntime::start(queue_capacity)
        .map_err(|error| error.to_string())?;
    match procnet_windows::capture_system_snapshot() {
        Ok(snapshot) => runtime
            .publish_system_snapshot(snapshot)
            .map_err(|error| error.to_string())?,
        Err(error) => eprintln!("WARNING: initial system snapshot unavailable: {error}"),
    }
    let ingress = runtime.ingress();
    let (reporter_stop, reporter) = spawn_runtime_reporter(runtime.snapshot_reader())?;
    let etw_result = run_capture_or_restricted(seconds, ports, allow_restricted, &runtime, ingress);
    stop_runtime_reporter(&reporter_stop, reporter)?;
    let etw_summary = etw_result?;
    let snapshot = runtime.stop().map_err(|error| error.to_string())?;
    export_runtime_snapshot(&snapshot, export_json.as_deref(), export_csv.as_deref())?;
    print_application_snapshot(&snapshot, etw_summary.as_ref());
    Ok(())
}

fn export_runtime_snapshot(
    snapshot: &procnet_application::ApplicationSnapshot,
    json: Option<&Path>,
    csv: Option<&Path>,
) -> Result<(), CommandError> {
    if let Some(output) = json {
        let rendered = procnet_application::render_snapshot_json(snapshot)
            .map_err(|error| format!("cannot render JSON snapshot: {error}"))?;
        atomic_write(output, rendered.as_bytes())?;
    }
    if let Some(output) = csv {
        let rendered = procnet_application::render_snapshot_csv(snapshot)
            .map_err(|error| format!("cannot render CSV snapshot: {error}"))?;
        atomic_write(output, rendered.as_bytes())?;
    }
    Ok(())
}

fn run_capture_or_restricted(
    seconds: u64,
    ports: Vec<u16>,
    allow_restricted: bool,
    runtime: &procnet_application::ApplicationRuntime,
    ingress: procnet_application::EventIngress,
) -> Result<Option<procnet_windows::EtwProbeSummary>, CommandError> {
    let probe_started = Instant::now();
    let etw_result = procnet_windows::run_tcp_ip_probe_with_sink(
        Duration::from_secs(seconds),
        ports,
        false,
        move |event| {
            let _ = ingress.try_submit(event);
        },
    );
    let Err(error) = etw_result else {
        return Ok(etw_result.ok());
    };
    let Some(status) = restricted_status(error.kind()).filter(|_| allow_restricted) else {
        return Err(CommandError::from_probe(&error));
    };
    runtime
        .set_capture_status(status)
        .map_err(|error| error.to_string())?;
    let (capture_status, restriction) = capture_status_labels(status);
    eprintln!(
        "WARNING: application continuing in restricted mode; capture_status={capture_status} \
         restriction={restriction}; {error}"
    );
    let requested = Duration::from_secs(seconds);
    if let Some(remaining) = requested.checked_sub(probe_started.elapsed()) {
        thread::sleep(remaining);
    }
    Ok(None)
}

fn print_application_snapshot(
    snapshot: &procnet_application::ApplicationSnapshot,
    etw_summary: Option<&procnet_windows::EtwProbeSummary>,
) {
    for flow in &snapshot.flows {
        println!(
            "APP_FLOW pid={} protocol={} direction={} source={} destination={} events={} bytes={} \
             first_timestamp_unix_nanos={} last_timestamp_unix_nanos={} \
             process_started_at_unix_nanos={}",
            flow.key.pid,
            match flow.key.protocol {
                procnet_core::TransportProtocol::Tcp => "TCP",
                procnet_core::TransportProtocol::Udp => "UDP",
            },
            match flow.key.direction {
                procnet_core::TrafficDirection::Send => "send",
                procnet_core::TrafficDirection::Receive => "receive",
            },
            flow.key.source,
            flow.key.destination,
            flow.events,
            flow.bytes,
            flow.first_timestamp_unix_nanos,
            flow.last_timestamp_unix_nanos,
            flow.process_key.map_or(0, |key| key.started_at_unix_nanos)
        );
    }
    for bucket in &snapshot.curve.buckets {
        println!(
            "APP_CURVE_BUCKET start_unix_nanos={} send_bytes={} receive_bytes={}",
            bucket.start_unix_nanos, bucket.send_bytes, bucket.receive_bytes
        );
    }
    let (capture_status, capture_restriction) = capture_status_labels(snapshot.capture_status);
    let (process_count, connection_count) = snapshot.system.as_ref().map_or((0, 0), |system| {
        (system.processes.len(), system.connections.len())
    });
    let (events_lost, real_time_buffers_lost, log_buffers_lost) = etw_summary.map_or(
        (
            "unavailable".to_owned(),
            "unavailable".to_owned(),
            "unavailable".to_owned(),
        ),
        |summary| {
            (
                summary.session_statistics.events_lost.to_string(),
                summary
                    .session_statistics
                    .real_time_buffers_lost
                    .to_string(),
                summary.session_statistics.log_buffers_lost.to_string(),
            )
        },
    );
    println!(
        "APP_RUNTIME_SNAPSHOT running={} events_received={} events_accepted={} \
         events_dropped_full={} events_dropped_stopped={} events_processed={} \
         queue_capacity={} queue_depth={} queue_peak={} snapshot_interval_millis={} \
         flow_idle_timeout_millis={} maximum_flows={} flow_keys={} etw_events_lost={} \
         etw_real_time_buffers_lost={} etw_log_buffers_lost={} capture_status={} \
         capture_restriction={} process_count={} connection_count={} \
         curve_bucket_width_nanos={} curve_maximum_buckets={} curve_buckets={} \
         curve_events_received={} curve_events_accepted={} curve_events_late_dropped={} \
         curve_bytes_received={} curve_bytes_accepted={} curve_bytes_late_dropped={}",
        snapshot.running,
        snapshot.events_received,
        snapshot.events_accepted,
        snapshot.events_dropped_full,
        snapshot.events_dropped_stopped,
        snapshot.events_processed,
        snapshot.queue_capacity,
        snapshot.queue_depth,
        snapshot.queue_peak,
        snapshot.snapshot_interval_millis,
        snapshot.flow_idle_timeout_millis,
        snapshot.maximum_flows,
        snapshot.flows.len(),
        events_lost,
        real_time_buffers_lost,
        log_buffers_lost,
        capture_status,
        capture_restriction,
        process_count,
        connection_count,
        snapshot.curve.bucket_width_nanos,
        snapshot.curve.maximum_buckets,
        snapshot.curve.buckets.len(),
        snapshot.curve.events_received,
        snapshot.curve.events_accepted,
        snapshot.curve.events_late_dropped,
        snapshot.curve.bytes_received,
        snapshot.curve.bytes_accepted,
        snapshot.curve.bytes_late_dropped,
    );
}

fn run_system_snapshot(arguments: &[String]) -> Result<(), CommandError> {
    if !arguments.is_empty() {
        return Err("usage: procnet-cli system-snapshot".to_owned().into());
    }
    let snapshot = procnet_windows::capture_system_snapshot()
        .map_err(|error| CommandError::from(error.to_string()))?;
    let associated = snapshot
        .connections
        .iter()
        .filter(|connection| connection.process_key.is_some())
        .count();
    let named = snapshot
        .connections
        .iter()
        .filter(|connection| connection.owner_name.is_some())
        .count();
    println!(
        "SYSTEM_SNAPSHOT captured_at_unix_nanos={} processes={} connections={} associated={} named={}",
        snapshot.captured_at_unix_nanos,
        snapshot.processes.len(),
        snapshot.connections.len(),
        associated,
        named
    );
    for process in &snapshot.processes {
        println!(
            "SYSTEM_PROCESS pid={} started_at_unix_nanos={} name={:?} image_path={:?}",
            process.key.pid, process.key.started_at_unix_nanos, process.name, process.image_path
        );
    }
    for connection in &snapshot.connections {
        println!(
            "SYSTEM_CONNECTION protocol={} local={} remote={} tcp_state={} pid={} \
             process_started_at_unix_nanos={} owner_name={:?}",
            match connection.protocol {
                procnet_core::TransportProtocol::Tcp => "TCP",
                procnet_core::TransportProtocol::Udp => "UDP",
            },
            connection.local,
            connection
                .remote
                .map_or_else(|| "none".to_owned(), |address| address.to_string()),
            connection
                .tcp_state
                .map_or_else(|| "none".to_owned(), |state| format!("{state:?}")),
            connection.pid,
            connection
                .process_key
                .map_or(0, |key| key.started_at_unix_nanos),
            connection.owner_name
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExportFormat {
    Json,
    Csv,
}

fn run_export_snapshot(arguments: &[String]) -> Result<(), CommandError> {
    let (format, output) = parse_export_options(arguments)?;
    let runtime =
        procnet_application::ApplicationRuntime::start(1).map_err(|error| error.to_string())?;
    runtime
        .publish_system_snapshot(
            procnet_windows::capture_system_snapshot().map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
    let snapshot = runtime.stop().map_err(|error| error.to_string())?;
    let rendered = match format {
        ExportFormat::Json => procnet_application::render_snapshot_json(&snapshot),
        ExportFormat::Csv => procnet_application::render_snapshot_csv(&snapshot),
    }
    .map_err(|error| format!("cannot render snapshot: {error}"))?;
    atomic_write(&output, rendered.as_bytes())?;
    println!(
        "SNAPSHOT_EXPORTED format={} bytes={} output={}",
        match format {
            ExportFormat::Json => "json",
            ExportFormat::Csv => "csv",
        },
        rendered.len(),
        output.display()
    );
    Ok(())
}

fn parse_export_options(arguments: &[String]) -> Result<(ExportFormat, PathBuf), String> {
    match arguments {
        [format_flag, format, output_flag, output]
            if format_flag == "--format" && output_flag == "--output" =>
        {
            let format = match format.as_str() {
                "json" => ExportFormat::Json,
                "csv" => ExportFormat::Csv,
                _ => return Err("--format must be json or csv".to_owned()),
            };
            if output.is_empty() {
                return Err("--output must not be empty".to_owned());
            }
            Ok((format, PathBuf::from(output)))
        }
        _ => {
            Err("usage: procnet-cli export-snapshot --format <json|csv> --output <path>".to_owned())
        }
    }
}

fn atomic_write(output: &Path, contents: &[u8]) -> Result<(), String> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(format!(
            "export parent directory does not exist: {}",
            parent.display()
        ));
    }
    let file_name = output
        .file_name()
        .ok_or_else(|| "export output must include a file name".to_owned())?;
    let mut temporary_name = file_name.to_os_string();
    temporary_name.push(format!(".tmp-{}", std::process::id()));
    let temporary = parent.join(temporary_name);
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("cannot create export temporary file: {error}"))?;
        file.write_all(contents)
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("cannot persist export temporary file: {error}"))?;
        drop(file);
        fs::rename(&temporary, output)
            .map_err(|error| format!("cannot atomically replace export output: {error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn restricted_status(
    kind: procnet_windows::EtwProbeErrorKind,
) -> Option<procnet_application::CaptureStatus> {
    match kind {
        procnet_windows::EtwProbeErrorKind::AccessDenied => {
            Some(procnet_application::CaptureStatus::Restricted(
                procnet_application::CaptureRestriction::PermissionRequired,
            ))
        }
        procnet_windows::EtwProbeErrorKind::SessionAlreadyExists => {
            Some(procnet_application::CaptureStatus::Restricted(
                procnet_application::CaptureRestriction::SessionAlreadyExists,
            ))
        }
        procnet_windows::EtwProbeErrorKind::Other => None,
    }
}

fn capture_status_labels(
    status: procnet_application::CaptureStatus,
) -> (&'static str, &'static str) {
    match status {
        procnet_application::CaptureStatus::Available => ("available", "none"),
        procnet_application::CaptureStatus::Restricted(
            procnet_application::CaptureRestriction::PermissionRequired,
        ) => ("restricted", "permission_required"),
        procnet_application::CaptureStatus::Restricted(
            procnet_application::CaptureRestriction::SessionAlreadyExists,
        ) => ("restricted", "session_already_exists"),
    }
}

fn stop_runtime_reporter(stop: &AtomicBool, reporter: JoinHandle<()>) -> Result<(), CommandError> {
    stop.store(true, Ordering::Release);
    reporter.thread().unpark();
    reporter
        .join()
        .map_err(|_| "runtime snapshot reporter panicked".to_owned().into())
}

fn spawn_runtime_reporter(
    reader: procnet_application::SnapshotReader,
) -> Result<(Arc<AtomicBool>, JoinHandle<()>), String> {
    let stop = Arc::new(AtomicBool::new(false));
    let reporter_stop = Arc::clone(&stop);
    let reporter = thread::Builder::new()
        .name("procnet-snapshot-report".to_owned())
        .spawn(move || {
            while !reporter_stop.load(Ordering::Acquire) {
                thread::park_timeout(RUNTIME_SAMPLE_INTERVAL);
                if reporter_stop.load(Ordering::Acquire) {
                    break;
                }
                match reader.snapshot() {
                    Ok(sample) => {
                        let (capture_status, capture_restriction) =
                            capture_status_labels(sample.capture_status);
                        let (process_count, connection_count) =
                            sample.system.as_ref().map_or((0, 0), |system| {
                                (system.processes.len(), system.connections.len())
                            });
                        println!(
                            "APP_RUNTIME_SAMPLE running={} events_received={} events_accepted={} \
                         events_dropped_full={} events_dropped_stopped={} events_processed={} \
                         queue_depth={} queue_peak={} flow_keys={} capture_status={} \
                         capture_restriction={} process_count={} connection_count={} \
                         curve_buckets={} curve_bytes_accepted={} curve_bytes_late_dropped={}",
                            sample.running,
                            sample.events_received,
                            sample.events_accepted,
                            sample.events_dropped_full,
                            sample.events_dropped_stopped,
                            sample.events_processed,
                            sample.queue_depth,
                            sample.queue_peak,
                            sample.flows.len(),
                            capture_status,
                            capture_restriction,
                            process_count,
                            connection_count,
                            sample.curve.buckets.len(),
                            sample.curve.bytes_accepted,
                            sample.curve.bytes_late_dropped,
                        );
                    }
                    Err(error) => {
                        eprintln!("APP_RUNTIME_SAMPLE_ERROR {error}");
                        break;
                    }
                }
            }
        })
        .map_err(|error| format!("cannot start runtime snapshot reporter: {error}"))?;
    Ok((stop, reporter))
}

fn print_ipv4_aggregates(summary: &procnet_windows::EtwProbeSummary) {
    for aggregate in &summary.ipv4_aggregates {
        let protocol = match aggregate.protocol {
            procnet_windows::NetworkProtocol::Tcp => "TCP",
            procnet_windows::NetworkProtocol::Udp => "UDP",
        };
        let direction = match aggregate.direction {
            procnet_windows::NetworkDirection::Send => "send",
            procnet_windows::NetworkDirection::Receive => "receive",
        };
        println!(
            "ETW_{protocol}_IPV4_AGGREGATE pid={} direction={direction} source={}:{} destination={}:{} \
             events={} bytes={}",
            aggregate.pid,
            aggregate.source_address,
            aggregate.source_port,
            aggregate.destination_address,
            aggregate.destination_port,
            aggregate.events,
            aggregate.bytes
        );
    }
}

fn print_ipv6_aggregates(summary: &procnet_windows::EtwProbeSummary) {
    for aggregate in &summary.ipv6_aggregates {
        let protocol = match aggregate.protocol {
            procnet_windows::NetworkProtocol::Tcp => "TCP",
            procnet_windows::NetworkProtocol::Udp => "UDP",
        };
        let direction = match aggregate.direction {
            procnet_windows::NetworkDirection::Send => "send",
            procnet_windows::NetworkDirection::Receive => "receive",
        };
        println!(
            "ETW_{protocol}_IPV6_AGGREGATE pid={} direction={direction} source=[{}]:{} destination=[{}]:{} \
             events={} bytes={}",
            aggregate.pid,
            aggregate.source_address,
            aggregate.source_port,
            aggregate.destination_address,
            aggregate.destination_port,
            aggregate.events,
            aggregate.bytes
        );
    }
}

fn print_probe_summary(summary: &procnet_windows::EtwProbeSummary) {
    println!(
        "ETW_PROBE_SUMMARY events_observed={} schemas_resolved={} schema_errors={} \
         tcp_ipv4_payloads_parsed={} tcp_ipv4_payload_errors={} tcp_send_ipv4_parsed={} \
         tcp_recv_ipv4_parsed={} udp_ipv4_payloads_parsed={} udp_ipv4_payload_errors={} \
         udp_send_ipv4_parsed={} udp_recv_ipv4_parsed={} tcp_ipv6_payloads_parsed={} \
         tcp_ipv6_payload_errors={} tcp_send_ipv6_parsed={} tcp_recv_ipv6_parsed={} \
         udp_ipv6_payloads_parsed={} udp_ipv6_payload_errors={} udp_send_ipv6_parsed={} \
         udp_recv_ipv6_parsed={}",
        summary.events_observed,
        summary.schemas_resolved,
        summary.schema_errors,
        summary.tcp_ipv4_payloads_parsed,
        summary.tcp_ipv4_payload_errors,
        summary.tcp_send_ipv4_parsed,
        summary.tcp_recv_ipv4_parsed,
        summary.udp_ipv4_payloads_parsed,
        summary.udp_ipv4_payload_errors,
        summary.udp_send_ipv4_parsed,
        summary.udp_recv_ipv4_parsed,
        summary.tcp_ipv6_payloads_parsed,
        summary.tcp_ipv6_payload_errors,
        summary.tcp_send_ipv6_parsed,
        summary.tcp_recv_ipv6_parsed,
        summary.udp_ipv6_payloads_parsed,
        summary.udp_ipv6_payload_errors,
        summary.udp_send_ipv6_parsed,
        summary.udp_recv_ipv6_parsed
    );
    println!(
        "ETW_PROBE_STOP stop_reason={}",
        if summary.interrupted {
            "console_ctrl_c"
        } else {
            "duration_elapsed"
        }
    );
    println!(
        "ETW_RUNTIME_STATS buffer_size_kb={} minimum_buffers={} maximum_buffers={} \
         active_buffers={} free_buffers={} buffers_written={} events_lost={} \
         real_time_buffers_lost={} log_buffers_lost={} application_queue_capacity={} \
         application_queue_peak={} application_events_dropped={} aggregate_keys={}",
        summary.session_statistics.buffer_size_kb,
        summary.session_statistics.minimum_buffers,
        summary.session_statistics.maximum_buffers,
        summary.session_statistics.active_buffers,
        summary.session_statistics.free_buffers,
        summary.session_statistics.buffers_written,
        summary.session_statistics.events_lost,
        summary.session_statistics.real_time_buffers_lost,
        summary.session_statistics.log_buffers_lost,
        summary.session_statistics.application_queue_capacity,
        summary.session_statistics.application_queue_peak,
        summary.session_statistics.application_events_dropped,
        summary.ipv4_aggregates.len() + summary.ipv6_aggregates.len()
    );
}

fn run_ctrl_c_validation() -> Result<(), String> {
    const SESSION_NAME: &str = "ProcNetRecorder-V0-TcpIp-Probe";
    procnet_windows::create_isolated_console_for_validation()?;
    let _ignore_guard = procnet_windows::ignore_ctrl_c_for_validation()?;
    let executable = env::current_exe()
        .map_err(|error| format!("cannot resolve current CLI executable: {error}"))?;
    let mut child = Command::new(executable)
        .args(["v0-probe", "--seconds", "60"])
        .spawn()
        .map_err(|error| format!("cannot start Ctrl+C probe child: {error}"))?;
    println!("CTRL_C_TEST_CHILD_STARTED pid={}", child.id());

    let result = exercise_ctrl_c_validation(&mut child, SESSION_NAME);
    if result.is_err() {
        cleanup_failed_ctrl_c_validation(&mut child, SESSION_NAME);
    }
    result
}

fn exercise_ctrl_c_validation(
    child: &mut std::process::Child,
    session_name: &str,
) -> Result<(), String> {
    std::thread::sleep(Duration::from_secs(1));
    match procnet_windows::cleanup_target(session_name).map_err(|error| error.to_string())? {
        procnet_windows::CleanupPreparation::Ready(_) => {}
        procnet_windows::CleanupPreparation::AlreadyAbsent => {
            return Err("Ctrl+C probe child did not create the exact ETW Session".to_owned());
        }
    }
    procnet_windows::generate_ctrl_c_for_validation()?;
    println!("CTRL_C_TEST_SIGNAL_SENT event=CTRL_C_EVENT");

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("cannot query Ctrl+C probe child: {error}"))?
        {
            if !status.success() {
                return Err(format!("Ctrl+C probe child exited with {status}"));
            }
            println!("CTRL_C_TEST_CHILD_EXITED status={status}");
            break;
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "Ctrl+C probe child PID {} did not exit within 10 seconds",
                child.id()
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    match procnet_windows::cleanup_target(session_name).map_err(|error| error.to_string())? {
        procnet_windows::CleanupPreparation::AlreadyAbsent => {
            println!("CTRL_C_TEST_SESSION_ABSENT session={session_name}");
            Ok(())
        }
        procnet_windows::CleanupPreparation::Ready(_) => {
            Err("exact ETW Session still exists after Ctrl+C child exit".to_owned())
        }
    }
}

fn cleanup_failed_ctrl_c_validation(child: &mut std::process::Child, session_name: &str) {
    if let Ok(procnet_windows::CleanupPreparation::Ready(target)) =
        procnet_windows::cleanup_target(session_name)
    {
        let _ = target.stop();
    }
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn parse_probe_options(arguments: &[String]) -> Result<(u64, Vec<u16>, bool), String> {
    match arguments {
        [] => Ok((DEFAULT_PROBE_SECONDS, Vec::new(), false)),
        [flag, value] if flag == "--seconds" => Ok((parse_seconds(value)?, Vec::new(), false)),
        [seconds_flag, seconds, quiet] if seconds_flag == "--seconds" && quiet == "--quiet" => {
            Ok((parse_seconds(seconds)?, Vec::new(), true))
        }
        [seconds_flag, seconds, port_flag, port]
            if seconds_flag == "--seconds" && port_flag == "--port" =>
        {
            Ok((parse_seconds(seconds)?, vec![parse_port(port)?], false))
        }
        [seconds_flag, seconds, ports_flag, ports]
            if seconds_flag == "--seconds" && ports_flag == "--ports" =>
        {
            Ok((parse_seconds(seconds)?, parse_ports(ports)?, false))
        }
        [seconds_flag, seconds, port_flag, port, quiet]
            if seconds_flag == "--seconds" && port_flag == "--port" && quiet == "--quiet" =>
        {
            Ok((parse_seconds(seconds)?, vec![parse_port(port)?], true))
        }
        [seconds_flag, seconds, ports_flag, ports, quiet]
            if seconds_flag == "--seconds" && ports_flag == "--ports" && quiet == "--quiet" =>
        {
            Ok((parse_seconds(seconds)?, parse_ports(ports)?, true))
        }
        _ => Err(
            "usage: procnet-cli v0-probe [--seconds 1..300] [--port N | --ports N,N] [--quiet]"
                .to_owned(),
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeOptions {
    seconds: u64,
    ports: Vec<u16>,
    queue_capacity: usize,
    allow_restricted: bool,
    export_json: Option<PathBuf>,
    export_csv: Option<PathBuf>,
}

fn parse_runtime_options(arguments: &[String]) -> Result<RuntimeOptions, String> {
    let (seconds, ports, queue_capacity) = match arguments.get(..6) {
        Some(
            [
                seconds_flag,
                seconds,
                port_flag,
                port,
                capacity_flag,
                capacity,
            ],
        ) if seconds_flag == "--seconds"
            && port_flag == "--port"
            && capacity_flag == "--queue-capacity" =>
        {
            (
                parse_runtime_seconds(seconds)?,
                vec![parse_port(port)?],
                parse_queue_capacity(capacity)?,
            )
        }
        Some(
            [
                seconds_flag,
                seconds,
                ports_flag,
                ports,
                capacity_flag,
                capacity,
            ],
        ) if seconds_flag == "--seconds"
            && ports_flag == "--ports"
            && capacity_flag == "--queue-capacity" =>
        {
            (
                parse_runtime_seconds(seconds)?,
                parse_ports(ports)?,
                parse_queue_capacity(capacity)?,
            )
        }
        _ => return Err(runtime_usage()),
    };
    let mut options = RuntimeOptions {
        seconds,
        ports,
        queue_capacity,
        allow_restricted: false,
        export_json: None,
        export_csv: None,
    };
    let mut tail = &arguments[6..];
    while let Some((flag, rest)) = tail.split_first() {
        match flag.as_str() {
            "--allow-restricted" if !options.allow_restricted => {
                options.allow_restricted = true;
                tail = rest;
            }
            "--export-json" if options.export_json.is_none() => {
                let (path, remaining) = rest.split_first().ok_or_else(runtime_usage)?;
                options.export_json = Some(PathBuf::from(path));
                tail = remaining;
            }
            "--export-csv" if options.export_csv.is_none() => {
                let (path, remaining) = rest.split_first().ok_or_else(runtime_usage)?;
                options.export_csv = Some(PathBuf::from(path));
                tail = remaining;
            }
            _ => return Err(runtime_usage()),
        }
    }
    Ok(options)
}

fn runtime_usage() -> String {
    "usage: procnet-cli v1-runtime-probe --seconds 1..3600 \
     [--port N | --ports N,N] --queue-capacity 1..1048576 \
     [--allow-restricted] [--export-json PATH] [--export-csv PATH]"
        .to_owned()
}

fn parse_runtime_seconds(value: &str) -> Result<u64, String> {
    let seconds = value
        .parse::<u64>()
        .map_err(|error| format!("invalid --seconds value: {error}"))?;
    if seconds == 0 || seconds > MAX_RUNTIME_SECONDS {
        return Err(format!(
            "runtime --seconds must be between 1 and {MAX_RUNTIME_SECONDS}"
        ));
    }
    Ok(seconds)
}

fn parse_queue_capacity(value: &str) -> Result<usize, String> {
    const MAX_QUEUE_CAPACITY: usize = 1_048_576;
    let capacity = value
        .parse::<usize>()
        .map_err(|error| format!("invalid --queue-capacity value: {error}"))?;
    if capacity == 0 || capacity > MAX_QUEUE_CAPACITY {
        return Err(format!(
            "--queue-capacity must be between 1 and {MAX_QUEUE_CAPACITY}"
        ));
    }
    Ok(capacity)
}

fn parse_seconds(value: &str) -> Result<u64, String> {
    let seconds = value
        .parse::<u64>()
        .map_err(|error| format!("invalid --seconds value: {error}"))?;
    if seconds == 0 || seconds > MAX_PROBE_SECONDS {
        return Err(format!(
            "--seconds must be between 1 and {MAX_PROBE_SECONDS}"
        ));
    }
    Ok(seconds)
}

fn parse_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|error| format!("invalid --port value: {error}"))?;
    if port == 0 {
        return Err("--port must be between 1 and 65535".to_owned());
    }
    Ok(port)
}

fn parse_ports(value: &str) -> Result<Vec<u16>, String> {
    let mut ports = value
        .split(',')
        .map(parse_port)
        .collect::<Result<Vec<_>, _>>()?;
    ports.sort_unstable();
    ports.dedup();
    if ports.len() < 2 {
        return Err("--ports requires at least two distinct ports".to_owned());
    }
    Ok(ports)
}

fn print_help() {
    println!("{} CLI", procnet_windows::project_name());
    println!("Usage:");
    println!("  procnet-cli v0-probe [--seconds 1..300] [--port N | --ports N,N] [--quiet]");
    println!(
        "  procnet-cli v1-runtime-probe --seconds 1..3600 [--port N | --ports N,N] \
         --queue-capacity 1..1048576 [--allow-restricted] [--export-json PATH] \
         [--export-csv PATH]"
    );
    println!("  procnet-cli v0-ctrl-c-test");
    println!("  procnet-cli cleanup-etw --session ProcNetRecorder-V0-TcpIp-Probe");
    println!("  procnet-cli system-snapshot");
    println!("  procnet-cli export-snapshot --format <json|csv> --output <path>");
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        ExportFormat, RuntimeOptions, atomic_write, parse_cleanup_session, parse_export_options,
        parse_probe_options, parse_runtime_options, probe_exit_code,
    };

    #[test]
    fn probe_duration_is_bounded() {
        assert!(parse_probe_options(&["--seconds".to_owned(), "0".to_owned()]).is_err());
        assert!(parse_probe_options(&["--seconds".to_owned(), "301".to_owned()]).is_err());
        assert_eq!(
            parse_probe_options(&["--seconds".to_owned(), "7".to_owned()]),
            Ok((7, Vec::new(), false))
        );
    }

    #[test]
    fn fixture_port_is_explicit_and_nonzero() {
        let arguments = [
            "--seconds".to_owned(),
            "10".to_owned(),
            "--port".to_owned(),
            "39001".to_owned(),
        ];
        assert_eq!(
            parse_probe_options(&arguments),
            Ok((10, vec![39_001], false))
        );
        assert!(
            parse_probe_options(&[
                "--seconds".to_owned(),
                "10".to_owned(),
                "--port".to_owned(),
                "0".to_owned(),
            ])
            .is_err()
        );
    }

    #[test]
    fn multiple_fixture_ports_are_distinct_and_sorted() {
        let arguments = [
            "--seconds".to_owned(),
            "15".to_owned(),
            "--ports".to_owned(),
            "39003,39001".to_owned(),
        ];
        assert_eq!(
            parse_probe_options(&arguments),
            Ok((15, vec![39_001, 39_003], false))
        );
        assert!(
            parse_probe_options(&[
                "--seconds".to_owned(),
                "15".to_owned(),
                "--ports".to_owned(),
                "39001,39001".to_owned(),
            ])
            .is_err()
        );
    }

    #[test]
    fn quiet_mode_is_explicit() {
        let arguments = [
            "--seconds".to_owned(),
            "30".to_owned(),
            "--ports".to_owned(),
            "39001,39003".to_owned(),
            "--quiet".to_owned(),
        ];
        assert_eq!(
            parse_probe_options(&arguments),
            Ok((30, vec![39_001, 39_003], true))
        );
    }

    #[test]
    fn cleanup_requires_one_explicit_session_option() {
        let arguments = [
            "--session".to_owned(),
            "ProcNetRecorder-V0-TcpIp-Probe".to_owned(),
        ];
        assert_eq!(
            parse_cleanup_session(&arguments),
            Ok("ProcNetRecorder-V0-TcpIp-Probe")
        );
        assert!(parse_cleanup_session(&[]).is_err());
    }

    #[test]
    fn runtime_probe_requires_explicit_bounded_queue() {
        let arguments = [
            "--seconds".to_owned(),
            "15".to_owned(),
            "--port".to_owned(),
            "39001".to_owned(),
            "--queue-capacity".to_owned(),
            "4096".to_owned(),
        ];
        assert_eq!(
            parse_runtime_options(&arguments),
            Ok(RuntimeOptions {
                seconds: 15,
                ports: vec![39_001],
                queue_capacity: 4096,
                allow_restricted: false,
                export_json: None,
                export_csv: None,
            })
        );
        assert!(
            parse_runtime_options(&[
                "--seconds".to_owned(),
                "15".to_owned(),
                "--port".to_owned(),
                "39001".to_owned(),
                "--queue-capacity".to_owned(),
                "0".to_owned(),
            ])
            .is_err()
        );

        let multiple = [
            "--seconds".to_owned(),
            "20".to_owned(),
            "--ports".to_owned(),
            "39005,39001,39004,39002".to_owned(),
            "--queue-capacity".to_owned(),
            "4096".to_owned(),
        ];
        assert_eq!(
            parse_runtime_options(&multiple),
            Ok(RuntimeOptions {
                seconds: 20,
                ports: vec![39_001, 39_002, 39_004, 39_005],
                queue_capacity: 4096,
                allow_restricted: false,
                export_json: None,
                export_csv: None,
            })
        );
        let long_run = [
            "--seconds".to_owned(),
            "1800".to_owned(),
            "--port".to_owned(),
            "39001".to_owned(),
            "--queue-capacity".to_owned(),
            "8192".to_owned(),
        ];
        assert_eq!(
            parse_runtime_options(&long_run),
            Ok(RuntimeOptions {
                seconds: 1800,
                ports: vec![39_001],
                queue_capacity: 8192,
                allow_restricted: false,
                export_json: None,
                export_csv: None,
            })
        );

        let restricted = [
            "--seconds".to_owned(),
            "2".to_owned(),
            "--port".to_owned(),
            "39001".to_owned(),
            "--queue-capacity".to_owned(),
            "64".to_owned(),
            "--allow-restricted".to_owned(),
        ];
        assert_eq!(
            parse_runtime_options(&restricted),
            Ok(RuntimeOptions {
                seconds: 2,
                ports: vec![39_001],
                queue_capacity: 64,
                allow_restricted: true,
                export_json: None,
                export_csv: None,
            })
        );
    }

    #[test]
    fn runtime_probe_accepts_both_export_paths() {
        let exports = [
            "--seconds".to_owned(),
            "2".to_owned(),
            "--port".to_owned(),
            "39001".to_owned(),
            "--queue-capacity".to_owned(),
            "64".to_owned(),
            "--export-json".to_owned(),
            "out.json".to_owned(),
            "--export-csv".to_owned(),
            "out.csv".to_owned(),
        ];
        let parsed = parse_runtime_options(&exports).unwrap();
        assert_eq!(parsed.export_json, Some("out.json".into()));
        assert_eq!(parsed.export_csv, Some("out.csv".into()));
    }

    #[test]
    fn probe_failure_categories_have_stable_exit_codes() {
        assert_eq!(
            probe_exit_code(procnet_windows::EtwProbeErrorKind::AccessDenied),
            5
        );
        assert_eq!(
            probe_exit_code(procnet_windows::EtwProbeErrorKind::SessionAlreadyExists),
            183
        );
        assert_eq!(
            probe_exit_code(procnet_windows::EtwProbeErrorKind::Other),
            1
        );
    }

    #[test]
    fn export_options_and_atomic_replacement_are_deterministic() {
        assert_eq!(
            parse_export_options(&[
                "--format".to_owned(),
                "json".to_owned(),
                "--output".to_owned(),
                "snapshot.json".to_owned(),
            ]),
            Ok((ExportFormat::Json, "snapshot.json".into()))
        );
        assert!(
            parse_export_options(&[
                "--format".to_owned(),
                "xml".to_owned(),
                "--output".to_owned(),
                "snapshot.xml".to_owned(),
            ])
            .is_err()
        );

        let directory =
            std::env::temp_dir().join(format!("procnet-export-test-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let output = directory.join("snapshot.json");
        atomic_write(&output, b"first").unwrap();
        atomic_write(&output, b"second").unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"second");
        fs::remove_dir_all(directory).unwrap();
    }
}
