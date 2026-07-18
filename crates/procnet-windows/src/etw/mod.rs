//! Minimal V0 ETW feasibility probe.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ferrisetw::EventRecord;
use ferrisetw::native::EvntraceNativeError;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::provider::kernel_providers::{KernelProvider, TCP_IP_PROVIDER};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{KernelTrace, TraceError, TraceProperties};
use windows::core::GUID;

use procnet_core::{NetworkEvent, TrafficDirection, TransportProtocol};

use crate::raw::console_control::ConsoleCtrlHandler;
use crate::raw::etw_control::{
    ControlOperation, ControlResult, NativeTraceStatistics, control_session,
    query_session_statistics,
};

const SESSION_NAME: &str = crate::PROJECT_ETW_SESSION_NAME;
const MAX_PRINTED_EVENTS: usize = 32;
const MAX_PRINTED_PAYLOADS: usize = 64;
const SEND_IPV4_OPCODE: u8 = 10;
const RECV_IPV4_OPCODE: u8 = 11;
const SEND_IPV6_OPCODE: u8 = 26;
const RECV_IPV6_OPCODE: u8 = 27;
const NETWORK_EVENT_VERSION: u8 = 2;
const NETWORK_TCPIP_FLAG: u32 = 0x0001_0000;
const TRACE_BUFFER_SIZE_KB: u32 = 64;
const TRACE_MINIMUM_BUFFERS: u32 = 64;
const TRACE_MAXIMUM_BUFFERS: u32 = 128;
const HRESULT_ACCESS_DENIED: u32 = 0x8007_0005;
static UDP_IP_PROVIDER: KernelProvider = KernelProvider::new(
    GUID::from_values(
        0xbf3a_50c5,
        0xa9c9,
        0x4988,
        [0xa0, 0x05, 0x2d, 0xf0, 0xb7, 0xc8, 0x0f, 0x80],
    ),
    NETWORK_TCPIP_FLAG,
);

type EventSink = Arc<dyn Fn(NetworkEvent) + Send + Sync>;

/// Summary returned after a bounded ETW probe run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwProbeSummary {
    /// True when a console Ctrl+C or Ctrl+Break requested the stop.
    pub interrupted: bool,
    /// Number of TCP/IP events observed by the callback.
    pub events_observed: usize,
    /// Number of event schemas that TDH resolved successfully.
    pub schemas_resolved: usize,
    /// Number of event schemas that TDH could not resolve.
    pub schema_errors: usize,
    /// Number of SendIPV4/RecvIPV4 version 2 payloads parsed successfully.
    pub tcp_ipv4_payloads_parsed: usize,
    /// Number of eligible TCP/IPv4 payloads that could not be parsed.
    pub tcp_ipv4_payload_errors: usize,
    /// Number of parsed TCP `SendIPV4` payloads.
    pub tcp_send_ipv4_parsed: usize,
    /// Number of parsed TCP `RecvIPV4` payloads.
    pub tcp_recv_ipv4_parsed: usize,
    /// Number of UDP `SendIPV4`/`RecvIPV4` payloads parsed successfully.
    pub udp_ipv4_payloads_parsed: usize,
    /// Number of eligible UDP/IPv4 payloads that could not be parsed.
    pub udp_ipv4_payload_errors: usize,
    /// Number of parsed UDP `SendIPV4` payloads.
    pub udp_send_ipv4_parsed: usize,
    /// Number of parsed UDP `RecvIPV4` payloads.
    pub udp_recv_ipv4_parsed: usize,
    /// Number of TCP `SendIPV6`/`RecvIPV6` payloads parsed successfully.
    pub tcp_ipv6_payloads_parsed: usize,
    /// Number of eligible TCP/IPv6 payloads that could not be parsed.
    pub tcp_ipv6_payload_errors: usize,
    /// Number of parsed TCP `SendIPV6` payloads.
    pub tcp_send_ipv6_parsed: usize,
    /// Number of parsed TCP `RecvIPV6` payloads.
    pub tcp_recv_ipv6_parsed: usize,
    /// Number of UDP `SendIPV6`/`RecvIPV6` payloads parsed successfully.
    pub udp_ipv6_payloads_parsed: usize,
    /// Number of eligible UDP/IPv6 payloads that could not be parsed.
    pub udp_ipv6_payload_errors: usize,
    /// Number of parsed UDP `SendIPV6` payloads.
    pub udp_send_ipv6_parsed: usize,
    /// Number of parsed UDP `RecvIPV6` payloads.
    pub udp_recv_ipv6_parsed: usize,
    /// Per-flow aggregates matching the requested fixture port.
    pub ipv4_aggregates: Vec<Ipv4Aggregate>,
    /// Per-flow IPv6 aggregates matching the requested fixture port.
    pub ipv6_aggregates: Vec<Ipv6Aggregate>,
    /// Live ETW buffer and loss snapshot captured immediately before stop.
    pub session_statistics: EtwSessionStatistics,
}

/// Bounded ETW Session statistics returned by an exact-name native query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtwSessionStatistics {
    pub buffer_size_kb: u32,
    pub minimum_buffers: u32,
    pub maximum_buffers: u32,
    pub active_buffers: u32,
    pub free_buffers: u32,
    pub events_lost: u32,
    pub buffers_written: u32,
    pub log_buffers_lost: u32,
    pub real_time_buffers_lost: u32,
    /// The V0 callback is synchronous and intentionally has no application queue.
    pub application_queue_capacity: usize,
    pub application_queue_peak: usize,
    pub application_events_dropped: usize,
}

impl From<NativeTraceStatistics> for EtwSessionStatistics {
    fn from(native: NativeTraceStatistics) -> Self {
        Self {
            buffer_size_kb: native.buffer_size_kb,
            minimum_buffers: native.minimum_buffers,
            maximum_buffers: native.maximum_buffers,
            active_buffers: native.active_buffers,
            free_buffers: native.free_buffers,
            events_lost: native.events_lost,
            buffers_written: native.buffers_written,
            log_buffers_lost: native.log_buffers_lost,
            real_time_buffers_lost: native.real_time_buffers_lost,
            application_queue_capacity: 0,
            application_queue_peak: 0,
            application_events_dropped: 0,
        }
    }
}

/// Network provider represented by a parsed IPv4 payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkProtocol {
    /// TCP/IP kernel provider.
    Tcp,
    /// UDP/IP kernel provider.
    Udp,
}

/// Provider payload direction for a parsed network event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkDirection {
    /// `SendIPV4` payload.
    Send,
    /// `RecvIPV4` payload.
    Receive,
}

/// Exact protocol, PID, direction and endpoints aggregate used by the V0 fixture comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Aggregate {
    pub protocol: NetworkProtocol,
    pub pid: u32,
    pub direction: NetworkDirection,
    pub source_address: IpAddr,
    pub source_port: u16,
    pub destination_address: IpAddr,
    pub destination_port: u16,
    pub events: u64,
    pub bytes: u64,
}

/// Exact IPv6 protocol, PID, direction and endpoints aggregate used by V0 fixtures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Aggregate {
    pub protocol: NetworkProtocol,
    pub pid: u32,
    pub direction: NetworkDirection,
    pub source_address: IpAddr,
    pub source_port: u16,
    pub destination_address: IpAddr,
    pub destination_port: u16,
    pub events: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct AggregateKey {
    protocol: NetworkProtocol,
    pid: u32,
    direction: NetworkDirection,
    source_address: IpAddr,
    source_port: u16,
    destination_address: IpAddr,
    destination_port: u16,
}

#[derive(Debug)]
struct NetworkPayload {
    pid: u32,
    size: u32,
    destination_address: IpAddr,
    source_address: IpAddr,
    destination_port: u16,
    source_port: u16,
}

fn parse_network_payload(parser: &Parser<'_, '_>) -> Result<NetworkPayload, String> {
    Ok(NetworkPayload {
        pid: parser
            .try_parse("PID")
            .map_err(|error| format!("PID: {error}"))?,
        size: parser
            .try_parse("size")
            .map_err(|error| format!("size: {error}"))?,
        destination_address: parser
            .try_parse("daddr")
            .map_err(|error| format!("daddr: {error}"))?,
        source_address: parser
            .try_parse("saddr")
            .map_err(|error| format!("saddr: {error}"))?,
        destination_port: normalize_port(
            parser
                .try_parse("dport")
                .map_err(|error| format!("dport: {error}"))?,
        ),
        source_port: normalize_port(
            parser
                .try_parse("sport")
                .map_err(|error| format!("sport: {error}"))?,
        ),
    })
}

const fn normalize_port(raw_port: u16) -> u16 {
    u16::from_be(raw_port)
}

#[derive(Clone)]
struct ProviderState {
    events: Arc<AtomicUsize>,
    schemas_resolved: Arc<AtomicUsize>,
    schema_errors: Arc<AtomicUsize>,
    parsed: Arc<AtomicUsize>,
    reported: Arc<AtomicUsize>,
    payload_errors: Arc<AtomicUsize>,
    sends: Arc<AtomicUsize>,
    receives: Arc<AtomicUsize>,
    aggregates: Arc<Mutex<HashMap<AggregateKey, (u64, u64)>>>,
}

impl ProviderState {
    fn new(
        events: Arc<AtomicUsize>,
        schemas_resolved: Arc<AtomicUsize>,
        schema_errors: Arc<AtomicUsize>,
        aggregates: Arc<Mutex<HashMap<AggregateKey, (u64, u64)>>>,
    ) -> Self {
        Self {
            events,
            schemas_resolved,
            schema_errors,
            parsed: Arc::new(AtomicUsize::new(0)),
            reported: Arc::new(AtomicUsize::new(0)),
            payload_errors: Arc::new(AtomicUsize::new(0)),
            sends: Arc::new(AtomicUsize::new(0)),
            receives: Arc::new(AtomicUsize::new(0)),
            aggregates,
        }
    }
}

struct PayloadContext<'a> {
    protocol: NetworkProtocol,
    address_family: u8,
    state: &'a ProviderState,
    fixture_ports: &'a [u16],
    print_samples: bool,
    event_sink: &'a EventSink,
}

fn process_network_payload(
    record: &EventRecord,
    schema: &ferrisetw::schema::Schema,
    context: &PayloadContext<'_>,
) {
    let opcode = record.opcode();
    let (send_opcode, receive_opcode) = if context.address_family == 4 {
        (SEND_IPV4_OPCODE, RECV_IPV4_OPCODE)
    } else {
        (SEND_IPV6_OPCODE, RECV_IPV6_OPCODE)
    };
    if record.version() != NETWORK_EVENT_VERSION
        || !matches!(opcode, value if value == send_opcode || value == receive_opcode)
    {
        return;
    }

    let parser = Parser::create(record, schema);
    match parse_network_payload(&parser) {
        Ok(payload) => handle_network_payload(&payload, opcode, send_opcode, context),
        Err(error) => {
            let error_ordinal = context.state.payload_errors.fetch_add(1, Ordering::Relaxed) + 1;
            if error_ordinal <= MAX_PRINTED_PAYLOADS {
                eprintln!(
                    "ETW_IPV{}_PAYLOAD_ERROR ordinal={error_ordinal} opcode={opcode} version={} \
                     detail={error}",
                    context.address_family,
                    record.version()
                );
            }
        }
    }
}

fn handle_network_payload(
    payload: &NetworkPayload,
    opcode: u8,
    send_opcode: u8,
    context: &PayloadContext<'_>,
) {
    context.state.parsed.fetch_add(1, Ordering::Relaxed);
    let direction = if opcode == send_opcode {
        context.state.sends.fetch_add(1, Ordering::Relaxed);
        NetworkDirection::Send
    } else {
        context.state.receives.fetch_add(1, Ordering::Relaxed);
        NetworkDirection::Receive
    };
    let matches_fixture = context.fixture_ports.is_empty()
        || context.fixture_ports.contains(&payload.source_port)
        || context.fixture_ports.contains(&payload.destination_port);
    if !context.fixture_ports.is_empty()
        && matches_fixture
        && let Ok(mut locked) = context.state.aggregates.lock()
    {
        let key = AggregateKey {
            protocol: context.protocol,
            pid: payload.pid,
            direction,
            source_address: payload.source_address,
            source_port: payload.source_port,
            destination_address: payload.destination_address,
            destination_port: payload.destination_port,
        };
        let value = locked.entry(key).or_insert((0, 0));
        value.0 = value.0.saturating_add(1);
        value.1 = value.1.saturating_add(u64::from(payload.size));
    }
    if matches_fixture {
        (context.event_sink)(normalized_event(payload, context.protocol, direction));
    }
    report_network_payload(payload, direction, matches_fixture, context);
}

fn normalized_event(
    payload: &NetworkPayload,
    protocol: NetworkProtocol,
    direction: NetworkDirection,
) -> NetworkEvent {
    NetworkEvent {
        timestamp_unix_nanos: current_unix_nanos(),
        pid: payload.pid,
        protocol: match protocol {
            NetworkProtocol::Tcp => TransportProtocol::Tcp,
            NetworkProtocol::Udp => TransportProtocol::Udp,
        },
        direction: match direction {
            NetworkDirection::Send => TrafficDirection::Send,
            NetworkDirection::Receive => TrafficDirection::Receive,
        },
        source: SocketAddr::new(payload.source_address, payload.source_port),
        destination: SocketAddr::new(payload.destination_address, payload.destination_port),
        bytes: u64::from(payload.size),
    }
}

fn report_network_payload(
    payload: &NetworkPayload,
    direction: NetworkDirection,
    matches_fixture: bool,
    context: &PayloadContext<'_>,
) {
    let report_ordinal = if matches_fixture {
        context.state.reported.fetch_add(1, Ordering::Relaxed) + 1
    } else {
        usize::MAX
    };
    if context.print_samples && report_ordinal <= MAX_PRINTED_PAYLOADS {
        println!(
            "ETW_IPV{}_PAYLOAD ordinal={report_ordinal} protocol={} direction={} pid={} \
             size={} source={}:{} destination={}:{}",
            context.address_family,
            match context.protocol {
                NetworkProtocol::Tcp => "tcp",
                NetworkProtocol::Udp => "udp",
            },
            match direction {
                NetworkDirection::Send => "send",
                NetworkDirection::Receive => "receive",
            },
            payload.pid,
            payload.size,
            payload.source_address,
            payload.source_port,
            payload.destination_address,
            payload.destination_port
        );
    }
}

fn current_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        })
}

fn collect_aggregates(
    aggregates: &Mutex<HashMap<AggregateKey, (u64, u64)>>,
    ipv6: bool,
) -> Result<Vec<(AggregateKey, u64, u64)>, EtwProbeError> {
    let mut collected = aggregates
        .lock()
        .map_err(|_| EtwProbeError::new("aggregate", "fixture aggregate lock was poisoned"))?
        .iter()
        .filter(|(key, _)| key.source_address.is_ipv6() == ipv6)
        .map(|(key, value)| (key.clone(), value.0, value.1))
        .collect::<Vec<_>>();
    collected.sort_by_key(|(key, _, _)| {
        (
            key.pid,
            key.protocol,
            key.direction,
            key.source_address,
            key.source_port,
            key.destination_address,
            key.destination_port,
        )
    });
    Ok(collected)
}

fn collect_ipv4_aggregates(
    aggregates: &Mutex<HashMap<AggregateKey, (u64, u64)>>,
) -> Result<Vec<Ipv4Aggregate>, EtwProbeError> {
    collect_aggregates(aggregates, false).map(|items| {
        items
            .into_iter()
            .map(|(key, events, bytes)| Ipv4Aggregate {
                protocol: key.protocol,
                pid: key.pid,
                direction: key.direction,
                source_address: key.source_address,
                source_port: key.source_port,
                destination_address: key.destination_address,
                destination_port: key.destination_port,
                events,
                bytes,
            })
            .collect()
    })
}

fn collect_ipv6_aggregates(
    aggregates: &Mutex<HashMap<AggregateKey, (u64, u64)>>,
) -> Result<Vec<Ipv6Aggregate>, EtwProbeError> {
    collect_aggregates(aggregates, true).map(|items| {
        items
            .into_iter()
            .map(|(key, events, bytes)| Ipv6Aggregate {
                protocol: key.protocol,
                pid: key.pid,
                direction: key.direction,
                source_address: key.source_address,
                source_port: key.source_port,
                destination_address: key.destination_address,
                destination_port: key.destination_port,
                events,
                bytes,
            })
            .collect()
    })
}

/// Failure to start or stop the V0 ETW probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwProbeError {
    operation: &'static str,
    detail: String,
    kind: EtwProbeErrorKind,
}

impl EtwProbeError {
    fn new(operation: &'static str, detail: impl Into<String>) -> Self {
        Self {
            operation,
            detail: detail.into(),
            kind: EtwProbeErrorKind::Other,
        }
    }

    fn from_trace(operation: &'static str, error: &TraceError) -> Self {
        let kind = match error {
            TraceError::EtwNativeError(EvntraceNativeError::IoError(error))
                if error.raw_os_error().is_some_and(|code| {
                    code == 5 || u32::from_ne_bytes(code.to_ne_bytes()) == HRESULT_ACCESS_DENIED
                }) =>
            {
                EtwProbeErrorKind::AccessDenied
            }
            TraceError::EtwNativeError(EvntraceNativeError::AlreadyExist) => {
                EtwProbeErrorKind::SessionAlreadyExists
            }
            _ => EtwProbeErrorKind::Other,
        };
        Self {
            operation,
            detail: format!("{error:?}"),
            kind,
        }
    }

    /// Returns the stable category needed by a restricted-mode caller.
    #[must_use]
    pub const fn kind(&self) -> EtwProbeErrorKind {
        self.kind
    }
}

/// Stable ETW probe failure category for CLI exit codes and future restricted mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtwProbeErrorKind {
    /// Windows denied access to kernel ETW capture.
    AccessDenied,
    /// The project's exact fixed-name Session already exists.
    SessionAlreadyExists,
    /// Any failure that is neither an access denial nor a Session conflict.
    Other,
}

impl fmt::Display for EtwProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ETW {} failed: {}", self.operation, self.detail)
    }
}

impl std::error::Error for EtwProbeError {}

/// Result of the mandatory query performed before an ETW cleanup attempt.
#[derive(Debug)]
pub enum CleanupPreparation {
    /// The exact project Session is already absent.
    AlreadyAbsent,
    /// The exact project Session exists and may be stopped.
    Ready(PreparedEtwCleanup),
}

/// A cleanup target that has passed the exact-name query precondition.
#[derive(Debug)]
pub struct PreparedEtwCleanup {
    session_name: &'static str,
}

impl PreparedEtwCleanup {
    /// Returns the complete, exact Session name that will be stopped.
    #[must_use]
    pub const fn session_name(&self) -> &'static str {
        self.session_name
    }

    /// Stops the previously queried Session and verifies that it no longer exists.
    ///
    /// # Errors
    ///
    /// Returns [`EtwCleanupError`] if access is denied, `ControlTraceW` fails, or the exact Session
    /// still exists after the stop attempt.
    pub fn stop(self) -> Result<CleanupResult, EtwCleanupError> {
        let stop_result = control_session(self.session_name, ControlOperation::Stop)
            .map_err(|code| EtwCleanupError::control_failed("stop", code))?;

        match stop_result {
            ControlResult::AccessDenied => Err(EtwCleanupError::AccessDenied { operation: "stop" }),
            ControlResult::NotFound => Ok(CleanupResult::AlreadyAbsent),
            ControlResult::Success => verify_stopped(self.session_name, false),
            ControlResult::MoreData => verify_stopped(self.session_name, true),
        }
    }
}

/// Successful result of cleaning the exact project ETW Session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupResult {
    /// The Session was stopped and post-stop query confirmed absence.
    Stopped,
    /// Stop returned `ERROR_MORE_DATA`, and a follow-up query confirmed absence.
    StoppedAfterMoreData,
    /// The Session disappeared between the preflight query and stop call.
    AlreadyAbsent,
}

/// Safe cleanup failure reported by the Windows platform layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EtwCleanupError {
    /// A caller attempted to target a Session other than this project's fixed Session.
    UnexpectedSessionName { supplied: String },
    /// Windows requires elevated privileges or Performance Log Users membership.
    AccessDenied { operation: &'static str },
    /// A native control call returned an unhandled Win32 error code.
    ControlFailed { operation: &'static str, code: u32 },
    /// The exact Session still exists after the stop call.
    StillRunning,
}

impl EtwCleanupError {
    const fn control_failed(operation: &'static str, code: u32) -> Self {
        Self::ControlFailed { operation, code }
    }
}

impl fmt::Display for EtwCleanupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedSessionName { supplied } => write!(
                formatter,
                "refusing to control unexpected ETW Session '{supplied}'; only '{SESSION_NAME}' is allowed"
            ),
            Self::AccessDenied { operation } => write!(
                formatter,
                "ETW {operation} access denied; run this cleanup command with administrator privileges"
            ),
            Self::ControlFailed { operation, code } => {
                write!(formatter, "ETW {operation} failed with Win32 error {code}")
            }
            Self::StillRunning => write!(
                formatter,
                "ETW Session '{SESSION_NAME}' still exists after the stop attempt"
            ),
        }
    }
}

impl std::error::Error for EtwCleanupError {}

/// Queries the exact project Session before authorizing a stop operation.
///
/// # Errors
///
/// Returns [`EtwCleanupError`] for any Session name other than the fixed project name, for access
/// denial, or when the native query fails.
pub fn cleanup_target(session_name: &str) -> Result<CleanupPreparation, EtwCleanupError> {
    if session_name != SESSION_NAME {
        return Err(EtwCleanupError::UnexpectedSessionName {
            supplied: session_name.to_owned(),
        });
    }

    let query_result = control_session(session_name, ControlOperation::Query)
        .map_err(|code| EtwCleanupError::control_failed("query", code))?;
    match query_result {
        ControlResult::Success => Ok(CleanupPreparation::Ready(PreparedEtwCleanup {
            session_name: SESSION_NAME,
        })),
        ControlResult::NotFound => Ok(CleanupPreparation::AlreadyAbsent),
        ControlResult::AccessDenied => Err(EtwCleanupError::AccessDenied { operation: "query" }),
        ControlResult::MoreData => Err(EtwCleanupError::control_failed("query", 234)),
    }
}

fn verify_stopped(
    session_name: &str,
    stop_returned_more_data: bool,
) -> Result<CleanupResult, EtwCleanupError> {
    let query_result = control_session(session_name, ControlOperation::Query)
        .map_err(|code| EtwCleanupError::control_failed("post-stop query", code))?;
    match query_result {
        ControlResult::NotFound => {
            if stop_returned_more_data {
                Ok(CleanupResult::StoppedAfterMoreData)
            } else {
                Ok(CleanupResult::Stopped)
            }
        }
        ControlResult::AccessDenied => Err(EtwCleanupError::AccessDenied {
            operation: "post-stop query",
        }),
        ControlResult::Success | ControlResult::MoreData => Err(EtwCleanupError::StillRunning),
    }
}

fn build_network_provider(
    kernel_provider: &KernelProvider,
    protocol: NetworkProtocol,
    fixture_ports: Vec<u16>,
    ipv4_state: ProviderState,
    ipv6_state: ProviderState,
    print_samples: bool,
    event_sink: EventSink,
) -> Provider {
    Provider::kernel(kernel_provider)
        .add_callback(
            move |record: &EventRecord, schema_locator: &SchemaLocator| {
                let ordinal = ipv4_state.events.fetch_add(1, Ordering::Relaxed) + 1;
                match schema_locator.event_schema(record) {
                    Ok(schema) => {
                        ipv4_state.schemas_resolved.fetch_add(1, Ordering::Relaxed);
                        if print_samples && ordinal <= MAX_PRINTED_EVENTS {
                            println!(
                                "ETW_EVENT ordinal={ordinal} provider={} task={} opcode_name={} \
                                 event_id={} opcode={} version={} header_pid={} thread_id={} \
                                 timestamp_raw={}",
                                schema.provider_name(),
                                schema.task_name(),
                                schema.opcode_name(),
                                record.event_id(),
                                record.opcode(),
                                record.version(),
                                record.process_id(),
                                record.thread_id(),
                                record.raw_timestamp()
                            );
                        }
                        process_network_payload(
                            record,
                            &schema,
                            &PayloadContext {
                                protocol,
                                address_family: 4,
                                state: &ipv4_state,
                                fixture_ports: &fixture_ports,
                                print_samples,
                                event_sink: &event_sink,
                            },
                        );
                        process_network_payload(
                            record,
                            &schema,
                            &PayloadContext {
                                protocol,
                                address_family: 6,
                                state: &ipv6_state,
                                fixture_ports: &fixture_ports,
                                print_samples,
                                event_sink: &event_sink,
                            },
                        );
                    }
                    Err(error) => {
                        ipv4_state.schema_errors.fetch_add(1, Ordering::Relaxed);
                        if ordinal <= MAX_PRINTED_EVENTS {
                            eprintln!(
                                "ETW_SCHEMA_ERROR ordinal={ordinal} event_id={} opcode={} \
                                 version={} detail={error:?}",
                                record.event_id(),
                                record.opcode(),
                                record.version()
                            );
                        }
                    }
                }
            },
        )
        .build()
}

/// Runs the kernel TCP/IP and UDP/IP providers for a bounded duration.
///
/// This probe intentionally does not claim that header PIDs are the originating process. V0 must
/// parse and validate the provider payload before the PID gate can pass.
///
/// # Errors
///
/// Returns [`EtwProbeError`] when Windows rejects the Session start or when the Session cannot be
/// stopped cleanly.
pub fn run_tcp_ip_probe(
    duration: Duration,
    fixture_ports: Vec<u16>,
    print_samples: bool,
) -> Result<EtwProbeSummary, EtwProbeError> {
    run_tcp_ip_probe_inner(
        duration,
        fixture_ports,
        print_samples,
        Arc::new(|_| {}),
        None,
    )
}

/// Runs the bounded network probe and forwards normalized owned events to a caller-provided sink.
///
/// The sink runs on the ETW callback thread and therefore must return promptly. Use a non-blocking
/// bounded ingress rather than doing aggregation, I/O, or UI work inside it.
///
/// # Errors
///
/// Returns [`EtwProbeError`] when Windows rejects the Session or it cannot stop cleanly.
pub fn run_tcp_ip_probe_with_sink(
    duration: Duration,
    fixture_ports: Vec<u16>,
    print_samples: bool,
    event_sink: impl Fn(NetworkEvent) + Send + Sync + 'static,
) -> Result<EtwProbeSummary, EtwProbeError> {
    run_tcp_ip_probe_inner(
        duration,
        fixture_ports,
        print_samples,
        Arc::new(event_sink),
        None,
    )
}

/// Runs the bounded probe until its deadline or a caller-owned cancellation flag is set.
///
/// # Errors
///
/// Returns [`EtwProbeError`] when Windows rejects the Session or it cannot stop cleanly.
pub fn run_tcp_ip_probe_with_sink_until(
    duration: Duration,
    fixture_ports: Vec<u16>,
    print_samples: bool,
    cancel: &AtomicBool,
    event_sink: impl Fn(NetworkEvent) + Send + Sync + 'static,
) -> Result<EtwProbeSummary, EtwProbeError> {
    run_tcp_ip_probe_inner(
        duration,
        fixture_ports,
        print_samples,
        Arc::new(event_sink),
        Some(cancel),
    )
}

fn run_tcp_ip_probe_inner(
    duration: Duration,
    fixture_ports: Vec<u16>,
    print_samples: bool,
    event_sink: EventSink,
    cancel: Option<&AtomicBool>,
) -> Result<EtwProbeSummary, EtwProbeError> {
    let _console_handler = ConsoleCtrlHandler::install()
        .map_err(|error| EtwProbeError::new("console handler", error))?;
    let events_observed = Arc::new(AtomicUsize::new(0));
    let schemas_resolved = Arc::new(AtomicUsize::new(0));
    let schema_errors = Arc::new(AtomicUsize::new(0));
    let aggregates = Arc::new(Mutex::new(HashMap::new()));
    let tcp_ipv4_state = ProviderState::new(
        Arc::clone(&events_observed),
        Arc::clone(&schemas_resolved),
        Arc::clone(&schema_errors),
        Arc::clone(&aggregates),
    );
    let tcp_ipv6_state = ProviderState::new(
        Arc::clone(&events_observed),
        Arc::clone(&schemas_resolved),
        Arc::clone(&schema_errors),
        Arc::clone(&aggregates),
    );
    let udp_ipv4_state = ProviderState::new(
        Arc::clone(&events_observed),
        Arc::clone(&schemas_resolved),
        Arc::clone(&schema_errors),
        Arc::clone(&aggregates),
    );
    let udp_ipv6_state = ProviderState::new(
        Arc::clone(&events_observed),
        Arc::clone(&schemas_resolved),
        Arc::clone(&schema_errors),
        Arc::clone(&aggregates),
    );

    let tcp_provider = build_network_provider(
        &TCP_IP_PROVIDER,
        NetworkProtocol::Tcp,
        fixture_ports.clone(),
        tcp_ipv4_state.clone(),
        tcp_ipv6_state.clone(),
        print_samples,
        Arc::clone(&event_sink),
    );
    let udp_provider = build_network_provider(
        &UDP_IP_PROVIDER,
        NetworkProtocol::Udp,
        fixture_ports,
        udp_ipv4_state.clone(),
        udp_ipv6_state.clone(),
        print_samples,
        event_sink,
    );

    let trace = KernelTrace::new()
        .named(SESSION_NAME.to_owned())
        .set_trace_properties(TraceProperties {
            buffer_size: TRACE_BUFFER_SIZE_KB,
            min_buffer: TRACE_MINIMUM_BUFFERS,
            max_buffer: TRACE_MAXIMUM_BUFFERS,
            ..TraceProperties::default()
        })
        .enable(tcp_provider)
        .enable(udp_provider)
        .start_and_process()
        .map_err(|error| EtwProbeError::from_trace("start", &error))?;

    wait_for_probe(duration, cancel);
    let interrupted = ConsoleCtrlHandler::stop_requested();

    let native_statistics = query_session_statistics(SESSION_NAME)
        .map_err(|code| EtwProbeError::new("statistics query", format!("Win32 error {code}")))?
        .ok_or_else(|| EtwProbeError::new("statistics query", "Session disappeared before stop"))?;

    trace
        .stop()
        .map_err(|error| EtwProbeError::new("stop", format!("{error:?}")))?;

    Ok(EtwProbeSummary {
        interrupted,
        events_observed: events_observed.load(Ordering::Relaxed),
        schemas_resolved: schemas_resolved.load(Ordering::Relaxed),
        schema_errors: schema_errors.load(Ordering::Relaxed),
        tcp_ipv4_payloads_parsed: tcp_ipv4_state.parsed.load(Ordering::Relaxed),
        tcp_ipv4_payload_errors: tcp_ipv4_state.payload_errors.load(Ordering::Relaxed),
        tcp_send_ipv4_parsed: tcp_ipv4_state.sends.load(Ordering::Relaxed),
        tcp_recv_ipv4_parsed: tcp_ipv4_state.receives.load(Ordering::Relaxed),
        udp_ipv4_payloads_parsed: udp_ipv4_state.parsed.load(Ordering::Relaxed),
        udp_ipv4_payload_errors: udp_ipv4_state.payload_errors.load(Ordering::Relaxed),
        udp_send_ipv4_parsed: udp_ipv4_state.sends.load(Ordering::Relaxed),
        udp_recv_ipv4_parsed: udp_ipv4_state.receives.load(Ordering::Relaxed),
        tcp_ipv6_payloads_parsed: tcp_ipv6_state.parsed.load(Ordering::Relaxed),
        tcp_ipv6_payload_errors: tcp_ipv6_state.payload_errors.load(Ordering::Relaxed),
        tcp_send_ipv6_parsed: tcp_ipv6_state.sends.load(Ordering::Relaxed),
        tcp_recv_ipv6_parsed: tcp_ipv6_state.receives.load(Ordering::Relaxed),
        udp_ipv6_payloads_parsed: udp_ipv6_state.parsed.load(Ordering::Relaxed),
        udp_ipv6_payload_errors: udp_ipv6_state.payload_errors.load(Ordering::Relaxed),
        udp_send_ipv6_parsed: udp_ipv6_state.sends.load(Ordering::Relaxed),
        udp_recv_ipv6_parsed: udp_ipv6_state.receives.load(Ordering::Relaxed),
        ipv4_aggregates: collect_ipv4_aggregates(&aggregates)?,
        ipv6_aggregates: collect_ipv6_aggregates(&aggregates)?,
        session_statistics: native_statistics.into(),
    })
}

fn wait_for_probe(duration: Duration, cancel: Option<&AtomicBool>) {
    let deadline = Instant::now() + duration;
    while !ConsoleCtrlHandler::stop_requested()
        && !cancel.is_some_and(|cancel| cancel.load(Ordering::Acquire))
    {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        thread::sleep((deadline - now).min(Duration::from_millis(50)));
    }
}

#[cfg(test)]
mod cleanup_tests {
    use std::io;

    use ferrisetw::native::EvntraceNativeError;
    use ferrisetw::trace::TraceError;

    use super::{
        EtwCleanupError, EtwProbeError, EtwProbeErrorKind, HRESULT_ACCESS_DENIED, cleanup_target,
        normalize_port,
    };

    #[test]
    fn cleanup_rejects_every_other_session_name_before_native_call() {
        let result = cleanup_target("NT Kernel Logger");
        assert_eq!(
            result.unwrap_err(),
            EtwCleanupError::UnexpectedSessionName {
                supplied: "NT Kernel Logger".to_owned()
            }
        );
    }

    #[test]
    fn provider_port_is_converted_from_network_byte_order() {
        assert_eq!(normalize_port(22_936), 39_001);
        assert_eq!(normalize_port(15_845), 58_685);
    }

    #[test]
    fn probe_errors_classify_access_denied_and_session_conflict() {
        let denied_error = TraceError::EtwNativeError(EvntraceNativeError::IoError(
            io::Error::from_raw_os_error(5),
        ));
        let denied = EtwProbeError::from_trace("start", &denied_error);
        assert_eq!(denied.kind(), EtwProbeErrorKind::AccessDenied);

        let denied_hresult = TraceError::EtwNativeError(EvntraceNativeError::IoError(
            io::Error::from_raw_os_error(i32::from_ne_bytes(HRESULT_ACCESS_DENIED.to_ne_bytes())),
        ));
        assert_eq!(
            EtwProbeError::from_trace("start", &denied_hresult).kind(),
            EtwProbeErrorKind::AccessDenied
        );

        let conflict_error = TraceError::EtwNativeError(EvntraceNativeError::AlreadyExist);
        let conflict = EtwProbeError::from_trace("start", &conflict_error);
        assert_eq!(conflict.kind(), EtwProbeErrorKind::SessionAlreadyExists);
    }
}
