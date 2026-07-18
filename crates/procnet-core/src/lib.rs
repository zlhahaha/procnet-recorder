//! Platform-independent domain boundary for `ProcNet Recorder`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

mod session;

pub use session::{
    AlertEvaluator, AlertKind, AlertObservation, AlertPolicy, AlertRecord, AlertRule, AlertSignal,
    EndpointSummary, ExportFormat, ProcessRiskObservation, ProcessSessionSummary, RiskEvaluator,
    RiskLevel, RiskObservation, RiskPolicy, RiskSignal, SessionBucket, SessionDetail, SessionId,
    SessionRecord, SessionRepository, SessionStatus,
};

/// Human-readable product name shared by entry points.
pub const PROJECT_NAME: &str = "ProcNet Recorder";

/// Transport protocol attached to a normalized network event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

/// Traffic direction reported by the collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrafficDirection {
    Send,
    Receive,
}

/// Owned, platform-independent event transferred from collection to aggregation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEvent {
    pub timestamp_unix_nanos: u64,
    pub pid: u32,
    pub protocol: TransportProtocol,
    pub direction: TrafficDirection,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub bytes: u64,
}

/// Stable key used to aggregate normalized traffic events.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowKey {
    pub pid: u32,
    pub protocol: TransportProtocol,
    pub direction: TrafficDirection,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

impl From<&NetworkEvent> for FlowKey {
    fn from(event: &NetworkEvent) -> Self {
        Self {
            pid: event.pid,
            protocol: event.protocol,
            direction: event.direction,
            source: event.source,
            destination: event.destination,
        }
    }
}

/// Immutable aggregate exposed through application snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSnapshot {
    pub key: FlowKey,
    pub process_key: Option<ProcessKey>,
    pub events: u64,
    pub bytes: u64,
    pub first_timestamp_unix_nanos: u64,
    pub last_timestamp_unix_nanos: u64,
}

/// Stable process identity that remains distinct when Windows reuses a PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessKey {
    pub pid: u32,
    pub started_at_unix_nanos: u64,
}

/// Immutable process metadata captured at one point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSnapshot {
    pub key: ProcessKey,
    pub name: String,
    pub image_path: Option<String>,
    pub icon: ProcessIconState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIcon {
    pub width: u32,
    pub height: u32,
    pub rgba: Arc<[u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessIconState {
    NotLoaded,
    Unavailable,
    Available(ProcessIcon),
}

/// Normalized TCP lifecycle state from the platform connection table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TcpConnectionState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown(u32),
}

/// Immutable TCP or UDP endpoint ownership captured from the platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionSnapshot {
    pub protocol: TransportProtocol,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub tcp_state: Option<TcpConnectionState>,
    pub pid: u32,
    pub process_key: Option<ProcessKey>,
    /// Best-effort name captured from the same `ToolHelp` snapshot, including protected processes
    /// whose creation time could not be queried without elevation.
    pub owner_name: Option<String>,
}

/// Point-in-time process and connection view used by Application consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemSnapshot {
    pub captured_at_unix_nanos: u64,
    /// PID/name pairs from the same process enumeration, including processes whose stable
    /// creation-time identity was unavailable to the current security context.
    pub process_names: Vec<(u32, String)>,
    pub processes: Vec<ProcessSnapshot>,
    pub connections: Vec<ConnectionSnapshot>,
}

/// Fixed-width upload/download sample used by the basic traffic curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficBucket {
    pub start_unix_nanos: u64,
    pub send_bytes: u64,
    pub receive_bytes: u64,
}

/// Immutable bounded curve plus explicit late-event accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficCurveSnapshot {
    pub bucket_width_nanos: u64,
    pub maximum_buckets: usize,
    pub events_received: u64,
    pub events_accepted: u64,
    pub events_late_dropped: u64,
    pub bytes_received: u64,
    pub bytes_accepted: u64,
    pub bytes_late_dropped: u64,
    pub buckets: Vec<TrafficBucket>,
}

/// Per-process cumulative traffic and the fixed-width rate bucket containing the sample time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessTrafficCounters {
    pub pid: u32,
    pub send_bytes_total: u64,
    pub receive_bytes_total: u64,
    pub send_bytes_per_second: u64,
    pub receive_bytes_per_second: u64,
    pub last_timestamp_unix_nanos: u64,
}

#[derive(Debug, Default)]
struct ProcessTrafficState {
    send_bytes_total: u64,
    receive_bytes_total: u64,
    last_timestamp_unix_nanos: u64,
    buckets: BTreeMap<u64, (u64, u64)>,
}

/// Bounded, fixed-width per-process traffic rate tracker.
#[derive(Debug)]
pub struct ProcessTrafficTracker {
    bucket_width_nanos: u64,
    processes: BTreeMap<u32, ProcessTrafficState>,
}

impl ProcessTrafficTracker {
    #[must_use]
    pub fn new(bucket_width_nanos: u64) -> Option<Self> {
        (bucket_width_nanos != 0).then_some(Self {
            bucket_width_nanos,
            processes: BTreeMap::new(),
        })
    }

    pub fn record(&mut self, event: &NetworkEvent) {
        let bucket_start =
            event.timestamp_unix_nanos / self.bucket_width_nanos * self.bucket_width_nanos;
        let state = self.processes.entry(event.pid).or_default();
        state.last_timestamp_unix_nanos = state
            .last_timestamp_unix_nanos
            .max(event.timestamp_unix_nanos);
        let bucket = state.buckets.entry(bucket_start).or_default();
        match event.direction {
            TrafficDirection::Send => {
                state.send_bytes_total = state.send_bytes_total.saturating_add(event.bytes);
                bucket.0 = bucket.0.saturating_add(event.bytes);
            }
            TrafficDirection::Receive => {
                state.receive_bytes_total = state.receive_bytes_total.saturating_add(event.bytes);
                bucket.1 = bucket.1.saturating_add(event.bytes);
            }
        }
        let earliest = bucket_start.saturating_sub(self.bucket_width_nanos);
        state.buckets.retain(|start, _| *start >= earliest);
    }

    #[must_use]
    pub fn snapshot_at(&self, timestamp_unix_nanos: u64) -> Vec<ProcessTrafficCounters> {
        let bucket_start = timestamp_unix_nanos / self.bucket_width_nanos * self.bucket_width_nanos;
        self.processes
            .iter()
            .map(|(&pid, state)| {
                let (send, receive) = state
                    .buckets
                    .get(&bucket_start)
                    .or_else(|| {
                        state
                            .buckets
                            .get(&bucket_start.saturating_sub(self.bucket_width_nanos))
                    })
                    .copied()
                    .unwrap_or_default();
                ProcessTrafficCounters {
                    pid,
                    send_bytes_total: state.send_bytes_total,
                    receive_bytes_total: state.receive_bytes_total,
                    send_bytes_per_second: bytes_per_second(send, self.bucket_width_nanos),
                    receive_bytes_per_second: bytes_per_second(receive, self.bucket_width_nanos),
                    last_timestamp_unix_nanos: state.last_timestamp_unix_nanos,
                }
            })
            .collect()
    }

    pub fn retain_since(&mut self, minimum_timestamp_unix_nanos: u64) {
        self.processes
            .retain(|_, state| state.last_timestamp_unix_nanos >= minimum_timestamp_unix_nanos);
    }

    pub fn trim_to_maximum(&mut self, maximum: usize) {
        if self.processes.len() <= maximum {
            return;
        }
        let mut oldest = self
            .processes
            .iter()
            .map(|(&pid, state)| (state.last_timestamp_unix_nanos, pid))
            .collect::<Vec<_>>();
        oldest.sort_unstable();
        for (_, pid) in oldest.into_iter().take(self.processes.len() - maximum) {
            self.processes.remove(&pid);
        }
    }
}

fn bytes_per_second(bytes: u64, bucket_width_nanos: u64) -> u64 {
    u64::try_from(
        u128::from(bytes)
            .saturating_mul(1_000_000_000)
            .saturating_div(u128::from(bucket_width_nanos)),
    )
    .unwrap_or(u64::MAX)
}

/// Deterministic result of adding an event to a bounded curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurveRecordOutcome {
    Accepted,
    LateDropped,
}

/// Single-threaded fixed-width, bounded upload/download curve.
#[derive(Debug)]
pub struct TrafficCurve {
    bucket_width_nanos: u64,
    maximum_buckets: usize,
    latest_bucket_start: Option<u64>,
    buckets: BTreeMap<u64, TrafficBucket>,
    events_received: u64,
    events_accepted: u64,
    events_late_dropped: u64,
    bytes_received: u64,
    bytes_accepted: u64,
    bytes_late_dropped: u64,
}

impl TrafficCurve {
    /// Creates a curve with nonzero fixed width and capacity.
    #[must_use]
    pub fn new(bucket_width_nanos: u64, maximum_buckets: usize) -> Option<Self> {
        if bucket_width_nanos == 0 || maximum_buckets == 0 {
            return None;
        }
        Some(Self {
            bucket_width_nanos,
            maximum_buckets,
            latest_bucket_start: None,
            buckets: BTreeMap::new(),
            events_received: 0,
            events_accepted: 0,
            events_late_dropped: 0,
            bytes_received: 0,
            bytes_accepted: 0,
            bytes_late_dropped: 0,
        })
    }

    pub fn record(&mut self, event: &NetworkEvent) -> CurveRecordOutcome {
        self.events_received = self.events_received.saturating_add(1);
        self.bytes_received = self.bytes_received.saturating_add(event.bytes);
        let bucket_start =
            event.timestamp_unix_nanos / self.bucket_width_nanos * self.bucket_width_nanos;
        self.latest_bucket_start = Some(
            self.latest_bucket_start
                .map_or(bucket_start, |latest| latest.max(bucket_start)),
        );
        let earliest = self.earliest_retained();
        if bucket_start < earliest {
            self.events_late_dropped = self.events_late_dropped.saturating_add(1);
            self.bytes_late_dropped = self.bytes_late_dropped.saturating_add(event.bytes);
            return CurveRecordOutcome::LateDropped;
        }

        self.events_accepted = self.events_accepted.saturating_add(1);
        self.bytes_accepted = self.bytes_accepted.saturating_add(event.bytes);
        let bucket = self.buckets.entry(bucket_start).or_insert(TrafficBucket {
            start_unix_nanos: bucket_start,
            send_bytes: 0,
            receive_bytes: 0,
        });
        match event.direction {
            TrafficDirection::Send => {
                bucket.send_bytes = bucket.send_bytes.saturating_add(event.bytes);
            }
            TrafficDirection::Receive => {
                bucket.receive_bytes = bucket.receive_bytes.saturating_add(event.bytes);
            }
        }
        self.normalize();
        CurveRecordOutcome::Accepted
    }

    /// Advances the visible curve clock and fills elapsed buckets with zero traffic.
    pub fn advance_to(&mut self, timestamp_unix_nanos: u64) {
        let bucket_start = timestamp_unix_nanos / self.bucket_width_nanos * self.bucket_width_nanos;
        if self
            .latest_bucket_start
            .is_none_or(|latest| bucket_start > latest)
        {
            self.latest_bucket_start = Some(bucket_start);
            self.normalize();
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> TrafficCurveSnapshot {
        TrafficCurveSnapshot {
            bucket_width_nanos: self.bucket_width_nanos,
            maximum_buckets: self.maximum_buckets,
            events_received: self.events_received,
            events_accepted: self.events_accepted,
            events_late_dropped: self.events_late_dropped,
            bytes_received: self.bytes_received,
            bytes_accepted: self.bytes_accepted,
            bytes_late_dropped: self.bytes_late_dropped,
            buckets: self.buckets.values().copied().collect(),
        }
    }

    fn earliest_retained(&self) -> u64 {
        let span = u64::try_from(self.maximum_buckets.saturating_sub(1))
            .unwrap_or(u64::MAX)
            .saturating_mul(self.bucket_width_nanos);
        self.latest_bucket_start.unwrap_or(0).saturating_sub(span)
    }

    fn normalize(&mut self) {
        let earliest = self.earliest_retained();
        let removed_history = self
            .buckets
            .first_key_value()
            .is_some_and(|(start, _)| *start < earliest);
        self.buckets.retain(|start, _| *start >= earliest);
        let Some(latest) = self.latest_bucket_start else {
            return;
        };
        let first = if removed_history {
            earliest
        } else {
            self.buckets
                .first_key_value()
                .map_or(latest, |(start, _)| *start)
                .max(earliest)
        };
        let mut start = first;
        loop {
            self.buckets.entry(start).or_insert(TrafficBucket {
                start_unix_nanos: start,
                send_bytes: 0,
                receive_bytes: 0,
            });
            if start >= latest {
                break;
            }
            start = start.saturating_add(self.bucket_width_nanos);
        }
    }
}

/// Single-threaded deterministic flow aggregator.
#[derive(Debug, Default)]
pub struct TrafficAggregator {
    flows: BTreeMap<FlowKey, FlowSnapshot>,
}

impl TrafficAggregator {
    pub fn record(&mut self, event: &NetworkEvent) {
        let key = FlowKey::from(event);
        let aggregate = self.flows.entry(key.clone()).or_insert(FlowSnapshot {
            key,
            process_key: None,
            events: 0,
            bytes: 0,
            first_timestamp_unix_nanos: event.timestamp_unix_nanos,
            last_timestamp_unix_nanos: event.timestamp_unix_nanos,
        });
        aggregate.events = aggregate.events.saturating_add(1);
        aggregate.bytes = aggregate.bytes.saturating_add(event.bytes);
        aggregate.first_timestamp_unix_nanos = aggregate
            .first_timestamp_unix_nanos
            .min(event.timestamp_unix_nanos);
        aggregate.last_timestamp_unix_nanos = aggregate
            .last_timestamp_unix_nanos
            .max(event.timestamp_unix_nanos);
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<FlowSnapshot> {
        self.flows.values().cloned().collect()
    }

    /// Removes flows whose last event predates the supplied Unix timestamp.
    pub fn retain_since(&mut self, minimum_timestamp_unix_nanos: u64) {
        self.flows
            .retain(|_, flow| flow.last_timestamp_unix_nanos >= minimum_timestamp_unix_nanos);
    }

    /// Retains at most `maximum` flows, removing the oldest last-seen entries first.
    pub fn trim_to_maximum(&mut self, maximum: usize) {
        if self.flows.len() <= maximum {
            return;
        }
        let mut oldest = self
            .flows
            .iter()
            .map(|(key, flow)| (flow.last_timestamp_unix_nanos, key.clone()))
            .collect::<Vec<_>>();
        oldest.sort_unstable();
        for (_, key) in oldest.into_iter().take(self.flows.len() - maximum) {
            self.flows.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::{
        ConnectionSnapshot, CurveRecordOutcome, NetworkEvent, PROJECT_NAME, ProcessIconState,
        ProcessKey, ProcessSnapshot, ProcessTrafficTracker, TcpConnectionState, TrafficAggregator,
        TrafficCurve, TrafficDirection, TransportProtocol,
    };

    #[test]
    fn project_name_is_stable() {
        assert_eq!(PROJECT_NAME, "ProcNet Recorder");
    }

    #[test]
    fn aggregator_groups_by_pid_direction_and_endpoints() {
        let mut aggregator = TrafficAggregator::default();
        let event = NetworkEvent {
            timestamp_unix_nanos: 10,
            pid: 42,
            protocol: TransportProtocol::Tcp,
            direction: TrafficDirection::Send,
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000),
            destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 39_001),
            bytes: 100,
        };
        aggregator.record(&event);
        aggregator.record(&NetworkEvent {
            timestamp_unix_nanos: 20,
            bytes: 200,
            ..event
        });

        let snapshot = aggregator.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].events, 2);
        assert_eq!(snapshot[0].bytes, 300);
        assert_eq!(snapshot[0].first_timestamp_unix_nanos, 10);
        assert_eq!(snapshot[0].last_timestamp_unix_nanos, 20);
    }

    #[test]
    fn aggregator_expires_and_caps_flows_deterministically() {
        let mut aggregator = TrafficAggregator::default();
        for (pid, timestamp) in [(1, 10), (2, 20), (3, 30)] {
            aggregator.record(&NetworkEvent {
                timestamp_unix_nanos: timestamp,
                pid,
                protocol: TransportProtocol::Tcp,
                direction: TrafficDirection::Send,
                source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000),
                destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 39_001),
                bytes: 1,
            });
        }
        aggregator.retain_since(20);
        aggregator.trim_to_maximum(1);
        let flows = aggregator.snapshot();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].key.pid, 3);
    }

    #[test]
    fn process_key_prevents_pid_reuse_from_matching_connections() {
        let old = ProcessKey {
            pid: 42,
            started_at_unix_nanos: 100,
        };
        let replacement = ProcessKey {
            pid: 42,
            started_at_unix_nanos: 200,
        };
        assert_ne!(old, replacement);

        let process = ProcessSnapshot {
            key: replacement,
            name: "replacement.exe".to_owned(),
            image_path: None,
            icon: ProcessIconState::NotLoaded,
        };
        let connection = ConnectionSnapshot {
            protocol: TransportProtocol::Tcp,
            local: "127.0.0.1:39001".parse().unwrap(),
            remote: None,
            tcp_state: Some(TcpConnectionState::Listen),
            pid: 42,
            process_key: Some(old),
            owner_name: Some("replacement.exe".to_owned()),
        };
        assert_ne!(connection.process_key, Some(process.key));
    }

    #[test]
    fn traffic_curve_fills_gaps_caps_history_and_accounts_late_events() {
        let mut curve = TrafficCurve::new(10, 3).unwrap();
        let mut item = NetworkEvent {
            timestamp_unix_nanos: 10,
            pid: 1,
            protocol: TransportProtocol::Tcp,
            direction: TrafficDirection::Send,
            source: "127.0.0.1:1".parse().unwrap(),
            destination: "127.0.0.1:2".parse().unwrap(),
            bytes: 100,
        };
        assert_eq!(curve.record(&item), CurveRecordOutcome::Accepted);
        item.timestamp_unix_nanos = 30;
        item.direction = TrafficDirection::Receive;
        item.bytes = 300;
        assert_eq!(curve.record(&item), CurveRecordOutcome::Accepted);
        let filled = curve.snapshot();
        assert_eq!(filled.buckets.len(), 3);
        assert_eq!(filled.buckets[1].start_unix_nanos, 20);
        assert_eq!(filled.buckets[1].send_bytes, 0);
        assert_eq!(filled.buckets[1].receive_bytes, 0);

        item.timestamp_unix_nanos = 0;
        item.bytes = 7;
        assert_eq!(curve.record(&item), CurveRecordOutcome::LateDropped);
        item.timestamp_unix_nanos = 50;
        item.bytes = 500;
        assert_eq!(curve.record(&item), CurveRecordOutcome::Accepted);
        let bounded = curve.snapshot();
        assert_eq!(
            bounded
                .buckets
                .iter()
                .map(|bucket| bucket.start_unix_nanos)
                .collect::<Vec<_>>(),
            vec![30, 40, 50]
        );
        assert_eq!(bounded.events_received, 4);
        assert_eq!(bounded.events_accepted, 3);
        assert_eq!(bounded.events_late_dropped, 1);
        assert_eq!(bounded.bytes_received, 907);
        assert_eq!(bounded.bytes_accepted, 900);
        assert_eq!(bounded.bytes_late_dropped, 7);

        curve.advance_to(70);
        let advanced = curve.snapshot();
        assert_eq!(
            advanced
                .buckets
                .iter()
                .map(|bucket| bucket.start_unix_nanos)
                .collect::<Vec<_>>(),
            vec![50, 60, 70]
        );
        assert_eq!(advanced.buckets[2].send_bytes, 0);
        assert_eq!(advanced.buckets[2].receive_bytes, 0);
        assert_eq!(advanced.events_received, bounded.events_received);
        assert_eq!(advanced.bytes_received, bounded.bytes_received);
    }

    #[test]
    fn process_rates_are_fixed_width_and_become_zero_in_the_next_bucket() {
        let mut tracker = ProcessTrafficTracker::new(1_000_000_000).unwrap();
        let mut item = NetworkEvent {
            timestamp_unix_nanos: 2_100_000_000,
            pid: 7,
            protocol: TransportProtocol::Tcp,
            direction: TrafficDirection::Send,
            source: "127.0.0.1:1".parse().unwrap(),
            destination: "127.0.0.1:2".parse().unwrap(),
            bytes: 250,
        };
        tracker.record(&item);
        item.direction = TrafficDirection::Receive;
        item.bytes = 125;
        tracker.record(&item);

        let active = tracker.snapshot_at(2_500_000_000);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].send_bytes_per_second, 250);
        assert_eq!(active[0].receive_bytes_per_second, 125);
        assert_eq!(active[0].send_bytes_total, 250);
        assert_eq!(active[0].receive_bytes_total, 125);

        let idle = tracker.snapshot_at(4_000_000_000);
        assert_eq!(idle[0].send_bytes_per_second, 0);
        assert_eq!(idle[0].receive_bytes_per_second, 0);
        assert_eq!(idle[0].send_bytes_total, 250);
    }
}
