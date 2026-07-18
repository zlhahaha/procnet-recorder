//! Bounded, platform-independent V1 application runtime.

#![forbid(unsafe_code)]

mod export;
mod session;

pub use export::{render_snapshot_csv, render_snapshot_json};
pub use procnet_core::{ExportFormat, SessionDetail, SessionRepository};
pub use session::{LiveRiskEvent, RecordingController, SessionUiState, V2Settings};

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use procnet_core::{
    ConnectionSnapshot, FlowSnapshot, NetworkEvent, ProcessKey, ProcessTrafficCounters,
    ProcessTrafficTracker, SystemSnapshot, TrafficAggregator, TrafficCurve, TrafficCurveSnapshot,
};

enum Message {
    Event(NetworkEvent),
    Stop,
}

/// Explicit bounded-runtime policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub queue_capacity: usize,
    pub snapshot_interval: Duration,
    pub flow_idle_timeout: Duration,
    pub maximum_flows: usize,
    pub curve_bucket_width: Duration,
    pub curve_maximum_buckets: usize,
}

impl RuntimeConfig {
    #[must_use]
    pub const fn bounded(queue_capacity: usize) -> Self {
        Self {
            queue_capacity,
            snapshot_interval: Duration::from_millis(100),
            flow_idle_timeout: Duration::from_secs(300),
            maximum_flows: 100_000,
            curve_bucket_width: Duration::from_secs(1),
            curve_maximum_buckets: 300,
        }
    }
}

#[derive(Debug)]
struct RuntimeCounters {
    received: AtomicU64,
    accepted: AtomicU64,
    dropped_full: AtomicU64,
    dropped_stopped: AtomicU64,
    processed: AtomicU64,
    queue_depth: AtomicUsize,
    queue_peak: AtomicUsize,
    submissions_in_flight: AtomicUsize,
    queue_capacity: usize,
    snapshot_interval: Duration,
    flow_idle_timeout: Duration,
    maximum_flows: usize,
}

impl RuntimeCounters {
    fn new(config: RuntimeConfig) -> Self {
        Self {
            received: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            dropped_full: AtomicU64::new(0),
            dropped_stopped: AtomicU64::new(0),
            processed: AtomicU64::new(0),
            queue_depth: AtomicUsize::new(0),
            queue_peak: AtomicUsize::new(0),
            submissions_in_flight: AtomicUsize::new(0),
            queue_capacity: config.queue_capacity,
            snapshot_interval: config.snapshot_interval,
            flow_idle_timeout: config.flow_idle_timeout,
            maximum_flows: config.maximum_flows,
        }
    }

    fn record_depth(&self, depth: usize) {
        self.queue_peak.fetch_max(depth, Ordering::Relaxed);
    }
}

/// Result of a non-blocking collector submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitOutcome {
    Accepted,
    DroppedFull,
    Stopped,
}

/// Read-only network capture availability exposed to future UI consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureStatus {
    Available,
    Restricted(CaptureRestriction),
}

/// Stable reason why the application is running without network capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureRestriction {
    PermissionRequired,
    SessionAlreadyExists,
}

/// Cloneable non-blocking ingress used by collection callbacks.
#[derive(Clone)]
pub struct EventIngress {
    sender: SyncSender<Message>,
    counters: Arc<RuntimeCounters>,
    accepting: Arc<AtomicBool>,
}

impl EventIngress {
    /// Attempts to transfer ownership without blocking the collection callback.
    #[must_use]
    pub fn try_submit(&self, event: NetworkEvent) -> SubmitOutcome {
        self.counters.received.fetch_add(1, Ordering::Relaxed);
        if !self.accepting.load(Ordering::Acquire) {
            self.counters
                .dropped_stopped
                .fetch_add(1, Ordering::Relaxed);
            return SubmitOutcome::Stopped;
        }

        self.counters
            .submissions_in_flight
            .fetch_add(1, Ordering::AcqRel);
        if !self.accepting.load(Ordering::Acquire) {
            self.counters
                .submissions_in_flight
                .fetch_sub(1, Ordering::AcqRel);
            self.counters
                .dropped_stopped
                .fetch_add(1, Ordering::Relaxed);
            return SubmitOutcome::Stopped;
        }

        let reserved_depth = self.counters.queue_depth.fetch_add(1, Ordering::Relaxed) + 1;
        let outcome = match self.sender.try_send(Message::Event(event)) {
            Ok(()) => {
                self.counters.accepted.fetch_add(1, Ordering::Relaxed);
                self.counters
                    .record_depth(reserved_depth.min(self.counters.queue_capacity));
                SubmitOutcome::Accepted
            }
            Err(TrySendError::Full(_)) => {
                self.counters.queue_depth.fetch_sub(1, Ordering::Relaxed);
                self.counters.dropped_full.fetch_add(1, Ordering::Relaxed);
                SubmitOutcome::DroppedFull
            }
            Err(TrySendError::Disconnected(_)) => {
                self.counters.queue_depth.fetch_sub(1, Ordering::Relaxed);
                self.counters
                    .dropped_stopped
                    .fetch_add(1, Ordering::Relaxed);
                SubmitOutcome::Stopped
            }
        };
        self.counters
            .submissions_in_flight
            .fetch_sub(1, Ordering::Release);
        outcome
    }
}

/// Immutable view consumed by CLI or future GUI code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationSnapshot {
    pub running: bool,
    pub capture_status: CaptureStatus,
    pub events_received: u64,
    pub events_accepted: u64,
    pub events_dropped_full: u64,
    pub events_dropped_stopped: u64,
    pub events_processed: u64,
    pub queue_capacity: usize,
    pub queue_depth: usize,
    pub queue_peak: usize,
    pub snapshot_interval_millis: u128,
    pub flow_idle_timeout_millis: u128,
    pub maximum_flows: usize,
    pub flows: Vec<FlowSnapshot>,
    pub curve: TrafficCurveSnapshot,
    pub recent_60_seconds: TrafficCurveSnapshot,
    pub network_rate: NetworkRateSnapshot,
    pub process_traffic: Vec<ProcessTrafficSnapshot>,
    pub connection_details: Vec<ConnectionDetailSnapshot>,
    pub system: Option<SystemSnapshot>,
}

/// Total upload/download rate derived from the same fixed-width ETW event buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkRateSnapshot {
    pub sampled_at_unix_nanos: u64,
    pub interval_nanos: u64,
    pub send_bytes_per_second: u64,
    pub receive_bytes_per_second: u64,
}

/// Process metadata joined with cumulative traffic, current rate, and connection count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessTrafficSnapshot {
    pub pid: u32,
    pub process_key: Option<ProcessKey>,
    pub name: Option<String>,
    pub image_path: Option<String>,
    pub icon: procnet_core::ProcessIconState,
    pub send_bytes_total: u64,
    pub receive_bytes_total: u64,
    pub send_bytes_per_second: u64,
    pub receive_bytes_per_second: u64,
    pub connection_count: usize,
    pub last_timestamp_unix_nanos: u64,
}

/// Connection row enriched with process metadata for detail views and exports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionDetailSnapshot {
    pub connection: ConnectionSnapshot,
    pub process_name: Option<String>,
    pub process_image_path: Option<String>,
    pub owner_status: ConnectionOwnerStatus,
}

/// Explains why a connection can or cannot be joined to a stable process identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionOwnerStatus {
    Matched,
    NameOnly,
    ProcessExited,
}

/// Application runtime lifecycle failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeError(String);

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RuntimeError {}

/// Owns the single aggregation worker and deterministic stop path.
pub struct ApplicationRuntime {
    ingress: EventIngress,
    flows: Arc<RwLock<Vec<FlowSnapshot>>>,
    running: Arc<AtomicBool>,
    capture_status: Arc<RwLock<CaptureStatus>>,
    system_snapshot: Arc<RwLock<Option<SystemSnapshot>>>,
    curve: Arc<RwLock<TrafficCurveSnapshot>>,
    process_counters: Arc<RwLock<Vec<ProcessTrafficCounters>>>,
    worker: Option<JoinHandle<()>>,
}

/// Cloneable read-only handle for periodic diagnostics and future UI consumers.
#[derive(Clone)]
pub struct SnapshotReader {
    counters: Arc<RuntimeCounters>,
    flows: Arc<RwLock<Vec<FlowSnapshot>>>,
    running: Arc<AtomicBool>,
    capture_status: Arc<RwLock<CaptureStatus>>,
    system_snapshot: Arc<RwLock<Option<SystemSnapshot>>>,
    curve: Arc<RwLock<TrafficCurveSnapshot>>,
    process_counters: Arc<RwLock<Vec<ProcessTrafficCounters>>>,
}

/// Cloneable publisher used by platform refresh workers without exposing runtime internals.
#[derive(Clone)]
pub struct SystemSnapshotPublisher {
    snapshot: Arc<RwLock<Option<SystemSnapshot>>>,
}

impl SystemSnapshotPublisher {
    /// Replaces the current owned process and connection view.
    ///
    /// # Errors
    ///
    /// Returns an error if the system snapshot lock was poisoned.
    pub fn publish(&self, snapshot: SystemSnapshot) -> Result<(), RuntimeError> {
        *self
            .snapshot
            .write()
            .map_err(|_| RuntimeError("system snapshot lock was poisoned".to_owned()))? =
            Some(snapshot);
        Ok(())
    }

    /// Merges icon results only into matching process identities in the latest snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error if the system snapshot lock was poisoned.
    pub fn merge_process_icons(&self, enriched: &SystemSnapshot) -> Result<(), RuntimeError> {
        let mut current = self
            .snapshot
            .write()
            .map_err(|_| RuntimeError("system snapshot lock was poisoned".to_owned()))?;
        let Some(current) = current.as_mut() else {
            return Ok(());
        };
        let icons = enriched
            .processes
            .iter()
            .map(|process| (process.key, (&process.image_path, &process.icon)))
            .collect::<BTreeMap<_, _>>();
        for process in &mut current.processes {
            if let Some((image_path, icon)) = icons.get(&process.key)
                && process.image_path == **image_path
                && !matches!(icon, procnet_core::ProcessIconState::NotLoaded)
            {
                process.icon = (*icon).clone();
            }
        }
        Ok(())
    }
}

struct WorkerShared {
    counters: Arc<RuntimeCounters>,
    flows: Arc<RwLock<Vec<FlowSnapshot>>>,
    running: Arc<AtomicBool>,
    curve: Arc<RwLock<TrafficCurveSnapshot>>,
    process_counters: Arc<RwLock<Vec<ProcessTrafficCounters>>>,
}

impl SnapshotReader {
    /// Returns the latest published immutable view.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal snapshot lock was poisoned by a worker panic.
    pub fn snapshot(&self) -> Result<ApplicationSnapshot, RuntimeError> {
        snapshot(
            &self.counters,
            &self.flows,
            &self.capture_status,
            &self.system_snapshot,
            &self.curve,
            &self.process_counters,
            self.running.load(Ordering::Acquire),
        )
    }
}

impl ApplicationRuntime {
    /// Starts one aggregation worker behind a fixed-capacity channel.
    ///
    /// # Errors
    ///
    /// Returns an error for zero capacity or if the aggregation thread cannot be created.
    pub fn start(queue_capacity: usize) -> Result<Self, RuntimeError> {
        Self::start_with_config(RuntimeConfig::bounded(queue_capacity))
    }

    /// Starts the worker with explicit queue, publication, expiry and flow-count bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when any bound is zero or the aggregation thread cannot be created.
    pub fn start_with_config(config: RuntimeConfig) -> Result<Self, RuntimeError> {
        validate_config(config)?;
        let (ingress, receiver) = new_ingress(config);
        let flows = Arc::new(RwLock::new(Vec::new()));
        let running = Arc::new(AtomicBool::new(true));
        let capture_status = Arc::new(RwLock::new(CaptureStatus::Available));
        let system_snapshot = Arc::new(RwLock::new(None));
        let curve_aggregator = TrafficCurve::new(
            duration_nanos(config.curve_bucket_width),
            config.curve_maximum_buckets,
        )
        .ok_or_else(|| RuntimeError("curve bounds must be nonzero".to_owned()))?;
        let initial_curve = curve_aggregator.snapshot();
        let curve = Arc::new(RwLock::new(initial_curve));
        let process_tracker = ProcessTrafficTracker::new(duration_nanos(config.curve_bucket_width))
            .ok_or_else(|| RuntimeError("process rate bucket width must be nonzero".to_owned()))?;
        let process_counters = Arc::new(RwLock::new(Vec::new()));
        let worker = spawn_worker(
            receiver,
            WorkerShared {
                counters: Arc::clone(&ingress.counters),
                flows: Arc::clone(&flows),
                running: Arc::clone(&running),
                curve: Arc::clone(&curve),
                process_counters: Arc::clone(&process_counters),
            },
            curve_aggregator,
            process_tracker,
            config,
        )?;
        Ok(Self {
            ingress,
            flows,
            running,
            capture_status,
            system_snapshot,
            curve,
            process_counters,
            worker: Some(worker),
        })
    }

    #[must_use]
    pub fn ingress(&self) -> EventIngress {
        self.ingress.clone()
    }

    #[must_use]
    pub fn snapshot_reader(&self) -> SnapshotReader {
        SnapshotReader {
            counters: Arc::clone(&self.ingress.counters),
            flows: Arc::clone(&self.flows),
            running: Arc::clone(&self.running),
            capture_status: Arc::clone(&self.capture_status),
            system_snapshot: Arc::clone(&self.system_snapshot),
            curve: Arc::clone(&self.curve),
            process_counters: Arc::clone(&self.process_counters),
        }
    }

    #[must_use]
    pub fn system_snapshot_publisher(&self) -> SystemSnapshotPublisher {
        SystemSnapshotPublisher {
            snapshot: Arc::clone(&self.system_snapshot),
        }
    }

    /// Changes the capture availability visible in subsequent read-only snapshots.
    ///
    /// # Errors
    ///
    /// Returns an error if the capture-status lock was poisoned.
    pub fn set_capture_status(&self, status: CaptureStatus) -> Result<(), RuntimeError> {
        *self
            .capture_status
            .write()
            .map_err(|_| RuntimeError("capture status lock was poisoned".to_owned()))? = status;
        Ok(())
    }

    /// Publishes an owned point-in-time process and connection view for read-only consumers.
    ///
    /// # Errors
    ///
    /// Returns an error if the system-snapshot lock was poisoned.
    pub fn publish_system_snapshot(&self, snapshot: SystemSnapshot) -> Result<(), RuntimeError> {
        self.system_snapshot_publisher().publish(snapshot)
    }

    /// Returns a cloned read-only view without exposing mutable runtime state.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal snapshot lock was poisoned by a worker panic.
    pub fn snapshot(&self) -> Result<ApplicationSnapshot, RuntimeError> {
        snapshot(
            &self.ingress.counters,
            &self.flows,
            &self.capture_status,
            &self.system_snapshot,
            &self.curve,
            &self.process_counters,
            self.running.load(Ordering::Acquire),
        )
    }

    /// Stops acceptance, drains all events queued before the stop marker, and joins the worker.
    ///
    /// # Errors
    ///
    /// Returns an error if the worker stopped prematurely, panicked, or poisoned the snapshot.
    pub fn stop(mut self) -> Result<ApplicationSnapshot, RuntimeError> {
        self.stop_inner()?;
        self.snapshot()
    }

    fn stop_inner(&mut self) -> Result<(), RuntimeError> {
        if self.worker.is_none() {
            return Ok(());
        }
        self.ingress.accepting.store(false, Ordering::Release);
        while self
            .ingress
            .counters
            .submissions_in_flight
            .load(Ordering::Acquire)
            != 0
        {
            thread::yield_now();
        }
        self.ingress
            .sender
            .send(Message::Stop)
            .map_err(|_| RuntimeError("aggregation worker stopped before shutdown".to_owned()))?;
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| RuntimeError("aggregation worker panicked".to_owned()))?;
        }
        Ok(())
    }
}

impl Drop for ApplicationRuntime {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

fn validate_config(config: RuntimeConfig) -> Result<(), RuntimeError> {
    if config.queue_capacity == 0
        || config.snapshot_interval.is_zero()
        || config.flow_idle_timeout.is_zero()
        || config.maximum_flows == 0
        || config.curve_bucket_width.is_zero()
        || config.curve_maximum_buckets == 0
    {
        return Err(RuntimeError(
            "runtime queue, snapshot interval, flow idle timeout and maximum flows must be nonzero"
                .to_owned(),
        ));
    }
    Ok(())
}

fn new_ingress(config: RuntimeConfig) -> (EventIngress, Receiver<Message>) {
    let (sender, receiver) = mpsc::sync_channel(config.queue_capacity);
    (
        EventIngress {
            sender,
            counters: Arc::new(RuntimeCounters::new(config)),
            accepting: Arc::new(AtomicBool::new(true)),
        },
        receiver,
    )
}

fn spawn_worker(
    receiver: Receiver<Message>,
    shared: WorkerShared,
    mut curve: TrafficCurve,
    mut process_tracker: ProcessTrafficTracker,
    config: RuntimeConfig,
) -> Result<JoinHandle<()>, RuntimeError> {
    thread::Builder::new()
        .name("procnet-aggregate".to_owned())
        .spawn(move || {
            let mut aggregator = TrafficAggregator::default();
            let mut curve_clock = None;
            let mut next_publication = Instant::now() + config.snapshot_interval;
            loop {
                let timeout = next_publication.saturating_duration_since(Instant::now());
                match receiver.recv_timeout(timeout) {
                    Ok(Message::Event(event)) => {
                        shared.counters.queue_depth.fetch_sub(1, Ordering::Relaxed);
                        if curve_clock
                            .is_none_or(|(timestamp, _)| event.timestamp_unix_nanos >= timestamp)
                        {
                            curve_clock = Some((event.timestamp_unix_nanos, Instant::now()));
                        }
                        aggregator.record(&event);
                        let _ = curve.record(&event);
                        process_tracker.record(&event);
                        shared.counters.processed.fetch_add(1, Ordering::Relaxed);
                        if Instant::now() >= next_publication {
                            advance_curve_clock(&mut curve, curve_clock);
                            publish_snapshot(
                                &mut aggregator,
                                &shared.flows,
                                &mut curve,
                                &shared.curve,
                                &mut process_tracker,
                                &shared.process_counters,
                                config,
                            );
                            next_publication = Instant::now() + config.snapshot_interval;
                        }
                    }
                    Ok(Message::Stop) | Err(RecvTimeoutError::Disconnected) => {
                        advance_curve_clock(&mut curve, curve_clock);
                        publish_snapshot(
                            &mut aggregator,
                            &shared.flows,
                            &mut curve,
                            &shared.curve,
                            &mut process_tracker,
                            &shared.process_counters,
                            config,
                        );
                        break;
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        advance_curve_clock(&mut curve, curve_clock);
                        publish_snapshot(
                            &mut aggregator,
                            &shared.flows,
                            &mut curve,
                            &shared.curve,
                            &mut process_tracker,
                            &shared.process_counters,
                            config,
                        );
                        next_publication = Instant::now() + config.snapshot_interval;
                    }
                }
            }
            shared.running.store(false, Ordering::Release);
        })
        .map_err(|error| RuntimeError(format!("cannot start aggregation worker: {error}")))
}

fn publish_snapshot(
    aggregator: &mut TrafficAggregator,
    flows: &RwLock<Vec<FlowSnapshot>>,
    curve: &mut TrafficCurve,
    curve_snapshot: &RwLock<TrafficCurveSnapshot>,
    process_tracker: &mut ProcessTrafficTracker,
    process_counters: &RwLock<Vec<ProcessTrafficCounters>>,
    config: RuntimeConfig,
) {
    let idle_nanos = u64::try_from(config.flow_idle_timeout.as_nanos()).unwrap_or(u64::MAX);
    aggregator.retain_since(current_unix_nanos().saturating_sub(idle_nanos));
    aggregator.trim_to_maximum(config.maximum_flows);
    process_tracker.retain_since(current_unix_nanos().saturating_sub(idle_nanos));
    process_tracker.trim_to_maximum(config.maximum_flows);
    if let Ok(mut snapshot) = flows.write() {
        *snapshot = aggregator.snapshot();
    }
    if let Ok(mut snapshot) = curve_snapshot.write() {
        *snapshot = curve.snapshot();
    }
    if let Ok(mut snapshot) = process_counters.write() {
        *snapshot = process_tracker.snapshot_at(current_unix_nanos());
    }
}

fn advance_curve_clock(curve: &mut TrafficCurve, clock: Option<(u64, Instant)>) {
    let timestamp = clock.map_or_else(current_unix_nanos, |(timestamp, observed_at)| {
        timestamp.saturating_add(duration_nanos(observed_at.elapsed()))
    });
    curve.advance_to(timestamp);
}

fn current_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        })
}

fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn snapshot(
    counters: &RuntimeCounters,
    flows: &RwLock<Vec<FlowSnapshot>>,
    capture_status: &RwLock<CaptureStatus>,
    system_snapshot: &RwLock<Option<SystemSnapshot>>,
    curve: &RwLock<TrafficCurveSnapshot>,
    process_counters: &RwLock<Vec<ProcessTrafficCounters>>,
    running: bool,
) -> Result<ApplicationSnapshot, RuntimeError> {
    let mut flows = flows
        .read()
        .map_err(|_| RuntimeError("application snapshot lock was poisoned".to_owned()))?
        .clone();
    let capture_status = *capture_status
        .read()
        .map_err(|_| RuntimeError("capture status lock was poisoned".to_owned()))?;
    let system = system_snapshot
        .read()
        .map_err(|_| RuntimeError("system snapshot lock was poisoned".to_owned()))?
        .clone();
    let curve = curve
        .read()
        .map_err(|_| RuntimeError("traffic curve lock was poisoned".to_owned()))?
        .clone();
    let process_counters = process_counters
        .read()
        .map_err(|_| RuntimeError("process traffic lock was poisoned".to_owned()))?
        .clone();
    if let Some(system) = &system {
        let keys = system
            .processes
            .iter()
            .map(|process| (process.key.pid, process.key))
            .collect::<BTreeMap<_, _>>();
        for flow in &mut flows {
            flow.process_key = keys.get(&flow.key.pid).copied().filter(|key| {
                key.started_at_unix_nanos <= flow.first_timestamp_unix_nanos
                    && system.captured_at_unix_nanos >= flow.last_timestamp_unix_nanos
            });
        }
    }
    let sampled_at_unix_nanos = current_unix_nanos();
    let mut process_traffic = derive_process_traffic(&process_counters, system.as_ref());
    process_traffic.sort_by(|left, right| {
        let left_rate = left
            .send_bytes_per_second
            .saturating_add(left.receive_bytes_per_second);
        let right_rate = right
            .send_bytes_per_second
            .saturating_add(right.receive_bytes_per_second);
        let left_total = left
            .send_bytes_total
            .saturating_add(left.receive_bytes_total);
        let right_total = right
            .send_bytes_total
            .saturating_add(right.receive_bytes_total);
        right_rate
            .cmp(&left_rate)
            .then_with(|| right_total.cmp(&left_total))
            .then_with(|| left.pid.cmp(&right.pid))
    });
    let network_rate = NetworkRateSnapshot {
        sampled_at_unix_nanos,
        interval_nanos: curve.bucket_width_nanos,
        send_bytes_per_second: process_traffic
            .iter()
            .map(|process| process.send_bytes_per_second)
            .fold(0_u64, u64::saturating_add),
        receive_bytes_per_second: process_traffic
            .iter()
            .map(|process| process.receive_bytes_per_second)
            .fold(0_u64, u64::saturating_add),
    };
    let recent_60_seconds = recent_curve(&curve, Duration::from_secs(60));
    let connection_details = derive_connection_details(system.as_ref());
    Ok(ApplicationSnapshot {
        running,
        capture_status,
        events_received: counters.received.load(Ordering::Relaxed),
        events_accepted: counters.accepted.load(Ordering::Relaxed),
        events_dropped_full: counters.dropped_full.load(Ordering::Relaxed),
        events_dropped_stopped: counters.dropped_stopped.load(Ordering::Relaxed),
        events_processed: counters.processed.load(Ordering::Relaxed),
        queue_capacity: counters.queue_capacity,
        queue_depth: counters.queue_depth.load(Ordering::Relaxed),
        queue_peak: counters.queue_peak.load(Ordering::Relaxed),
        snapshot_interval_millis: counters.snapshot_interval.as_millis(),
        flow_idle_timeout_millis: counters.flow_idle_timeout.as_millis(),
        maximum_flows: counters.maximum_flows,
        flows,
        curve,
        recent_60_seconds,
        network_rate,
        process_traffic,
        connection_details,
        system,
    })
}

fn recent_curve(curve: &TrafficCurveSnapshot, duration: Duration) -> TrafficCurveSnapshot {
    let duration_nanos = duration_nanos(duration);
    let bucket_count_u64 = duration_nanos
        .saturating_add(curve.bucket_width_nanos.saturating_sub(1))
        / curve.bucket_width_nanos;
    let bucket_count = usize::try_from(bucket_count_u64)
        .unwrap_or(usize::MAX)
        .max(1);
    let mut recent = curve.clone();
    recent.maximum_buckets = curve.maximum_buckets.min(bucket_count);
    let skip = recent.buckets.len().saturating_sub(recent.maximum_buckets);
    recent.buckets.drain(..skip);
    recent
}

fn derive_process_traffic(
    counters: &[ProcessTrafficCounters],
    system: Option<&SystemSnapshot>,
) -> Vec<ProcessTrafficSnapshot> {
    let processes = system.map(|snapshot| {
        snapshot
            .processes
            .iter()
            .map(|process| (process.key.pid, process))
            .collect::<BTreeMap<_, _>>()
    });
    let owner_names = system.map(|snapshot| {
        snapshot
            .process_names
            .iter()
            .cloned()
            .chain(snapshot.connections.iter().filter_map(|connection| {
                connection
                    .owner_name
                    .as_ref()
                    .map(|name| (connection.pid, name.clone()))
            }))
            .collect::<BTreeMap<_, _>>()
    });
    counters
        .iter()
        .map(|counter| {
            let process_hint = processes
                .as_ref()
                .and_then(|processes| processes.get(&counter.pid).copied());
            let process = process_hint.filter(|process| {
                process.key.started_at_unix_nanos <= counter.last_timestamp_unix_nanos
                    && system.is_some_and(|snapshot| {
                        snapshot.captured_at_unix_nanos >= counter.last_timestamp_unix_nanos
                    })
            });
            let process_key = process.map(|process| process.key);
            let connection_count = system.map_or(0, |snapshot| {
                snapshot
                    .connections
                    .iter()
                    .filter(|connection| {
                        connection.pid == counter.pid
                            && process_key.is_none_or(|key| connection.process_key == Some(key))
                    })
                    .count()
            });
            ProcessTrafficSnapshot {
                pid: counter.pid,
                process_key,
                name: process_hint
                    .map(|process| process.name.clone())
                    .or_else(|| {
                        owner_names
                            .as_ref()
                            .and_then(|names| names.get(&counter.pid).cloned())
                    }),
                image_path: process_hint.and_then(|process| process.image_path.clone()),
                icon: process_hint.map_or(procnet_core::ProcessIconState::NotLoaded, |process| {
                    process.icon.clone()
                }),
                send_bytes_total: counter.send_bytes_total,
                receive_bytes_total: counter.receive_bytes_total,
                send_bytes_per_second: counter.send_bytes_per_second,
                receive_bytes_per_second: counter.receive_bytes_per_second,
                connection_count,
                last_timestamp_unix_nanos: counter.last_timestamp_unix_nanos,
            }
        })
        .collect()
}

fn derive_connection_details(system: Option<&SystemSnapshot>) -> Vec<ConnectionDetailSnapshot> {
    let Some(system) = system else {
        return Vec::new();
    };
    let processes = system
        .processes
        .iter()
        .map(|process| (process.key, process))
        .collect::<BTreeMap<_, _>>();
    system
        .connections
        .iter()
        .map(|connection| {
            let process = connection
                .process_key
                .and_then(|key| processes.get(&key).copied());
            let process_name = process
                .map(|process| process.name.clone())
                .or_else(|| connection.owner_name.clone());
            let owner_status = if process.is_some() {
                ConnectionOwnerStatus::Matched
            } else if process_name.is_some() {
                ConnectionOwnerStatus::NameOnly
            } else {
                ConnectionOwnerStatus::ProcessExited
            };
            ConnectionDetailSnapshot {
                connection: connection.clone(),
                process_name,
                process_image_path: process.and_then(|process| process.image_path.clone()),
                owner_status,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use procnet_core::{
        ConnectionSnapshot, NetworkEvent, ProcessKey, ProcessSnapshot, SystemSnapshot,
        TcpConnectionState, TrafficCurve, TrafficDirection, TransportProtocol,
    };

    use super::{
        ApplicationRuntime, CaptureRestriction, CaptureStatus, RuntimeConfig, SubmitOutcome,
        current_unix_nanos, new_ingress, recent_curve,
    };

    fn event(bytes: u64) -> NetworkEvent {
        NetworkEvent {
            timestamp_unix_nanos: current_unix_nanos().saturating_add(bytes),
            pid: 7,
            protocol: TransportProtocol::Tcp,
            direction: TrafficDirection::Send,
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000),
            destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 39_001),
            bytes,
        }
    }

    #[test]
    fn full_channel_drops_without_blocking() {
        let (ingress, _receiver) = new_ingress(RuntimeConfig::bounded(1));
        assert_eq!(ingress.try_submit(event(1)), SubmitOutcome::Accepted);
        assert_eq!(ingress.try_submit(event(2)), SubmitOutcome::DroppedFull);
    }

    #[test]
    fn stop_drains_accepted_events_and_returns_final_snapshot() {
        let runtime = ApplicationRuntime::start(4).unwrap();
        let ingress = runtime.ingress();
        assert_eq!(ingress.try_submit(event(100)), SubmitOutcome::Accepted);
        assert_eq!(ingress.try_submit(event(200)), SubmitOutcome::Accepted);

        let final_snapshot = runtime.stop().unwrap();
        assert!(!final_snapshot.running);
        assert_eq!(final_snapshot.events_received, 2);
        assert_eq!(final_snapshot.events_accepted, 2);
        assert_eq!(final_snapshot.events_processed, 2);
        assert_eq!(final_snapshot.queue_depth, 0);
        assert_eq!(final_snapshot.flows.len(), 1);
        assert_eq!(final_snapshot.flows[0].bytes, 300);
        assert_eq!(final_snapshot.curve.events_accepted, 2);
        assert_eq!(final_snapshot.curve.bytes_accepted, 300);
        assert_eq!(final_snapshot.curve.events_late_dropped, 0);
    }

    #[test]
    fn zero_capacity_is_rejected() {
        assert!(ApplicationRuntime::start(0).is_err());
    }

    #[test]
    fn concurrent_stop_processes_every_accepted_event() {
        let runtime = ApplicationRuntime::start(8).unwrap();
        let producers = (0..4)
            .map(|_| {
                let ingress = runtime.ingress();
                std::thread::spawn(move || {
                    for value in 1..=10_000 {
                        let _ = ingress.try_submit(event(value));
                    }
                })
            })
            .collect::<Vec<_>>();

        let final_snapshot = runtime.stop().unwrap();
        for producer in producers {
            producer.join().unwrap();
        }
        assert_eq!(
            final_snapshot.events_accepted,
            final_snapshot.events_processed
        );
        assert_eq!(final_snapshot.queue_depth, 0);
    }

    #[test]
    fn snapshot_publication_caps_flow_count() {
        let runtime = ApplicationRuntime::start_with_config(RuntimeConfig {
            queue_capacity: 16,
            snapshot_interval: Duration::from_millis(5),
            flow_idle_timeout: Duration::from_secs(1),
            maximum_flows: 2,
            curve_bucket_width: Duration::from_secs(1),
            curve_maximum_buckets: 10,
        })
        .unwrap();
        let ingress = runtime.ingress();
        for pid in 1..=3 {
            let mut item = event(1);
            item.pid = pid;
            assert_eq!(ingress.try_submit(item), SubmitOutcome::Accepted);
        }
        std::thread::sleep(Duration::from_millis(30));
        let bounded = runtime.snapshot().unwrap();
        assert_eq!(bounded.flows.len(), 2);
        assert_eq!(bounded.maximum_flows, 2);
        let final_snapshot = runtime.stop().unwrap();
        assert_eq!(final_snapshot.events_accepted, 3);
        assert_eq!(final_snapshot.events_processed, 3);
    }

    #[test]
    fn snapshot_publication_expires_idle_flows() {
        let runtime = ApplicationRuntime::start_with_config(RuntimeConfig {
            queue_capacity: 4,
            snapshot_interval: Duration::from_millis(2),
            flow_idle_timeout: Duration::from_millis(10),
            maximum_flows: 4,
            curve_bucket_width: Duration::from_secs(1),
            curve_maximum_buckets: 10,
        })
        .unwrap();
        assert_eq!(
            runtime.ingress().try_submit(event(1)),
            SubmitOutcome::Accepted
        );
        std::thread::sleep(Duration::from_millis(50));
        let expired = runtime.snapshot().unwrap();
        assert!(expired.flows.is_empty());
        assert_eq!(expired.events_processed, 1);
        let _ = runtime.stop().unwrap();
    }

    #[test]
    fn restricted_capture_status_keeps_runtime_alive_and_is_read_only() {
        let runtime = ApplicationRuntime::start(4).unwrap();
        runtime
            .set_capture_status(CaptureStatus::Restricted(
                CaptureRestriction::PermissionRequired,
            ))
            .unwrap();
        let snapshot = runtime.snapshot_reader().snapshot().unwrap();
        assert!(snapshot.running);
        assert_eq!(
            snapshot.capture_status,
            CaptureStatus::Restricted(CaptureRestriction::PermissionRequired)
        );
        assert_eq!(snapshot.events_received, 0);

        let stopped = runtime.stop().unwrap();
        assert!(!stopped.running);
        assert_eq!(stopped.capture_status, snapshot.capture_status);
    }

    #[test]
    fn system_snapshot_is_owned_and_visible_to_readers() {
        let runtime = ApplicationRuntime::start(4).unwrap();
        runtime
            .publish_system_snapshot(SystemSnapshot {
                captured_at_unix_nanos: 123,
                process_names: Vec::new(),
                processes: Vec::new(),
                connections: Vec::new(),
            })
            .unwrap();
        let reader = runtime.snapshot_reader();
        let published = reader.snapshot().unwrap().system.unwrap();
        assert_eq!(published.captured_at_unix_nanos, 123);

        runtime
            .publish_system_snapshot(SystemSnapshot {
                captured_at_unix_nanos: 456,
                process_names: Vec::new(),
                processes: Vec::new(),
                connections: Vec::new(),
            })
            .unwrap();
        assert_eq!(published.captured_at_unix_nanos, 123);
        assert_eq!(
            reader
                .snapshot()
                .unwrap()
                .system
                .unwrap()
                .captured_at_unix_nanos,
            456
        );
        let _ = runtime.stop().unwrap();
    }

    #[test]
    fn flow_attribution_rejects_a_reused_pid() {
        let runtime = ApplicationRuntime::start_with_config(RuntimeConfig {
            queue_capacity: 4,
            snapshot_interval: Duration::from_millis(2),
            flow_idle_timeout: Duration::from_secs(1),
            maximum_flows: 4,
            curve_bucket_width: Duration::from_secs(1),
            curve_maximum_buckets: 10,
        })
        .unwrap();
        let item = event(10);
        assert_eq!(
            runtime.ingress().try_submit(item.clone()),
            SubmitOutcome::Accepted
        );
        std::thread::sleep(Duration::from_millis(20));
        let original = ProcessKey {
            pid: item.pid,
            started_at_unix_nanos: item.timestamp_unix_nanos - 1,
        };
        runtime
            .publish_system_snapshot(SystemSnapshot {
                captured_at_unix_nanos: item.timestamp_unix_nanos + 1,
                process_names: vec![(item.pid, "original.exe".to_owned())],
                processes: vec![ProcessSnapshot {
                    key: original,
                    name: "original.exe".to_owned(),
                    image_path: None,
                    icon: procnet_core::ProcessIconState::NotLoaded,
                }],
                connections: Vec::new(),
            })
            .unwrap();
        assert_eq!(
            runtime.snapshot().unwrap().flows[0].process_key,
            Some(original)
        );

        runtime
            .publish_system_snapshot(SystemSnapshot {
                captured_at_unix_nanos: item.timestamp_unix_nanos + 20,
                process_names: vec![(item.pid, "replacement.exe".to_owned())],
                processes: vec![ProcessSnapshot {
                    key: ProcessKey {
                        pid: item.pid,
                        started_at_unix_nanos: item.timestamp_unix_nanos + 10,
                    },
                    name: "replacement.exe".to_owned(),
                    image_path: None,
                    icon: procnet_core::ProcessIconState::NotLoaded,
                }],
                connections: Vec::new(),
            })
            .unwrap();
        assert_eq!(runtime.snapshot().unwrap().flows[0].process_key, None);
        let _ = runtime.stop().unwrap();
    }

    #[test]
    fn runtime_curve_preserves_accepted_and_late_byte_conservation() {
        let runtime = ApplicationRuntime::start_with_config(RuntimeConfig {
            queue_capacity: 8,
            snapshot_interval: Duration::from_millis(2),
            flow_idle_timeout: Duration::from_secs(1),
            maximum_flows: 4,
            curve_bucket_width: Duration::from_nanos(10),
            curve_maximum_buckets: 3,
        })
        .unwrap();
        let ingress = runtime.ingress();
        let mut item = event(100);
        item.timestamp_unix_nanos = 10;
        assert_eq!(ingress.try_submit(item.clone()), SubmitOutcome::Accepted);
        item.timestamp_unix_nanos = 50;
        item.bytes = 500;
        assert_eq!(ingress.try_submit(item.clone()), SubmitOutcome::Accepted);
        item.timestamp_unix_nanos = 0;
        item.bytes = 7;
        assert_eq!(ingress.try_submit(item), SubmitOutcome::Accepted);
        let stopped = runtime.stop().unwrap();
        assert_eq!(stopped.events_accepted, 3);
        assert_eq!(stopped.events_processed, 3);
        assert_eq!(stopped.curve.events_received, 3);
        assert_eq!(stopped.curve.events_accepted, 2);
        assert_eq!(stopped.curve.events_late_dropped, 1);
        assert_eq!(stopped.curve.bytes_received, 607);
        assert_eq!(stopped.curve.bytes_accepted, 600);
        assert_eq!(stopped.curve.bytes_late_dropped, 7);
        assert_eq!(stopped.curve.buckets.len(), 3);
    }

    #[test]
    fn recent_curve_contains_at_most_sixty_one_second_buckets() {
        let mut curve = TrafficCurve::new(1_000_000_000, 100).unwrap();
        for second in 0..=60 {
            let mut item = event(1);
            item.timestamp_unix_nanos = second * 1_000_000_000;
            let _ = curve.record(&item);
        }
        let recent = recent_curve(&curve.snapshot(), Duration::from_secs(60));
        assert_eq!(recent.maximum_buckets, 60);
        assert_eq!(recent.buckets.len(), 60);
        assert_eq!(recent.buckets[0].start_unix_nanos, 1_000_000_000);
        assert_eq!(recent.buckets[59].start_unix_nanos, 60_000_000_000);
    }

    #[test]
    fn curve_clock_advances_through_idle_publications() {
        let runtime = ApplicationRuntime::start_with_config(RuntimeConfig {
            queue_capacity: 4,
            snapshot_interval: Duration::from_millis(2),
            flow_idle_timeout: Duration::from_secs(1),
            maximum_flows: 4,
            curve_bucket_width: Duration::from_millis(10),
            curve_maximum_buckets: 10,
        })
        .unwrap();
        assert_eq!(
            runtime.ingress().try_submit(event(100)),
            SubmitOutcome::Accepted
        );
        std::thread::sleep(Duration::from_millis(60));

        let snapshot = runtime.snapshot().unwrap();
        assert!(snapshot.curve.buckets.len() >= 4);
        let first = snapshot.curve.buckets.first().unwrap();
        let last = snapshot.curve.buckets.last().unwrap();
        assert!(last.start_unix_nanos > first.start_unix_nanos);
        assert_eq!(last.send_bytes, 0);
        assert_eq!(last.receive_bytes, 0);
        assert_eq!(snapshot.curve.events_accepted, 1);
        let _ = runtime.stop().unwrap();
    }

    #[test]
    fn process_ranking_and_connection_details_are_joined_in_application() {
        let runtime = ApplicationRuntime::start_with_config(RuntimeConfig {
            queue_capacity: 4,
            snapshot_interval: Duration::from_millis(2),
            flow_idle_timeout: Duration::from_secs(1),
            maximum_flows: 4,
            curve_bucket_width: Duration::from_secs(1),
            curve_maximum_buckets: 60,
        })
        .unwrap();
        let item = event(321);
        let key = ProcessKey {
            pid: item.pid,
            started_at_unix_nanos: item.timestamp_unix_nanos - 1,
        };
        assert_eq!(
            runtime.ingress().try_submit(item.clone()),
            SubmitOutcome::Accepted
        );
        std::thread::sleep(Duration::from_millis(20));
        runtime
            .publish_system_snapshot(SystemSnapshot {
                captured_at_unix_nanos: item.timestamp_unix_nanos - 1,
                process_names: vec![(item.pid, "ranked.exe".to_owned())],
                processes: vec![ProcessSnapshot {
                    key,
                    name: "ranked.exe".to_owned(),
                    image_path: Some("C:\\ranked.exe".to_owned()),
                    icon: procnet_core::ProcessIconState::NotLoaded,
                }],
                connections: Vec::new(),
            })
            .unwrap();
        let early = runtime.snapshot().unwrap();
        assert_eq!(early.process_traffic[0].process_key, None);
        assert_eq!(early.process_traffic[0].name.as_deref(), Some("ranked.exe"));

        runtime
            .publish_system_snapshot(SystemSnapshot {
                captured_at_unix_nanos: item.timestamp_unix_nanos + 1,
                process_names: vec![(item.pid, "ranked.exe".to_owned())],
                processes: vec![ProcessSnapshot {
                    key,
                    name: "ranked.exe".to_owned(),
                    image_path: Some("C:\\ranked.exe".to_owned()),
                    icon: procnet_core::ProcessIconState::NotLoaded,
                }],
                connections: vec![ConnectionSnapshot {
                    protocol: TransportProtocol::Tcp,
                    local: item.source,
                    remote: Some(item.destination),
                    tcp_state: Some(TcpConnectionState::Established),
                    pid: item.pid,
                    process_key: Some(key),
                    owner_name: Some("ranked.exe".to_owned()),
                }],
            })
            .unwrap();

        let snapshot = runtime.snapshot().unwrap();
        assert_eq!(snapshot.process_traffic.len(), 1);
        let ranked = &snapshot.process_traffic[0];
        assert_eq!(ranked.process_key, Some(key));
        assert_eq!(ranked.name.as_deref(), Some("ranked.exe"));
        assert_eq!(ranked.send_bytes_total, 321);
        assert_eq!(ranked.send_bytes_per_second, 321);
        assert_eq!(ranked.connection_count, 1);
        assert_eq!(snapshot.network_rate.send_bytes_per_second, 321);
        assert_eq!(snapshot.connection_details.len(), 1);
        assert_eq!(
            snapshot.connection_details[0].process_name.as_deref(),
            Some("ranked.exe")
        );
        let _ = runtime.stop().unwrap();
    }
}
