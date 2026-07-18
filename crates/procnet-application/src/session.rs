//! Session lifecycle orchestration and the persistence port.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, RwLock};
use std::thread;

use procnet_core::{
    AlertKind, AlertRecord, EndpointSummary, ExportFormat, ProcessRiskObservation,
    ProcessSessionSummary, RiskEvaluator, RiskLevel, RiskObservation, RiskPolicy, RiskSignal,
    SessionBucket, SessionDetail, SessionId, SessionRecord, SessionRepository, SessionStatus,
};

use crate::ApplicationSnapshot;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Settings {
    pub retention_days: u32,
    pub upload_alert_bytes_per_second: u64,
    pub download_alert_bytes_per_second: u64,
    pub spike_multiplier: u32,
    pub alert_new_process: bool,
    pub alert_new_endpoint: bool,
}

impl Default for V2Settings {
    fn default() -> Self {
        Self {
            retention_days: 30,
            upload_alert_bytes_per_second: 10 * 1024 * 1024,
            download_alert_bytes_per_second: 25 * 1024 * 1024,
            spike_multiplier: 4,
            alert_new_process: true,
            alert_new_endpoint: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SessionUiState {
    pub active: Option<SessionRecord>,
    pub sessions: Vec<SessionRecord>,
    pub selected: Option<SessionDetail>,
    pub compare_left: Option<SessionDetail>,
    pub compare_right: Option<SessionDetail>,
    pub settings: V2Settings,
    pub persistence_queue_dropped: u64,
    pub last_error: Option<String>,
    pub recovered_sessions: usize,
    pub live_risk_events: Vec<LiveRiskEvent>,
}

/// Recent explainable event exposed to the GUI independently of manual recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveRiskEvent {
    pub id: u64,
    pub occurred_at_unix_nanos: u64,
    pub level: RiskLevel,
    pub score: u32,
    pub title: String,
    pub detail: String,
    pub process_name: String,
    pub remote_address: Option<String>,
}

enum Command {
    Start(String, String, u64),
    Stop(u64),
    Record(Box<ApplicationSnapshot>),
    Select(SessionId),
    Compare(SessionId, SessionId),
    Delete(SessionId),
    Refresh,
    SaveSettings(V2Settings),
    Retain(u64),
    Export(SessionId, ExportFormat, std::path::PathBuf),
    Shutdown(u64),
}

/// UI-facing command channel backed by exactly one persistence worker.
pub struct RecordingController {
    sender: SyncSender<Command>,
    state: Arc<RwLock<SessionUiState>>,
    worker: Option<thread::JoinHandle<()>>,
}

#[allow(clippy::missing_errors_doc)]
impl RecordingController {
    pub fn start(repository: Arc<dyn SessionRepository>, now: u64) -> Result<Self, String> {
        let (sender, receiver) = mpsc::sync_channel(64);
        let state = Arc::new(RwLock::new(SessionUiState::default()));
        let worker_state = Arc::clone(&state);
        let worker = thread::Builder::new()
            .name("procnet-persistence".to_owned())
            .spawn(move || run_worker(&repository, &receiver, &worker_state, now))
            .map_err(|error| format!("cannot start persistence worker: {error}"))?;
        Ok(Self {
            sender,
            state,
            worker: Some(worker),
        })
    }

    #[must_use]
    pub fn state(&self) -> SessionUiState {
        self.state
            .read()
            .map_or_else(|_| SessionUiState::default(), |state| state.clone())
    }
    pub fn start_recording(
        &self,
        name: String,
        notes: String,
        timestamp: u64,
    ) -> Result<(), String> {
        self.send(Command::Start(name, notes, timestamp))
    }
    pub fn stop_recording(&self, timestamp: u64) -> Result<(), String> {
        self.send(Command::Stop(timestamp))
    }
    pub fn select(&self, id: SessionId) -> Result<(), String> {
        self.send(Command::Select(id))
    }
    pub fn compare(&self, left: SessionId, right: SessionId) -> Result<(), String> {
        self.send(Command::Compare(left, right))
    }
    pub fn delete_session(&self, id: SessionId) -> Result<(), String> {
        self.send(Command::Delete(id))
    }
    pub fn refresh(&self) -> Result<(), String> {
        self.send(Command::Refresh)
    }
    pub fn save_settings(&self, value: V2Settings) -> Result<(), String> {
        self.send(Command::SaveSettings(value))
    }
    pub fn apply_retention(&self, now: u64) -> Result<(), String> {
        self.send(Command::Retain(now))
    }
    pub fn export_session(
        &self,
        id: SessionId,
        format: ExportFormat,
        path: std::path::PathBuf,
    ) -> Result<(), String> {
        self.send(Command::Export(id, format, path))
    }
    pub fn try_record(&self, snapshot: ApplicationSnapshot) {
        match self.sender.try_send(Command::Record(Box::new(snapshot))) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                if let Ok(mut state) = self.state.write() {
                    state.persistence_queue_dropped =
                        state.persistence_queue_dropped.saturating_add(1);
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                set_error(&self.state, "persistence worker stopped");
            }
        }
    }
    fn send(&self, command: Command) -> Result<(), String> {
        self.sender
            .try_send(command)
            .map_err(|error| format!("persistence command rejected: {error}"))
    }
}

impl Drop for RecordingController {
    fn drop(&mut self) {
        let _ = self.sender.send(Command::Shutdown(now()));
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Default)]
struct ActiveSession {
    id: Option<SessionId>,
    last_bucket: Option<u64>,
    last_events: u64,
    baselines: std::collections::BTreeMap<(u32, u64), (u64, u64)>,
    process_metadata: BTreeMap<u32, SessionProcessMetadata>,
    next_alert_id: i64,
    automatic: bool,
    automatic_stop_at: Option<u64>,
}

#[derive(Default)]
struct SessionProcessMetadata {
    started_at_unix_nanos: u64,
    name: Option<String>,
    image_path: Option<String>,
}

const RISK_HISTORY_NANOS: u64 = 120 * 1_000_000_000;
const AUTOMATIC_AFTER_NANOS: u64 = 60 * 1_000_000_000;
const MAX_LIVE_RISK_EVENTS: usize = 200;

struct LiveRuntime {
    evaluator: RiskEvaluator,
    retained: VecDeque<Box<ApplicationSnapshot>>,
    next_event_id: u64,
}

impl LiveRuntime {
    fn new(settings: &V2Settings) -> Self {
        Self {
            evaluator: RiskEvaluator::new(risk_policy(settings)),
            retained: VecDeque::new(),
            next_event_id: 0,
        }
    }
}

fn run_worker(
    repository: &Arc<dyn SessionRepository>,
    receiver: &Receiver<Command>,
    state: &Arc<RwLock<SessionUiState>>,
    timestamp: u64,
) {
    let mut active = ActiveSession::default();
    match repository.recover_interrupted(timestamp) {
        Ok(count) => {
            if let Ok(mut state) = state.write() {
                state.recovered_sessions = count;
            }
        }
        Err(error) => set_error(state, error),
    }
    load_settings(repository.as_ref(), state);
    refresh(repository.as_ref(), state, None);
    let settings = state
        .read()
        .map_or_else(|_| V2Settings::default(), |value| value.settings.clone());
    let mut live = LiveRuntime::new(&settings);
    while let Ok(command) = receiver.recv() {
        let result = match command {
            Command::Start(name, notes, time) => {
                start_recording(repository.as_ref(), state, &mut active, &name, &notes, time)
            }
            Command::Stop(time) => stop_recording(repository.as_ref(), state, &mut active, time),
            Command::Record(snapshot) => {
                handle_live_snapshot(repository.as_ref(), state, &mut active, &mut live, snapshot)
            }
            Command::Select(id) => select(repository.as_ref(), state, id),
            Command::Compare(left, right) => compare(repository.as_ref(), state, left, right),
            Command::Delete(id) => delete_session(repository.as_ref(), state, active.id, id),
            Command::Refresh => {
                refresh(repository.as_ref(), state, active.id);
                Ok(())
            }
            Command::SaveSettings(value) => save_settings(repository.as_ref(), state, value),
            Command::Retain(time) => retain(repository.as_ref(), state, active.id, time),
            Command::Export(id, format, path) => repository.export_session(id, format, &path),
            Command::Shutdown(time) => {
                let result = stop_recording(repository.as_ref(), state, &mut active, time);
                if let Err(error) = result {
                    set_error(state, error);
                }
                break;
            }
        };
        if let Err(error) = result {
            set_error(state, error);
        }
    }
}

fn handle_live_snapshot(
    repository: &dyn SessionRepository,
    state: &Arc<RwLock<SessionUiState>>,
    active: &mut ActiveSession,
    live: &mut LiveRuntime,
    snapshot: Box<ApplicationSnapshot>,
) -> Result<(), String> {
    let timestamp = snapshot.network_rate.sampled_at_unix_nanos;
    let settings = state
        .read()
        .map_or_else(|_| V2Settings::default(), |value| value.settings.clone());
    live.evaluator.set_policy(risk_policy(&settings));
    let observation = risk_observation(&snapshot);
    let signals = live.evaluator.evaluate(&observation);
    let events = publish_live_events(state, live, timestamp, &signals);
    let high_risk = signals.iter().any(|signal| signal.level == RiskLevel::High);

    live.retained.push_back(snapshot);
    while live.retained.front().is_some_and(|oldest| {
        timestamp.saturating_sub(oldest.network_rate.sampled_at_unix_nanos) > RISK_HISTORY_NANOS
    }) {
        live.retained.pop_front();
    }

    if active.id.is_some() {
        let current = live
            .retained
            .back()
            .expect("the current snapshot was just retained");
        record(repository, state, active, current, &events, true)?;
        if active.automatic && high_risk {
            active.automatic_stop_at = Some(timestamp.saturating_add(AUTOMATIC_AFTER_NANOS));
        }
        if active.automatic
            && active
                .automatic_stop_at
                .is_some_and(|stop_at| timestamp >= stop_at)
        {
            stop_recording(repository, state, active, timestamp)?;
        }
        return Ok(());
    }

    if !high_risk {
        return Ok(());
    }

    let started_at = live.retained.front().map_or(timestamp, |snapshot| {
        snapshot.network_rate.sampled_at_unix_nanos
    });
    let primary = signals
        .iter()
        .find(|signal| signal.level == RiskLevel::High)
        .expect("high-risk state requires a high-risk signal");
    start_recording(
        repository,
        state,
        active,
        &format!("自动高风险事件 · {}", primary.process_name),
        &format!(
            "由实时风险检测自动建立；风险分数 {}；已回溯保存异常前最多 2 分钟。{}",
            primary.score, primary.detail
        ),
        started_at,
    )?;
    active.automatic = true;
    active.automatic_stop_at = Some(timestamp.saturating_add(AUTOMATIC_AFTER_NANOS));
    if let Some(first) = live.retained.front() {
        active.last_events = first.events_processed;
    }
    let last_index = live.retained.len().saturating_sub(1);
    for (index, retained) in live.retained.iter().enumerate() {
        let attached: &[LiveRiskEvent] = if index == last_index { &events } else { &[] };
        record(
            repository,
            state,
            active,
            retained,
            attached,
            index == last_index,
        )?;
    }
    Ok(())
}

fn risk_observation(snapshot: &ApplicationSnapshot) -> RiskObservation {
    let mut endpoints = BTreeMap::<u32, BTreeSet<String>>::new();
    for detail in &snapshot.connection_details {
        if let Some(remote) = detail.connection.remote {
            endpoints
                .entry(detail.connection.pid)
                .or_default()
                .insert(remote.to_string());
        }
    }
    let processes = snapshot
        .process_traffic
        .iter()
        .map(|process| {
            let started = process
                .process_key
                .map_or(0, |key| key.started_at_unix_nanos);
            ProcessRiskObservation {
                identity: format!("{}:{started}", process.pid),
                name: process
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("PID {}", process.pid)),
                send_bytes_per_second: process.send_bytes_per_second,
                receive_bytes_per_second: process.receive_bytes_per_second,
                remote_addresses: endpoints
                    .remove(&process.pid)
                    .unwrap_or_default()
                    .into_iter()
                    .collect(),
            }
        })
        .collect();
    RiskObservation {
        timestamp_unix_nanos: snapshot.network_rate.sampled_at_unix_nanos,
        processes,
    }
}

fn publish_live_events(
    state: &Arc<RwLock<SessionUiState>>,
    live: &mut LiveRuntime,
    timestamp: u64,
    signals: &[RiskSignal],
) -> Vec<LiveRiskEvent> {
    let events = signals
        .iter()
        .map(|signal| {
            live.next_event_id = live.next_event_id.saturating_add(1);
            LiveRiskEvent {
                id: live.next_event_id,
                occurred_at_unix_nanos: timestamp,
                level: signal.level,
                score: signal.score,
                title: signal.title.clone(),
                detail: signal.detail.clone(),
                process_name: signal.process_name.clone(),
                remote_address: signal.remote_address.clone(),
            }
        })
        .collect::<Vec<_>>();
    if !events.is_empty()
        && let Ok(mut state) = state.write()
    {
        state.live_risk_events.extend(events.iter().cloned());
        let overflow = state
            .live_risk_events
            .len()
            .saturating_sub(MAX_LIVE_RISK_EVENTS);
        if overflow > 0 {
            state.live_risk_events.drain(..overflow);
        }
    }
    events
}

fn start_recording(
    repository: &dyn SessionRepository,
    state: &Arc<RwLock<SessionUiState>>,
    active: &mut ActiveSession,
    name: &str,
    notes: &str,
    timestamp: u64,
) -> Result<(), String> {
    if active.id.is_some() {
        return Err("a recording session is already active".to_owned());
    }
    let name = if name.trim().is_empty() {
        format!("Session {}", timestamp / 1_000_000_000)
    } else {
        name.trim().to_owned()
    };
    active.id = Some(repository.start_session(&name, notes.trim(), timestamp)?);
    active.last_bucket = None;
    active.last_events = 0;
    active.baselines.clear();
    active.process_metadata.clear();
    active.next_alert_id = i64::try_from(timestamp).unwrap_or(i64::MAX);
    active.automatic = false;
    active.automatic_stop_at = None;
    refresh(repository, state, active.id);
    Ok(())
}

fn stop_recording(
    repository: &dyn SessionRepository,
    state: &Arc<RwLock<SessionUiState>>,
    active: &mut ActiveSession,
    timestamp: u64,
) -> Result<(), String> {
    let Some(id) = active.id.take() else {
        return Ok(());
    };
    if !repository.finish_session(id, timestamp, SessionStatus::Completed)? {
        return Err("active session disappeared before stop".to_owned());
    }
    active.last_bucket = None;
    active.baselines.clear();
    active.process_metadata.clear();
    active.automatic = false;
    active.automatic_stop_at = None;
    refresh(repository, state, None);
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn record(
    repository: &dyn SessionRepository,
    state: &Arc<RwLock<SessionUiState>>,
    active: &mut ActiveSession,
    snapshot: &ApplicationSnapshot,
    live_events: &[LiveRiskEvent],
    refresh_after: bool,
) -> Result<(), String> {
    let Some(id) = active.id else {
        return Ok(());
    };
    let start = snapshot.network_rate.sampled_at_unix_nanos / 1_000_000_000 * 1_000_000_000;
    if active.last_bucket.is_some_and(|last| start <= last) {
        return Ok(());
    }
    let bucket = SessionBucket {
        start_unix_nanos: start,
        send_bytes: snapshot.network_rate.send_bytes_per_second,
        receive_bytes: snapshot.network_rate.receive_bytes_per_second,
        event_count: snapshot.events_processed.saturating_sub(active.last_events),
    };
    active.last_bucket = Some(start);
    active.last_events = snapshot.events_processed;
    let processes = snapshot
        .process_traffic
        .iter()
        .map(|process| {
            let metadata = active.process_metadata.entry(process.pid).or_default();
            if let Some(key) = process.process_key {
                if metadata.started_at_unix_nanos != 0
                    && metadata.started_at_unix_nanos != key.started_at_unix_nanos
                {
                    metadata.name = None;
                    metadata.image_path = None;
                }
                metadata.started_at_unix_nanos = key.started_at_unix_nanos;
            }
            if let Some(name) = &process.name {
                metadata.name = Some(name.clone());
            }
            if let Some(path) = &process.image_path {
                metadata.image_path = Some(path.clone());
            }
            let started = metadata.started_at_unix_nanos;
            let baseline = active
                .baselines
                .entry((process.pid, started))
                .or_insert((process.send_bytes_total, process.receive_bytes_total));
            ProcessSessionSummary {
                pid: process.pid,
                started_at_unix_nanos: started,
                name: metadata
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("PID {}", process.pid)),
                image_path: metadata.image_path.clone(),
                send_bytes: process.send_bytes_total.saturating_sub(baseline.0),
                receive_bytes: process.receive_bytes_total.saturating_sub(baseline.1),
                connection_count: process.connection_count as u64,
            }
        })
        .collect::<Vec<_>>();
    let mut endpoint_counts = std::collections::BTreeMap::<(String, String, String), u64>::new();
    for item in &snapshot.connection_details {
        let Some(remote) = item.connection.remote else {
            continue;
        };
        let protocol = match item.connection.protocol {
            procnet_core::TransportProtocol::Tcp => "TCP",
            procnet_core::TransportProtocol::Udp => "UDP",
        }
        .to_owned();
        let process = item
            .process_name
            .clone()
            .unwrap_or_else(|| format!("PID {}", item.connection.pid));
        *endpoint_counts
            .entry((protocol, remote.to_string(), process))
            .or_default() += 1;
    }
    let endpoints = endpoint_counts
        .into_iter()
        .map(
            |((protocol, remote_address, process_name), connection_count)| EndpointSummary {
                protocol,
                remote_address,
                process_name,
                first_seen_unix_nanos: start,
                last_seen_unix_nanos: start,
                connection_count,
            },
        )
        .collect::<Vec<_>>();
    let mut alerts = Vec::new();
    for event in live_events {
        active.next_alert_id = active.next_alert_id.saturating_add(1);
        alerts.push(AlertRecord {
            id: active.next_alert_id,
            session_id: id,
            occurred_at_unix_nanos: event.occurred_at_unix_nanos,
            kind: AlertKind::RiskEvent,
            title: event.title.clone(),
            detail: format!("风险分数 {} · {}", event.score, event.detail),
            process_name: Some(event.process_name.clone()),
            remote_address: event.remote_address.clone(),
        });
    }
    repository.append_batch(id, &[bucket], &processes, &endpoints, &alerts)?;
    if refresh_after {
        refresh(repository, state, Some(id));
    }
    Ok(())
}

fn select(
    repository: &dyn SessionRepository,
    state: &Arc<RwLock<SessionUiState>>,
    id: SessionId,
) -> Result<(), String> {
    let value = repository.detail(id)?;
    if let Ok(mut state) = state.write() {
        state.selected = value;
    }
    Ok(())
}
fn compare(
    repository: &dyn SessionRepository,
    state: &Arc<RwLock<SessionUiState>>,
    left: SessionId,
    right: SessionId,
) -> Result<(), String> {
    let left = repository.detail(left)?;
    let right = repository.detail(right)?;
    if let Ok(mut state) = state.write() {
        state.compare_left = left;
        state.compare_right = right;
    }
    Ok(())
}

fn delete_session(
    repository: &dyn SessionRepository,
    state: &Arc<RwLock<SessionUiState>>,
    active_id: Option<SessionId>,
    id: SessionId,
) -> Result<(), String> {
    if active_id == Some(id) {
        return Err("cannot delete the active recording session".to_owned());
    }
    if !repository.delete_session(id)? {
        return Err(format!("session {id} does not exist or is still recording"));
    }
    if let Ok(mut state) = state.write() {
        if state
            .selected
            .as_ref()
            .is_some_and(|detail| detail.session.id == id)
        {
            state.selected = None;
        }
        if state
            .compare_left
            .as_ref()
            .is_some_and(|detail| detail.session.id == id)
            || state
                .compare_right
                .as_ref()
                .is_some_and(|detail| detail.session.id == id)
        {
            state.compare_left = None;
            state.compare_right = None;
        }
    }
    refresh(repository, state, active_id);
    Ok(())
}

fn refresh(
    repository: &dyn SessionRepository,
    state: &Arc<RwLock<SessionUiState>>,
    active: Option<SessionId>,
) {
    match repository.list_sessions(500) {
        Ok(sessions) => {
            if let Ok(mut state) = state.write() {
                state.active =
                    active.and_then(|id| sessions.iter().find(|item| item.id == id).cloned());
                state.sessions = sessions;
            }
        }
        Err(error) => set_error(state, error),
    }
}

fn save_settings(
    repository: &dyn SessionRepository,
    state: &Arc<RwLock<SessionUiState>>,
    value: V2Settings,
) -> Result<(), String> {
    for (key, setting) in settings_pairs(&value) {
        repository.set_setting(key, &setting)?;
    }
    if let Ok(mut state) = state.write() {
        state.settings = value;
    }
    Ok(())
}

fn load_settings(repository: &dyn SessionRepository, state: &Arc<RwLock<SessionUiState>>) {
    let mut value = V2Settings::default();
    if let Ok(Some(text)) = repository.setting("retention_days") {
        value.retention_days = text.parse().unwrap_or(value.retention_days);
    }
    if let Ok(Some(text)) = repository.setting("upload_alert_bps") {
        value.upload_alert_bytes_per_second =
            text.parse().unwrap_or(value.upload_alert_bytes_per_second);
    }
    if let Ok(Some(text)) = repository.setting("download_alert_bps") {
        value.download_alert_bytes_per_second = text
            .parse()
            .unwrap_or(value.download_alert_bytes_per_second);
    }
    if let Ok(Some(text)) = repository.setting("spike_multiplier") {
        value.spike_multiplier = text.parse().unwrap_or(value.spike_multiplier).max(2);
    }
    if let Ok(Some(text)) = repository.setting("alert_new_process") {
        value.alert_new_process = text == "true";
    }
    if let Ok(Some(text)) = repository.setting("alert_new_endpoint") {
        value.alert_new_endpoint = text == "true";
    }
    if let Ok(mut state) = state.write() {
        state.settings = value;
    }
}

fn settings_pairs(value: &V2Settings) -> [(&'static str, String); 6] {
    [
        ("retention_days", value.retention_days.to_string()),
        (
            "upload_alert_bps",
            value.upload_alert_bytes_per_second.to_string(),
        ),
        (
            "download_alert_bps",
            value.download_alert_bytes_per_second.to_string(),
        ),
        ("spike_multiplier", value.spike_multiplier.to_string()),
        ("alert_new_process", value.alert_new_process.to_string()),
        ("alert_new_endpoint", value.alert_new_endpoint.to_string()),
    ]
}

fn risk_policy(value: &V2Settings) -> RiskPolicy {
    RiskPolicy {
        new_process: value.alert_new_process,
        new_endpoint: value.alert_new_endpoint,
        upload_threshold: value.upload_alert_bytes_per_second,
        download_threshold: value.download_alert_bytes_per_second,
        spike_multiplier: value.spike_multiplier,
    }
}
fn retain(
    repository: &dyn SessionRepository,
    state: &Arc<RwLock<SessionUiState>>,
    active: Option<SessionId>,
    timestamp: u64,
) -> Result<(), String> {
    let days = state
        .read()
        .map_or(30, |state| state.settings.retention_days);
    let cutoff = timestamp.saturating_sub(u64::from(days) * 86_400 * 1_000_000_000);
    repository.delete_sessions_ended_before(cutoff)?;
    refresh(repository, state, active);
    Ok(())
}
fn set_error(state: &Arc<RwLock<SessionUiState>>, error: impl Into<String>) {
    if let Ok(mut state) = state.write() {
        state.last_error = Some(error.into());
    }
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        })
}
