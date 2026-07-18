//! Platform-independent recording-session and alert domain models.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

/// Stable database identity of one recording session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub i64);

impl fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Durable lifecycle state. A `Recording` row found during startup is recovered as `Interrupted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    Recording,
    Completed,
    Interrupted,
}

impl SessionStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Completed => "completed",
            Self::Interrupted => "interrupted",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "recording" => Some(Self::Recording),
            "completed" => Some(Self::Completed),
            "interrupted" => Some(Self::Interrupted),
            _ => None,
        }
    }
}

/// Summary shown in the history and comparison pages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub id: SessionId,
    pub name: String,
    pub notes: String,
    pub started_at_unix_nanos: u64,
    pub ended_at_unix_nanos: Option<u64>,
    pub status: SessionStatus,
    pub send_bytes: u64,
    pub receive_bytes: u64,
    pub event_count: u64,
}

/// One persisted fixed-width traffic point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionBucket {
    pub start_unix_nanos: u64,
    pub send_bytes: u64,
    pub receive_bytes: u64,
    pub event_count: u64,
}

/// Per-process totals accumulated inside one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSessionSummary {
    pub pid: u32,
    pub started_at_unix_nanos: u64,
    pub name: String,
    pub image_path: Option<String>,
    pub send_bytes: u64,
    pub receive_bytes: u64,
    pub connection_count: u64,
}

/// Endpoint history accumulated inside one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSummary {
    pub protocol: String,
    pub remote_address: String,
    pub process_name: String,
    pub first_seen_unix_nanos: u64,
    pub last_seen_unix_nanos: u64,
    pub connection_count: u64,
}

/// Supported local alert categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    NewProcess,
    NewEndpoint,
    UploadThreshold,
    DownloadThreshold,
    TrafficSpike,
    RiskEvent,
}

impl AlertKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NewProcess => "new_process",
            Self::NewEndpoint => "new_endpoint",
            Self::UploadThreshold => "upload_threshold",
            Self::DownloadThreshold => "download_threshold",
            Self::TrafficSpike => "traffic_spike",
            Self::RiskEvent => "risk_event",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "new_process" => Some(Self::NewProcess),
            "new_endpoint" => Some(Self::NewEndpoint),
            "upload_threshold" => Some(Self::UploadThreshold),
            "download_threshold" => Some(Self::DownloadThreshold),
            "traffic_spike" => Some(Self::TrafficSpike),
            "risk_event" => Some(Self::RiskEvent),
            _ => None,
        }
    }
}

/// Explainable severity assigned by the always-on local risk evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Information,
    Attention,
    High,
}

/// One process observation consumed by the always-on risk evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRiskObservation {
    pub identity: String,
    pub name: String,
    pub send_bytes_per_second: u64,
    pub receive_bytes_per_second: u64,
    pub remote_addresses: Vec<String>,
}

/// One fixed-width system observation consumed by the risk evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskObservation {
    pub timestamp_unix_nanos: u64,
    pub processes: Vec<ProcessRiskObservation>,
}

/// Runtime policy. Absolute floors prevent tiny relative changes from becoming warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskPolicy {
    pub upload_threshold: u64,
    pub download_threshold: u64,
    pub spike_multiplier: u32,
    pub new_process: bool,
    pub new_endpoint: bool,
}

/// A scored, human-readable local event. It is not a malware verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskSignal {
    pub level: RiskLevel,
    pub score: u32,
    pub title: String,
    pub detail: String,
    pub process_name: String,
    pub remote_address: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct ProcessRiskState {
    baseline_rate: u64,
    samples: u32,
    consecutive_upload: u32,
    consecutive_download: u32,
    last_level: Option<RiskLevel>,
    last_emitted_at: u64,
    new_process_until: u64,
    new_endpoint_until: u64,
    last_new_remote: Option<String>,
}

/// Stateful, bounded, explainable risk evaluator for live per-process observations.
#[derive(Debug, Clone)]
pub struct RiskEvaluator {
    policy: RiskPolicy,
    initialized: bool,
    known_processes: BTreeSet<String>,
    known_endpoints: BTreeSet<(String, String)>,
    states: BTreeMap<String, ProcessRiskState>,
}

impl RiskEvaluator {
    const HIGH_SCORE: u32 = 60;
    const ATTENTION_SCORE: u32 = 30;
    const MINIMUM_SPIKE_RATE: u64 = 1024 * 1024;
    const MINIMUM_BASELINE_RATE: u64 = 64 * 1024;
    const REQUIRED_SUSTAINED_SAMPLES: u32 = 3;
    const COOLDOWN_NANOS: u64 = 120 * 1_000_000_000;
    const NOVELTY_WINDOW_NANOS: u64 = 30 * 1_000_000_000;

    #[must_use]
    pub fn new(policy: RiskPolicy) -> Self {
        Self {
            policy,
            initialized: false,
            known_processes: BTreeSet::new(),
            known_endpoints: BTreeSet::new(),
            states: BTreeMap::new(),
        }
    }

    pub fn set_policy(&mut self, policy: RiskPolicy) {
        self.policy = policy;
    }

    #[allow(clippy::too_many_lines)]
    pub fn evaluate(&mut self, observation: &RiskObservation) -> Vec<RiskSignal> {
        let mut signals = Vec::new();
        let mut present = BTreeSet::new();
        for process in &observation.processes {
            present.insert(process.identity.clone());
            let endpoints = process
                .remote_addresses
                .iter()
                .map(|remote| (process.identity.clone(), remote.clone()))
                .collect::<BTreeSet<_>>();
            let is_new_process =
                self.initialized && !self.known_processes.contains(&process.identity);
            let new_endpoints = if self.initialized {
                endpoints
                    .difference(&self.known_endpoints)
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            let state = self.states.entry(process.identity.clone()).or_default();
            if self.policy.new_process && is_new_process {
                state.new_process_until = observation
                    .timestamp_unix_nanos
                    .saturating_add(Self::NOVELTY_WINDOW_NANOS);
            }
            if self.policy.new_endpoint && !new_endpoints.is_empty() {
                state.new_endpoint_until = observation
                    .timestamp_unix_nanos
                    .saturating_add(Self::NOVELTY_WINDOW_NANOS);
                state.last_new_remote = new_endpoints.first().map(|(_, remote)| remote.clone());
            }
            let total_rate = process
                .send_bytes_per_second
                .saturating_add(process.receive_bytes_per_second);
            state.consecutive_upload =
                if process.send_bytes_per_second >= self.policy.upload_threshold {
                    state.consecutive_upload.saturating_add(1)
                } else {
                    0
                };
            state.consecutive_download =
                if process.receive_bytes_per_second >= self.policy.download_threshold {
                    state.consecutive_download.saturating_add(1)
                } else {
                    0
                };

            let mut score = 0_u32;
            let mut reasons = Vec::new();
            if self.policy.new_process
                && observation.timestamp_unix_nanos <= state.new_process_until
            {
                score += 10;
                reasons.push("新进程开始联网".to_owned());
            }
            if self.policy.new_endpoint
                && observation.timestamp_unix_nanos <= state.new_endpoint_until
            {
                score += 10;
                reasons.push("出现新远程端点".to_owned());
            }
            if new_endpoints.len() >= 10 {
                score += 25;
                reasons.push("短时间连接大量新端点".to_owned());
            }
            if state.consecutive_upload >= Self::REQUIRED_SUSTAINED_SAMPLES {
                score += 40;
                reasons.push(format!("持续上传 {} B/s", process.send_bytes_per_second));
            }
            if state.consecutive_download >= Self::REQUIRED_SUSTAINED_SAMPLES {
                score += 25;
                reasons.push(format!("持续下载 {} B/s", process.receive_bytes_per_second));
            }
            if state.samples > 0
                && state.baseline_rate >= Self::MINIMUM_BASELINE_RATE
                && total_rate >= Self::MINIMUM_SPIKE_RATE
                && total_rate
                    >= state
                        .baseline_rate
                        .saturating_mul(u64::from(self.policy.spike_multiplier.max(2)))
            {
                score += 20;
                reasons.push(format!(
                    "流量达到近期基线的 {} 倍以上",
                    self.policy.spike_multiplier.max(2)
                ));
            }

            let level = if score >= Self::HIGH_SCORE {
                Some(RiskLevel::High)
            } else if score >= Self::ATTENTION_SCORE {
                Some(RiskLevel::Attention)
            } else if score > 0 {
                Some(RiskLevel::Information)
            } else {
                None
            };
            if let Some(level) = level {
                let cooldown_elapsed = observation
                    .timestamp_unix_nanos
                    .saturating_sub(state.last_emitted_at)
                    >= Self::COOLDOWN_NANOS;
                if state.last_level.is_none_or(|previous| level > previous) || cooldown_elapsed {
                    signals.push(RiskSignal {
                        level,
                        score,
                        title: match level {
                            RiskLevel::Information => "网络活动信息",
                            RiskLevel::Attention => "需要关注的网络活动",
                            RiskLevel::High => "高风险网络活动",
                        }
                        .to_owned(),
                        detail: reasons.join("；"),
                        process_name: process.name.clone(),
                        remote_address: state.last_new_remote.clone(),
                    });
                    state.last_level = Some(level);
                    state.last_emitted_at = observation.timestamp_unix_nanos;
                }
            } else {
                state.last_level = None;
            }

            state.baseline_rate = if state.samples == 0 {
                total_rate
            } else {
                state
                    .baseline_rate
                    .saturating_mul(7)
                    .saturating_add(total_rate)
                    / 8
            };
            state.samples = state.samples.saturating_add(1);
            self.known_endpoints.extend(endpoints);
        }
        self.known_processes.extend(present.iter().cloned());
        self.states.retain(|identity, _| present.contains(identity));
        self.initialized = true;
        signals
    }
}

/// User-configurable alert rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertRule {
    pub id: i64,
    pub kind: AlertKind,
    pub enabled: bool,
    pub threshold_bytes_per_second: u64,
}

/// Alert emitted while recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertRecord {
    pub id: i64,
    pub session_id: SessionId,
    pub occurred_at_unix_nanos: u64,
    pub kind: AlertKind,
    pub title: String,
    pub detail: String,
    pub process_name: Option<String>,
    pub remote_address: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDetail {
    pub session: SessionRecord,
    pub buckets: Vec<SessionBucket>,
    pub processes: Vec<ProcessSessionSummary>,
    pub endpoints: Vec<EndpointSummary>,
    pub alerts: Vec<AlertRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
    Markdown,
}

/// Infrastructure port implemented by storage and consumed by application use cases.
#[allow(clippy::missing_errors_doc)]
pub trait SessionRepository: Send + Sync + 'static {
    fn recover_interrupted(&self, timestamp: u64) -> Result<usize, String>;
    fn start_session(&self, name: &str, notes: &str, timestamp: u64) -> Result<SessionId, String>;
    fn finish_session(
        &self,
        id: SessionId,
        timestamp: u64,
        status: SessionStatus,
    ) -> Result<bool, String>;
    fn append_batch(
        &self,
        id: SessionId,
        buckets: &[SessionBucket],
        processes: &[ProcessSessionSummary],
        endpoints: &[EndpointSummary],
        alerts: &[AlertRecord],
    ) -> Result<(), String>;
    fn list_sessions(&self, limit: usize) -> Result<Vec<SessionRecord>, String>;
    fn detail(&self, id: SessionId) -> Result<Option<SessionDetail>, String>;
    fn delete_session(&self, id: SessionId) -> Result<bool, String>;
    fn delete_sessions_ended_before(&self, cutoff: u64) -> Result<usize, String>;
    fn setting(&self, key: &str) -> Result<Option<String>, String>;
    fn set_setting(&self, key: &str, value: &str) -> Result<(), String>;
    fn export_session(
        &self,
        id: SessionId,
        format: ExportFormat,
        path: &Path,
    ) -> Result<(), String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertPolicy {
    pub new_process: bool,
    pub new_endpoint: bool,
    pub upload_threshold: u64,
    pub download_threshold: u64,
    pub spike_multiplier: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertObservation {
    pub timestamp_unix_nanos: u64,
    pub send_bytes_per_second: u64,
    pub receive_bytes_per_second: u64,
    pub process_names: Vec<String>,
    pub endpoints: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertSignal {
    pub kind: AlertKind,
    pub title: String,
    pub detail: String,
    pub process_name: Option<String>,
    pub remote_address: Option<String>,
}

/// Stateful rule evaluator that suppresses startup noise and repeated threshold alerts.
#[derive(Debug, Clone)]
pub struct AlertEvaluator {
    policy: AlertPolicy,
    initialized: bool,
    known_processes: BTreeSet<String>,
    known_endpoints: BTreeSet<(String, String)>,
    upload_above: bool,
    download_above: bool,
    previous_rate: u64,
}

impl AlertEvaluator {
    #[must_use]
    pub fn new(policy: AlertPolicy) -> Self {
        Self {
            policy,
            initialized: false,
            known_processes: BTreeSet::new(),
            known_endpoints: BTreeSet::new(),
            upload_above: false,
            download_above: false,
            previous_rate: 0,
        }
    }

    pub fn set_policy(&mut self, policy: AlertPolicy) {
        self.policy = policy;
    }

    pub fn evaluate(&mut self, observation: &AlertObservation) -> Vec<AlertSignal> {
        let processes = observation
            .process_names
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let endpoints = observation
            .endpoints
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut signals = Vec::new();
        if self.initialized {
            if self.policy.new_process {
                for name in processes.difference(&self.known_processes) {
                    signals.push(AlertSignal {
                        kind: AlertKind::NewProcess,
                        title: "新进程开始联网".to_owned(),
                        detail: name.clone(),
                        process_name: Some(name.clone()),
                        remote_address: None,
                    });
                }
            }
            if self.policy.new_endpoint {
                for (process, remote) in endpoints.difference(&self.known_endpoints) {
                    signals.push(AlertSignal {
                        kind: AlertKind::NewEndpoint,
                        title: "发现新远程端点".to_owned(),
                        detail: format!("{process} → {remote}"),
                        process_name: Some(process.clone()),
                        remote_address: Some(remote.clone()),
                    });
                }
            }
            let upload_above = observation.send_bytes_per_second >= self.policy.upload_threshold;
            if upload_above && !self.upload_above {
                signals.push(AlertSignal {
                    kind: AlertKind::UploadThreshold,
                    title: "上传速率超过阈值".to_owned(),
                    detail: format!("{} B/s", observation.send_bytes_per_second),
                    process_name: None,
                    remote_address: None,
                });
            }
            self.upload_above = upload_above;
            let download_above =
                observation.receive_bytes_per_second >= self.policy.download_threshold;
            if download_above && !self.download_above {
                signals.push(AlertSignal {
                    kind: AlertKind::DownloadThreshold,
                    title: "下载速率超过阈值".to_owned(),
                    detail: format!("{} B/s", observation.receive_bytes_per_second),
                    process_name: None,
                    remote_address: None,
                });
            }
            self.download_above = download_above;
            let rate = observation
                .send_bytes_per_second
                .saturating_add(observation.receive_bytes_per_second);
            if self.previous_rate > 0
                && rate
                    >= self
                        .previous_rate
                        .saturating_mul(u64::from(self.policy.spike_multiplier.max(2)))
            {
                signals.push(AlertSignal {
                    kind: AlertKind::TrafficSpike,
                    title: "流量突增".to_owned(),
                    detail: format!("{} B/s → {rate} B/s", self.previous_rate),
                    process_name: None,
                    remote_address: None,
                });
            }
        }
        self.known_processes.extend(processes);
        self.known_endpoints.extend(endpoints);
        self.previous_rate = observation
            .send_bytes_per_second
            .saturating_add(observation.receive_bytes_per_second);
        self.initialized = true;
        signals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(
        send: u64,
        receive: u64,
        processes: &[&str],
        endpoints: &[(&str, &str)],
    ) -> AlertObservation {
        AlertObservation {
            timestamp_unix_nanos: 1,
            send_bytes_per_second: send,
            receive_bytes_per_second: receive,
            process_names: processes.iter().map(|value| (*value).to_owned()).collect(),
            endpoints: endpoints
                .iter()
                .map(|(process, remote)| ((*process).to_owned(), (*remote).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn evaluator_suppresses_initial_inventory_and_repeated_thresholds() {
        let mut evaluator = AlertEvaluator::new(AlertPolicy {
            new_process: true,
            new_endpoint: true,
            upload_threshold: 100,
            download_threshold: 200,
            spike_multiplier: 4,
        });
        assert!(
            evaluator
                .evaluate(&observation(0, 0, &["a"], &[("a", "one")]))
                .is_empty()
        );
        let signals = evaluator.evaluate(&observation(
            100,
            0,
            &["a", "b"],
            &[("a", "one"), ("b", "two")],
        ));
        assert!(
            signals
                .iter()
                .any(|signal| signal.kind == AlertKind::NewProcess)
        );
        assert!(
            signals
                .iter()
                .any(|signal| signal.kind == AlertKind::NewEndpoint)
        );
        assert!(
            signals
                .iter()
                .any(|signal| signal.kind == AlertKind::UploadThreshold)
        );
        assert!(
            !evaluator
                .evaluate(&observation(
                    150,
                    0,
                    &["a", "b"],
                    &[("a", "one"), ("b", "two")]
                ))
                .iter()
                .any(|signal| signal.kind == AlertKind::UploadThreshold)
        );
    }

    fn risk_observation(
        second: u64,
        identity: &str,
        send: u64,
        receive: u64,
        endpoints: &[&str],
    ) -> RiskObservation {
        RiskObservation {
            timestamp_unix_nanos: second * 1_000_000_000,
            processes: vec![ProcessRiskObservation {
                identity: identity.to_owned(),
                name: identity.to_owned(),
                send_bytes_per_second: send,
                receive_bytes_per_second: receive,
                remote_addresses: endpoints.iter().map(|value| (*value).to_owned()).collect(),
            }],
        }
    }

    fn risk_policy() -> RiskPolicy {
        RiskPolicy {
            new_process: true,
            new_endpoint: true,
            upload_threshold: 100,
            download_threshold: 200,
            spike_multiplier: 4,
        }
    }

    #[test]
    fn risk_evaluator_suppresses_inventory_then_combines_sustained_novel_activity() {
        let mut evaluator = RiskEvaluator::new(risk_policy());
        assert!(
            evaluator
                .evaluate(&risk_observation(100, "known", 0, 0, &["one"]))
                .is_empty()
        );
        let first = evaluator.evaluate(&risk_observation(101, "new", 100, 200, &["two"]));
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].level, RiskLevel::Information);
        assert!(
            evaluator
                .evaluate(&risk_observation(102, "new", 100, 200, &["two"]))
                .is_empty()
        );
        let third = evaluator.evaluate(&risk_observation(103, "new", 100, 200, &["two"]));
        assert_eq!(third.len(), 1);
        assert_eq!(third[0].level, RiskLevel::High);
        assert!(third[0].score >= 60);
    }

    #[test]
    fn sustained_upload_from_known_process_is_attention_not_high_risk() {
        let mut evaluator = RiskEvaluator::new(risk_policy());
        evaluator.evaluate(&risk_observation(100, "known", 0, 0, &["one"]));
        evaluator.evaluate(&risk_observation(101, "known", 100, 0, &["one"]));
        evaluator.evaluate(&risk_observation(102, "known", 100, 0, &["one"]));
        let signals = evaluator.evaluate(&risk_observation(103, "known", 100, 0, &["one"]));
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].level, RiskLevel::Attention);
        assert_eq!(signals[0].score, 40);
    }
}
