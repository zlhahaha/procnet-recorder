use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use procnet_application::{
    ApplicationRuntime, ApplicationSnapshot, CaptureRestriction, CaptureStatus,
};

pub enum CollectorUpdate {
    Snapshot(Box<ApplicationSnapshot>),
    Error(String),
}

pub struct CollectorHandle {
    pub receiver: Receiver<CollectorUpdate>,
    cancel: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl CollectorHandle {
    pub fn start(elevated_handoff: bool) -> Self {
        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker = thread::Builder::new()
            .name("procnet-gui-collector".to_owned())
            .spawn(move || run_collector(&worker_cancel, &sender, elevated_handoff))
            .expect("cannot start GUI collector thread");
        Self {
            receiver,
            cancel,
            worker: Some(worker),
        }
    }
}

impl Drop for CollectorHandle {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_collector(
    cancel: &Arc<AtomicBool>,
    sender: &Sender<CollectorUpdate>,
    elevated_handoff: bool,
) {
    let Ok(runtime) = ApplicationRuntime::start(16_384) else {
        let _ = sender.send(CollectorUpdate::Error("无法启动有界聚合运行时".to_owned()));
        return;
    };
    let publisher = runtime.system_snapshot_publisher();
    let (icon_sender, icon_receiver) = mpsc::sync_channel(1);
    let icon_publisher = publisher.clone();
    let _icon_worker = thread::Builder::new()
        .name("procnet-icon-loader".to_owned())
        .spawn(move || {
            let mut icon_cache = procnet_windows::ProcessIconCache::default();
            while let Ok(mut snapshot) = icon_receiver.recv() {
                icon_cache.enrich(&mut snapshot, 1);
                let _ = icon_publisher.merge_process_icons(&snapshot);
            }
        });
    if let Ok(snapshot) = procnet_windows::capture_system_snapshot() {
        let _ = publisher.publish(snapshot.clone());
        let _ = icon_sender.try_send(snapshot);
    }
    let refresh_cancel = Arc::clone(cancel);
    let refresh = thread::Builder::new()
        .name("procnet-system-refresh".to_owned())
        .spawn(move || {
            while !refresh_cancel.load(Ordering::Acquire) {
                if let Ok(snapshot) = procnet_windows::capture_system_snapshot() {
                    let _ = publisher.publish(snapshot.clone());
                    match icon_sender.try_send(snapshot) {
                        Ok(()) | Err(TrySendError::Full(_)) => {}
                        Err(TrySendError::Disconnected(_)) => break,
                    }
                }
                for _ in 0..10 {
                    if refresh_cancel.load(Ordering::Acquire) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            }
        });

    let reader = runtime.snapshot_reader();
    let report_cancel = Arc::clone(cancel);
    let report_sender = sender.clone();
    let reporter = thread::Builder::new()
        .name("procnet-gui-snapshot".to_owned())
        .spawn(move || {
            while !report_cancel.load(Ordering::Acquire) {
                if let Ok(snapshot) = reader.snapshot()
                    && report_sender
                        .send(CollectorUpdate::Snapshot(Box::new(snapshot)))
                        .is_err()
                {
                    break;
                }
                thread::sleep(Duration::from_millis(250));
            }
        });

    let result = run_etw_with_handoff(&runtime, cancel, elevated_handoff);
    if let Err(error) = result {
        let status = match error.kind() {
            procnet_windows::EtwProbeErrorKind::AccessDenied => Some(CaptureStatus::Restricted(
                CaptureRestriction::PermissionRequired,
            )),
            procnet_windows::EtwProbeErrorKind::SessionAlreadyExists => Some(
                CaptureStatus::Restricted(CaptureRestriction::SessionAlreadyExists),
            ),
            procnet_windows::EtwProbeErrorKind::Other => None,
        };
        if let Some(status) = status {
            let _ = runtime.set_capture_status(status);
            while !cancel.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(100));
            }
        } else {
            let _ = sender.send(CollectorUpdate::Error(format!("网络采集失败：{error}")));
        }
    }
    cancel.store(true, Ordering::Release);
    if let Ok(reporter) = reporter {
        let _ = reporter.join();
    }
    if let Ok(refresh) = refresh {
        let _ = refresh.join();
    }
    if let Ok(snapshot) = runtime.stop() {
        let _ = sender.send(CollectorUpdate::Snapshot(Box::new(snapshot)));
    }
}

fn run_etw_with_handoff(
    runtime: &ApplicationRuntime,
    cancel: &Arc<AtomicBool>,
    elevated_handoff: bool,
) -> Result<procnet_windows::EtwProbeSummary, procnet_windows::EtwProbeError> {
    let handoff_deadline = Instant::now() + Duration::from_secs(3);
    let mut orphan_recovery_attempted = false;
    loop {
        let ingress = runtime.ingress();
        let result = procnet_windows::run_tcp_ip_probe_with_sink_until(
            Duration::from_secs(24 * 60 * 60),
            Vec::new(),
            false,
            cancel.as_ref(),
            move |event| {
                let _ = ingress.try_submit(event);
            },
        );
        let session_conflict = result.as_ref().is_err_and(|error| {
            error.kind() == procnet_windows::EtwProbeErrorKind::SessionAlreadyExists
        });
        let handoff_state = if !elevated_handoff || !session_conflict {
            HandoffState::Inactive
        } else if cancel.load(Ordering::Acquire) {
            HandoffState::Cancelled
        } else if orphan_recovery_attempted {
            HandoffState::RecoveryAttempted
        } else if Instant::now() < handoff_deadline {
            HandoffState::Waiting
        } else {
            HandoffState::Orphan
        };
        match handoff_step(handoff_state) {
            HandoffStep::Return => return result,
            HandoffStep::Wait => {
                thread::sleep(Duration::from_millis(200));
                continue;
            }
            HandoffStep::Recover => {
                if !recover_exact_project_session() {
                    return result;
                }
            }
        }
        orphan_recovery_attempted = true;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandoffStep {
    Return,
    Wait,
    Recover,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandoffState {
    Inactive,
    Cancelled,
    Waiting,
    Orphan,
    RecoveryAttempted,
}

const fn handoff_step(state: HandoffState) -> HandoffStep {
    match state {
        HandoffState::Inactive | HandoffState::Cancelled | HandoffState::RecoveryAttempted => {
            HandoffStep::Return
        }
        HandoffState::Waiting => HandoffStep::Wait,
        HandoffState::Orphan => HandoffStep::Recover,
    }
}

fn recover_exact_project_session() -> bool {
    match procnet_windows::cleanup_target(procnet_windows::PROJECT_ETW_SESSION_NAME) {
        Ok(procnet_windows::CleanupPreparation::AlreadyAbsent) => true,
        Ok(procnet_windows::CleanupPreparation::Ready(target)) => target.stop().is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{HandoffState, HandoffStep, handoff_step};

    #[test]
    fn elevated_handoff_waits_then_recovers_one_exact_orphan() {
        assert_eq!(handoff_step(HandoffState::Waiting), HandoffStep::Wait);
        assert_eq!(handoff_step(HandoffState::Orphan), HandoffStep::Recover);
        assert_eq!(
            handoff_step(HandoffState::RecoveryAttempted),
            HandoffStep::Return
        );
    }

    #[test]
    fn handoff_never_recovers_without_marker_conflict_or_live_caller() {
        assert_eq!(handoff_step(HandoffState::Inactive), HandoffStep::Return);
        assert_eq!(handoff_step(HandoffState::Cancelled), HandoffStep::Return);
    }
}
