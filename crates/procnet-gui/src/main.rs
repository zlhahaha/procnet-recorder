//! Native desktop entry point for `ProcNet Recorder`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod collector;
mod ui;

fn main() -> eframe::Result {
    let (smoke_duration, smoke_report, screenshot, initial_page, elevated_handoff) =
        parse_smoke_options(std::env::args().skip(1));
    let recording = create_recording_controller();
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 720.0])
            .with_min_inner_size([960.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "ProcNet Recorder",
        options,
        Box::new(move |context| {
            Ok(Box::new(ui::ProcNetApp::new(
                context,
                smoke_duration,
                smoke_report,
                screenshot,
                initial_page.as_deref(),
                elevated_handoff,
                recording,
            )))
        }),
    )
}

fn create_recording_controller() -> Result<procnet_application::RecordingController, String> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map_or_else(|| std::path::PathBuf::from("."), std::path::PathBuf::from)
        .join("ProcNet Recorder");
    std::fs::create_dir_all(&base)
        .map_err(|error| format!("无法创建数据目录 {}：{error}", base.display()))?;
    let database = procnet_storage::Database::open(base.join("procnet.db"))
        .map_err(|error| format!("无法打开会话数据库：{error}"))?;
    procnet_application::RecordingController::start(std::sync::Arc::new(database), unix_nanos_now())
}

fn unix_nanos_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        })
}

fn parse_smoke_options(
    arguments: impl Iterator<Item = String>,
) -> (
    Option<std::time::Duration>,
    Option<std::path::PathBuf>,
    Option<std::path::PathBuf>,
    Option<String>,
    bool,
) {
    let arguments = arguments.collect::<Vec<_>>();
    let value_after = |flag: &str| {
        arguments
            .iter()
            .position(|value| value == flag)
            .and_then(|index| arguments.get(index + 1))
    };
    (
        value_after("--smoke-seconds").and_then(|value| bounded_smoke_duration(value)),
        value_after("--smoke-report").map(std::path::PathBuf::from),
        value_after("--screenshot").map(std::path::PathBuf::from),
        value_after("--page").cloned(),
        arguments.iter().any(|value| value == "--elevated-handoff"),
    )
}

fn bounded_smoke_duration(seconds: &str) -> Option<std::time::Duration> {
    seconds
        .parse::<u64>()
        .ok()
        .filter(|seconds| (1..=600).contains(seconds))
        .map(std::time::Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::parse_smoke_options;

    #[test]
    fn smoke_duration_is_explicitly_bounded() {
        assert_eq!(
            parse_smoke_options(["--smoke-seconds".to_owned(), "5".to_owned()].into_iter()).0,
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            parse_smoke_options(["--smoke-seconds".to_owned(), "0".to_owned()].into_iter()).0,
            None
        );
        assert_eq!(
            parse_smoke_options(["--smoke-seconds".to_owned(), "601".to_owned()].into_iter()).0,
            None
        );
        assert!(
            parse_smoke_options(["--elevated-handoff".to_owned()].into_iter()).4,
            "the elevated restart marker must reach the collector handoff"
        );
    }
}
