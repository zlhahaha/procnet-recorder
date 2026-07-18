use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::{fs, sync::Arc};

use eframe::egui::{self, Color32, RichText};
use egui_plot::{Legend, Line, Plot};
use procnet_application::{
    ApplicationSnapshot, CaptureRestriction, CaptureStatus, ConnectionOwnerStatus, ExportFormat,
    LiveRiskEvent, ProcessTrafficSnapshot, RecordingController, SessionUiState, V2Settings,
};
use procnet_core::{
    AlertKind, ProcessIconState, RiskLevel, SessionId, SessionRecord, SessionStatus,
};

use crate::collector::{CollectorHandle, CollectorUpdate};

const SEND_COLOR: Color32 = Color32::from_rgb(73, 155, 255);
const RECEIVE_COLOR: Color32 = Color32::from_rgb(55, 206, 159);
const DEFAULT_SESSION_CURVE_Y_MAX: u64 = 64 * 1_024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Overview,
    Processes,
    Connections,
    Sessions,
    Compare,
    Alerts,
    Settings,
    About,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessSort {
    Rate,
    Send,
    Receive,
    Connections,
}

enum ScreenshotState {
    Disabled,
    Pending(PathBuf),
    Requested(PathBuf),
    Saved,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VisualSeedState {
    Disabled,
    Pending,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionCurveMode {
    FollowLatest,
    Historical,
}

struct SessionCurveView {
    session_id: Option<SessionId>,
    start: usize,
    mode: SessionCurveMode,
    y_max: u64,
}

impl Default for SessionCurveView {
    fn default() -> Self {
        Self {
            session_id: None,
            start: 0,
            mode: SessionCurveMode::FollowLatest,
            y_max: DEFAULT_SESSION_CURVE_Y_MAX,
        }
    }
}

pub struct ProcNetApp {
    collector: CollectorHandle,
    snapshot: Option<ApplicationSnapshot>,
    error: Option<String>,
    page: Page,
    dark_mode: bool,
    search: String,
    process_sort: ProcessSort,
    selected_pid: Option<u32>,
    selected_connection: Option<usize>,
    close_at: Option<Instant>,
    icon_textures: BTreeMap<String, egui::TextureHandle>,
    smoke_reported: bool,
    smoke_report: Option<PathBuf>,
    elevation_error: Option<String>,
    last_system_capture: Option<u64>,
    system_refreshes: u64,
    recording: Option<RecordingController>,
    session_name: String,
    session_notes: String,
    compare_left: Option<SessionId>,
    compare_right: Option<SessionId>,
    settings_draft: V2Settings,
    last_settings_seen: V2Settings,
    export_message: Option<String>,
    pending_delete: Option<SessionRecord>,
    delete_message: Option<String>,
    session_curve: SessionCurveView,
    smoke_stop_requested: bool,
    screenshot: ScreenshotState,
    visual_seed: VisualSeedState,
    last_risk_event_id: u64,
    risk_popup: Option<(LiveRiskEvent, Instant)>,
}

impl ProcNetApp {
    pub fn new(
        context: &eframe::CreationContext<'_>,
        smoke_duration: Option<Duration>,
        smoke_report: Option<PathBuf>,
        screenshot_path: Option<PathBuf>,
        initial_page: Option<&str>,
        elevated_handoff: bool,
        recording: Result<RecordingController, String>,
    ) -> Self {
        context.egui_ctx.set_theme(egui::Theme::Light);
        context.egui_ctx.set_visuals(egui::Visuals::light());
        install_chinese_font(&context.egui_ctx);
        let (recording, storage_error, settings_draft) = match recording {
            Ok(recording) => {
                let settings = recording.state().settings;
                (Some(recording), None, settings)
            }
            Err(error) => (None, Some(error), V2Settings::default()),
        };
        if smoke_duration.is_some()
            && let Some(recording) = &recording
        {
            let _ = recording.start_recording(
                "V2 GUI Smoke".to_owned(),
                "Automatic GUI validation session".to_owned(),
                unix_nanos_now(),
            );
        }
        Self {
            collector: CollectorHandle::start(elevated_handoff),
            snapshot: None,
            error: storage_error,
            page: match initial_page {
                Some("processes") => Page::Processes,
                Some("connections") => Page::Connections,
                Some("sessions") => Page::Sessions,
                Some("compare") => Page::Compare,
                Some("alerts") => Page::Alerts,
                Some("settings") => Page::Settings,
                Some("about") => Page::About,
                _ => Page::Overview,
            },
            dark_mode: false,
            search: String::new(),
            process_sort: ProcessSort::Rate,
            selected_pid: None,
            selected_connection: None,
            close_at: smoke_duration.map(|duration| Instant::now() + duration),
            icon_textures: BTreeMap::new(),
            smoke_reported: false,
            smoke_report,
            elevation_error: None,
            last_system_capture: None,
            system_refreshes: 0,
            recording,
            session_name: String::new(),
            session_notes: String::new(),
            compare_left: None,
            compare_right: None,
            settings_draft,
            last_settings_seen: V2Settings::default(),
            export_message: None,
            pending_delete: None,
            delete_message: None,
            session_curve: SessionCurveView::default(),
            smoke_stop_requested: false,
            visual_seed: if screenshot_path.is_some() {
                VisualSeedState::Pending
            } else {
                VisualSeedState::Disabled
            },
            screenshot: screenshot_path.map_or(ScreenshotState::Disabled, ScreenshotState::Pending),
            last_risk_event_id: 0,
            risk_popup: None,
        }
    }

    fn seed_screenshot_page(&mut self) {
        if self.visual_seed != VisualSeedState::Pending {
            return;
        }
        let Some(recording) = &self.recording else {
            self.visual_seed = VisualSeedState::Disabled;
            return;
        };
        let state = recording.state();
        match self.page {
            Page::Sessions | Page::Alerts => {
                if state.selected.is_some() {
                    self.visual_seed = VisualSeedState::Disabled;
                } else if let Some(session) = state.sessions.first() {
                    let _ = recording.select(session.id);
                }
            }
            Page::Compare => {
                if state.compare_left.is_some() && state.compare_right.is_some() {
                    self.visual_seed = VisualSeedState::Disabled;
                } else if state.sessions.len() >= 2 {
                    self.compare_left = Some(state.sessions[0].id);
                    self.compare_right = Some(state.sessions[1].id);
                    let _ = recording.compare(state.sessions[0].id, state.sessions[1].id);
                }
            }
            _ => self.visual_seed = VisualSeedState::Disabled,
        }
    }

    fn receive_updates(&mut self, context: &egui::Context) {
        let updates = self.collector.receiver.try_iter().collect::<Vec<_>>();
        for update in updates {
            match update {
                CollectorUpdate::Snapshot(snapshot) => {
                    let captured_at = snapshot
                        .system
                        .as_ref()
                        .map(|system| system.captured_at_unix_nanos);
                    if captured_at.is_some() && captured_at != self.last_system_capture {
                        self.system_refreshes = self.system_refreshes.saturating_add(1);
                        self.last_system_capture = captured_at;
                    }
                    let snapshot = *snapshot;
                    if let Some(recording) = &self.recording {
                        recording.try_record(snapshot.clone());
                    }
                    self.snapshot = Some(snapshot);
                }
                CollectorUpdate::Error(error) => self.error = Some(error),
            }
        }
        if let Some(recording) = &self.recording {
            let state = recording.state();
            let persisted = state.settings;
            if self.settings_draft == self.last_settings_seen {
                self.settings_draft.clone_from(&persisted);
            }
            self.last_settings_seen = persisted;
            if let Some(event) = state
                .live_risk_events
                .iter()
                .rev()
                .find(|event| event.level == RiskLevel::High && event.id > self.last_risk_event_id)
                .cloned()
            {
                self.last_risk_event_id = event.id;
                self.risk_popup = Some((event, Instant::now()));
            }
        }
        self.refresh_icon_textures(context);
    }

    fn refresh_icon_textures(&mut self, context: &egui::Context) {
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        for process in &snapshot.process_traffic {
            let (Some(path), ProcessIconState::Available(icon)) =
                (process.image_path.as_ref(), &process.icon)
            else {
                continue;
            };
            if self.icon_textures.contains_key(path) {
                continue;
            }
            let size = [
                usize::try_from(icon.width).unwrap_or(1),
                usize::try_from(icon.height).unwrap_or(1),
            ];
            if size[0].saturating_mul(size[1]).saturating_mul(4) != icon.rgba.len() {
                continue;
            }
            let texture = context.load_texture(
                format!("process-icon:{path}"),
                egui::ColorImage::from_rgba_unmultiplied(size, icon.rgba.as_ref()),
                egui::TextureOptions::LINEAR,
            );
            self.icon_textures.insert(path.clone(), texture);
        }
    }

    fn sidebar(&mut self, root: &mut egui::Ui) {
        let panel_frame = egui::Frame::side_top_panel(root.style()).inner_margin(18.0);
        egui::Panel::left("navigation")
            .resizable(false)
            .exact_size(190.0)
            .frame(panel_frame)
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                    ui.painter()
                        .circle_filled(rect.center(), 6.0, RECEIVE_COLOR);
                    ui.label(RichText::new("ProcNet").size(22.0).strong());
                });
                ui.label(RichText::new("Recorder").color(ui.visuals().weak_text_color()));
                ui.add_space(24.0);
                navigation_button(ui, &mut self.page, Page::Overview, "总览");
                navigation_button(ui, &mut self.page, Page::Processes, "进程");
                navigation_button(ui, &mut self.page, Page::Connections, "连接");
                ui.add_space(8.0);
                navigation_button(ui, &mut self.page, Page::Sessions, "历史会话");
                navigation_button(ui, &mut self.page, Page::Compare, "会话对比");
                navigation_button(ui, &mut self.page, Page::Alerts, "提醒");
                ui.add_space(8.0);
                navigation_button(ui, &mut self.page, Page::Settings, "设置");
                navigation_button(ui, &mut self.page, Page::About, "关于");
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    if ui
                        .button(if self.dark_mode {
                            "☀ 浅色模式"
                        } else {
                            "☾ 深色模式"
                        })
                        .clicked()
                    {
                        self.dark_mode = !self.dark_mode;
                        ui.ctx().set_theme(if self.dark_mode {
                            egui::Theme::Dark
                        } else {
                            egui::Theme::Light
                        });
                    }
                    ui.label(RichText::new("V2 · 实时录制与历史分析").small().weak());
                });
            });
    }

    fn top_bar(&mut self, root: &mut egui::Ui) {
        let panel_frame = egui::Frame::side_top_panel(root.style()).inner_margin(14.0);
        egui::Panel::top("top_bar")
            .exact_size(72.0)
            .frame(panel_frame)
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    ui.heading(match self.page {
                        Page::Overview => "网络总览",
                        Page::Processes => "进程流量",
                        Page::Connections => "连接详情",
                        Page::Sessions => "历史会话",
                        Page::Compare => "会话对比",
                        Page::Alerts => "本地提醒",
                        Page::Settings => "设置",
                        Page::About => "关于 ProcNet Recorder",
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (label, color, fill) = self.snapshot.as_ref().map_or(
                            (
                                "正在初始化",
                                Color32::from_rgb(105, 72, 0),
                                Color32::from_rgb(255, 242, 204),
                            ),
                            |snapshot| match snapshot.capture_status {
                                CaptureStatus::Available => (
                                    "● 正在采集",
                                    Color32::from_rgb(18, 112, 79),
                                    Color32::from_rgb(220, 247, 237),
                                ),
                                CaptureStatus::Restricted(_) => (
                                    "● 受限模式",
                                    Color32::from_rgb(128, 78, 0),
                                    Color32::from_rgb(255, 239, 199),
                                ),
                            },
                        );
                        egui::Frame::new()
                            .fill(fill)
                            .corner_radius(999.0)
                            .inner_margin(egui::Margin::symmetric(12, 6))
                            .show(ui, |ui| {
                                ui.label(RichText::new(label).color(color).strong());
                            });
                    });
                });
            });
    }

    fn content(&mut self, root: &mut egui::Ui) {
        let panel_frame = egui::Frame::central_panel(root.style()).inner_margin(18.0);
        egui::CentralPanel::default()
            .frame(panel_frame)
            .show(root, |ui| {
                if let Some(error) = &self.error {
                    warning_banner(ui, "采集错误", error, Color32::from_rgb(185, 65, 65));
                }
                let Some(snapshot) = self.snapshot.clone() else {
                    ui.vertical_centered(|ui| {
                        ui.add_space(ui.available_height() * 0.35);
                        ui.spinner();
                        ui.heading("正在准备本机网络视图");
                        ui.label(RichText::new("正在读取进程、连接并启动网络采集…").weak());
                    });
                    return;
                };
                if let CaptureStatus::Restricted(reason) = snapshot.capture_status {
                    let detail = match reason {
                        CaptureRestriction::PermissionRequired => {
                            "当前没有管理员或 Performance Log Users 权限。进程与连接仍可查看，实时流量暂不可用。"
                        }
                        CaptureRestriction::SessionAlreadyExists => {
                            "本项目采集 Session 已存在。界面保持只读受限模式，不会停止其他 ETW Session。"
                        }
                    };
                    self.restricted_banner(ui, detail);
                }
                if snapshot.events_dropped_full != 0 || snapshot.events_dropped_stopped != 0 {
                    warning_banner(
                        ui,
                        "事件丢失",
                        &format!(
                            "队列已满丢失 {}，停止后到达 {}。",
                            snapshot.events_dropped_full, snapshot.events_dropped_stopped
                        ),
                        Color32::from_rgb(185, 65, 65),
                    );
                }
                match self.page {
                    Page::Overview => self.overview(ui, &snapshot),
                    Page::Processes => self.processes(ui, &snapshot),
                    Page::Connections => self.connections(ui, &snapshot),
                    Page::Sessions => self.sessions(ui),
                    Page::Compare => self.session_compare(ui),
                    Page::Alerts => self.alerts(ui),
                    Page::Settings => self.settings(ui),
                    Page::About => Self::about(ui),
                }
            });
    }

    fn overview(&mut self, ui: &mut egui::Ui, snapshot: &ApplicationSnapshot) {
        ui.horizontal_wrapped(|ui| {
            metric_card(
                ui,
                "上传速度",
                &format_rate(snapshot.network_rate.send_bytes_per_second),
                SEND_COLOR,
            );
            metric_card(
                ui,
                "下载速度",
                &format_rate(snapshot.network_rate.receive_bytes_per_second),
                RECEIVE_COLOR,
            );
            metric_card(
                ui,
                "活跃进程",
                &snapshot.process_traffic.len().to_string(),
                Color32::from_rgb(170, 125, 245),
            );
            metric_card(
                ui,
                "当前连接",
                &snapshot.connection_details.len().to_string(),
                Color32::from_rgb(245, 166, 73),
            );
        });
        ui.add_space(10.0);
        egui::Frame::group(ui.style())
            .inner_margin(14.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.strong("最近 60 秒流量");
                    ui.label(RichText::new("蓝色上传 · 绿色下载").small().weak());
                });
                let send = snapshot
                    .recent_60_seconds
                    .buckets
                    .iter()
                    .enumerate()
                    .map(|(index, bucket)| [plot_index(index), plot_bytes(bucket.send_bytes)])
                    .collect::<Vec<_>>();
                let receive = snapshot
                    .recent_60_seconds
                    .buckets
                    .iter()
                    .enumerate()
                    .map(|(index, bucket)| [plot_index(index), plot_bytes(bucket.receive_bytes)])
                    .collect::<Vec<_>>();
                Plot::new("traffic_curve")
                    .height(245.0)
                    .show_axes([false, true])
                    .allow_drag(false)
                    .allow_zoom(false)
                    .legend(Legend::default())
                    .show(ui, |plot| {
                        plot.line(Line::new("上传", send).color(SEND_COLOR).width(2.0));
                        plot.line(Line::new("下载", receive).color(RECEIVE_COLOR).width(2.0));
                    });
            });
        ui.add_space(10.0);
        ui.strong("实时进程排行");
        process_table(
            ui,
            &snapshot.process_traffic,
            &self.search,
            self.process_sort,
            &mut self.selected_pid,
            &self.icon_textures,
            8,
        );
    }

    fn processes(&mut self, ui: &mut egui::Ui, snapshot: &ApplicationSnapshot) {
        ui.horizontal(|ui| {
            ui.label("搜索");
            ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("进程名、路径或 PID")
                    .desired_width(280.0),
            );
            ui.separator();
            sort_button(ui, &mut self.process_sort, ProcessSort::Rate, "总速率");
            sort_button(ui, &mut self.process_sort, ProcessSort::Send, "上传");
            sort_button(ui, &mut self.process_sort, ProcessSort::Receive, "下载");
            sort_button(
                ui,
                &mut self.process_sort,
                ProcessSort::Connections,
                "连接数",
            );
        });
        ui.separator();
        process_table(
            ui,
            &snapshot.process_traffic,
            &self.search,
            self.process_sort,
            &mut self.selected_pid,
            &self.icon_textures,
            usize::MAX,
        );
        if let Some(pid) = self.selected_pid
            && let Some(process) = snapshot.process_traffic.iter().find(|row| row.pid == pid)
        {
            let mut detail_open = true;
            egui::Window::new("进程详情")
                .id(egui::Id::new(("process_detail_window", pid)))
                .anchor(egui::Align2::RIGHT_TOP, egui::vec2(-24.0, 96.0))
                .default_width(420.0)
                .resizable(true)
                .collapsible(true)
                .open(&mut detail_open)
                .show(ui.ctx(), |ui| process_detail(ui, process));
            if !detail_open {
                self.selected_pid = None;
            }
        }
    }

    fn connections(&mut self, ui: &mut egui::Ui, snapshot: &ApplicationSnapshot) {
        ui.horizontal(|ui| {
            ui.label("筛选");
            ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("进程、地址、端口或 PID")
                    .desired_width(320.0),
            );
        });
        ui.separator();
        let needle = self.search.to_lowercase();
        let table_width = ui.available_width();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let width = table_width;
                let columns = [
                    width * 0.07,
                    width * 0.20,
                    width * 0.08,
                    width * 0.23,
                    width * 0.27,
                    width * 0.15,
                ];
                egui::Grid::new("connections_table")
                    .striped(true)
                    .spacing([0.0, 2.0])
                    .show(ui, |ui| {
                        for (heading, width) in
                            ["协议", "进程", "PID", "本地地址", "远程地址", "状态"]
                                .into_iter()
                                .zip(columns)
                        {
                            table_cell(ui, width, 30.0, |ui| {
                                ui.label(RichText::new(heading).strong());
                            });
                        }
                        ui.end_row();
                        for (index, detail) in snapshot.connection_details.iter().enumerate() {
                            let connection = &detail.connection;
                            let searchable = format!(
                                "{} {} {} {:?}",
                                detail.process_name.as_deref().unwrap_or(""),
                                connection.pid,
                                connection.local,
                                connection.remote
                            )
                            .to_lowercase();
                            if !needle.is_empty() && !searchable.contains(&needle) {
                                continue;
                            }
                            connection_data_row(
                                ui,
                                index,
                                detail,
                                columns,
                                &mut self.selected_connection,
                            );
                        }
                    });
            });
        if snapshot.connection_details.is_empty() {
            empty_state(ui, "暂无连接", "等待系统连接表出现 TCP 或 UDP 端点。");
        }
    }

    fn session_state(&self) -> SessionUiState {
        self.recording
            .as_ref()
            .map_or_else(SessionUiState::default, RecordingController::state)
    }

    #[allow(clippy::too_many_lines)]
    fn sessions(&mut self, ui: &mut egui::Ui) {
        let state = self.session_state();
        if let Some(error) = &state.last_error {
            warning_banner(ui, "历史保存错误", error, Color32::from_rgb(185, 65, 65));
        }
        let recording_card_width = ui.available_width();
        surface_frame(ui).show(ui, |ui| {
            ui.set_min_width((recording_card_width - 34.0).max(200.0));
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(if state.active.is_some() {
                        "正在录制"
                    } else {
                        "新建录制会话"
                    })
                    .size(18.0)
                    .strong(),
                );
                if let Some(active) = &state.active {
                    ui.label(
                        RichText::new(format!("#{}  {}", active.id, active.name))
                            .color(RECEIVE_COLOR)
                            .strong(),
                    );
                    if ui.button("停止并保存").clicked()
                        && let Some(recording) = &self.recording
                    {
                        let _ = recording.stop_recording(unix_nanos_now());
                    }
                }
            });
            if state.active.is_none() {
                ui.add_space(8.0);
                ui.columns(2, |columns| {
                    columns[0].label(RichText::new("会话名称").small().weak());
                    columns[0].add(
                        egui::TextEdit::singleline(&mut self.session_name)
                            .hint_text("例如：发布演示录制")
                            .desired_width(f32::INFINITY),
                    );
                    columns[1].label(RichText::new("备注").small().weak());
                    columns[1].add(
                        egui::TextEdit::singleline(&mut self.session_notes)
                            .hint_text("可选")
                            .desired_width(f32::INFINITY),
                    );
                });
                ui.add_space(8.0);
                if ui
                    .add_enabled(self.recording.is_some(), egui::Button::new("开始录制"))
                    .clicked()
                    && let Some(recording) = &self.recording
                {
                    let _ = recording.start_recording(
                        self.session_name.clone(),
                        self.session_notes.clone(),
                        unix_nanos_now(),
                    );
                }
            }
            if state.persistence_queue_dropped > 0 {
                history_save_warning(ui, state.persistence_queue_dropped);
            }
        });
        ui.add_space(12.0);
        let max_master_height = (ui.available_height() * 0.62).max(210.0);
        egui::Panel::top("session_history_master")
            .resizable(true)
            .default_size(280.0)
            .size_range(190.0..=max_master_height)
            .show_separator_line(true)
            .frame(
                surface_frame(ui)
                    .inner_margin(12.0)
                    .outer_margin(egui::Margin {
                        left: 0,
                        right: 0,
                        top: 0,
                        bottom: 7,
                    }),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("历史会话  {}", state.sessions.len()))
                            .size(17.0)
                            .strong(),
                    );
                    if ui.button("刷新").clicked()
                        && let Some(recording) = &self.recording
                    {
                        let _ = recording.refresh();
                    }
                    if state.recovered_sessions > 0 {
                        ui.label(
                            RichText::new(format!(
                                "已恢复 {} 个异常中断会话",
                                state.recovered_sessions
                            ))
                            .color(Color32::from_rgb(151, 96, 0)),
                        );
                    }
                    if let Some(message) = &self.delete_message {
                        ui.label(RichText::new(message).small().weak());
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new("北京时间 · 拖动中间分割线调整区域")
                                .small()
                                .weak(),
                        );
                    });
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let width = ui.available_width();
                        let columns = [
                            width * 0.20,
                            width * 0.09,
                            width * 0.09,
                            width * 0.09,
                            width * 0.16,
                            width * 0.16,
                            width * 0.09,
                            width * 0.12,
                        ];
                        egui::Grid::new("session_history")
                            .striped(true)
                            .spacing([0.0, 3.0])
                            .show(ui, |ui| {
                                for (heading, width) in [
                                    "名称",
                                    "状态",
                                    "上传",
                                    "下载",
                                    "开始时间",
                                    "结束时间",
                                    "持续时长",
                                    "操作",
                                ]
                                .into_iter()
                                .zip(columns)
                                {
                                    table_cell(ui, width, 30.0, |ui| {
                                        ui.strong(heading);
                                    });
                                }
                                ui.end_row();
                                for session in &state.sessions {
                                    table_text_cell(ui, columns[0], &session.name);
                                    table_text_cell(
                                        ui,
                                        columns[1],
                                        session_status_label(session.status),
                                    );
                                    table_text_cell(
                                        ui,
                                        columns[2],
                                        &format_bytes(session.send_bytes),
                                    );
                                    table_text_cell(
                                        ui,
                                        columns[3],
                                        &format_bytes(session.receive_bytes),
                                    );
                                    table_text_cell(
                                        ui,
                                        columns[4],
                                        &format_timestamp(session.started_at_unix_nanos),
                                    );
                                    table_text_cell(
                                        ui,
                                        columns[5],
                                        &session
                                            .ended_at_unix_nanos
                                            .map_or_else(|| "进行中".to_owned(), format_timestamp),
                                    );
                                    table_text_cell(
                                        ui,
                                        columns[6],
                                        &format_duration(
                                            session.started_at_unix_nanos,
                                            session
                                                .ended_at_unix_nanos
                                                .unwrap_or_else(unix_nanos_now),
                                        ),
                                    );
                                    table_cell(ui, columns[7], 24.0, |ui| {
                                        if ui.button("详情").clicked()
                                            && let Some(recording) = &self.recording
                                        {
                                            let _ = recording.select(session.id);
                                        }
                                        if ui
                                            .add_enabled(
                                                session.status != SessionStatus::Recording,
                                                egui::Button::new(
                                                    RichText::new("删除")
                                                        .color(Color32::from_rgb(185, 65, 65)),
                                                ),
                                            )
                                            .clicked()
                                        {
                                            self.pending_delete = Some(session.clone());
                                            self.delete_message = None;
                                        }
                                    });
                                    ui.end_row();
                                }
                            });
                    });
            });
        let selected = state.selected.clone();
        egui::ScrollArea::vertical()
            .id_salt("session_detail_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if let Some(detail) = &selected {
                    surface_frame(ui)
                        .outer_margin(egui::Margin {
                            left: 0,
                            right: 0,
                            top: 7,
                            bottom: 0,
                        })
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(&detail.session.name).size(20.0).strong(),
                                    );
                                    ui.label(
                                        RichText::new(format!(
                                            "{} · {} 个采样点 · {} 条提醒",
                                            session_status_label(detail.session.status),
                                            detail.buckets.len(),
                                            detail.alerts.len()
                                        ))
                                        .weak(),
                                    );
                                    ui.label(
                                        RichText::new(format!(
                                            "开始 {}  ·  结束 {}  ·  持续 {}",
                                            format_timestamp(detail.session.started_at_unix_nanos),
                                            detail.session.ended_at_unix_nanos.map_or_else(
                                                || "进行中".to_owned(),
                                                format_timestamp,
                                            ),
                                            format_duration(
                                                detail.session.started_at_unix_nanos,
                                                detail
                                                    .session
                                                    .ended_at_unix_nanos
                                                    .unwrap_or_else(unix_nanos_now),
                                            )
                                        ))
                                        .small()
                                        .weak(),
                                    );
                                });
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        for (label, format, extension) in [
                                            ("导出 Markdown", ExportFormat::Markdown, "md"),
                                            ("导出 CSV", ExportFormat::Csv, "csv"),
                                            ("导出 JSON", ExportFormat::Json, "json"),
                                        ] {
                                            if ui.button(label).clicked()
                                                && let Some(recording) = &self.recording
                                            {
                                                let path =
                                                    export_path(detail.session.id, extension);
                                                match recording.export_session(
                                                    detail.session.id,
                                                    format,
                                                    path.clone(),
                                                ) {
                                                    Ok(()) => {
                                                        self.export_message = Some(format!(
                                                            "已提交导出：{}",
                                                            path.display()
                                                        ));
                                                    }
                                                    Err(error) => self.export_message = Some(error),
                                                }
                                            }
                                        }
                                    },
                                );
                            });
                            ui.add_space(12.0);
                            metric_grid(
                                ui,
                                &[
                                    ("上传", format_bytes(detail.session.send_bytes), SEND_COLOR),
                                    (
                                        "下载",
                                        format_bytes(detail.session.receive_bytes),
                                        RECEIVE_COLOR,
                                    ),
                                    (
                                        "进程",
                                        detail.processes.len().to_string(),
                                        Color32::from_rgb(145, 94, 220),
                                    ),
                                    (
                                        "远程端点",
                                        detail.endpoints.len().to_string(),
                                        Color32::from_rgb(213, 126, 34),
                                    ),
                                ],
                            );
                            ui.add_space(10.0);
                            ui.label(format!(
                                "备注：{}",
                                if detail.session.notes.is_empty() {
                                    "—"
                                } else {
                                    &detail.session.notes
                                }
                            ));
                        });
                    ui.add_space(10.0);
                    self.session_curve(ui, detail);
                    ui.add_space(10.0);
                    ui.columns(2, |columns| {
                        session_process_card(&mut columns[0], detail);
                        session_endpoint_card(&mut columns[1], detail);
                    });
                    if let Some(message) = &self.export_message {
                        ui.add_space(8.0);
                        ui.label(RichText::new(message).weak());
                    }
                } else {
                    surface_frame(ui).show(ui, |ui| {
                        ui.set_min_height(180.0);
                        empty_state(
                            ui,
                            "选择一个历史会话",
                            "详情、趋势、进程和端点会在这里完整展开。",
                        );
                    });
                }
            });
        self.delete_session_dialog(ui.ctx());
    }

    fn session_curve(&mut self, ui: &mut egui::Ui, detail: &procnet_core::SessionDetail) {
        const WINDOW_BUCKETS: usize = 60;
        if self.session_curve.session_id != Some(detail.session.id) {
            self.session_curve = SessionCurveView {
                session_id: Some(detail.session.id),
                ..SessionCurveView::default()
            };
        }

        let maximum_start = detail.buckets.len().saturating_sub(WINDOW_BUCKETS);
        self.session_curve.start = session_window_start(
            detail.buckets.len(),
            self.session_curve.start,
            self.session_curve.mode == SessionCurveMode::FollowLatest,
        );
        let peak = detail
            .buckets
            .iter()
            .map(|bucket| bucket.send_bytes.max(bucket.receive_bytes))
            .max()
            .unwrap_or(0);
        self.session_curve.y_max = self
            .session_curve
            .y_max
            .max(nice_curve_ceiling(peak.max(DEFAULT_SESSION_CURVE_Y_MAX)));

        let end = self
            .session_curve
            .start
            .saturating_add(WINDOW_BUCKETS)
            .min(detail.buckets.len());
        let visible = &detail.buckets[self.session_curve.start..end];
        let send = visible
            .iter()
            .enumerate()
            .map(|(index, bucket)| [plot_index(index), plot_bytes(bucket.send_bytes)])
            .collect::<Vec<_>>();
        let receive = visible
            .iter()
            .enumerate()
            .map(|(index, bucket)| [plot_index(index), plot_bytes(bucket.receive_bytes)])
            .collect::<Vec<_>>();
        let range_start = visible
            .first()
            .map_or(detail.session.started_at_unix_nanos, |bucket| {
                bucket.start_unix_nanos
            });
        let range_end = visible
            .last()
            .map_or(range_start, |bucket| bucket.start_unix_nanos);
        let y_max = plot_bytes(self.session_curve.y_max);

        surface_frame(ui).show(ui, |ui| {
            if session_curve_header(
                ui,
                detail.buckets.len(),
                visible.len(),
                self.session_curve.y_max,
                self.session_curve.mode,
            ) {
                self.session_curve.mode = SessionCurveMode::FollowLatest;
                self.session_curve.start = maximum_start;
            }
            Plot::new(format!("session_curve_{}", detail.session.id.0))
                .height(225.0)
                .allow_drag(false)
                .allow_zoom(false)
                .allow_scroll(false)
                .show_axes([true, true])
                .x_axis_formatter(|mark, _| format_session_x_axis(mark.value))
                .y_axis_formatter(|mark, _| format_plot_rate(mark.value))
                .legend(Legend::default())
                .show(ui, |plot| {
                    plot.set_plot_bounds_x(0.0..=plot_index(WINDOW_BUCKETS - 1));
                    plot.set_plot_bounds_y(0.0..=y_max);
                    plot.line(Line::new("上传", send).color(SEND_COLOR).width(2.0));
                    plot.line(Line::new("下载", receive).color(RECEIVE_COLOR).width(2.0));
                });

            let slider = egui::Slider::new(&mut self.session_curve.start, 0..=maximum_start)
                .show_value(false)
                .trailing_fill(true);
            let response = ui.add_enabled_ui(maximum_start > 0, |ui| {
                ui.add_sized([ui.available_width(), 20.0], slider)
            });
            if response.inner.changed() {
                self.session_curve.mode = if self.session_curve.start == maximum_start {
                    SessionCurveMode::FollowLatest
                } else {
                    SessionCurveMode::Historical
                };
            }
            ui.horizontal(|ui| {
                ui.label(RichText::new(format_timestamp(range_start)).small().weak());
                ui.label(RichText::new("← 拖动时间轴查看历史 →").small().weak());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(format_timestamp(range_end)).small().weak());
                });
            });
        });
    }

    fn delete_session_dialog(&mut self, context: &egui::Context) {
        let Some(session) = self.pending_delete.clone() else {
            return;
        };
        let mut cancel = false;
        let mut confirm = false;
        egui::Window::new("删除历史会话")
            .id(egui::Id::new("delete_session_confirmation"))
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .default_width(460.0)
            .show(context, |ui| {
                ui.label(RichText::new(&session.name).size(18.0).strong());
                ui.label(
                    RichText::new(format!(
                        "{} → {} · {}",
                        format_timestamp(session.started_at_unix_nanos),
                        session
                            .ended_at_unix_nanos
                            .map_or_else(|| "进行中".to_owned(), format_timestamp),
                        format_duration(
                            session.started_at_unix_nanos,
                            session.ended_at_unix_nanos.unwrap_or_else(unix_nanos_now),
                        )
                    ))
                    .weak(),
                );
                ui.add_space(10.0);
                ui.label("该操作会删除此会话以及关联的采样、进程、端点和提醒记录，且无法撤销。");
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    if ui.button("取消").clicked() {
                        cancel = true;
                    }
                    if ui
                        .add(
                            egui::Button::new(RichText::new("确认删除").color(Color32::WHITE))
                                .fill(Color32::from_rgb(185, 65, 65)),
                        )
                        .clicked()
                    {
                        confirm = true;
                    }
                });
            });
        if cancel {
            self.pending_delete = None;
        }
        if confirm {
            if let Some(recording) = &self.recording {
                match recording.delete_session(session.id) {
                    Ok(()) => {
                        self.delete_message = Some(format!("已提交删除：“{}”", session.name));
                        if self.compare_left == Some(session.id) {
                            self.compare_left = None;
                        }
                        if self.compare_right == Some(session.id) {
                            self.compare_right = None;
                        }
                    }
                    Err(error) => self.delete_message = Some(error),
                }
            }
            self.pending_delete = None;
        }
    }

    fn session_compare(&mut self, ui: &mut egui::Ui) {
        let state = self.session_state();
        surface_frame(ui).show(ui, |ui| {
            ui.label(RichText::new("选择对比会话").size(19.0).strong());
            ui.label(RichText::new("并排查看总流量、进程、端点与提醒差异。").weak());
            ui.add_space(12.0);
            ui.columns(2, |columns| {
                columns[0].label(RichText::new("基准会话 A").small().weak());
                egui::ComboBox::from_id_salt("compare_session_a")
                    .selected_text(session_name_for(&state, self.compare_left))
                    .width(columns[0].available_width())
                    .show_ui(&mut columns[0], |ui| {
                        for session in &state.sessions {
                            ui.selectable_value(
                                &mut self.compare_left,
                                Some(session.id),
                                format!(
                                    "{}  ·  {}",
                                    session.name,
                                    format_timestamp(session.started_at_unix_nanos)
                                ),
                            );
                        }
                    });
                columns[1].label(RichText::new("对比会话 B").small().weak());
                egui::ComboBox::from_id_salt("compare_session_b")
                    .selected_text(session_name_for(&state, self.compare_right))
                    .width(columns[1].available_width())
                    .show_ui(&mut columns[1], |ui| {
                        for session in &state.sessions {
                            ui.selectable_value(
                                &mut self.compare_right,
                                Some(session.id),
                                format!(
                                    "{}  ·  {}",
                                    session.name,
                                    format_timestamp(session.started_at_unix_nanos)
                                ),
                            );
                        }
                    });
            });
            ui.add_space(12.0);
            let enabled = self.compare_left.is_some()
                && self.compare_right.is_some()
                && self.compare_left != self.compare_right;
            if ui
                .add_enabled(enabled, egui::Button::new("生成对比视图"))
                .clicked()
                && let (Some(left), Some(right), Some(recording)) =
                    (self.compare_left, self.compare_right, &self.recording)
            {
                let _ = recording.compare(left, right);
            }
        });
        ui.add_space(12.0);
        if let (Some(left), Some(right)) = (&state.compare_left, &state.compare_right) {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.columns(2, |columns| {
                        compare_session_summary(&mut columns[0], "会话 A", left, SEND_COLOR);
                        compare_session_summary(&mut columns[1], "会话 B", right, RECEIVE_COLOR);
                    });
                    ui.add_space(10.0);
                    compare_metrics_table(ui, left, right);
                });
        } else {
            surface_frame(ui).show(ui, |ui| {
                ui.set_min_height((ui.available_height() - 24.0).max(240.0));
                empty_state(
                    ui,
                    "等待选择两个会话",
                    "选择不同会话后，对比结果会平铺在整个内容区域。",
                );
            });
        }
    }

    #[allow(clippy::too_many_lines)]
    fn alerts(&mut self, ui: &mut egui::Ui) {
        let state = self.session_state();
        let live_list_height = (ui.available_height() * 0.25).clamp(130.0, 200.0);
        surface_frame(ui).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("实时风险事件").size(19.0).strong());
                ui.label(
                    RichText::new(format!("最近 {} 条", state.live_risk_events.len()))
                        .small()
                        .weak(),
                );
            });
            ui.label(
                RichText::new(
                    "GUI运行期间持续评估；高风险会立即提示，并自动保存异常前最多2分钟与后续1分钟。",
                )
                .weak(),
            );
            ui.add_space(8.0);
            if state.live_risk_events.is_empty() {
                ui.label(RichText::new("尚未发现需要记录的网络行为变化。").weak());
            } else {
                egui::ScrollArea::vertical()
                    .id_salt("live_risk_event_scroll")
                    .max_height(live_list_height)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        for event in state.live_risk_events.iter().rev() {
                            let (level, color) = risk_level_style(event.level);
                            ui.horizontal_wrapped(|ui| {
                                ui.label(RichText::new(level).color(color).strong());
                                ui.label(RichText::new(format!("{} 分", event.score)).color(color));
                                ui.label(RichText::new(&event.process_name).strong());
                                ui.label(&event.detail);
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            RichText::new(format_timestamp(
                                                event.occurred_at_unix_nanos,
                                            ))
                                            .small()
                                            .weak(),
                                        );
                                    },
                                );
                            });
                            ui.separator();
                        }
                    });
            }
        });
        ui.add_space(8.0);
        surface_frame(ui).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("会话归档提醒").size(17.0).strong());
                ui.add_space(10.0);
                egui::ComboBox::from_id_salt("alert_session")
                    .selected_text(
                        state
                            .selected
                            .as_ref()
                            .map_or("选择会话", |detail| detail.session.name.as_str()),
                    )
                    .width(ui.available_width())
                    .show_ui(ui, |ui| {
                        for session in &state.sessions {
                            if ui
                                .selectable_label(
                                    state
                                        .selected
                                        .as_ref()
                                        .is_some_and(|detail| detail.session.id == session.id),
                                    &session.name,
                                )
                                .clicked()
                                && let Some(recording) = &self.recording
                            {
                                let _ = recording.select(session.id);
                            }
                        }
                    });
            });
            ui.label(
                RichText::new("归档提醒保存在本机，并跟随所属会话导出。")
                    .small()
                    .weak(),
            );
        });
        ui.add_space(8.0);
        if let Some(detail) = &state.selected {
            let has_scored_events = detail
                .alerts
                .iter()
                .any(|alert| alert.kind == AlertKind::RiskEvent);
            let visible_alerts = detail
                .alerts
                .iter()
                .filter(|alert| !has_scored_events || alert.kind == AlertKind::RiskEvent)
                .collect::<Vec<_>>();
            let hidden_legacy = detail.alerts.len().saturating_sub(visible_alerts.len());
            ui.horizontal(|ui| {
                ui.label(RichText::new(&detail.session.name).size(18.0).strong());
                ui.label(RichText::new(format!("{} 条提醒", visible_alerts.len())).weak());
                if hidden_legacy > 0 {
                    ui.label(
                        RichText::new(format!("已隐藏 {hidden_legacy} 条旧版重复记录"))
                            .small()
                            .weak(),
                    );
                }
            });
            ui.add_space(8.0);
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for alert in &visible_alerts {
                        surface_frame(ui).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&alert.title).size(16.0).strong());
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            RichText::new(format_timestamp(
                                                alert.occurred_at_unix_nanos,
                                            ))
                                            .small()
                                            .weak(),
                                        );
                                    },
                                );
                            });
                            ui.add_space(5.0);
                            ui.label(&alert.detail);
                            if let Some(process) = &alert.process_name {
                                ui.label(RichText::new(format!("进程  {process}")).small().weak());
                            }
                            if let Some(remote) = &alert.remote_address {
                                ui.label(
                                    RichText::new(format!("远程端点  {remote}")).small().weak(),
                                );
                            }
                        });
                        ui.add_space(8.0);
                    }
                    if visible_alerts.is_empty() {
                        surface_frame(ui).show(ui, |ui| {
                            ui.set_min_height(240.0);
                            empty_state(ui, "暂无提醒", "该会话没有触发本地提醒规则。");
                        });
                    }
                });
        } else {
            surface_frame(ui).show(ui, |ui| {
                ui.set_min_height((ui.available_height() - 20.0).max(260.0));
                empty_state(ui, "选择一个会话", "提醒将按时间完整显示在这里。");
            });
        }
    }

    fn risk_popup(&mut self, context: &egui::Context) {
        let Some((event, shown_at)) = self.risk_popup.clone() else {
            return;
        };
        if shown_at.elapsed() >= Duration::from_secs(10) {
            self.risk_popup = None;
            return;
        }
        egui::Area::new(egui::Id::new("high_risk_notification"))
            .anchor(egui::Align2::RIGHT_TOP, egui::vec2(-24.0, 92.0))
            .order(egui::Order::Foreground)
            .show(context, |ui| {
                egui::Frame::new()
                    .fill(Color32::from_rgb(255, 241, 238))
                    .stroke(egui::Stroke::new(1.5, Color32::from_rgb(196, 61, 54)))
                    .corner_radius(12.0)
                    .shadow(egui::epaint::Shadow {
                        offset: [0, 4],
                        blur: 16,
                        spread: 0,
                        color: Color32::from_black_alpha(45),
                    })
                    .inner_margin(egui::Margin::same(16))
                    .show(ui, |ui| {
                        ui.set_width(380.0);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("高风险网络活动")
                                    .size(17.0)
                                    .strong()
                                    .color(Color32::from_rgb(145, 35, 31)),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    ui.label(
                                        RichText::new(format!("{} 分", event.score))
                                            .strong()
                                            .color(Color32::from_rgb(145, 35, 31)),
                                    );
                                },
                            );
                        });
                        ui.add_space(5.0);
                        ui.label(
                            RichText::new(&event.process_name)
                                .strong()
                                .color(Color32::from_rgb(58, 45, 43)),
                        );
                        ui.label(RichText::new(&event.detail).color(Color32::from_rgb(77, 60, 57)));
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if ui.button("查看提醒").clicked() {
                                self.page = Page::Alerts;
                                self.risk_popup = None;
                            }
                            if ui.button("关闭").clicked() {
                                self.risk_popup = None;
                            }
                            ui.label(
                                RichText::new("正在自动保留事件现场")
                                    .small()
                                    .color(Color32::from_rgb(145, 35, 31)),
                            );
                        });
                    });
            });
    }

    #[allow(clippy::too_many_lines)]
    fn settings(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.columns(2, |columns| {
                    surface_frame(&columns[0]).show(&mut columns[0], |ui| {
                        settings_heading(ui, "数据保留", "控制本机历史数据库的保留周期。");
                        ui.add_space(12.0);
                        labeled_value(ui, "保留天数", |ui| {
                            ui.add(
                                egui::DragValue::new(&mut self.settings_draft.retention_days)
                                    .range(1..=3650),
                            );
                        });
                        ui.add_space(16.0);
                        if ui
                            .add_enabled(
                                self.recording.is_some(),
                                egui::Button::new("立即执行保留策略"),
                            )
                            .clicked()
                            && let Some(recording) = &self.recording
                        {
                            let _ = recording.apply_retention(unix_nanos_now());
                        }
                    });
                    surface_frame(&columns[1]).show(&mut columns[1], |ui| {
                        settings_heading(ui, "提醒事件", "选择需要记录到会话中的变化。");
                        ui.add_space(12.0);
                        ui.checkbox(&mut self.settings_draft.alert_new_process, "新进程开始联网");
                        ui.checkbox(
                            &mut self.settings_draft.alert_new_endpoint,
                            "发现新远程端点",
                        );
                    });
                });
                ui.add_space(10.0);
                let threshold_width = ui.available_width();
                surface_frame(ui).show(ui, |ui| {
                    ui.set_min_width((threshold_width - 34.0).max(200.0));
                    settings_heading(
                        ui,
                        "检测参数",
                        "以下参数可调整并按进程计算；固定分级规则在下方完整说明。",
                    );
                    ui.add_space(12.0);
                    ui.columns(3, |columns| {
                        labeled_value(&mut columns[0], "上传阈值 (B/s)", |ui| {
                            ui.add(
                                egui::DragValue::new(
                                    &mut self.settings_draft.upload_alert_bytes_per_second,
                                )
                                .range(1..=u64::MAX),
                            );
                        });
                        labeled_value(&mut columns[1], "下载阈值 (B/s)", |ui| {
                            ui.add(
                                egui::DragValue::new(
                                    &mut self.settings_draft.download_alert_bytes_per_second,
                                )
                                .range(1..=u64::MAX),
                            );
                        });
                        labeled_value(&mut columns[2], "流量突增倍数", |ui| {
                            ui.add(
                                egui::DragValue::new(&mut self.settings_draft.spike_multiplier)
                                    .range(2..=100),
                            );
                        });
                    });
                    ui.add_space(14.0);
                    if ui
                        .add_enabled(self.recording.is_some(), egui::Button::new("保存全部设置"))
                        .clicked()
                        && let Some(recording) = &self.recording
                    {
                        let _ = recording.save_settings(self.settings_draft.clone());
                    }
                    ui.add_space(14.0);
                    ui.separator();
                    ui.add_space(10.0);
                    ui.label(RichText::new("事件分级规则").size(16.0).strong());
                    ui.label(
                        RichText::new(
                            "新进程 +10；新端点 +10；单次出现至少10个新端点 +25；连续3个采样点超过上传阈值 +40、下载阈值 +25；达到近期基线设定倍数且至少1 MiB/s +20。",
                        )
                        .weak(),
                    );
                    ui.add_space(8.0);
                    ui.columns(3, |columns| {
                        columns[0].label(
                            RichText::new("信息 · 1–29分")
                                .strong()
                                .color(Color32::from_rgb(45, 103, 168)),
                        );
                        columns[0].label("记录行为变化，不弹高风险提示。");
                        columns[1].label(
                            RichText::new("关注 · 30–59分")
                                .strong()
                                .color(Color32::from_rgb(166, 98, 15)),
                        );
                        columns[1].label("表示持续或明显偏离基线的活动。");
                        columns[2].label(
                            RichText::new("高风险 · 60分以上")
                                .strong()
                                .color(Color32::from_rgb(185, 52, 47)),
                        );
                        columns[2].label("弹出提示并触发自动事件回溯。");
                    });
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(
                            "固定保护：初始库存不提醒；新颖性组合窗口30秒；同一进程同级事件冷却120秒；回溯最多120秒。风险分数是行为提示，不是恶意软件判定。",
                        )
                        .small()
                        .weak(),
                    );
                });
                ui.add_space(10.0);
                ui.columns(2, |columns| {
                    surface_frame(&columns[0]).show(&mut columns[0], |ui| {
                        settings_heading(ui, "外观", "默认浅色，可随时切换。");
                        ui.add_space(12.0);
                        if ui
                            .button(if self.dark_mode {
                                "切换到浅色模式"
                            } else {
                                "切换到深色模式"
                            })
                            .clicked()
                        {
                            self.dark_mode = !self.dark_mode;
                            ui.ctx().set_theme(if self.dark_mode {
                                egui::Theme::Dark
                            } else {
                                egui::Theme::Light
                            });
                        }
                    });
                    surface_frame(&columns[1]).show(&mut columns[1], |ui| {
                        settings_heading(ui, "权限模式", "管理员权限仅用于 ETW 实时采集。");
                        ui.add_space(12.0);
                        ui.horizontal_wrapped(|ui| {
                            if ui.button("切换到管理员模式").clicked() {
                                match procnet_windows::restart_elevated() {
                                    Ok(()) => {
                                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                                    }
                                    Err(error) => self.elevation_error = Some(error),
                                }
                            }
                            if ui.button("退出管理员模式").clicked() {
                                match procnet_windows::restart_unelevated() {
                                    Ok(()) => {
                                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                                    }
                                    Err(error) => self.elevation_error = Some(error),
                                }
                            }
                        });
                    });
                });
            });
        if let Some(error) = &self.elevation_error {
            ui.label(RichText::new(error).color(Color32::from_rgb(220, 90, 90)));
        }
    }

    fn about(ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                surface_frame(ui).show(ui, |ui| {
                    ui.set_min_height(150.0);
                    ui.vertical_centered(|ui| {
                        ui.add_space(12.0);
                        ui.label(RichText::new("ProcNet Recorder").size(30.0).strong());
                        ui.label(
                            RichText::new("V2 · Windows 进程级网络流量录制与分析")
                                .size(16.0)
                                .weak(),
                        );
                        ui.add_space(8.0);
                        ui.label("实时观察 · 会话归档 · 历史对比 · 本地提醒");
                    });
                });
                ui.add_space(12.0);
                ui.columns(3, |columns| {
                    about_card(
                        &mut columns[0],
                        "实时采集",
                        "使用 Windows ETW 获取进程级网络事件，后台有界聚合，不阻塞界面。",
                    );
                    about_card(
                        &mut columns[1],
                        "本地数据",
                        "SQLite 数据库保存在本机，不上传会话、进程或连接信息。",
                    );
                    about_card(
                        &mut columns[2],
                        "权限边界",
                        "管理员权限仅用于实时 ETW；历史查看、对比和导出无需管理员权限。",
                    );
                });
                ui.add_space(12.0);
                let technical_width = ui.available_width();
                surface_frame(ui).show(ui, |ui| {
                    ui.set_min_width((technical_width - 34.0).max(200.0));
                    settings_heading(ui, "技术信息", "清晰、可验证的数据路径。");
                    ui.add_space(10.0);
                    ui.label("ETW 采集  →  有界通道  →  聚合快照  →  后台 SQLite  →  原生 GUI");
                    ui.label(
                        RichText::new("数据库  %LOCALAPPDATA%\\ProcNet Recorder\\procnet.db")
                            .weak(),
                    );
                });
            });
    }

    fn restricted_banner(&mut self, ui: &mut egui::Ui, detail: &str) {
        let color = Color32::from_rgb(124, 76, 0);
        let fill = if self.dark_mode {
            Color32::from_rgb(67, 51, 24)
        } else {
            Color32::from_rgb(255, 246, 222)
        };
        let banner_width = ui.available_width();
        egui::Frame::new()
            .fill(fill)
            .stroke(egui::Stroke::new(1.0, Color32::from_rgb(218, 167, 67)))
            .corner_radius(10.0)
            .inner_margin(12.0)
            .show(ui, |ui| {
                ui.set_min_width((banner_width - 26.0).max(200.0));
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("受限模式").color(color).strong().size(15.0));
                    ui.label(RichText::new(detail).color(if self.dark_mode {
                        Color32::from_rgb(244, 225, 183)
                    } else {
                        Color32::from_rgb(83, 59, 18)
                    }));
                    if ui.button("切换到管理员模式").clicked() {
                        match procnet_windows::restart_elevated() {
                            Ok(()) => ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close),
                            Err(error) => self.elevation_error = Some(error),
                        }
                    }
                });
                if let Some(error) = &self.elevation_error {
                    ui.label(RichText::new(error).color(Color32::from_rgb(220, 90, 90)));
                }
            });
        ui.add_space(8.0);
    }
}

fn connection_data_row(
    ui: &mut egui::Ui,
    index: usize,
    detail: &procnet_application::ConnectionDetailSnapshot,
    columns: [f32; 6],
    selected_connection: &mut Option<usize>,
) {
    let connection = &detail.connection;
    let protocol = format!("{:?}", connection.protocol);
    table_cell(ui, columns[0], 24.0, |ui| {
        let selected = *selected_connection == Some(index);
        let label = egui::Label::new(if selected {
            RichText::new(&protocol).strong()
        } else {
            RichText::new(&protocol)
        })
        .halign(egui::Align::Min)
        .sense(egui::Sense::click());
        if ui.add(label).clicked() {
            *selected_connection = Some(index);
        }
    });
    table_text_cell(ui, columns[1], &connection_owner_label(detail));
    table_text_cell(ui, columns[2], &connection.pid.to_string());
    table_text_cell(ui, columns[3], &connection.local.to_string());
    table_text_cell(
        ui,
        columns[4],
        &connection
            .remote
            .map_or_else(|| "—".to_owned(), |value| value.to_string()),
    );
    table_text_cell(
        ui,
        columns[5],
        &connection
            .tcp_state
            .map_or_else(|| "—".to_owned(), |value| format!("{value:?}")),
    );
    ui.end_row();
}

fn table_text_cell(ui: &mut egui::Ui, width: f32, text: &str) {
    table_cell(ui, width, 24.0, |ui| {
        ui.add(egui::Label::new(text).halign(egui::Align::Min).truncate())
            .on_hover_text(text);
    });
}

fn connection_owner_label(detail: &procnet_application::ConnectionDetailSnapshot) -> String {
    match detail.owner_status {
        ConnectionOwnerStatus::Matched | ConnectionOwnerStatus::NameOnly => detail
            .process_name
            .clone()
            .unwrap_or_else(|| format!("PID {}", detail.connection.pid)),
        ConnectionOwnerStatus::ProcessExited if detail.connection.pid == 0 => {
            "连接已结束".to_owned()
        }
        ConnectionOwnerStatus::ProcessExited => {
            format!("进程已结束 · PID {}", detail.connection.pid)
        }
    }
}

fn install_chinese_font(context: &egui::Context) {
    let candidates = [
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\msyh.ttf",
        r"C:\Windows\Fonts\simhei.ttf",
    ];
    let Some(bytes) = candidates.iter().find_map(|path| fs::read(path).ok()) else {
        return;
    };
    let mut fonts = egui::FontDefinitions::default();
    let name = "procnet-cjk".to_owned();
    fonts
        .font_data
        .insert(name.clone(), Arc::new(egui::FontData::from_owned(bytes)));
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts.families.entry(family).or_default().push(name.clone());
    }
    context.set_fonts(fonts);
}

impl eframe::App for ProcNetApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let context = ui.ctx().clone();
        self.handle_screenshot_events(&context);
        self.receive_updates(&context);
        self.seed_screenshot_page();
        self.sidebar(ui);
        self.top_bar(ui);
        self.content(ui);
        self.risk_popup(&context);
        if self.system_refreshes >= 2
            && self.visual_seed != VisualSeedState::Pending
            && let ScreenshotState::Pending(path) = &self.screenshot
        {
            let path = path.clone();
            context.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
            self.screenshot = ScreenshotState::Requested(path);
        }
        if self
            .close_at
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            if !self.smoke_stop_requested {
                if let Some(recording) = &self.recording {
                    let _ = recording.stop_recording(unix_nanos_now());
                }
                self.smoke_stop_requested = true;
                self.close_at = Some(Instant::now() + Duration::from_millis(500));
            } else if matches!(
                self.screenshot,
                ScreenshotState::Pending(_) | ScreenshotState::Requested(_)
            ) {
                self.close_at = Some(Instant::now() + Duration::from_millis(250));
            } else if !self.smoke_reported {
                self.print_smoke_summary();
                self.smoke_reported = true;
                context.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
        context.request_repaint_after(Duration::from_millis(250));
    }
}

fn risk_level_style(level: RiskLevel) -> (&'static str, Color32) {
    match level {
        RiskLevel::Information => ("信息", Color32::from_rgb(45, 103, 168)),
        RiskLevel::Attention => ("关注", Color32::from_rgb(166, 98, 15)),
        RiskLevel::High => ("高风险", Color32::from_rgb(185, 52, 47)),
    }
}

impl ProcNetApp {
    fn handle_screenshot_events(&mut self, context: &egui::Context) {
        let ScreenshotState::Requested(path) = &self.screenshot else {
            return;
        };
        let path = path.clone();
        let image = context.input(|input| {
            input.events.iter().find_map(|event| match event {
                egui::Event::Screenshot { image, .. } => Some(Arc::clone(image)),
                _ => None,
            })
        });
        let Some(image) = image else {
            return;
        };
        self.screenshot = ScreenshotState::Saved;
        if let Err(error) = save_color_image_png(&path, &image) {
            self.error = Some(format!("无法保存 GUI 截图 {}：{error}", path.display()));
        }
    }

    fn print_smoke_summary(&self) {
        let Some(snapshot) = &self.snapshot else {
            self.emit_smoke_summary("GUI_SMOKE snapshot=unavailable");
            return;
        };
        let (processes, connections, icons_available) =
            snapshot.system.as_ref().map_or((0, 0, 0), |system| {
                (
                    system.processes.len(),
                    system.connections.len(),
                    system
                        .processes
                        .iter()
                        .filter(|process| matches!(process.icon, ProcessIconState::Available(_)))
                        .count(),
                )
            });
        let unnamed_traffic_processes = snapshot
            .process_traffic
            .iter()
            .filter(|process| process.name.is_none())
            .count();
        let curve_span_buckets = snapshot
            .recent_60_seconds
            .buckets
            .first()
            .zip(snapshot.recent_60_seconds.buckets.last())
            .map_or(0, |(first, last)| {
                last.start_unix_nanos.saturating_sub(first.start_unix_nanos)
                    / snapshot.recent_60_seconds.bucket_width_nanos
            });
        let session_state = self.session_state();
        self.emit_smoke_summary(&format!(
            "GUI_SMOKE snapshot=available theme={} events_processed={} traffic_processes={} unnamed_traffic_processes={} processes={} connections={} icons_available={} system_refreshes={} curve_buckets={} curve_span_buckets={} send_rate={} receive_rate={} sessions={} recording_active={} persistence_dropped={} storage_error={} screenshot_saved={}",
            if self.dark_mode { "dark" } else { "light" },
            snapshot.events_processed,
            snapshot.process_traffic.len(),
            unnamed_traffic_processes,
            processes,
            connections,
            icons_available,
            self.system_refreshes,
            snapshot.recent_60_seconds.buckets.len(),
            curve_span_buckets,
            snapshot.network_rate.send_bytes_per_second,
            snapshot.network_rate.receive_bytes_per_second,
            session_state.sessions.len(),
            session_state.active.is_some(),
            session_state.persistence_queue_dropped,
            session_state.last_error.is_some(),
            matches!(self.screenshot, ScreenshotState::Saved),
        ));
    }

    fn emit_smoke_summary(&self, summary: &str) {
        println!("{summary}");
        if let Some(path) = &self.smoke_report {
            let _ = std::fs::write(path, format!("{summary}\n"));
        }
    }
}

fn save_color_image_png(path: &std::path::Path, image: &egui::ColorImage) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let width = u32::try_from(image.size[0]).map_err(|error| error.to_string())?;
    let height = u32::try_from(image.size[1]).map_err(|error| error.to_string())?;
    let mut bytes = Vec::with_capacity(image.pixels.len().saturating_mul(4));
    for pixel in &image.pixels {
        bytes.extend_from_slice(&pixel.to_array());
    }
    let file = std::fs::File::create(path).map_err(|error| error.to_string())?;
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().map_err(|error| error.to_string())?;
    writer
        .write_image_data(&bytes)
        .map_err(|error| error.to_string())
}

fn navigation_button(ui: &mut egui::Ui, page: &mut Page, target: Page, label: &str) {
    if ui
        .add_sized(
            [154.0, 38.0],
            egui::Button::selectable(*page == target, label),
        )
        .clicked()
    {
        *page = target;
    }
}

fn session_status_label(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Recording => "正在录制",
        SessionStatus::Completed => "已完成",
        SessionStatus::Interrupted => "异常中断",
    }
}

fn session_name_for(state: &SessionUiState, id: Option<SessionId>) -> &str {
    id.and_then(|id| state.sessions.iter().find(|session| session.id == id))
        .map_or("选择会话", |session| session.name.as_str())
}

fn compare_row(ui: &mut egui::Ui, label: &str, left: u64, right: u64, bytes: bool) {
    ui.label(label);
    ui.label(if bytes {
        format_bytes(left)
    } else {
        left.to_string()
    });
    ui.label(if bytes {
        format_bytes(right)
    } else {
        right.to_string()
    });
    let difference = i128::from(right) - i128::from(left);
    let absolute = u64::try_from(difference.unsigned_abs()).unwrap_or(u64::MAX);
    let text = if bytes {
        format_bytes(absolute)
    } else {
        absolute.to_string()
    };
    ui.label(format!("{}{text}", if difference >= 0 { "+" } else { "−" }));
    ui.end_row();
}

fn session_curve_header(
    ui: &mut egui::Ui,
    saved: usize,
    visible: usize,
    y_max: u64,
    mode: SessionCurveMode,
) -> bool {
    let mut return_to_latest = false;
    ui.horizontal(|ui| {
        ui.strong("会话流量趋势");
        ui.label(
            RichText::new(format!(
                "已保存 {saved} 个 · 当前显示 {visible} 个 · 无降采样 · 纵轴 0 – {}",
                format_rate(y_max)
            ))
            .small()
            .weak(),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if mode == SessionCurveMode::FollowLatest {
                ui.label(RichText::new("● 正在跟随最新").small().color(RECEIVE_COLOR));
            } else if ui.button("回到最新").clicked() {
                return_to_latest = true;
            }
        });
    });
    return_to_latest
}

fn format_duration(start_unix_nanos: u64, end_unix_nanos: u64) -> String {
    let total_seconds = end_unix_nanos.saturating_sub(start_unix_nanos) / 1_000_000_000;
    let days = total_seconds / 86_400;
    let hours = total_seconds / 3_600 % 24;
    let minutes = total_seconds / 60 % 60;
    let seconds = total_seconds % 60;
    if days > 0 {
        format!("{days}天 {hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    }
}

fn session_window_start(total: usize, requested: usize, follow_latest: bool) -> usize {
    let latest = total.saturating_sub(60);
    if follow_latest {
        latest
    } else {
        requested.min(latest)
    }
}

fn nice_curve_ceiling(value: u64) -> u64 {
    let mut magnitude = 1_u64;
    while value > magnitude.saturating_mul(10) && magnitude <= u64::MAX / 10 {
        magnitude = magnitude.saturating_mul(10);
    }
    [1_u64, 2, 5, 10]
        .into_iter()
        .map(|multiplier| magnitude.saturating_mul(multiplier))
        .find(|candidate| *candidate >= value)
        .unwrap_or(u64::MAX)
}

fn format_plot_rate(value: f64) -> String {
    const KIB: f64 = 1_024.0;
    const MIB: f64 = 1_048_576.0;
    if value >= MIB {
        format!("{:.1} MiB/s", value / MIB)
    } else if value >= KIB {
        format!("{:.0} KiB/s", value / KIB)
    } else {
        format!("{value:.0} B/s")
    }
}

fn format_session_x_axis(value: f64) -> String {
    if value.abs() < 0.5 {
        String::new()
    } else {
        format!("{value:.0}s")
    }
}

fn format_timestamp(unix_nanos: u64) -> String {
    const BEIJING_UTC_OFFSET_SECONDS: u64 = 8 * 60 * 60;
    let seconds = (unix_nanos / 1_000_000_000).saturating_add(BEIJING_UTC_OFFSET_SECONDS);
    let second = seconds % 60;
    let minute = seconds / 60 % 60;
    let hour = seconds / 3_600 % 24;
    let days = seconds / 86_400;
    let shifted = days.saturating_add(719_468);
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    if month <= 2 {
        year += 1;
    }
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

fn unix_nanos_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        })
}

fn export_path(id: SessionId, extension: &str) -> PathBuf {
    std::env::var_os("USERPROFILE")
        .map_or_else(|| PathBuf::from("."), PathBuf::from)
        .join("Documents")
        .join("ProcNet Recorder Exports")
        .join(format!("session-{}.{}", id.0, extension))
}

fn warning_banner(ui: &mut egui::Ui, title: &str, detail: &str, color: Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.18))
        .stroke(egui::Stroke::new(1.0, color))
        .corner_radius(8.0)
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(title).color(color).strong());
                ui.label(detail);
            });
        });
    ui.add_space(8.0);
}

fn history_save_warning(ui: &mut egui::Ui, dropped_samples: u64) {
    let (fill, stroke, title_color, detail_color) = if ui.visuals().dark_mode {
        (
            Color32::from_rgb(67, 51, 24),
            Color32::from_rgb(218, 167, 67),
            Color32::from_rgb(255, 211, 116),
            Color32::from_rgb(244, 225, 183),
        )
    } else {
        (
            Color32::from_rgb(255, 246, 222),
            Color32::from_rgb(191, 124, 0),
            Color32::from_rgb(112, 68, 0),
            Color32::from_rgb(83, 59, 18),
        )
    };
    egui::Frame::new()
        .fill(fill)
        .stroke(egui::Stroke::new(1.0, stroke))
        .corner_radius(8.0)
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("历史保存延迟").color(title_color).strong());
                ui.label(
                    RichText::new(format!(
                        "有 {dropped_samples} 次定时采样未写入历史记录；实时界面仍可继续查看。请停止录制并检查磁盘或系统负载。"
                    ))
                    .color(detail_color),
                );
            });
        });
}

fn metric_card(ui: &mut egui::Ui, title: &str, value: &str, color: Color32) {
    egui::Frame::group(ui.style())
        .fill(color.gamma_multiply(0.08))
        .inner_margin(14.0)
        .show(ui, |ui| {
            ui.set_min_width(180.0);
            ui.label(RichText::new(title).weak());
            ui.label(RichText::new(value).size(22.0).color(color).strong());
        });
}

fn surface_frame(ui: &egui::Ui) -> egui::Frame {
    let fill = if ui.visuals().dark_mode {
        Color32::from_rgb(31, 34, 39)
    } else {
        Color32::WHITE
    };
    let stroke = if ui.visuals().dark_mode {
        Color32::from_rgb(58, 63, 72)
    } else {
        Color32::from_rgb(222, 226, 232)
    };
    egui::Frame::new()
        .fill(fill)
        .stroke(egui::Stroke::new(1.0, stroke))
        .corner_radius(12.0)
        .inner_margin(16.0)
}

fn metric_grid(ui: &mut egui::Ui, metrics: &[(&str, String, Color32)]) {
    ui.columns(metrics.len(), |columns| {
        for (column, (title, value, color)) in columns.iter_mut().zip(metrics) {
            let available = column.available_width();
            egui::Frame::new()
                .fill(color.gamma_multiply(if column.visuals().dark_mode {
                    0.20
                } else {
                    0.08
                }))
                .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.35)))
                .corner_radius(10.0)
                .inner_margin(14.0)
                .show(column, |ui| {
                    ui.set_min_width((available - 30.0).max(80.0));
                    ui.label(RichText::new(*title).small().weak());
                    ui.label(RichText::new(value).size(21.0).color(*color).strong());
                });
        }
    });
}

fn session_process_card(ui: &mut egui::Ui, detail: &procnet_core::SessionDetail) {
    surface_frame(ui).show(ui, |ui| {
        ui.label(RichText::new("进程排行").size(17.0).strong());
        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .id_salt(("session_processes", detail.session.id.0))
            .max_height(230.0)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let width = ui.available_width();
                let columns = [width * 0.52, width * 0.24, width * 0.24];
                egui::Grid::new(("session_process_grid", detail.session.id.0))
                    .striped(true)
                    .spacing([0.0, 3.0])
                    .show(ui, |ui| {
                        for (heading, width) in ["进程", "上传", "下载"].into_iter().zip(columns)
                        {
                            table_cell(ui, width, 28.0, |ui| {
                                ui.strong(heading);
                            });
                        }
                        ui.end_row();
                        for process in &detail.processes {
                            table_text_cell(ui, columns[0], &process.name);
                            table_text_cell(ui, columns[1], &format_bytes(process.send_bytes));
                            table_text_cell(ui, columns[2], &format_bytes(process.receive_bytes));
                            ui.end_row();
                        }
                    });
            });
    });
}

fn session_endpoint_card(ui: &mut egui::Ui, detail: &procnet_core::SessionDetail) {
    surface_frame(ui).show(ui, |ui| {
        ui.label(RichText::new("远程端点").size(17.0).strong());
        ui.add_space(8.0);
        egui::ScrollArea::vertical()
            .id_salt(("session_endpoints", detail.session.id.0))
            .max_height(230.0)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let width = ui.available_width();
                let columns = [width * 0.16, width * 0.46, width * 0.38];
                egui::Grid::new(("session_endpoint_grid", detail.session.id.0))
                    .striped(true)
                    .spacing([0.0, 3.0])
                    .show(ui, |ui| {
                        for (heading, width) in ["协议", "地址", "进程"].into_iter().zip(columns)
                        {
                            table_cell(ui, width, 28.0, |ui| {
                                ui.strong(heading);
                            });
                        }
                        ui.end_row();
                        for endpoint in &detail.endpoints {
                            table_text_cell(ui, columns[0], &endpoint.protocol);
                            table_text_cell(ui, columns[1], &endpoint.remote_address);
                            table_text_cell(ui, columns[2], &endpoint.process_name);
                            ui.end_row();
                        }
                    });
            });
    });
}

fn compare_session_summary(
    ui: &mut egui::Ui,
    eyebrow: &str,
    detail: &procnet_core::SessionDetail,
    color: Color32,
) {
    surface_frame(ui).show(ui, |ui| {
        ui.label(RichText::new(eyebrow).small().color(color).strong());
        ui.label(RichText::new(&detail.session.name).size(19.0).strong());
        ui.label(RichText::new(format_timestamp(detail.session.started_at_unix_nanos)).weak());
        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(format!("上传 {}", format_bytes(detail.session.send_bytes)));
            ui.label(format!(
                "下载 {}",
                format_bytes(detail.session.receive_bytes)
            ));
            ui.label(format!("提醒 {}", detail.alerts.len()));
        });
    });
}

fn compare_metrics_table(
    ui: &mut egui::Ui,
    left: &procnet_core::SessionDetail,
    right: &procnet_core::SessionDetail,
) {
    surface_frame(ui).show(ui, |ui| {
        ui.label(RichText::new("指标差异").size(18.0).strong());
        ui.add_space(10.0);
        let width = ui.available_width();
        let columns = [width * 0.22, width * 0.26, width * 0.26, width * 0.26];
        egui::Grid::new("session_compare_table_modern")
            .striped(true)
            .spacing([0.0, 6.0])
            .show(ui, |ui| {
                for (heading, width) in ["指标", "会话 A", "会话 B", "差值 B − A"]
                    .into_iter()
                    .zip(columns)
                {
                    table_cell(ui, width, 32.0, |ui| {
                        ui.strong(heading);
                    });
                }
                ui.end_row();
                compare_row(
                    ui,
                    "上传",
                    left.session.send_bytes,
                    right.session.send_bytes,
                    true,
                );
                compare_row(
                    ui,
                    "下载",
                    left.session.receive_bytes,
                    right.session.receive_bytes,
                    true,
                );
                compare_row(
                    ui,
                    "进程数",
                    left.processes.len() as u64,
                    right.processes.len() as u64,
                    false,
                );
                compare_row(
                    ui,
                    "端点数",
                    left.endpoints.len() as u64,
                    right.endpoints.len() as u64,
                    false,
                );
                compare_row(
                    ui,
                    "提醒数",
                    left.alerts.len() as u64,
                    right.alerts.len() as u64,
                    false,
                );
            });
    });
}

fn settings_heading(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(RichText::new(title).size(18.0).strong());
    ui.label(RichText::new(subtitle).small().weak());
}

fn labeled_value(ui: &mut egui::Ui, label: &str, body: impl FnOnce(&mut egui::Ui)) {
    ui.label(RichText::new(label).small().weak());
    body(ui);
}

fn about_card(ui: &mut egui::Ui, title: &str, detail: &str) {
    surface_frame(ui).show(ui, |ui| {
        ui.set_min_height(126.0);
        ui.label(RichText::new(title).size(17.0).strong());
        ui.add_space(8.0);
        ui.label(detail);
    });
}

fn process_table(
    ui: &mut egui::Ui,
    processes: &[ProcessTrafficSnapshot],
    search: &str,
    sort: ProcessSort,
    selected_pid: &mut Option<u32>,
    icon_textures: &BTreeMap<String, egui::TextureHandle>,
    limit: usize,
) {
    let needle = search.to_lowercase();
    let mut rows = processes
        .iter()
        .filter(|process| process.name.is_some())
        .filter(|process| {
            needle.is_empty()
                || format!(
                    "{} {} {}",
                    process.pid,
                    process.name.as_deref().unwrap_or(""),
                    process.image_path.as_deref().unwrap_or("")
                )
                .to_lowercase()
                .contains(&needle)
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|process| {
        std::cmp::Reverse(match sort {
            ProcessSort::Rate => process
                .send_bytes_per_second
                .saturating_add(process.receive_bytes_per_second),
            ProcessSort::Send => process.send_bytes_per_second,
            ProcessSort::Receive => process.receive_bytes_per_second,
            ProcessSort::Connections => u64::try_from(process.connection_count).unwrap_or(u64::MAX),
        })
    });
    if rows.is_empty() {
        empty_state(
            ui,
            "暂无进程流量",
            "产生网络访问后，进程会按实时速率显示在这里。",
        );
        return;
    }
    let table_width = ui.available_width();
    let max_height = process_table_height(limit, ui.available_height());
    egui::ScrollArea::vertical()
        .max_height(max_height)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let width = table_width;
            let columns = [
                width * 0.34,
                width * 0.10,
                width * 0.15,
                width * 0.15,
                width * 0.16,
                width * 0.10,
            ];
            egui::Grid::new("process_table")
                .striped(true)
                .spacing([0.0, 2.0])
                .show(ui, |ui| {
                    for (heading, width) in ["进程", "PID", "上传", "下载", "累计", "连接"]
                        .into_iter()
                        .zip(columns)
                    {
                        table_cell(ui, width, 30.0, |ui| {
                            ui.strong(heading);
                        });
                    }
                    ui.end_row();
                    for process in rows.into_iter().take(limit) {
                        process_data_row(ui, process, columns, selected_pid, icon_textures);
                    }
                });
        });
}

fn process_table_height(limit: usize, available_height: f32) -> f32 {
    if limit == usize::MAX {
        available_height.max(340.0)
    } else {
        340.0
    }
}

fn process_data_row(
    ui: &mut egui::Ui,
    process: &ProcessTrafficSnapshot,
    columns: [f32; 6],
    selected_pid: &mut Option<u32>,
    icon_textures: &BTreeMap<String, egui::TextureHandle>,
) {
    let name = process
        .name
        .clone()
        .unwrap_or_else(|| format!("PID {}", process.pid));
    table_cell(ui, columns[0], 24.0, |ui| {
        if let Some(texture) = process
            .image_path
            .as_ref()
            .and_then(|path| icon_textures.get(path))
        {
            ui.add(egui::Image::new(texture).fit_to_exact_size(egui::vec2(18.0, 18.0)));
        } else {
            ui.label(RichText::new("●").color(ui.visuals().weak_text_color()));
        }
        let selected = *selected_pid == Some(process.pid);
        let label = egui::Label::new(if selected {
            RichText::new(&name).strong()
        } else {
            RichText::new(&name)
        })
        .halign(egui::Align::Min)
        .truncate()
        .sense(egui::Sense::click());
        if ui.add(label).on_hover_text(&name).clicked() {
            *selected_pid = Some(process.pid);
        }
    });
    table_cell(ui, columns[1], 24.0, |ui| {
        ui.label(process.pid.to_string());
    });
    table_cell(ui, columns[2], 24.0, |ui| {
        ui.label(RichText::new(format_rate(process.send_bytes_per_second)).color(SEND_COLOR));
    });
    table_cell(ui, columns[3], 24.0, |ui| {
        ui.label(RichText::new(format_rate(process.receive_bytes_per_second)).color(RECEIVE_COLOR));
    });
    table_cell(ui, columns[4], 24.0, |ui| {
        ui.label(format_bytes(
            process
                .send_bytes_total
                .saturating_add(process.receive_bytes_total),
        ));
    });
    table_cell(ui, columns[5], 24.0, |ui| {
        ui.label(process.connection_count.to_string());
    });
    ui.end_row();
}

fn table_cell(ui: &mut egui::Ui, width: f32, height: f32, body: impl FnOnce(&mut egui::Ui)) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let mut cell = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(rect)
            .layout(egui::Layout::left_to_right(egui::Align::Center)),
    );
    body(&mut cell);
}

fn process_detail(ui: &mut egui::Ui, process: &ProcessTrafficSnapshot) {
    egui::Frame::group(ui.style())
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.strong(format!(
                "{} · PID {}",
                process
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("PID {}", process.pid)),
                process.pid
            ));
            ui.label(process.image_path.as_deref().unwrap_or("路径不可用"));
            ui.horizontal_wrapped(|ui| {
                ui.label(format!(
                    "累计上传 {}",
                    format_bytes(process.send_bytes_total)
                ));
                ui.label(format!(
                    "累计下载 {}",
                    format_bytes(process.receive_bytes_total)
                ));
                ui.label(format!("连接 {}", process.connection_count));
            });
        });
}

fn sort_button(ui: &mut egui::Ui, sort: &mut ProcessSort, target: ProcessSort, label: &str) {
    if ui.selectable_label(*sort == target, label).clicked() {
        *sort = target;
    }
}

fn empty_state(ui: &mut egui::Ui, title: &str, detail: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(24.0);
        ui.label(RichText::new(title).size(18.0).strong());
        ui.label(RichText::new(detail).weak());
        ui.add_space(24.0);
    });
}

fn format_rate(bytes: u64) -> String {
    format!("{}/s", format_bytes(bytes))
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if bytes >= GIB {
        decimal_unit(bytes, GIB, "GiB")
    } else if bytes >= MIB {
        decimal_unit(bytes, MIB, "MiB")
    } else if bytes >= KIB {
        decimal_unit(bytes, KIB, "KiB")
    } else {
        format!("{bytes} B")
    }
}

fn decimal_unit(bytes: u64, unit: u64, suffix: &str) -> String {
    let whole = bytes / unit;
    let decimal = bytes % unit * 10 / unit;
    format!("{whole}.{decimal} {suffix}")
}

fn plot_index(index: usize) -> f64 {
    f64::from(u32::try_from(index).unwrap_or(u32::MAX))
}

#[allow(clippy::cast_precision_loss)]
fn plot_bytes(bytes: u64) -> f64 {
    bytes as f64
}

#[cfg(test)]
mod tests {
    use super::{
        format_bytes, format_duration, format_plot_rate, format_rate, format_session_x_axis,
        format_timestamp, nice_curve_ceiling, process_table_height, session_window_start,
    };

    #[test]
    fn byte_labels_are_compact_and_stable() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1_024), "1.0 KiB");
        assert_eq!(format_rate(1_048_576), "1.0 MiB/s");
    }

    #[test]
    fn timestamps_use_calendar_dates() {
        assert_eq!(format_timestamp(0), "1970-01-01 08:00:00");
        assert_eq!(
            format_timestamp(1_735_689_599_000_000_000),
            "2025-01-01 07:59:59"
        );
    }

    #[test]
    fn durations_are_stable_and_saturating() {
        assert_eq!(format_duration(0, 3_661_000_000_000), "01:01:01");
        assert_eq!(format_duration(0, 90_061_000_000_000), "1天 01:01:01");
        assert_eq!(format_duration(20, 10), "00:00:00");
    }

    #[test]
    fn full_process_page_uses_all_available_height() {
        assert!((process_table_height(usize::MAX, 720.0) - 720.0).abs() < f32::EPSILON);
        assert!((process_table_height(8, 720.0) - 340.0).abs() < f32::EPSILON);
    }

    #[test]
    fn session_curve_keeps_all_samples_addressable_in_fixed_windows() {
        assert_eq!(session_window_start(30, 0, true), 0);
        assert_eq!(session_window_start(180, 0, true), 120);
        assert_eq!(session_window_start(180, 25, false), 25);
        assert_eq!(session_window_start(180, 999, false), 120);
    }

    #[test]
    fn session_curve_uses_stable_human_scale_steps() {
        assert_eq!(nice_curve_ceiling(65_536), 100_000);
        assert_eq!(nice_curve_ceiling(100_001), 200_000);
        assert_eq!(format_plot_rate(1_048_576.0), "1.0 MiB/s");
    }

    #[test]
    fn session_curve_origin_has_only_one_axis_label() {
        assert!(format_session_x_axis(0.0).is_empty());
        assert_eq!(format_session_x_axis(10.0), "10s");
    }
}
