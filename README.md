# ProcNet Recorder

ProcNet Recorder 是一个使用 Rust 编写的 Windows 进程级网络活动监测、事件分级与会话取证工具。它通过 ETW 采集真实网络活动，将流量归属到进程，并提供原生 GUI、历史会话、风险提醒、对比和导出能力。

## 主要功能

- 实时总览：上传/下载速率、活跃进程、连接数量和最近 60 秒曲线。
- 进程与连接：进程名称、图标、PID、速率、累计流量、TCP/UDP 端点和连接状态。
- 历史会话：开始/结束时间、持续时长、完整采样曲线、进程排行、端点历史和安全删除。
- 会话对比：并排比较两个历史会话的流量、进程、端点和提醒。
- 实时风险事件：基于持续窗口、近期基线和组合信号进行可解释分级；高风险事件可弹窗并自动保存异常前最多 2 分钟及后续 1 分钟。
- 本地持久化与导出：SQLite 数据库，支持 JSON、CSV 和 Markdown。
- 权限安全：仅操作本项目固定名称的 ETW Session，不枚举或批量停止其他 Session。

风险分数是本地行为提示，用于帮助定位“哪个进程在什么时间与哪些端点产生了异常网络活动”，不是恶意软件判定。

## 系统要求

- Windows 10/11 x64
- Rust 1.94 或更高版本，MSVC 工具链
- Visual Studio Build Tools（包含 C++ 桌面开发工具）
- 实时 ETW 采集需要管理员权限，或属于 `Performance Log Users` 组

没有采集权限时，GUI 会进入受限模式；进程、连接和已有历史数据仍可查看。需要实时流量时，在 GUI 中点击“以管理员身份重新启动”，并在 Windows UAC 安全界面确认授权。

## 从源码构建

在 PowerShell 中进入仓库目录并执行：

```powershell
cargo build --workspace --release
```

构建完成后启动 GUI：

```powershell
.\target\release\procnet-gui.exe
```

Release GUI 使用 Windows 图形子系统，直接双击 `procnet-gui.exe` 不会附带控制台黑框。

## 一键演示（推荐）

仓库提供了可重复的本机双向 TCP 流量演示，不需要浏览器下载，也不需要复制粘贴客户端代码。

1. 先完成一次 Release 构建。
2. 启动 ProcNet GUI，进入管理员模式，确认右上角显示“正在采集”。
3. 回到仓库根目录，直接双击 **`demo-risk-traffic.cmd`**。
4. 切回 GUI，观察实时曲线、进程排行、风险事件、高风险弹窗和自动事件会话。

CMD 启动器会隐藏运行 Fixture 服务端，并立即产生约 15 秒的受控双向环回流量；结束后只清理它自己启动的子进程。默认使用端口 `39110`，如果端口已被占用会明确报错，不会终止占用该端口的其他程序。

如需自定义参数，也可以从 PowerShell 运行底层脚本：

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\demo-risk-traffic.ps1 `
  -Port 39001 `
  -DurationSeconds 12
```

脚本结束时会显示实际传输量和平均速率。演示流量仅使用 `127.0.0.1`，不会上传数据到互联网。

## 数据与导出位置

本地数据库：

```text
%LOCALAPPDATA%\ProcNet Recorder\procnet.db
```

默认导出目录：

```text
%USERPROFILE%\Documents\ProcNet Recorder Exports
```

导出成功后，GUI 会显示生成文件的完整路径。程序启动时发现未正常结束的录制，会将其标记为“异常中断”，不会伪装为正常完成。

## 安全清理本项目 ETW Session

如果程序被强制终止并遗留本项目 Session，可在管理员 PowerShell 中执行：

```powershell
cargo run -p procnet-cli -- cleanup-etw --session ProcNetRecorder-V0-TcpIp-Probe
```

该命令只接受精确 Session 名称 `ProcNetRecorder-V0-TcpIp-Probe`。它会先查询、输出目标名称、停止后再次确认；不会调用 `logman`，也不会停止或枚举后批量停止其他 ETW Session。

## 项目结构

- `procnet-core`：领域模型、聚合、风险规则和 Repository 接口。
- `procnet-windows`：ETW、IP Helper、Shell 图标、权限提升和 Windows API 边界。
- `procnet-application`：运行时、只读快照、会话用例和后台持久化。
- `procnet-storage`：SQLite migration、Repository、保留策略和导出。
- `procnet-gui`：基于 eframe/egui 的 Windows 原生 GUI。
- `procnet-cli`：诊断、探针、精确 ETW 清理和基础导出。
- `procnet-fixture`：可重复的真实 TCP/UDP 测试流量。

更详细的边界和依赖方向见 [架构说明](docs/architecture/overview.md)、[依赖规则](docs/architecture/dependency-rules.md) 和 [SQLite 会话边界 ADR](docs/adr/0002-v2-sqlite-session-boundary.md)。

## 验证

运行完整本地检查：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check.ps1
```

它会依次执行格式检查、编译检查、Clippy、测试、Release 构建和依赖检查。GitHub Actions 也会在 Windows 环境运行核心质量检查。

## 产品边界

ProcNet Recorder 目前仅支持 Windows。它观察和分析网络元数据，不限速、不断网、不修改防火墙、不解密 HTTPS，也不检查数据包正文。Fixture 只用于产生可复现的真实测试流量；采集失败时，界面不会用模拟数据冒充监测结果。

## 许可证

本项目采用 [MIT](LICENSE-MIT) 或 [Apache License 2.0](LICENSE-APACHE) 双许可证，使用者可任选其一。
