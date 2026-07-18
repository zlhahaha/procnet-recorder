# 架构概览

ProcNet Recorder 采用单向依赖的 Cargo Workspace，并按阶段逐步创建目录。

## 最终分层

```text
procnet-core
    ^
    +-- procnet-windows
    +-- procnet-storage
    +-- procnet-application
             ^
             +-- procnet-cli
             +-- procnet-gui

procnet-fixture（独立测试程序）
```

P0、V0、V1 已通过；V2 已创建 Storage 并接入完整原生 GUI。

## 边界

- `procnet-core`：纯 Rust 领域模型、聚合算法、时间桶、会话统计、规则和必要 Trait；禁止 Windows API、ETW、GUI、SQLite 和具体路径。
- `procnet-windows`：唯一直接接触 ETW、TDH、IP Helper、进程 API、权限、图标和原生句柄的 crate。未来 `unsafe` 只允许集中在其底层 `raw` 模块，每块必须有 `// SAFETY:` 说明。
- `procnet-application`：负责有界通道、后台线程、聚合、快照、会话用例、批量持久化命令和关闭流程；不直接绘制 GUI、写 SQL 或包含 Windows API。
- `procnet-storage`：负责 SQLite、migration、Repository、JSON/CSV/Markdown 和保留策略，只依赖 Core，不启动 ETW 或重做核心聚合。
- `procnet-cli`：参数解析、依赖组装、诊断和终端输出，是 V0 入口，不重做聚合。
- `procnet-gui`：消费 Application 的只读 Snapshot，通过命令通道控制会话；数据库写入和文件导出不在 UI 线程执行。
- `procnet-fixture`：只生成可重复的真实 TCP/UDP 流量，不进入产品采集路径。

## V2 运行时

```text
ETW 回调线程 -> 有界消息通道 -> 聚合线程 -> 只读 Snapshot -> GUI
                                           |
                                           +-> 有界命令 -> procnet-persistence -> SQLite/导出
```

ETW 回调只解析和投递事件，不更新 GUI、不写数据库、不做 DNS、图标或其他耗时操作。运行时必须记录收到/丢弃事件数、队列长度、ETW 状态、权限和采集模式。

`procnet-windows` 输出 owned `procnet-core::NetworkEvent`，入口把 `procnet-application::EventIngress::try_submit` 组装为 callback sink。Application 不依赖 Windows，Windows 也不依赖 Application。Storage 实现 Core 中的 `SessionRepository` port，Application 和 Storage 不互相依赖。

## Rust 约束

- 用所有权通过通道转移事件，避免共享可变事件。
- 用枚举与模式匹配表达协议、方向、IP 版本、采集/会话状态和错误分类。
- 用 RAII 管理 ETW Session、句柄、Consumer、线程、事务和临时文件。
- 生产路径通过 `Result` 传播错误，避免随意 `unwrap`、`expect` 和 `panic!`。
- Trait 只用于确有多实现或依赖倒置的边界。
