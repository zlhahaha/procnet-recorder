# ADR-0002：V2 SQLite 与会话边界

- 状态：Accepted
- 日期：2026-07-17

## 决策

V2 新增 `procnet-storage`。`procnet-core` 持有会话、提醒和 Repository port；`procnet-application` 持有会话用例、持久化线程和有界命令通道；`procnet-storage` 只依赖核心层并实现 port；GUI 仅组装依赖和发送命令。

SQLite 使用 `rusqlite 0.37.0` 的 `bundled` 特性，避免依赖目标机器的 SQLite DLL。0.40.1 在当前 Rust 1.94 上因底层构建脚本使用未稳定 `cfg_select` 而失败，因此锁定已验证版本。

## 数据流

`ETW callback → 有界事件通道 → 聚合线程 → 只读 ApplicationSnapshot → 有界持久化命令通道 → procnet-persistence → SQLite WAL`

ETW 回调不执行 SQL，GUI 线程不执行 SQL 或文件导出，Storage 不启动 ETW、不查询进程、不计算实时流量。

## 生命周期

- 启动时把数据库中遗留的 `recording` 会话精确改为 `interrupted`。
- 正常停止写入结束时间和 `completed`。
- 每秒最多提交一个 bucket，同秒重复快照被抑制。
- 进程使用 PID + 启动时间，避免 PID 复用污染历史。
- 应用退出时先提交停止命令，再回收持久化线程。

## 主题决策

规划原稿提出现代深色主题，但用户后续明确要求默认浅色。因此 V2 默认浅色，保留深色切换；这是需求优先级覆盖，不是遗漏。
