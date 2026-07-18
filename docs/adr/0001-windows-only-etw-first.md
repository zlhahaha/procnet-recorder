# ADR-0001：Windows-only 与 ETW-first

- 状态：Accepted
- 日期：2026-07-16
- 适用阶段：P0-V2

## 背景

项目目标是 Windows 进程级网络流量观察与会话分析。最大的风险不是 GUI，而是能否从真实 ETW 网络事件稳定获得 PID、协议、方向、字节数和端点。

## 决策

1. 项目以 Windows 和 MSVC 工具链为唯一目标平台。
2. V0 先通过 CLI、`procnet-windows` 与独立 fixture 验证 ETW/TDH 路线。
3. 禁止用连接数、连接时长、平均分配、随机数或 fixture 输出冒充监控结果。
4. V0 通过前不创建正式 GUI、完整 Application 运行时或 SQLite 历史。
5. 优先评估 `ferrisetw`、`windows` crate、ETW Controller/Consumer、Kernel TCP/IP 或相应 provider 与 TDH schema；最小实验后只保留一套实现。

## 结果

若最多三轮有明确假设的修复实验后仍无法稳定获得核心字段，则记录 `V0 GATE: FAIL`，停止 V1/V2，并输出完整失败分析。

