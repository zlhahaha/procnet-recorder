# 依赖规则

## 允许方向

- `procnet-core` 不依赖其他项目 crate。
- `procnet-windows` 只依赖 `procnet-core`。
- `procnet-storage` 只依赖 `procnet-core`。
- `procnet-application` 依赖 `procnet-core`，通过 Trait 使用采集、存储和导出能力。
- `procnet-cli` 和 `procnet-gui` 负责具体实现组装。
- `procnet-fixture` 独立运行。

## 禁止方向

- 核心层不得依赖 Windows、GUI 或数据库。
- Windows、Storage、Application 不得依赖 GUI。
- GUI 不得依赖 CLI。
- 不得出现循环依赖。

新增依赖后必须执行：

```powershell
cargo tree --workspace
cargo tree --duplicates
cargo metadata --no-deps
```

