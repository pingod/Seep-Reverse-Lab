# Tool/audits —— 已整理的审计交付物

本目录只存放**面向阅读的审计交付物**：报告、方法论、只读基线数据，以及带单元测试的
可复用检查工具。

**不放**真实样本、补丁二进制、自签私钥与签名许可——这些属于本地 `lab/` 工作区
（该目录被 `.gitignore` 排除）。`Tool/audits/.gitignore` 另有一层防御性规则，防止
它们被误提交。

## 目录约定

```
Tool/audits/<目标>/
├─ README.md          索引：本目标是什么、有哪些交付物、在哪找工作产物
├─ <平台>/            按平台分目录（windows / macos / ...）
│  ├─ REPORT.md       该平台的完整审计报告
│  ├─ METHODOLOGY.md  平台差异与可移植性结论（可选）
│  ├─ tools/          可复用检查工具（带 main，可单独运行）
│  └─ tests/          上述工具的单元测试与夹具
└─ <平台>/BASELINE-*.md   阶段性只读基线快照（历史记录，不是最终结论）
```

同一目标的多个平台共用一个 `<目标>/` 目录，**不要**按平台再拆顶层目录。
早期版本的 `tessa` / `tessa-mac` / `tessa-macos` / `tessa-win-v0.28.1` 四目录
已于 2026-10-08 合并为单个 `tessoa/`。

## 当前审计

| 目标 | 交付物 | 说明 |
|---|---|---|
| [`tessoa/`](tessoa/README.md) | `windows/REPORT.md`、`macos/REPORT.md` 等 | 桌面文件管理器客户端授权链审计；Windows 与 macOS 双平台实弹 |

## 相关位置

- 案例包（可发布的 PoC 与方法论文档）：`Tool/cases/tessoa/`
- 本地工作区（样本 / 证据 / 一次性探针 / 补丁产物）：`lab/<目标>/`
- 目录规范：`Tool/docs/WORKSPACE_RULES.md`
