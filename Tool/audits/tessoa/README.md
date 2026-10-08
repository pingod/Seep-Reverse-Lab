# tessoa 客户端授权链审计

对 `tessoa`（Rust 原生 winit + wgpu 桌面文件管理器）客户端授权链的审计，覆盖
**Windows x64 PE32+** 与 **macOS arm64 Mach-O** 两个平台的实弹验证。

审计结论是：离线许可的信任锚是**编译进二进制的内置公钥**；只要把该公钥换成
自签公钥并重签二进制，就能在不触碰厂商服务端的前提下签发任意设备绑定的许可。
两平台用的是**同一密钥对**，因此结论可互相印证。

## 交付物

| 路径 | 内容 |
|---|---|
| [`windows/REPORT.md`](windows/REPORT.md) | Windows v0.28.1 实弹：地址级事实、公钥等长替换、部署与验证 |
| [`macos/REPORT.md`](macos/REPORT.md) | macOS arm64 实弹：Mach-O 偏移、ad-hoc 重签、设备指纹与激活 |
| [`macos/METHODOLOGY.md`](macos/METHODOLOGY.md) | PE 与 Mach-O 的平台差异、哪些逻辑可移植、哪些不可移植 |
| [`macos/BASELINE-0.27.1.md`](macos/BASELINE-0.27.1.md) | 早期 0.27.1 只读基线快照（历史记录，已被上面报告取代） |
| `macos/mac_facts.json` | Mach-O 只读基线：偏移 / 依赖 / 签名 / 加固状态 |
| `macos/tools/` | 可复用只读检查工具（`inspect_sample.py`、`isolation_preflight.py`） |
| `macos/tests/` | 上述工具的单元测试与沙箱边界夹具 |

## 工作产物（不在本目录，也不在版本库）

真实样本、补丁二进制、自签密钥与签名许可都在本地工作区：

```
lab/<目标>/audit-v0.28.1/
├─ windows/samples/    v0.28.1 pristine 副本
├─ windows/out/        补丁版 exe、自签 license.ini / license.sig、mint_keys.json
├─ windows/probes/     只读探针
├─ macos/probes/       提取 / 诊断 / 补丁 / 重签 / 启动 / 取证脚本
└─ macos/variants/     4 种 device_fp 候选的签发产物
```

## 案例包

可发布的 PoC 与方法论文档在 [`Tool/cases/tessoa/`](../../cases/tessoa/README.txt)，
其中的 `src/keygen.py` 是唯一权威的签发实现（Windows 与 macOS 共用同一协议层）。
