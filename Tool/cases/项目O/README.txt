  Case     : 项目O（Electron/asar 授权流审计范式 —— 首例，第 16 种工业级范式）
  Target   : 项目O <目标版本>  (macOS arm64 桌面下载器 / Electron + Vite / NSIS 同架构 Windows 姊妹版)
  Scope    : 客户端授权流安全审计（CWE-602 / CWE-347 / CWE-693）· 脚本层（asar/JS + V8 字节码）
  Release  : 项目O.<目标版本>.License-Flow-Report-INT0

  ============================================================================
  1. 架构定性
  ============================================================================
  双进程 Electron 桌面应用：
    - 主进程  dist-electron/main/*.js    （Vite 编译产物，CommonJS）
    - 侧进程  sidecar（下载引擎，独立 Node 子进程，manifest 签名校验）

  授权信任链分层（本案例核心发现）：
    明文 JS 薄转发层（25 个 license 模块）
        │  module.exports = require('../license-core')["<模块名>"]
        ▼
    license-core.js（4 行引导：require('bytenode'); require('./license-core.jsc')）
        ▼
    license-core.jsc（bytenode 编译的 V8 字节码 —— 全部授权逻辑在此，源码不可见）

  依赖（package.json 原文）：
    @noble/curves ^1.9.7   Ed25519 验签
    @noble/hashes ^1.8.0   摘要
    bytenode    ^1.5.7     V8 字节码加载
    electron-updater ^6.2.1  自动更新
    semver      ^7.7.4

  与 项目A–N 的差异：前 15 个案例全部是**原生二进制范式**
  （PE x86/x64、.NET WPF、Java/JVM、Qt5/C++、Rust），本案例首次落在
  **打包脚本层**：授权判定点不在二进制里，而在 asar 内的 JS/字节码里。

  ============================================================================
  2. 字节码内授权链路（jsc 字符串取证重建）
  ============================================================================
  从 license-core.jsc 提取的明文字符串（符号串 + 路由串）重建出 10 段链路：

  (1) 指纹      fingerprint  —— 设备指纹（deviceId，16 位 hex）
  (2) 密钥      keys / crypto —— Ed25519 验签（@noble/curves），公钥内嵌字节码
  (3) 激活      activator → POST /v1/activate · /v1/deactivate · /v1/devices?key=
  (4) 验证      verifier —— 授权数据本地验签，产出布尔判定
  (5) 时钟锚定  clock-store + session-clock + epoch-watch
                三件套：本地时间回拨被高水位（hwm）文件夹住
  (6) 过期锁存  expiry-latch —— 到期状态只进不退（抗时间回拨的单向闩）
  (7) 心跳      heartbeat-policy + heartbeat-send + hb-secret
                POST /v1/heartbeat；断网进入本地降级判定（判定权在本地）
  (8) 服务端裁决 server-verdict / server-notice → /v1/diag
  (9) 持久化    storage / persist-util —— license.json + hwm + 缓存
  (10) 门控     gate / consent-gate / ticker —— 判定结果对 UI 的放行门

  API 路由（相对路径，端点走环境变量不硬编码）：
    LICENSE_API_URL  →  /v1/activate · /v1/deactivate · /v1/devices?key=
                        /v1/heartbeat · /v1/diag
                       · /api/v1/<product>/commerce/handoffs
                       · /api/v1/<product>/license-epoch
    LICENSE_EPOCH_PATH / LICENSE_EPOCH_TIMEOUT_MS

  版本策略（明文 JS）：
    https://github.com/<vendor>/<product>-desktop/releases/latest/download/version-policy.json

  ============================================================================
  3. 判定模型（CWE-602）
  ============================================================================
  权威归属：**本地布尔**（CWE-602 成立）。心跳是"增强"不是"权威"——verifier
  用内嵌公钥对本地 license 数据验签，判定全程不依赖服务端在线。

  **⚠ 2026-10-10 CDP 实测修订（macOS 0.12.5）**："断网 + 数据层伪造即可绕过"
  **不成立**。渲染层 CDP 直测门控三组对照：

    A 伪造 license.json（补丁态）          → getStatus() = unactivated
    B 伪造 license.json（mode=offline）    → getStatus() = unactivated
    C 伪造 json + 还原原厂 license.bin     → getStatus() = blocked:expired

  判定链真实结构：license.bin（加密，915B，熵 7.81）是**主授权存储**，
  license.json 只是激活成功后的明文缓存；数据未过 Ed25519 验签时 gate 直接判
  unactivated，"断网降级放行"只对**签名合法**的数据开放。jsc 字符串表含反补丁
  标记 `clearedVerdictPatch` + `require_server_verdict`。

  → 可复现旁路 = **替换 jsc 内嵌公钥（bytecode patch）→ 自签授权数据**
    （对应早期 Windows 侧补丁脚本 `patched-keys` + `gen_tokens` 的命名），
    纯数据层重写在 0.12.5 必然失败（完整证据链存内部工作区 evidence/，不入库）。
  ============================================================================
  4. 复现步骤（脱敏版，macOS arm64）
  ============================================================================
  1) npx @electron/asar extract <app>.app/Contents/Resources/app.asar asar/
  2) 确认信任链：grep -r "license-core" asar/dist-electron/main/license/
     （25 个模块全部单行转发）
  3) strings asar/dist-electron/main/license-core.jsc | grep -E '/v1/|license'
  4) 运行时数据取证：<app data>/license.json · license-hwm.json · *.db
  5) 门控直测（CDP）：open -a <app> --args --remote-debugging-port=9333
     → node cdp.mjs 9333 "window.api.license.getStatus().then(JSON.stringify)"
  6) 旁路（0.12.5 实测修订）：纯数据层重写 license.json/hwm → 验签失败判
     unactivated，不放行；可复现旁路 = patch jsc 内嵌公钥 + 自签授权数据
     （完整证据链存于内部工作区 evidence/patch_verification.md，不入库）

  完整性基线（macOS arm64，<目标版本>）：
    app.asar SHA256: 44b529eeb37f01a8da36427ef427366efc542c95b92eb317f83c3c00258dc659
    体积 6,740,911 B

  ============================================================================
  5. 结论
  ============================================================================
  - 判定模型：本地权威（CWE-602 成立）；但 0.12.5 实测证明纯数据层伪造**不可绕**
    （验签失败 → unactivated），旁路需下沉字节码层（公钥替换 + 自签）。
  - 防护亮点：bytenode 字节码隐藏授权源码 + 加密 license.bin 主存储
    + 时间高水位防回拨 + 单向过期闩 + 反补丁标记 `clearedVerdictPatch`。
  - 防护缺口：公钥内嵌可提取（待办）；判定全程离线（无服务端强制在线校验）；
    渲染层 CDP 未禁用（--remote-debugging-port 可直通授权门 API）。
  - 范式意义：脚本层授权流审计 = 无需脱壳、无需 AOB、分钟级出结论，
    是原生二进制范式的低成本补充路径。
