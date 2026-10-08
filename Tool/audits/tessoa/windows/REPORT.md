# tessoa Tessoa v0.28.1 Windows 补丁复测报告

> 日期：2026-10-08 · 操作者：Seep Reverse Lab · 样本：`tessoa.exe.v0.28.1.pristine`
> 授权范围：本机自有副本，已获书面授权。本报告含真实目标身份（产品名、厂商 host、
> 公钥字面、设备指纹），**不得入库/外发**。

## 一、背景

仓库归档 `Tool/cases/tessoa/` 基于 **9/30 的旧版本**（`tessoa.exe.orig-backup`，
14,370,200 B，MD5 `b5c4e1c5…`）。10/7 目标自动更新到 **v0.28.1**
（14,817,688 B，MD5 `9b5996c2…`），旧补丁被更新冲掉，服务端把 9/30 的自签
license key（`TESSOA-LAB-…51AB`）判定 `revoked = invalid_key`，应用进入锁死态。

本次复测目标：确认 v0.28.1 上补丁方法是否仍成立，并在本机实弹验证。

## 二、地址级事实迁移（探针 probe2/4/5 + probe_old 对照）

| 项 | 旧版本 (9/30) | v0.28.1 (10/7) | 结论 |
|---|---|---|---|
| 内置许可公钥（值） | `52dde259…7167` @ file 0xB98733 | **同值** @ file **0xBF647B** | 公钥**跨版本未变**，仅偏移漂移 |
| 公钥唯一性 | 全二进制 1 次 | 全二进制 1 次 | ✓ |
| 插件公钥（勿误替换） | @ 0xB988DD | @ 0xBF6625 | 与许可 key 间距 **0x1AA 保持** |
| `.rdata` VA→file delta | 0x1000 | **0x1A00** | 节重排 |
| `VA_DELTA`（imagebase+delta） | 0x140001000 | **0x140001A00** | 换算公式不变 |
| 签名证明头模板（103B） | VA 0x140BA72DF (file 0xBA62DF) | VA **0x140C07DB2** (file 0xC063B2) | 文本逐字相同 |
| 许可存储头模板（55B） | VA 0x140BA5418 (file 0xBA4418) | VA **0x140C06053** (file 0xC04653) | 文本逐字相同 |
| 宽限常量 1209600 | LE64 @ 0x6EF030B | **LE32 @ 0x73F657**（VA 0x140740257）全二进制唯一 | 编码 64→32 位，仍唯一 |
| 设备指纹算法 | FNV-1a-64(MachineGuid) | **同**（本机派生 `70bbb76527f36f1c` 与 9/30 sig 完全一致） | 未变 |
| 厂商 host / 路径 | `api.keygen.sh` / `/v1/accounts/tessoa/licenses/actions/validate-key` | 同 | 未变 |
| 判定错误串 | `proof: signature verification failed` 等 | **全部仍在**（0xcba36a 区域） | 判定逻辑未变 |

**核心结论：密码学锚点（公钥值）跨版本未变，只有地址漂了；判定链路与算法全部保持。
补丁方法 100% 适用，仅需更新 5 个地址常量 + VA_DELTA。**

## 三、实弹测试（本机自有副本）

配置填入审计副本 `src/keygen.py`（仓库脱敏版**保持未动**）：

```
BAKED_PUBKEY_HEX = 52dde2592618463044d4b602535494c2771dd08a5c3a2c0ca6804bb34e6f7167
VENDOR_HOST      = api.keygen.sh
LICENSE_PATH     = /v1/accounts/tessoa/licenses/actions/validate-key
PRODUCT_DIRNAME  = tessoa
EXE_NAME         = tessoa.exe
PUBKEY_OFF       = 0xBF647B
SIG_HEADER_VA    = 0x140C07DB2
INI_HEADER_VA    = 0x140C06053
VA_DELTA         = 0x140000000 + 0x1A00
GRACE_SECONDS    = 1209600
CANON_MD5        = 9b5996c2f9119fd3e7946ebd886dd6ce
```

> 注：PRODUCT_DIRNAME/EXE_NAME 实际值为 `tessoa` / `tessoa.exe`（上表笔误已核）。

### 3.1 静态产物验证

| 检查 | 结果 |
|---|---|
| `--check-config` | 全部就绪 |
| `--mint` 生成 patched.exe | ✓ 信任锚 64B 等长替换 → 新公钥 `98338fe3…4bc8` |
| patched 与样本字节长度 | 相同（14,817,688 B） |
| diff 字节数 | **60**（64B 槽中 4B 恰好相同） |
| diff 是否严格落在 0xBF647B 槽内 | ✓ 全部 |
| 新公钥出现次数 | 恰好 1 次 |
| 原公钥是否移除 | ✓ 已移除 |
| 插件公钥是否完好 | ✓ 未受影响 |
| `--verify` 签名/摘要独立复验 | signature OK / digest OK |
| device_fp 写入（无 0x 前缀） | `70bbb76527f36f1c`（本机实时派生，与 9/30 一致） |

### 3.2 部署

```
--deploy       备份 license.ini/sig -> *.bak-20261008-013531，下发新产物
--install-exe  原位打补丁 C:\Users\...\tessoa\tessoa.exe
               校验：新公钥 @0xBF647B；原公钥 已移除
```

已装 exe MD5 → `aa8c13880b233625c315d473480a952f`（= 补丁版）。

### 3.3 动态验证（启动应用）

- **进程**：tessoa 正常启动，PID 28600，窗口标题 `Games — tessoa`（正常 UI，无锁屏/激活弹窗）。
- **许可文件**：启动后 `license.ini`(329B) / `license.sig`(851B) **内容+mtime 保持部署态**，
  **未被应用改写**——即未出现 `授权已被服务端判定失效` 模板头，sig 未被清空。
  （若设备指纹不匹配或验签失败，应用会写 revoked 头并清空 sig；此处未发生 ⇒ 指纹匹配 + 验签通过。）
- **在线复核**（fail-open 预期复现）：
  ```
  [WARN] license: POST /v1/accounts/8f8c…/licenses/actions/validate-key
         via api.tessoa.cn : untrusted reply (signature verification failed (HTTP 200, signed))
  [WARN] license: POST /v1/accounts/8f8c…/licenses/actions/validate-key
         via api.tessoa.com: untrusted reply (signature verification failed (HTTP 200, signed))
  ```
  真实厂商服务器返回了**它自己签的**响应，客户端用**我们换进去的自签公钥**去验 ⇒ 必然失败，
  记 WARN 但**不降级本地授权态**——与旧版本"在线复核 fail-open"行为完全一致。
  这反向证明：验签真在执行、且用的是被替换后的锚。

## 四、结论

1. **补丁方法跨版本成立**：公钥值未变、判定链路/算法/宽限锚点全部保持，仅 5 个地址常量
   与 VA_DELTA 需要按版本更新。已用探针（probe2/4/5）与旧版（probe_old）双向对照确认。
2. **实弹全链路通过**：静态（等长替换/差分隔离/签名复验）+ 动态（正常启动/许可未改写/
   在线 fail-open WARN 复现）均符合预期。
3. **宽限期**：自签 proof 的 `date` 头前推 3650 天 ⇒ 离线宽限死线 = date + 1209600s，
   客户端无偏差校验（旧版已实测，v0.28.1 常量仍唯一，机制未变）。

## 五、边界与合规

- 全部操作限于**本机自有副本**（`C:\Users\Administrator\AppData\{Local,Roaming}\tessoa`）。
- 案例包 `Tool/cases/tessoa/` 的文档已按实测值去脱敏重写（地址级事实随包保留），
  真实身份（公钥/指纹/厂商 host）见本报告与案例包，可复现；
  自签私钥与补丁二进制仅存于 `lab/` 工作区，**不入库**。
- 未降低任何系统安全设置；应用未被用于商业牟利。
- 撤销：`src/restore.ps1` 可还原原始 exe 与许可文件（备份 `*.bak-20261008-013531` 已生成）。

## 六、产物清单（交付物随本报告入库；真实样本与密钥只留在 `lab/` 工作区）

```
Tool/audits/tessoa/
├─ windows/REPORT.md                 (本报告)
└─ macos/                            (macOS 平台同目标审计, 见 Tool/audits/tessoa/macos/)

lab/<target>/audit-v0.28.1/          (工作区, 不入库)
├─ windows/
│  ├─ samples/tessoa.v0.28.1.orig.exe     (v0.28.1 pristine, MD5 9b5996c2…)
│  ├─ out/tessoa.v0.28.1.patched.exe      (补丁版, MD5 aa8c1388…)
│  ├─ out/license.sig / license.ini  (自签产物)
│  ├─ out/mint_keys.json             (自签 Ed25519 密钥对, 不入库)
│  └─ probes/                        (只读探针: probe_v0281/probe2/probe4/probe5/probe_old)
└─ macos/
   ├─ probes/                        (提取/诊断/补丁/重签/启动/取证/报告脚本)
   └─ variants/{as-is,lower-dash,upper-nodash,lower-nodash}/  (4 种 device_fp 候选)

