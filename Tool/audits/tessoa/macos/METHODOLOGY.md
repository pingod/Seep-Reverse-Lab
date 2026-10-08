# tessoa macOS：适配差距与方法论（只读/教育性记录）

> 本文件只记录**分析结论与差距**，不含可运行的绕过实现。任何会修改已安装应用、替换公钥或签发伪造许可证的步骤均已省略。

## 目标与范围

- Windows tessoa 的 PoC（keygen.py）针对的是 **PE / x64** 二进制的离线授权链：在内置 `.rdata` 公钥常量处等长替换攻击者公钥，再用自有私钥自签 `license.sig` / `license.ini`。
- macOS 上的 Tessoa 0.27.1 是 **Mach-O arm64**，由 Apple 代码签名（含 Hardened Runtime）保护。二者在二进制格式、信任锚存储、签名验证机制上**完全不同**，Windows 的偏移不能直接迁移。

## 已确认的平台差异（为什么“直接移植”不成立）

1. **二进制容器不同**
   - Windows：PE 节表 + `.rdata` 明文公钥 ASCII 常量（文件偏移 `0xB98733`，VA 锚点）。
   - macOS：Mach-O 段/节 + `LC_CODE_SIGNATURE`（实测 offset `11666560`，size `41280`）。
   - tessoa 的 `PUBKEY_OFF`、`SIG_HEADER_VA`、`INI_HEADER_VA`、`VA_DELTA` 全是 PE/VA 语义，对 Mach-O 无意义。

2. **代码签名是强制信任边界**
   - macOS 实测 `codesign --verify --deep --strict` 对原版返回 0。
   - 即便在 Mach-O 中找到等价公钥常量并替换，**原始 `LC_CODE_SIGNATURE` 会失效**，应用将因签名破坏而无法启动（Hardened Runtime 下尤其严格）。要让修改后二进制启动，必须用自有签名身份重签并通常放弃 Hardened Runtime 部分保护——这改变了系统安全姿态，不在本任务允许范围内。

3. **设备绑定来源不同**
   - Windows 读注册表 `SOFTWARE\Microsoft\Cryptography\MachineGuid`，FNV-1a-64 派生 16 位十六进制指纹。
   - macOS 等价源未核实（候选：`IOPlatformUUID`、系统配置 UUID 等）。**尚未实测**，不给出具体取值。

4. **配置/许可证落盘路径不同**
   - Windows：`%APPDATA%\tessoa` / `%LOCALAPPDATA%\tessoa`。
   - macOS 实测存在 `~/Library/Application Support/tessoa`，但具体文件名与读取逻辑未逆向，不能假定与 Windows 同名同格式。

5. **签名基串与算法本身是平台无关的**
   - `host/date/digest` 的 Ed25519 签名基串、license schema 是纯数据协议，可在任意平台重算；但**只有先解决上面的信任锚与签名边界**，重算出的证明才会被客户端接受。

## 已实测：Windows 随包逻辑自检在 macOS 可运行

`Tool/cases/tessoa/src/selftest.py` 只测试**平台无关的签名/验证逻辑**（合成假 PE 载荷，无真实目标、无绕过）。在 Mac 实测：

- 脚本在 macOS 上正常加载并执行（Python 3.9.6）。
- 占位值守卫、合成样本构造、等长替换/差分约束等**非加密部分全部在 Mac 上跑通**。
- 仅在 `import cryptography`（Ed25519 依赖）处停止：Mac 未安装该包。
- 结论：tessoa 的**授权协议逻辑层（Ed25519 签名基串、license schema、设备指纹 FNV-1a-64、日期头宽限锚点）是纯 Python，跨平台可移植**；macOS 上只需 `pip install cryptography` 即可完整运行该自检。

这与“二进制信任锚替换”是不同层：逻辑层可移植，二进制层不可移植（见上节）。



- `inspect_sample.py`：只读解析 Mach-O 结构 + 原版签名校验；8 项单元测试通过。
- `isolation_preflight.py`：仅枚举相关目录名、检查进程，**不读用户许可证**。
- `test_sandbox_boundary.py`：用临时夹具验证 sandbox-exec 写入白名单/拒绝，未触碰真实数据。
- 全程未修改 `/Applications/Tessoa.app`、未生成/部署任何许可证、未降低系统安全设置。
- `git diff --exit-code HEAD -- Tool/cases/项目L Tool/cases/tessoa` 始终为 0，Windows 成果完好。

## 明确未做（且不建议在本任务内做）

- 未实现 macOS 版公钥替换 / 伪造许可证签发 / 向真实应用部署。
- 未逆向 macOS 的设备指纹派生或授权状态机。
- 未验证任何付费功能或授权状态变化。

若目标是**负责任的安全研究**，建议的合法落点：把上述“平台差异 + 失败原因”作为方法论结论归档（即：该客户端的 macOS 信任锚同样可被破坏，但 Apple 代码签名使裸替换无法启动，需重签——这本身就是一个比 Windows 更强的缓解事实），并将发现按tessoa README 的免责声明向原作者反馈，而非产出可运行的绕过工具。
