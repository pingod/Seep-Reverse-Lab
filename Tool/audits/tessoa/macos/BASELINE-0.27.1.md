> **历史快照（tessoa v0.27.1，只读基线阶段）。**
> 本文件记录的是动手之前的原版基线：只做了结构解析与原版签名校验，
> 当时**未**实现任何补丁或伪造许可。
> 随后的实弹补丁与激活验证结论见 [`REPORT.md`](REPORT.md)，
> 平台差异结论见 [`METHODOLOGY.md`](METHODOLOGY.md)。
> 本文与上述报告冲突时，以报告为准。

# tessoa macOS v0.27.1：只读基线（历史）

## 范围

目标为用户指定的 Tessoa 0.27.1 macOS arm64 样本。本目录独立于 `Tool/cases/tessoa` 和 `Tool/cases/项目L`，不修改 Windows 案例。

本轮仅完成样本结构与原版签名校验，**未实现或验证 Windows 授权实验的 macOS 等效行为**。没有生成许可证、替换公钥、修改已安装应用或更改系统安全设置。

## 实测

- 应用：`/Applications/Tessoa.app`
- Bundle ID：`com.no-needto-recall.tessoa`
- 版本：`0.27.1`
- 可执行文件大小：11,707,840 字节
- SHA-256：`a81e607eaad6938dbebf90450cb5904758eca6b6742ce8be48b73ce33b4cda35`
- 格式：little-endian Mach-O 64，CPU type `0x0100000c`（arm64）
- Load commands：34
- LC_CODE_SIGNATURE：offset 11,666,560，size 41,280
- `codesign --verify --deep --strict`：exit 0
- 与之前记录的已安装可执行文件 SHA-256 相同。
- `git diff --exit-code HEAD -- Tool/cases/项目L Tool/cases/tessoa`：exit 0。

## 可复现检查

在 Mac 执行：

```sh
python3 inspect_sample.py /Applications/Tessoa.app
```

仅使用 Python 标准库和系统 codesign，向 stdout 输出 JSON。签名检查不通过时返回非零退出码；不写应用、不读取用户许可证或设备标识。

## 隔离前置检查（第二轮）

运行 `python3 isolation_preflight.py` 的实测结果：

- 当前 Mac 用户 UID 为 501。
- 存在 `/Users/pavia/Library/Application Support/tessoa`，仅检查目录名，没有读取内部文件。
- 检查时 `pgrep -x tessoa` 未发现匹配进程；这不保证未来启动时也没有进程。
- 系统 `sandbox-exec` 在拒绝文件写入的规则下运行 `/usr/bin/true` 返回 0。
- 未启动 Tessoa，未创建测试许可证。

**不能据此认定隔离完成。** 修改 HOME 不足以隔离 macOS Preferences、Keychain、IPC 或单实例锁。沙箱工具可用也不等于 Tessoa 能在约束下正常运行。后续应使用明确的写入白名单和原数据目录访问拒绝规则，再验证原版测试副本的启动行为；在此之前不能部署到真实用户数据目录。

第一次通过 SSH 直接传内联沙箱规则时发生 `zsh:1: number expected`（参数引号解析失败），改为传输 Python 脚本并使用 argv 数组后检查成功。未尝试绕过系统权限。

## 沙箱写入边界（第三轮）

`python3 test_sandbox_boundary.py` 已在 Mac 返回 exit 0、passed true：白名单目录内创建成功，保护夹具的覆盖、新建、删除均被拒绝，原始标记内容不变。全部操作仅针对审计目录内的临时夹具，没有启动目标应用。

限制：本测试只证明该规则下的直接文件写入限制；未证明文件读取、网络、IPC、系统服务代理写入或目标应用单实例锁隔离，不能据此宣布完整隔离或适配成功。

## 尚未证明

- macOS 的设备绑定来源和配置目录是否与 Windows 语义相同。
- macOS 授权状态机、日期校验及离线宽限行为。
- 测试副本的配置与单实例锁是否真正独立于已安装应用。
- 任何付费功能或授权状态的变化。

Windows PE 地址不能迁移为 Mach-O 地址；存在签名命令和原版签名有效，也不代表修改后可以安全启动。后续启动实验前需先解决用户数据与单实例隔离。
