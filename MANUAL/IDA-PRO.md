# IDA Pro 准备指引

> **IDA Pro 是商业软件，不随本包分发。** 你需要自备授权，或使用免费替代方案。

---

## 方案 A：已有 IDA Pro 授权（推荐，功能最全）

### 支持版本

IDA Pro **9.4+**（官方 `ida-mcp` 插件要求 `idaVersions >= 9.4`、`requiresPython >= 3.11`）
+ Hex-Rays 反编译器。8.x / 9.0–9.3 装不上官方插件，请走下面的「方案 B / C」。

### 安装后需要做的

> 一句话版：跑 `setup\install-ida.ps1`，它把四件事全做完。下面是它到底装了什么，
> 便于手工排查。

1. **确认 IDA 自带的 Python 运行时存在**：
   ```
   <IDA安装目录>\python311\python.exe
   ```
   IDA 根目录不要猜，从 `%APPDATA%\Hex-Rays\IDA Pro\ida-config.json` 的 `IDAPATH` 读。
   若该文件不存在，用 `<IDA安装目录>\idapyswitch.exe --auto` 绑定一次。

2. **装 `uv` / `uvx`**（官方 MCP 的启动器，必需）：
   ```powershell
   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
   uvx --version
   ```
   ⚠️ `mcp.json` 里的 `command` **必须写 uvx 的绝对路径**。Windows 上直接写 `"uvx"`
   会因 PATHEXT 解析失败报 `FileNotFoundError: [WinError 2]`。

3. **给 IDA 的 Python 装 `ida-nexus`**（插件的运行时依赖）：
   ```powershell
   & "<IDA安装目录>\python311\python.exe" -m pip install "ida-nexus>=0.13.3"
   ```

4. **装官方 GUI 插件**（`install-ida.ps1` 用的是包内自带的发行包，离线可用）：
   源文件在 `Tool/mcp/Tool/safe/ida-mcp-plugin/ida-mcp-plugin-20261003.0.1.zip`，
   安装位置为 `%APPDATA%\Hex-Rays\IDA Pro\plugins\`。

5. **写 `mcp.json`** —— `install-ida.ps1` 会自动替换 `ida` 条目；手工填则：
   ```json
   "ida": {
     "command": "C:\\...\\Scripts\\uvx.exe",
     "args": ["ida-mcp", "stdio", "--agent=pi"],
     "env": { "PYTHONIOENCODING": "utf-8" },
     "transport": "stdio",
     "lifecycle": "eager",
     "requestTimeoutMs": 420000
   }
   ```
   `requestTimeoutMs` 不能小于 420000 —— `execute_python` 服务端默认超时就是 360 s。

6. **验证**（别靠"目录在不在"判断，一定要真握手）：
   ```powershell
   python Tool\scripts\ida_mcp_handshake.py            # 纯预检 + 真实 JSON-RPC 握手
   powershell -File Tool\scripts\ida_ensure_ready.ps1 -Status
   ```
   握手成功会打印 `SERVER ida <版本>` / `TOOLS 6 个` / `OPEN ...` / `READY` / 函数与字符串计数。

7. **使用方式**：在 pi 里说「用 IDA 分析这个文件」，`ida-reverse` Skill 走的是
   `open_database` → `reference` → `execute_python`，**不需要开 IDA 图形界面**
   （idalib 无头后端按需自己拉起来）。

> **旧版说明**：本包早期文档写的 mrexodia `ida-pro-mcp`（66 工具 / `127.0.0.1:13337` /
> Ctrl+Alt+M 唤醒）已被官方实现取代。`Tool/mcp/Tool/safe/ida-pro-mcp/` 仅作历史保留，
> **不要再注册进 mcp.json**；`Tool/scripts/trigger_ida_mcp.ps1` 已改为提示已废弃的空壳。
> 战术细节见 `Tool/skill/ida-reverse/SKILL.md`（v3）。


### 购买渠道
- 官方：https://hex-rays.com/ida-pro
- 免费版 IDA Free（无 Hex-Rays 反编译）：https://hex-rays.com/ida-free

---

## 方案 B：免费替代（无 IDA 授权时）

**核心结论：seep MCP 的 8 个 Radare2 工具已覆盖大部分场景，无需 IDA 也能干活。**

| 能力 | IDA MCP | 免费替代 |
| :--- | :--- | :--- |
| 快速侦察（架构/壳/熵/字符串） | — | ✅ `seep_r2_info` / `seep_r2_strings` |
| 反汇编（含交叉引用） | ✅ | ✅ `seep_r2_disasm` |
| 反编译为类 C 伪代码 | ✅ Hex-Rays | ✅ `seep_r2_decompile` |
| 二进制差分 | — | ✅ `seep_r2_diff` |
| 汇编 ↔ 机器码 | — | ✅ `seep_r2_asm` |
| 函数表 / 导入导出 | ✅ | ✅ `seep_r2_functions` |
| 结构体恢复 | ✅ | ⚠️ Ghidra |
| 类型推断 | ✅ | ⚠️ Ghidra |

### 推荐组合

```
基础层：seep MCP（r2 八件套）      ← 脚本自动装，开箱可用
增强层：Ghidra（免费，含反编译）    ← 需要时下载
可选层：IDA Free（无反编译）        ← 需要 GUI 时
```

### Ghidra 安装

```powershell
# 需先装 JDK 17+
winget install EclipseAdoptium.Temurin.17.JDK
# 下载 Ghidra
# https://github.com/NationalSecurityAgency/ghidra/releases
```

> `Tool/kb/tools/skills/mcp/GhidraMCP/` 提供了 Ghidra 桥接 MCP，可按需注册。

---

## 方案 C：只用 Radare2（最轻量）

**完全跳过 IDA**，只依赖 seep MCP：

```powershell
# install.ps1 已自动装 radare2 到 tools/radare2/
# 直接用这些工具：
#   seep_r2_info / _strings / _functions / _disasm / _decompile / _diff / _asm
```

对以下任务**足够**：
- 壳检测与熵分析
- 字符串与端点提取
- 授权判定点定位
- 补丁点确认（配合 `seep_r2_asm` 验字节）
- Android SO 分析

**不足**：
- 复杂 C++ 逆向的类型恢复
- 大规模交叉引用图谱
- 大型二进制的交互式分析

---

## 三种方案对比

| | 方案 A（IDA Pro） | 方案 B（免费组合） | 方案 C（仅 r2） |
| :--- | :--- | :--- | :--- |
| **成本** | 商业授权 | 免费 | 免费 |
| **反编译** | ✅ Hex-Rays（最强） | ⚠️ Ghidra（次之） | ⚠️ r2 伪代码 |
| **结构体恢复** | ✅ | ⚠️ 部分 | ❌ |
| **上手成本** | 低（自动联动） | 中 | 最低 |
| **覆盖场景** | 全部 | 90% | 70% |

> **建议**：先用**方案 C** 跑通流程，遇到真正需要深度反编译的目标再上方案 A。
