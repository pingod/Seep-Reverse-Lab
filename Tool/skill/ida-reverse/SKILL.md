---
name: ida-reverse
description: 当用户要求“使用 IDA Pro 进行逆向分析”、分析指定可执行文件/库、反编译函数、查找授权/分支判定点时触发此技能。基于官方 Hex-Rays ida-mcp（6 个工具 + ida-domain Python API），无 GUI 也能跑，一条 open_database 即完成加载与自动分析。
license: MIT
compatibility: Windows 10 / Windows 11 x64, IDA Pro ≥ 9.4（含 Hex-Rays 与 idalib/）, IDA Python ≥ 3.11, ida-mcp 20261003.x, ida-domain 0.5.x, ida-nexus ≥ 0.13.3
---

# ida-reverse — IDA Pro 自动化逆向战术技能

> **修订 v3（2026-09-27）**：整条链路换为 **Hex-Rays 官方 `ida-mcp`**，v2 的一半内容作废。
> 本文所有结论均为实测（probe 记录：工具契约 / ida-domain 全 API 面 / 用法与报错形状 / GUI attach）。
>
> **v2 → v3 作废清单**（不要再照 v2 做）：
> 轮询 `127.0.0.1:13337` ❌ · `Ctrl+Alt+M` 唤醒 ❌ · `server_health` / `survey_binary` /
> `find_regex` / `decompile` / `xrefs_to` 等 66 个工具名 ❌ · `strings_cache_ready` 就绪门槛 ❌ ·
> 「不要用 `-A`」❌（实测 9.4 上 `-A` 常驻且免对话框）。
> 保留有价值的部分：UIA 清障（§6）、字符串/交叉引用锚点套路（§7）、PowerShell/WSL 实测坑（§8）。

---

## 〇、五条铁律（v3）

| # | 铁律 | 违反后的**实测**表现 |
| :-- | :--- | :--- |
| 1 | **先 `open_database`，再 `execute_python`** | 跳过直接执行 → `no open database instance; call open_database() first` |
| 2 | **写 API 前先 `reference(query)`**，不要凭记忆猜方法名 | 猜出来的一律报错：`'Xrefs' object has no attribute 'to'`（真实名是 `to_ea`） |
| 3 | **默认无 GUI 即可干活**（backend=`idalib`）；要人眼复核才开 GUI | 以为必须开 IDA/唤醒插件 → 白等数分钟，v2 的死循环根源 |
| 4 | **`execute_python` 里抛异常不返回空，返回 `isError:true` + traceback** | 只看 `stdout` 会把异常当成「没找到」，误判成假阴性 |
| 5 | **改动了 IDB（rename/comment/patch）要显式 `save_database`** | `db` 没有 `save()` 方法（实测 `AttributeError`）；不显式保存则 lease 释放后改动丢失 |

> 官方 server = stdio 桥（进程名 `ida-mcp`）+ **ida-nexus** 发现层。
> 注册表在 `%APPDATA%\Hex-Rays\IDA Pro\nexus\instances\<pid>-<hex>.json`，
> 里面是 `{"backend":"gui","pid":...,"port":49497,"idb_path":...,"token":...}` —— **端口每次随机**，
> 所以任何「固定 13337」的旧脚本天然失效。

---

## 一、拉起（只有一步）

```text
open_database { "path": "C:\\abs\\path\\to\\sample.exe" }
```

实测耗时（同一个 13 MB Rust/PE 目标）：

| 场景 | 首次 `open_database` | 首次 `execute_python` | 说明 |
| :--- | :--- | :--- | :--- |
| 冷（无 `.i64`，无 GUI） | 4.5 s | 54.8 s | 自动分析在后台跑，第一次执行要等它 |
| 热（`.i64` 已存在） | **1.4 – 1.9 s** | 0.0 – 0.5 s | 之后每次都是这个速度 |
| GUI 已开着库 | **0.1 s** | 0.0 s | attach 到 GUI，`backend:"gui"` |

返回体（照抄实测结构）：

```json
{
  "instance_id": "d135c2f15f7c",
  "backend": "idalib",
  "status": "current",
  "recovery": "none",
  "log_path": "C:\\Users\\<you>\\AppData\\Roaming\\Hex-Rays\\IDA Pro\\mcp\\sessions\\00f5b036c24d.jsonl",
  "mcp_id": null,
  "hint": "Call reference(query) to inspect the IDA Domain API before using execute_python; `db` and `ida_domain` are available globally."
}
```

**就绪判据（替代 v2 的 `server_health` 三门槛）**：`open_database` 返回 `isError:false` 且

```python
len(db.functions) > 0 and len(db.strings) > 0     # 实测 13MB Rust/PE: 24698 / 29220
```

`log_path` 指向的 `sessions\<id>.jsonl` 是**本次会话全部 execute_python 的留痕**，复盘/取证直接读它。

收尾：`save_database {}` → `{"path": "...exe.i64"}`；`close_database {}` → `{"closed": true}`。
GUI 里开的库**不会**被 close 关掉（官方文档如此，实测一致：close 后 `nexus\instances` 记录仍在）。

---

## 二、6 个工具（官方 server 的全部面）

| 工具 | 必填参数 | 实测返回 |
| :--- | :--- | :--- |
| `open_database` | `path`（`set_current` 默认 true） | `{instance_id, backend, status, recovery, log_path, hint}` |
| `execute_python` | `code`（`timeout` 默认 **360** s） | `{result, stdout, stderr}` |
| `reference` | `query` | 纯文本 API 参考（`ida_domain` docstring + `Source: 文件:行号`，有时给整段示例脚本） |
| `list_databases` | — | `{instances:[{path, backend, status, instance_id, error}]}` |
| `save_database` | —（`instance_id` 可选） | `{path: "...i64"}` |
| `close_database` | — | `{closed: true}` |

`initialize` 握手与 v2 相同（`protocolVersion:"2024-11-05"`），但**不需要**任何前置端口探测。
server instructions 原文要点：*「IDA Pro 编译产物逆向…用它替代 objdump/readelf/nm/strings」*，
且明确写着 **do not guess the API shape** —— 即铁律 2。

### `execute_python` 的三个实测语义

1. **全局可用**：`db`（`ida_domain.database.Database`）与 `ida_domain` 已注入；`import idaapi/idautils/idc` 也照常工作（经典 IDAPython 与 ida-domain 同库混用实测通过）。
2. **状态在 lease 期内持续**：imports、变量、定义跨调用保留（同一 `instance_id` 内）。
3. **返回单个表达式或尾行表达式**；函数式写法请定义 `run(db)` / `execute(db)` / `main(db)`，无尾表达式时会自动调用。

---

## 三、ida-domain API 面（实测 `dir()`，别再猜）

`db` 的属性：`architecture · base_address · bitness · bytes · comments · compiler_information · crc32 · current_ea · entries · execute_script · execution_mode · filesize · format · functions · heads · hook/hooks/unhook · imports · instructions · is_open · load_time · maximum_ea/minimum_ea · md5/sha256 · metadata · microcode · module · names · path · pseudocode · save_on_close · segments · signature_files · start_ip · strings · types · xrefs`

各 handler 的关键方法（完整清单见 probe2 日志）：

| handler | 实测可用方法（择要） |
| :--- | :--- |
| `db.functions` | `get_at` · `get_all` · `get_between` · `get_by_name` / `get_function_by_name` · `get_callers` / `get_callees` · `get_pseudocode` · `get_disassembly` · `get_name` · `set_name` · `get_comment` / `set_comment` · `get_local_variables` · `get_microcode` · `get_flowchart` · `get_chunks` · `get_signature` · `create` / `remove` · `reanalyze` |
| `db.strings` | `get_all` · `get_at` · `get_at_index` · `get_between` · `rebuild` · `clear` （**可 `len()` 与整表迭代**） |
| `db.xrefs` | `to_ea` · `from_ea` · `code_refs_to_ea` · `data_refs_to_ea` · `calls_to_ea` · `calls_from_ea` · `jumps_to_ea` · `reads_of_ea` · `writes_to_ea` · `get_callers` · `add_code_ref` / `add_data_ref` |
| `db.pseudocode` | `decompile` · `decompile_many` · `get_text` |
| `db.names` | `get_at` · `set_name` · `force_name` · `get_all` · `get_count` · `delete` · `demangle_name` |
| `db.bytes` | `get_bytes_at` · `get_cstring_at` · `get_string_at` · `find_text_between` · `find_bytes_between` · `find_binary_sequence` · `patch_bytes_at` · `set_byte_at` · `create_string_at` · `is_string_literal_at` |
| `db.types` | `get_all` · `get_by_name` · `apply_declaration` · `parse_declarations` · `get_details` · `get_members` · `get_xrefs_to` · `create_struct` / `create_enum` |
| `db.imports` | `get_all_imports` · `get_import_by_name` · `get_imports_for_module` · `get_all_modules` · `exists` |
| `db.comments` | `get_at` · `set_at` · `delete_at` · `get_all` · `set_extra_at` |
| `db.instructions` / `db.heads` | `get_at` · `get_between` · `get_disassembly` · `is_call_instruction` · `call_targets` · `jump_targets` |

### 实测踩到的 6 个签名陷阱

| 想当然 | 真实情况（报错原文） |
| :--- | :--- |
| `db.xrefs.to(ea)` | ❌ `'Xrefs' object has no attribute 'to'` → ✅ `db.xrefs.to_ea(ea)` |
| `db.functions.get_name(ea)` | ❌ 内部对 `int` 取 `.start_ea` → `AttributeError` → ✅ `get_name(db.functions.get_at(ea))`，或干脆 `db.names.get_at(ea)` |
| `db.pseudocode.get_text(ea)` 返回 str | ❌ 返回 **list[str]** → ✅ `"\n".join(...)`；要 str 就用 `str(db.pseudocode.decompile(ea))` |
| `StringItem.ea` | ❌ 字段叫 **`address`**（还有 `length`/`contents`/`encoding`/`type`） |
| `db.bytes.find_text_between(..., case_sensitive=True)` | ❌ 无此形参 → ✅ 先 `reference('search text in bytes')` 看签名 |
| `db.save()` | ❌ `'Database' object has no attribute 'save'` → ✅ 调 **`save_database` 工具** |

---

## 四、典型战术链（VIP / 授权分支定位）

> 目标：字符串 → 引用它的地址 → 所在函数 → 调用者 → 伪代码 → 落注释/改名 → 保存。
> 代码全部为实测可跑形状（示例目标：一个 13 MB 的 Rust/PE 授权客户端；下文用 `sample.exe`、`0xSAMPLE_*` 代指实测地址）。

```python
# 0) 加载
open_database {"path": "C:\\...\\sample.exe"}

# 1) 敏感字符串：整表正则扫（实测 29220 条只花 0.1 s，不存在 v2 的「缓存未就绪静默空」）
execute_python:
  import re
  pat = re.compile(rb'vip|licen|keygen|unlock|expire|owner|admin', re.I)
  hits = [(hex(s.address), s.contents.decode('utf-8','replace')[:80]) for s in db.strings
          if pat.search(s.contents)]
  print('hits', len(hits))
  for h in hits[:40]: print(h)

# 2) 收窄：Rust 目标按模块路径过滤，噪声立降
#    例：某 Rust 授权客户端命中 '<crate>::license::net_keygen\tlicense: ' @ 0xSAMPLE_STR
  sel = [s for s in db.strings if b'<crate>::license' in s.contents]

# 3) 字符串 → 引用者（注意 *_refs_to_ea 返回 int，to_ea 返回 XrefInfo）
  ea = 0xSAMPLE_STR
  refs = list(db.xrefs.data_refs_to_ea(ea))      # 实测 6 条
  for x in db.xrefs.to_ea(ea):
      print(hex(x.from_ea), x.is_code, x.type)

# 4) 取所在函数 + 调用者（CallerInfo 带 name / function_ea，最实用）
  f = db.functions.get_at(0xSAMPLE_FN)
  print(f, db.names.get_at(f.start_ea))
  for c in db.xrefs.get_callers(f.start_ea):      # 实测 3 个调用点
      print(hex(c.ea), c.name, hex(c.function_ea), c.xref_type)

# 5) 伪代码（两种都行；decompile 给对象、可结构化查询）
  cf = db.pseudocode.decompile(f.start_ea)        # str(cf) 实测 18969 字符
  print(str(cf)[:3000])
  print(cf.find_strings(), cf.find_calls())       # 对象上可直接做结构化检索
  # 只要文本行：lines = db.pseudocode.get_text(f.start_ea)

# 6) 一次多函数
  for ea2, cf2 in zip([0xSAMPLE_FN, 0xSAMPLE_OTHER], db.pseudocode.decompile_many([0xSAMPLE_FN, 0xSAMPLE_OTHER])):
      print(hex(ea2), type(cf2).__name__, len(str(cf2)))

# 7) 标注并落盘（实测均返回 True）
  db.names.set_name(0xSAMPLE_FN, 'license_net_keygen_check')
  db.comments.set_at(0xSAMPLE_FN, '授权/网络校验主体')
  save_database {}
```

**要人眼复核时**（GUI 模式）：

```powershell
Start-Process "D:\Program Files\IDA Professional 9.4\ida.exe" -ArgumentList @('-A', '<目标绝对路径>')
# 实测 5 s 内出现 nexus\instances\<pid>-*.json，backend 变 "gui"，open_database 只要 0.1 s
```

---

## 五、`reference` 怎么用（它是这个 server 的“文档检索”）

```text
reference { "query": "decompile function" }
reference { "query": "xrefs to address" }
reference { "query": "search strings with regex" }
reference { "query": "rename function" }
```

实测输出形状：

```
IDA Domain API reference 0.5.1

Query: decompile function

API entries:

method ida_domain.pseudocode.Pseudocode.decompile(self, ea_or_func: Union[int, func_t],
       flags: DecompilationFlags = DecompilationFlags(0)) -> PseudocodeFunction
Decompile a function and return the ctree result.
...
Source: ida_domain\pseudocode.py:3370
```

要点：返回 **top-N 相关条目**（带完整签名 + `Source: 文件:行号`），不是精确单条命中；
有时会直接给一段可抄的示例脚本。**每次写新 API 调用前问一次**，比试错快得多（0.0–0.2 s）。

---

## 六、GUI 模式清障（仅开 GUI 时才需要；UIA 读文本，别盲发 Enter）

⚠️ 主窗口标题会骗人：显示 `Please wait...` 时真正的阻塞框是它的**子窗口**；
Qt 自绘对话框用 `EnumChildWindows` 读不到，必须 UI Automation。

| 模态框（UIA 可见文本判据） | 点哪个按钮 | 原因 |
| :--- | :--- | :--- |
| `Load PDB file` / `Microsoft Symbol Server` | **`No`** | 点 `Yes` 会挂在网络上 |
| `already exists`（`Please confirm`） | **`Load existing`** | 默认不覆盖已有分析 |
| `Load file … as` / `Processor type` | **`OK`** | 首载选文件类型/处理器 |
| 只有 `OK` 的其他提示 | `OK` | 通用兜底 |

**用 `-A` 可以整段跳过**：实测 9.4 下 `ida.exe -A <target>` 常驻（5 s 注册 nexus）、
自动分析照跑、且不再弹「Load a new file」/「Load PDB file」。
v2「`-A` 加载完直接退出、严禁使用」是 **9.3 + mrexodia 插件** 时代的结论，已作废。

手工 UIA 片段（`ida_ensure_ready.ps1` 内已封装为 `Read-Window` / `Invoke-Btn`）：

```powershell
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$AE=[System.Windows.Automation.AutomationElement]; $TS=[System.Windows.Automation.TreeScope]
$CT=[System.Windows.Automation.ControlType]
$ANYCOND=[System.Windows.Automation.Condition]::TrueCondition   # 不能叫 $TRUE，$true 只读
$p    = Get-Process ida | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
$root = $AE::FromHandle($p.MainWindowHandle)
foreach ($e in $root.FindAll($TS::Descendants, $ANYCOND)) {
    if ($e.Current.Name -and $e.Current.ControlType -eq $CT::Button) {
        # 命中判据后：$e.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    }
}
```

---

## 七、环境自检（替代 v2 的「装没装 mrexodia 插件」）

| 项 | 期望值（本机实测） |
| :--- | :--- |
| IDA 安装根 | `D:\Program Files\IDA Professional 9.4`（见 `%APPDATA%\Hex-Rays\IDA Pro\ida-config.json`） |
| MCP 桥启动方式 | `uvx ida-mcp stdio --agent=<name>`，`command` 必须是 **绝对路径** `D:\Program Files\Python\Python314\Scripts\uvx.exe` |
| GUI 插件 | `%APPDATA%\Hex-Rays\IDA Pro\plugins\ida-mcp\`（`ida-plugin.json` + `ida_mcp_plugin.py` + `README.md`）；仓库内置副本在 `Tool\mcp\Tool\safe\ida-mcp-plugin\` |
| 插件版本约束 | `ida-plugin.json` 明写 **`idaVersions: ">=9.4"`**、`requiresPython: ">=3.11"`、`pythonDependencies: ["ida-nexus>=0.13.3"]` |
| 插件依赖 | IDA 自带 Python 3.11 里有 `ida-nexus`（0.13.3）/ `ida-domain`（0.5.1）—— **必须装进 IDA 的解释器**，装进系统 Python 无效 |
| 无头模式 | 只需 IDA 根下有 `idalib/`（9.4 自带）；`ida-domain` 由 uv 环境提供（实测在 `%LOCALAPPDATA%\uv\cache\archive-v0\<hash>\site-packages\`） |
| 运行痕迹 | `...\IDA Pro\nexus\instances\*.json`（活着的后端）· `nexus\logs\<pid>-*.log`（打印 `http://127.0.0.1:<随机端口>`）· `mcp\sessions\*.jsonl`（execute_python 留痕） |
| Qoder 侧配置 | `~\.qoder\settings.json` → `mcpServers.ida`；Pi 侧 `~\.pi\agent\mcp.json` → `ida`（`requestTimeoutMs: 420000`） |
| IDB 落盘位置 | 目标同目录 `<target>.i64` / `.id0/.id1/.nam/.til` |

> ⚠️ **`requestTimeoutMs` 必须 ≥ 420000**。`execute_python` 默认 360 s，
> 冷库首次执行实测 54.8 s，大目标自动分析可能顶满；180 s（旧值）必然超时。

> ⚠️ **搬动过 python 目录后，pip 的 `Scripts\*.exe` 启动器会静默失效**（exit=1 无输出），
> 因为它内嵌了旧的绝对解释器路径。修法：在该 Python 里
> `python.exe -m pip install --force-reinstall --no-deps --no-cache-dir ida-nexus==0.13.3`。
> `ida_nexus._find_console_script()` 会在 IDA 内部 spawn 那个启动器，所以必须可用。

自检脚本：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File Tool\scripts\ida_ensure_ready.ps1 -Status
# 逐项打印 IDA 根 / uvx / 插件 / ida-nexus / nexus 在线实例，并可 -Target 做真实握手
```

---

## 八、排障速查

> 标 ★ 的处置为本文实测；其余为本仓库既有案例或合理推断，用前请先核对。

| 症状 | 真实原因 | 处置 |
| :--- | :--- | :--- |
| `no open database instance; call open_database() first` ★ | 没先开库（设计如此） | §1 |
| `'Xrefs' object has no attribute 'to'` 等 `AttributeError` ★ | 猜了 API 名 | 先 `reference(query)`（§5）；对照 §3 表 |
| `'int' object has no attribute 'start_ea'` ★ | `get_name` 等要 `func_t` 不是地址 | 传 `db.functions.get_at(ea)` 或用 `db.names.get_at(ea)` |
| 伪代码「只有一行」/切片全是 `['` ★ | `get_text` 返回 **list** | `"\n".join(lines)` |
| 字符串检索 0 命中 ★ | 真没有，或正则写成 str 而 `contents` 是 **bytes** | 用 `rb'...'` 模式 |
| `isError:true` + traceback 被当成空结果 ★ | 该工具用 isError 表达异常 | 每次先看 `isError`，再看 `stdout` |
| 改名/注释后重启 IDA 丢失 ★ | 未落盘（`db` 无 `save()`） | 调 `save_database` |
| `ida-mcp` 起不来：`WinError 2` ★ | `command` 写了裸 `uvx` | 用绝对 `...\Scripts\uvx.exe` |
| `.ps1` 报「Try 缺少 Catch」/中文语法错 ★ | 缺 UTF-8 **BOM**，PS 5.1 按 GBK 解析 | 给 `.ps1` 加 `efbbbf`（`.md` 不需要） |
| 每次调用卡满 `requestTimeoutMs` | 超时值太小 / 冷库首次执行慢 | 420000 + 先做一次小 `execute_python` 预热 |
| GUI 开着但 `backend` 仍是 `idalib` | GUI 未注册进 nexus（插件缺失 / 打开的不是同一个文件） | 看 `nexus\instances\*.json` 的 `exe_path` 是否与 `open_database` 的 `path` 同文件 |
| 打开目标报「权限不足」/ 卡在 `.id0` | 上次 worker 变孤儿，咬着数据库文件 | 结束残留 `ida` / `ida-mcp` 进程，或 `-Clean` 删残骸重建 |
| IDA 停在 `Please wait...` | 自动分析仍在跑（13 MB Rust 需数分钟），不是对话框 | UIA 先看有无子框，再决定等还是点（§6） |
| 变量赋值报「只读」 | 用了 `$TRUE` / `$PID` 等保留名 | 换名（如 `$ANYCOND`） |
| WSL/Git Bash 里长命令被 abort、输出全丢 | 后台子进程被连带杀；`$_` 被写成 `extglob.` | 命令要短 + 写日志文件再 tail；PowerShell 一律落成 `.ps1` 用 `-File` |

---

## 九、变更记录

| 版本 | 日期 | 说明 |
| :--- | :--- | :--- |
| v1 | — | 初版。含 3 处硬伤：旧方法名、未提插件唤醒、未提字符串缓存静默空 |
| v2 | 2026-09-26 | 针对 mrexodia `ida-pro-mcp` 2.0.0（66 工具 / 13337 / Ctrl+Alt+M）全量实测修正 |
| **v3** | 2026-09-27 | **迁到 Hex-Rays 官方 `ida-mcp`**：① 生命周期改为单步 `open_database`，删除 13337 轮询、`Ctrl+Alt+M` 唤醒、`server_health`/`strings_cache_ready` 门槛与 66 工具表；② 新增实测 6 工具契约 + ida-domain API 面（probe2 `dir()` 全量）；③ 新增 §3「6 个签名陷阱」与 §8 报错原文对照；④ 双后端实测数据（idalib 冷/热 4.5 s/1.4 s、gui 0.1 s、首次执行 54.8 s）；⑤ `-A` 结论反转并给出证据；⑥ 环境自检换成 nexus/sessions 路径与 `requestTimeoutMs≥420000`、python 搬迁后启动器失效修法 |

**关联文件**

- `Tool\scripts\ida_ensure_ready.ps1` — 官方模型的环境自检 + 真实握手（§7）
- `Tool\scripts\trigger_ida_mcp.ps1` — **已废弃**（mrexodia Ctrl+Alt+M 专用，保留仅作历史说明）
- 复现脚本（`probe_official_contract.py` / `probe_ida_domain_api.py` / `probe_usage_recipes.py` / `probe_gui_attach.py`）与其 `ida_mcp_v3_probe*.log` 输出：本文 v3 修订时的一次性验证件，**未随仓库分发**；如需重跑，按 §1/§3/§6 的形状重写即可。
