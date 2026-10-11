# workbench — tessoa macOS 补丁流水线工作台（TUI + CLI）

对已授权审计目标 tessoa.app（macOS）做**公钥等长替换 → ad-hoc 重签 → 自签发证 → 下发 → 验证**的一键工作台。
核心价值：**偏移永不手填** —— 公钥槽/sig头/ini头全部按字节内容自动定位，版本漂移不用改代码。

## 快速开始

```bash
cd src
python3 -m workbench            # 无终端控制能力时自动落回 CLI
python3 -m workbench tui        # 强制 TUI
python3 -m workbench locate     # 只定位锚点（零落盘）
python3 -m workbench run --dry-run   # 全管线预演，不写任何文件、不建任何目录
```

TUI 快捷键：`[R]` 跑流水线 · `[V]` 验证激活 · `[L]` 定位 · `[N]` 换新钥匙 · `[D]` dry-run 开关 · `[↑↓]` 翻日志 · `[Q]` 退出。

## 子命令

| 子命令 | 作用 |
|---|---|
| `info` | 目标体检：版本/大小/md5/数据目录/备份目录 |
| `locate` | 内容寻址定位三锚点（公钥槽 + sig头 + ini头），`--json` 出结构化结果 |
| `run` | 完整 9 步管线：探测→定位→备份→钥匙→补丁→重签→签发→下发→自校验 |
| `verify` | 启动应用强制重校验 + exit.log 取证（`--no-launch` 只读态检查） |
| `restore` | 还原补丁前原件 + 清许可。**两道确认门**：CLI 必须 `--yes`（否则只预览），TUI 按两次 `X`（单次只预览，任意其他键取消） |
| `tui` | 终端工作台（curses，stdlib 零依赖） |

公共参数：`--binary / --data-dir / --backup-dir / --out-dir`。**沙盒演练**时把 `--binary` 与 `--data-dir` 同时指到 .app 副本，可完全替代真机路径。

## 安全纪律（内置，非口头）

- **dry-run 纯净**：预演模式零落盘——不建目录、不写密钥、不动备份。`detect/mint` 里所有 `_mkdirs` 都有 gate。
- **备份非阻塞**：已存在同名备份且内容不同 → 保留原备份继续跑，不中断管线。
- **默认复用钥匙**：`load_or_create_keypair` 复用 `out_dir/mint_keys.json`，补丁幂等；`priv` 字段接受 PEM **或 64-hex 原始种子**（兼容历史 keygen.py 资产）。
- **指纹变体显式化**：`device_fp(variant=...)`，默认 `as-is`（IOPlatformUUID 原样大写带横线），四变体与审计报告 §3.3 一致。
- **验证要正面证据**：`verify` 要求应用侧日志出现通过性证据，不以「没报错」当「已激活」。
- **还原 = 字节级还原**：备份是整字节拷贝、自带完整签名，写回即还原，**不自动重签**（重签会使签名 blob 尺寸漂移，字节级回不到备份态）；仅当写回后 `codesign --verify` 失败才补救性重签。
- **破坏性动作不静默**：`restore` 对真机目标的执行必须显式确认。

## 验证记录（2026-10-11）

- `run --dry-run` 8/8 步绿，前后 `~/githome` 零差异。
- 沙盒全闭环「补丁 → 还原」：还原后 md5 与备份态逐字节一致（`836c4f56…`），签名有效。
- `restore` 无 `--yes` 时为纯预览（rc=2），TUI 单次 `X` 仅布防不执行。
- `locate --json` / 顶层 `--json locate` 双形态均通过（`default=SUPPRESS` + `getattr` 兜底）。
- TUI 在 pty 下渲染正常、`Q` 退出 rc=0。
- 阳性对照：权威钥匙现签 license.sig 在自验与 `verify_sig` 下双向通过；现役 license.sig 验签通过、digest 完整。
