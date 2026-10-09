# tessoa 授权补丁工具（双击版）

单文件 Windows x64 可执行程序，双击即用，无需 Python 环境。
源码：`tessoa_patch_gui.py`（tkinter + cryptography）。

## 使用

1. 双击 `tessoa_patcher.exe` 打开窗口。
2. 看顶部 **状态** 区：
   - 信任锚 ⚠️原始 = 未补丁；✅已补丁 = 已打补丁。
   - 版本 v0.28.x 由二进制字符串自动识别。
   - 备份行显示该版本的原始 exe 备份（还原用）。
3. 点 **完整补丁 PATCH**：
   - 结束既有进程 → 备份原始 exe（版本专属 `.orig-backup-<ver>`）
   - 等长替换内置公钥为自签公钥
   - 自签离线许可证（宽限死线 = date 头 + 14 天，date 头前推 10 年）
   - 部署 license.ini / license.sig 到 `%APPDATA%\tessoa\`
   - 自校验 Ed25519 签名。
4. 完成后正常启动 tessoa 即可，离线可长期存活。

## 还原

点 **还原 RESTORE**：从**同版本**备份恢复原始 exe，删除已部署许可证。
跨版本备份会被拒绝（避免误回滚）。

## 版本兼容

内置公钥为**版本无关锚点**，工具在二进制中扫描定位（不依赖固定偏移），
许可证头模板按 `# tessoa license proof/store` 行自动提取。已实测
v0.28.1 与 v0.28.3 均可自动定位。若未来公钥值本身改变，需更新
`BAKED_PUBKEY` 常量。

## 文件位置

| 项目 | 路径 |
|---|---|
| 已安装 exe | `%LOCALAPPDATA%\tessoa\tessoa.exe` |
| 原始备份 | 同目录 `tessoa.exe.orig-backup-<版本>` |
| 自签密钥 | `%APPDATA%\tessoa_patch_tool\mint_keys.json` |
| 许可证产物 | `%APPDATA%\tessoa_patch_tool\license.{sig,ini}` |
| 部署位置 | `%APPDATA%\tessoa\license.{sig,ini}` |

## 安全说明

仅在本机自有副本上做授权审计实验。补丁为等长字节替换 + 离线证明自签，
不修改系统安全设置。还原按钮可回到打补丁前的原始状态（同版本备份）。
