# tessoa 授权补丁工具（macOS 双击版）

双击 `tessoa-patch.command` 运行 tkinter GUI，无需安装额外组件。
依赖：`/opt/homebrew/bin/python3.14`（需 `cryptography`）。
源码：`tessoa_mac_patcher.py`。

## 与 Windows 版差异

- macOS 强制代码签名：改字节后必须 **ad-hoc 重签**
  （`codesign --force --sign - --entitlements`）才能启动；Windows 只需等长替换公钥。
- 设备指纹 = `FNV-1a-64(IOPlatformUUID)`，Windows 用 `MachineGuid`。
- 许可部署 `~/Library/Application Support/tessoa/`。
- 密钥对**不内嵌**于源码：首次运行在本工具目录自动生成并持久化
  （`mint_keys.json`，gitignore），公钥写入 binary 后即为该机的信任锚。

## 使用

1. 双击 `tessoa-patch.command`（或命令行 `python3 tessoa_mac_patcher.py gui`）。
2. 看顶部 **状态** 区：
   - 信任锚 ⚠️原始 = 未补丁；🔸旧版自签 = 历史补丁态；✅已补丁 = 本机公钥在位。
   - 签名行显示 ad-hoc / Developer ID 状态。
3. 点 **完整补丁 PATCH**：
   - 结束既有进程 → 备份当前 binary（`tessoa.orig-backup`）
   - 等长替换内置公钥为自签公钥（公钥槽内为 64 字符 ASCII hex 串）
   - ad-hoc 重签整个 .app
   - 自签离线许可证（宽限死线 = date 头 + 14 天，date 头前推 10 年）
   - 部署 license.ini / license.sig 到数据目录（旧文件备份 `*.bak-<时间戳>`）。
4. 完成后正常启动应用即可，离线可长期存活。

## 还原

点 **还原 RESTORE**：从 `tessoa.orig-backup` 恢复 binary → 重签 →
删除已部署许可。注意：若本机没有原始 Developer ID binary 的备份，
该备份是**首次补丁前状态**的还原点（本机当前即 adhoc 补丁态）。

## 版本兼容

内置公钥为**版本无关锚点**：工具先在二进制中内容扫描定位（唯一性校验），
失败回退 v0.28.1 已知偏移（公钥槽 `0x821F76`，头模板
`0x82E2F7`/`0x82D649`）；头模板按 `# tessoa license proof/store`
行自动提取（103B/55B 长度校验）。已实测 v0.28.1 arm64。
若未来公钥值本身改变，需更新 `ORIG_PUB` 常量。

## 命令行模式（SSH 远程可用）

```
/opt/homebrew/bin/python3.14 tessoa_mac_patcher.py status
/opt/homebrew/bin/python3.14 tessoa_mac_patcher.py patch
/opt/homebrew/bin/python3.14 tessoa_mac_patcher.py verify
/opt/homebrew/bin/python3.14 tessoa_mac_patcher.py restore
```

## 文件位置（所有项目文件集中在同一目录）

| 项目 | 路径 |
|---|---|
| 已安装 app | `/Applications/tessoa.app` |
| 工具目录 | 本目录（patcher + .command + README） |
| binary 备份 | 工具目录 `tessoa.orig-backup` |
| 自签密钥 | 工具目录 `mint_keys.json` |
| 许可证产物 | 工具目录 `license.{sig,ini}` |
| 部署位置 | `~/Library/Application Support/tessoa/license.{sig,ini}` |

## 安全说明

仅在本机自有副本上做授权审计实验。补丁为等长字节替换 + ad-hoc 应用级重签
+ 离线证明自签，不修改系统安全设置。还原按钮可回到打补丁前的 binary 状态。
