<#
.SYNOPSIS
    [已废弃] 向 IDA 发送 Ctrl+Alt+M 唤醒 mrexodia 版 ida-pro-mcp 插件。

.DESCRIPTION
    本工作台已切到 **Hex-Rays 官方 ida-mcp**（SKILL: ida-reverse v3），这套机制整体作废：

      * 官方插件不需要唤醒 —— 它靠 ida-nexus 注册，端口每次随机（实测 49497/30657/52784），
        所以「按热键 + 轮询 127.0.0.1:13337」永远不会成功。
      * 官方 server 连 IDA GUI 都不必须 —— open_database 会自起无头 idalib worker。
      * 旧插件与旧符号链接（%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_mcp*）已删除。

    请改用：
      powershell -NoProfile -ExecutionPolicy Bypass -File Tool\scripts\ida_ensure_ready.ps1 -Status
      powershell -NoProfile -ExecutionPolicy Bypass -File Tool\scripts\ida_ensure_ready.ps1 -Target "<目标>"

    本文件仅为兼容历史文档链接而保留，运行只会打印指引并以 1 退出。
#>
param(
    [int]$WaitSeconds = 0,
    [string]$Target
)

Write-Host 'trigger_ida_mcp.ps1 已废弃（mrexodia ida-pro-mcp 专用）。' -ForegroundColor Yellow
Write-Host '官方 ida-mcp 无需唤醒插件，也没有固定端口。' -ForegroundColor Yellow
Write-Host ''
Write-Host '环境体检：  Tool\scripts\ida_ensure_ready.ps1 -Status'
Write-Host '拉起并握手：Tool\scripts\ida_ensure_ready.ps1 -Target "<绝对路径>" [-Gui]'
Write-Host '战术文档：  Tool\skill\ida-reverse\SKILL.md (v3)'
if ($Target) { Write-Host "(传入的 -Target '$Target' 已忽略)" -ForegroundColor DarkGray }
exit 1
