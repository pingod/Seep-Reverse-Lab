<#
.SYNOPSIS
    一条命令把「IDA Pro + 官方 Hex-Rays ida-mcp」拉到可用状态（SKILL: ida-reverse §1/§7）。

.DESCRIPTION
    v2 时代本脚本做三件事：启动 IDA GUI → UIA 清模态框 → 发 Ctrl+Alt+M 唤醒 mrexodia
    插件 → 轮询 127.0.0.1:13337。**换成官方 ida-mcp 后，前三步里只有「GUI 可选」还成立，
    端口轮询与插件唤醒整体作废**，原因（2026-09-27 实测）：

      1) 官方 server 不需要 IDA 常驻。`open_database` 会自己起**无头 idalib worker**，
         冷启动（无 .i64）4.5s，热启动 1.4~1.9s，全程无 GUI、无弹窗。
      2) 没有固定端口。GUI/worker 通过 **ida-nexus** 注册在
         %APPDATA%\Hex-Rays\IDA Pro\nexus\instances\<pid>-<hex>.json，
         端口是**随机**的（实测 49497 / 30657 / 52784 / 20807），所以「等 13337 开」必然失败。
      3) `ida.exe -A`（autonomous）在 9.4 上**是常驻的**，且免掉「Load a new file」/
         「Load PDB file」弹窗 —— v2「严禁 -A」的结论只对 9.3 + mrexodia 插件成立。
      4) 就绪判据不是某个 health 字段，而是 open_database 成功 + len(db.functions)/
         len(db.strings) > 0（实测 13 MB Rust/PE 目标：24698 / 29220）。

    因此本脚本现在只做官方模型下仍有意义的三件事：
      环境体检（ida.exe / uvx / GUI 插件 / ida-nexus / 两个 agent 的 mcp 注册）
        -> 可选启动 GUI（-Gui，带 -A + UIA 兜底清障）
        -> 真实握手（把 JSON-RPC 细节交给同目录 ida_mcp_handshake.py）

    ⚠️ 从 WSL 调用时务必让本脚本尽快返回：WSL 会连带杀互操作子进程，长命令会被 abort
       并丢弃输出。所以进度同时写入 $PSScriptRoot\ida_ensure_ready.log，可另行 tail。

.PARAMETER Status
    只做环境体检，不碰任何数据库。

.PARAMETER Target
    要握手的二进制绝对路径。给了它才会真正 open_database 并读取函数/字符串计数。

.PARAMETER Gui
    先启动 IDA GUI（-A）并等它注册进 nexus，让握手 attach 到 GUI（backend=gui，0.1s），
    便于人眼复核反编译结果。需配合 -Target。

.PARAMETER Clean
    删除 $Target 旁的残留数据库（*.id0/.id1/.id2/.nam/.til/.i64）后重新加载。
    仅在确认那些文件是「上次被强杀的残骸」时使用 —— 会丢弃已有分析。

.PARAMETER Force
    先杀掉所有 ida.exe / ida-mcp 进程再重来。

.PARAMETER NoSave
    握手结束时不落盘（只读侦察）。默认会调 save_database。

.PARAMETER KeepOpen
    握手结束后不 close_database（同一 lease 继续用）。

.PARAMETER TimeoutSeconds
    -Gui 等待 nexus 注册的超时，默认 180。

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Tool\scripts\ida_ensure_ready.ps1 -Status

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File Tool\scripts\ida_ensure_ready.ps1 `
        -Target "D:\path\to\sample.exe"

.EXAMPLE
    # 要在 IDA 界面里同步看结果
    powershell -NoProfile -ExecutionPolicy Bypass -File Tool\scripts\ida_ensure_ready.ps1 `
        -Target "D:\path\to\sample.exe" -Gui -Clean
#>
param(
    [switch]$Status,
    [string]$Target,
    [switch]$Gui,
    [switch]$Clean,
    [switch]$Force,
    [switch]$NoSave,
    [switch]$KeepOpen,
    [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$logPath = Join-Path $PSScriptRoot 'ida_ensure_ready.log'
function Say([string]$m) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m
    Write-Host $line
    try { Add-Content -Path $logPath -Value $line -Encoding UTF8 } catch {}
}
try { Set-Content -Path $logPath -Value "=== ida_ensure_ready(v3) $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" -Encoding UTF8 } catch {}

$Handshake = Join-Path $PSScriptRoot 'ida_mcp_handshake.py'
$NexusInst = Join-Path $env:APPDATA 'Hex-Rays\IDA Pro\nexus\instances'

# ---------------------------------------------------------------- Python 解释器
function Find-Python {
    $uvx = Find-Uvx
    if ($uvx) {
        $py = Join-Path (Split-Path $uvx -Parent) '..\python.exe'
        if (Test-Path $py) { return (Resolve-Path $py).Path }
    }
    foreach ($c in @('python', 'py')) {
        $g = Get-Command $c -ErrorAction SilentlyContinue
        if ($g) { return $g.Source }
    }
    return $null
}
function Find-Uvx {
    foreach ($c in @('uvx', 'uvx.exe')) {
        $g = Get-Command $c -ErrorAction SilentlyContinue
        if ($g) { return $g.Source }
    }
    $pats = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python*\Scripts\uvx.exe'),
        (Join-Path $env:USERPROFILE '.local\bin\uvx.exe'),
        'D:\Program Files\Python\Python*\Scripts\uvx.exe',
        'C:\Program Files\Python*\Scripts\uvx.exe'
    )
    foreach ($p in $pats) {
        $hit = Get-ChildItem $p -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

# ---------------------------------------------------------------- IDA 定位
function Find-IdaRoot {
    $cfg = Join-Path $env:APPDATA 'Hex-Rays\IDA Pro\ida-config.json'
    if (Test-Path $cfg) {
        try {
            $paths = (Get-Content $cfg -Raw -Encoding UTF8 | ConvertFrom-Json).Paths
            foreach ($k in 'ida-install-dir','IDA-install-dir','ida_install_dir') {
                $v = $paths.$k
                if ($v -and (Test-Path $v)) { return $v }
            }
        } catch {}
    }
    if ($env:IDAPATH -and (Test-Path $env:IDAPATH)) { return $env:IDAPATH }
    $root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    foreach ($base in @($root, 'D:\Program Files', 'C:\Program Files', 'D:\Program Files (x86)', 'C:\Program Files (x86)')) {
        $hit = Get-ChildItem -Path $base -Directory -Filter 'IDA*' -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName 'ida.exe' } |
            Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($hit) { return (Split-Path $hit -Parent) }
    }
    return $null
}
function Find-IdaExe {
    $r = Find-IdaRoot
    if ($r) { $e = Join-Path $r 'ida.exe'; if (Test-Path $e) { return $e } }
    return $null
}

# ---------------------------------------------------------------- UIA 清障（仅 -Gui 用）
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class K {
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
}
"@
$AE   = [System.Windows.Automation.AutomationElement]
$TS   = [System.Windows.Automation.TreeScope]
$CT   = [System.Windows.Automation.ControlType]
$ANYCOND = [System.Windows.Automation.Condition]::TrueCondition   # 不能叫 $TRUE：$true 是只读自动变量

function Read-Window($proc) {
    $root = $null
    try { $root = $AE::FromHandle($proc.MainWindowHandle) } catch { return $null }
    if (-not $root) { return $null }
    $all = $root.FindAll($TS::Descendants, $ANYCOND)
    $texts = New-Object System.Collections.ArrayList
    $btns  = New-Object System.Collections.ArrayList
    foreach ($e in $all) {
        try {
            $n = $e.Current.Name
            if (-not $n) { continue }
            if ($e.Current.ControlType -eq $CT::Button) { [void]$btns.Add($e) }
            else { [void]$texts.Add($n) }
        } catch {}
    }
    [pscustomobject]@{ Root = $root; Texts = $texts; Buttons = $btns }
}

function Invoke-Btn($win, [string]$name) {
    foreach ($b in $win.Buttons) {
        try { if ($b.Current.Name -eq $name) {
            $b.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
            Say "    -> 点击按钮 '$name'"
            return $true
        } } catch {}
    }
    return $false
}

# 实测三个阻塞框；一律 UIA 读文本 + 点指定按钮，绝不盲发 Enter
function Clear-IdaDialogs {
    $procs = @(Get-Process ida -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 })
    foreach ($proc in $procs) {
        $win = Read-Window $proc
        if (-not $win) { continue }
        $joined = ($win.Texts -join ' | ')
        if     ($joined -match 'Load PDB file')                                          { [void](Invoke-Btn $win 'No') }
        elseif ($joined -match 'already exists')                                          { [void](Invoke-Btn $win 'Load existing') }
        elseif ($joined -match 'Load file .* as' -or $joined -match 'Processor type')      { [void](Invoke-Btn $win 'OK') }
    }
}

function Get-NexusInstance([string]$forTarget) {
    $files = Get-ChildItem -Path $NexusInst -Filter '*.json' -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        try {
            $j = Get-Content $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            if (-not $forTarget) { return $j }
            $exe = $j.exe_path; $idb = $j.idb_path
            if (($exe -and $exe -ieq $forTarget) -or
                ($idb -and $idb -ieq ($forTarget + '.i64')) -or
                ($idb -and $forTarget -and ($idb -ieq [System.IO.Path]::ChangeExtension($forTarget, $null) + 'i64'))) { return $j }
        } catch {}   # 被占用时读不到，正常
    }
    return $null
}

# ---------------------------------------------------------------- 0. 强制清理
if ($Force) {
    foreach ($n in 'ida','ida-mcp','idaq','idat') {
        Get-Process $n -ErrorAction SilentlyContinue | ForEach-Object {
            Say "kill $n pid=$($_.Id)"; try { $_.Kill() } catch {}
        }
    }
    Start-Sleep -Seconds 2
}

if ($Clean -and $Target) {
    $stub = [System.IO.Path]::ChangeExtension($Target, $null)
    foreach ($ext in 'id0','id1','id2','nam','til','i64') {
        $f = "$stub.$ext"
        if (Test-Path $f) { Say "删除残留数据库: $f"; Remove-Item $f -Force -ErrorAction SilentlyContinue }
    }
}

# ---------------------------------------------------------------- 1. 体检（-Status 到此为止）
$uvx  = Find-Uvx
$ida  = Find-IdaExe
$pyEx = Find-Python
Say ("ida.exe   = " + $(if ($ida) { $ida } else { '未找到' }))
Say ("uvx       = " + $(if ($uvx) { $uvx } else { '未找到（官方 server 靠它启动，MCP 里必须写绝对路径）' }))
Say ("python    = " + $(if ($pyEx) { $pyEx } else { '未找到' }))
Say ("handshake = " + $(if (Test-Path $Handshake) { $Handshake } else { '缺失！' + $Handshake }))

if ($Status -or -not $Target) {
    if (-not (Test-Path $Handshake)) { Say 'FAIL: 缺少 ida_mcp_handshake.py'; exit 1 }
    if ($pyEx) { & $pyEx $Handshake --status; exit $LASTEXITCODE }
    Say 'FAIL: 没有可用的 Python 解释器'; exit 1
}

# ---------------------------------------------------------------- 2. 可选 GUI
if ($Gui) {
    if (-not (Get-NexusInstance $Target)) {
        if (-not $ida) { Say 'FAIL: 未找到 ida.exe，无法 -Gui'; exit 1 }
        if (-not (Test-Path $Target)) { Say "FAIL: 目标不存在: $Target"; exit 1 }
        # 实测：-A 在 9.4 常驻且免弹窗（v2 禁 -A 的结论已作废）
        Say "启动 IDA GUI（-A）: $Target"
        Start-Process -FilePath $ida -ArgumentList @('-A', $Target) | Out-Null
    } else {
        Say 'IDA GUI 已注册在 nexus，跳过启动'
    }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $inst = $null
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        Clear-IdaDialogs                       # 手工启动（不带 -A）时仍会弹窗，这里兜底
        $inst = Get-NexusInstance $Target
        if ($inst) { break }
    }
    if ($inst) {
        Say ("nexus 已注册: pid={0} backend={1} port={2}" -f $inst.pid, $inst.backend, $inst.port)
    } else {
        Say "WARN: ${TimeoutSeconds}s 内没等到 GUI 注册；改用无头 idalib worker 继续"
    }
}

# ---------------------------------------------------------------- 3. 真实握手
if (-not $pyEx) { Say 'FAIL: 没有可用的 Python 解释器'; exit 1 }
$hsArgs = @($Handshake, '--target', $Target)
if ($NoSave)    { $hsArgs += '--no-save' }
if ($KeepOpen)  { $hsArgs += '--keep-open' }
Say "握手：initialize -> tools/list -> open_database -> 就绪判据"
& $pyEx @hsArgs
$rc = $LASTEXITCODE
if ($rc -eq 0) {
    Say 'OK: 官方 ida-mcp 就绪。下一步按 SKILL ida-reverse §4 的战术链写 execute_python。'
    Say '    注意：写任何 ida-domain API 前先 reference(query) —— 猜名字一定报错。'
} else {
    Say "FAIL: 握手退出码 $rc（1=环境缺件 / 2=握手失败）。见上方 FAIL 行与 §8 排障表。"
}
exit $rc
