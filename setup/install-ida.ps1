#Requires -Version 5.1
<#
  Seep 工作台 —— IDA Pro + 官方 ida-mcp 配置（v3，2026-09-27）
  ----------------------------------------------------------------
  IDA Pro 是商业软件，不随包分发。本脚本负责官方 Hex-Rays ida-mcp 的四件事：
    1. 探测本机 IDA 安装位置（ida-config.json → 环境变量 → 常见目录）
    2. 定位/校验 uvx —— server 由 `uvx ida-mcp stdio` 启动，**MCP 里必须写绝对路径**
       （裸 'uvx'/'npx' 在 Windows 上会以 WinError 2 失败）
    3. 装 GUI 插件 + 给 IDA 的 Python 装 ida-nexus（只影响「人眼复核」模式；
       无头 idalib 后端不需要插件）
    4. 把真实路径写进 ~/.pi/agent/mcp.json 的 ida 条目

  未装 IDA 时：不报错，仅提示，并说明免费替代路线。

  与 v2 的区别：不再 pip install ida-pro-mcp（那是 mrexodia 版，已废弃），
  不再关心 13337 端口，也不再需要 Ctrl+Alt+M 唤醒插件。详见
  Tool\skill\ida-reverse\SKILL.md 的 v2→v3 作废清单。
#>
[CmdletBinding()]
param(
    [string]$IdaRoot = '',        # 手工指定 IDA 安装目录
    [string]$Uvx = '',            # 手工指定 uvx.exe
    [string]$PluginZip = '',      # 官方 release 的 ida-mcp-plugin-*.zip（离线安装用）
    [switch]$SkipPip              # 只探测+写配置，不装 ida-nexus / 插件
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = Split-Path -Parent $ScriptDir
$AgentDir  = Join-Path $env:USERPROFILE '.pi\agent'
$McpJson   = Join-Path $AgentDir 'mcp.json'
$IdaAppDir = Join-Path $env:APPDATA 'Hex-Rays\IDA Pro'
$PluginDst = Join-Path $IdaAppDir 'plugins\ida-mcp'
$Vendored  = Join-Path $Root 'Tool\mcp\Tool\safe\ida-mcp-plugin'

function Write-Ok($m)   { Write-Host "    [OK] $m" -ForegroundColor Green }
function Write-Warn($m) { Write-Host "    [!!] $m" -ForegroundColor Yellow }
function Write-Info($m) { Write-Host "    [..] $m" -ForegroundColor Gray }
function Esc-JsonPath([string]$s) { if ($null -eq $s) { return $s } return $s.Replace('\', '\\') }

Write-Host "`n  === IDA Pro + 官方 ida-mcp 配置 ===" -ForegroundColor Cyan

# ---------------------------------------------------------------- 1. 探测 IDA
$candidates = @()
if ($IdaRoot -ne '') { $candidates += $IdaRoot }
$cfg = Join-Path $IdaAppDir 'ida-config.json'
if (Test-Path $cfg) {
    try {
        $paths = (Get-Content $cfg -Raw -Encoding UTF8 | ConvertFrom-Json).Paths
        foreach ($k in 'ida-install-dir','IDA-install-dir','ida_install_dir') {
            if ($paths.$k) { $candidates += $paths.$k }
        }
    } catch {}
}
if ($env:IDAPATH) { $candidates += $env:IDAPATH }
$candidates += @(
    'D:\Program Files', 'C:\Program Files', 'D:\Program Files (x86)', 'C:\Program Files (x86)',
    'D:\Tool\IDA Pro', 'C:\Program Files\IDA Pro', 'C:\IDA Pro', 'C:\IDA',
    (Join-Path $Root 'IDA Pro 9.3'), (Join-Path $Root 'IDA Pro 9.4')
)

$found = $null
foreach ($c in $candidates) {
    if (-not $c -or -not (Test-Path $c)) { continue }
    if (Test-Path (Join-Path $c 'ida.exe')) { $found = $c; break }
    # 候选本身是父目录时，扫一层 IDA*
    $sub = Get-ChildItem -Path $c -Directory -Filter 'IDA*' -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName 'ida.exe' } |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($sub) { $found = Split-Path $sub -Parent; break }
}

if (-not $found) {
    Write-Warn '未探测到 IDA Pro 安装'
    Write-Host @'

    说明：IDA Pro 为商业软件，本包不包含，需你自备授权。
    · 下载：https://hex-rays.com/ida-pro  （IDAX 用户走 inst.hex-rays.com）
    · 免费替代：见 MANUAL\IDA-PRO.md（seep MCP 的 radare2 八件套已覆盖大部分场景）
    · 已装但未探测到？手工指定：
        powershell -File .\install-ida.ps1 -IdaRoot "你的IDA目录"

    mcp.json 中 ida 条目将保留占位符，不影响 seep MCP 使用。
'@ -ForegroundColor Gray
    exit 0
}
Write-Ok "探测到 IDA: $found"

# ---------------------------------------------------------------- 2. 定位 uvx
if ($Uvx -ne '') {
    if (-not (Test-Path $Uvx)) { Write-Warn "指定的 -Uvx 不存在: $Uvx"; $Uvx = '' }
}
if (-not $Uvx) {
    $g = Get-Command uvx -ErrorAction SilentlyContinue
    if (-not $g) { $g = Get-Command uvx.exe -ErrorAction SilentlyContinue }
    if ($g) { $Uvx = $g.Source }
}
if (-not $Uvx) {
    $pats = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python*\Scripts\uvx.exe'),
        (Join-Path $env:USERPROFILE '.local\bin\uvx.exe'),
        'D:\Program Files\Python\Python*\Scripts\uvx.exe',
        'C:\Program Files\Python*\Scripts\uvx.exe'
    )
    foreach ($p in $pats) {
        $hit = Get-ChildItem $p -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { $Uvx = $hit.FullName; break }
    }
}
if ($Uvx) {
    Write-Ok "uvx: $Uvx"
} else {
    Write-Warn '未找到 uvx —— 官方 ida-mcp 靠它启动'
    Write-Host @'
    装 uv（任选其一，装完重跑本脚本）：
      · pip install uv
      · powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
      · winget install astral-sh.uv
    装好后 uvx 通常在 <Python>\Scripts\uvx.exe 或 %USERPROFILE%\.local\bin\uvx.exe
'@ -ForegroundColor Gray
    exit 0
}

# ---------------------------------------------------------------- 3. IDA 的 Python + ida-nexus
$idaPy = $null
foreach ($sub in @('python311\python.exe','python312\python.exe','python313\python.exe','python3\python.exe')) {
    $p = Join-Path $found $sub
    if (Test-Path $p) { $idaPy = $p; break }
}
if (-not $idaPy) {
    Write-Info 'IDA 目录下没有自带 python3xx —— 用 idapyswitch 绑定一个'
    $sw = Join-Path $found 'idapyswitch.exe'
    if (Test-Path $sw) {
        Write-Info "idapyswitch.exe --force-path 可选目标："
        & $sw --auto 2>&1 | ForEach-Object { Write-Host "        $_" -ForegroundColor DarkGray }
    } else { Write-Warn '未找到 idapyswitch.exe，跳过 Python 绑定' }
}
if ($idaPy) {
    Write-Ok "IDA Python: $idaPy"
    if ($SkipPip) {
        Write-Info '-SkipPip：跳过 ida-nexus 安装'
    } else {
        # GUI 插件入口只 `import ida_nexus.plugin`，所以 nexus 必须装进 **IDA 的解释器**，
        # 装进系统 Python 没用（实测：插件 init 直接 PLUGIN_SKIP）。
        Write-Info 'pip install ida-nexus（IDA Python）...'
        & $idaPy -m pip install --upgrade ida-nexus 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Info '直连失败，尝试本机代理 127.0.0.1:9565 ...'
            & $idaPy -m pip install --upgrade --proxy http://127.0.0.1:9565 ida-nexus 2>&1 | Out-Null
        }
        if ($LASTEXITCODE -eq 0) { Write-Ok 'ida-nexus 已装入 IDA Python' }
        else { Write-Warn 'ida-nexus 安装失败（无头模式仍可用；仅 GUI attach 模式受影响）' }
    }
} else {
    Write-Warn 'IDA 无可用 Python：GUI 插件模式不可用，但无头 idalib 模式照常工作'
}

# ---------------------------------------------------------------- 4. GUI 插件
if ($SkipPip) {
    Write-Info '-SkipPip：跳过插件安装'
} elseif (Test-Path (Join-Path $PluginDst 'ida-plugin.json')) {
    Write-Ok "GUI 插件已就位: $PluginDst"
} else {
    $src = $null
    if ($PluginZip -and (Test-Path $PluginZip)) { $src = $PluginZip }
    elseif (Test-Path $Vendored) {
        $z = Get-ChildItem (Join-Path $Vendored 'ida-mcp-plugin-*.zip') -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($z) { $src = $z.FullName }
    }
    if ($src) {
        Write-Info "解压插件: $src -> $PluginDst"
        New-Item -ItemType Directory -Force -Path $PluginDst | Out-Null
        $tmp = Join-Path $env:TEMP ('ida-mcp-plugin-' + [guid]::NewGuid().ToString('N'))
        try {
            Expand-Archive -Path $src -DestinationPath $tmp -Force
            Copy-Item (Join-Path $tmp '*') $PluginDst -Recurse -Force
            Write-Ok 'GUI 插件已安装（ida-plugin.json / ida_mcp_plugin.py）'
        } catch { Write-Warn "解压失败: $_" }
        Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    } elseif (Test-Path (Join-Path $Vendored 'ida-plugin.json')) {
        Write-Info "从仓库内置副本安装插件: $Vendored"
        New-Item -ItemType Directory -Force -Path $PluginDst | Out-Null
        Copy-Item (Join-Path $Vendored '*') $PluginDst -Force
        Write-Ok 'GUI 插件已安装'
    } else {
        Write-Warn '找不到插件包（--agent 侧不受影响）'
        Write-Host @'
    官方 release 里取 ida-mcp-plugin-<ver>.zip：
      https://github.com/HexRaysSA/ida-mcp/releases
    然后：powershell -File .\install-ida.ps1 -PluginZip "D:\Downloads\ida-mcp-plugin-x.zip"
    或直接把 3 个文件放进 %APPDATA%\Hex-Rays\IDA Pro\plugins\ida-mcp\
'@ -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------- 5. 写 mcp.json
if (-not (Test-Path $McpJson)) {
    Write-Warn 'mcp.json 不存在，请先运行 install-pi.ps1'
    exit 0
}
$raw = Get-Content $McpJson -Raw -Encoding UTF8
$before = $raw

$idaBlock = @'
"ida": {
      "command": "__UVX__",
      "args": [
        "ida-mcp",
        "stdio",
        "--agent=pi"
      ],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      },
      "transport": "stdio",
      "lifecycle": "eager",
      "requestTimeoutMs": 420000
    }
'@
$idaBlock = $idaBlock.Replace('__UVX__', (Esc-JsonPath $Uvx)).TrimEnd()

# 5a. 先解析 JSON：能解析就整体重写 ida 条目（同时干掉 ida_pro_mcp / 13337 旧写法）
$parsed = $null
try { $parsed = $raw | ConvertFrom-Json } catch { Write-Info 'mcp.json 含占位符，无法按 JSON 解析 —— 走文本替换' }

if ($parsed -and $parsed.mcpServers -and $null -ne $parsed.mcpServers.ida) {
    $old = $parsed.mcpServers.ida
    $oldArgs = @(foreach ($a in $old.args) { [string]$a })
    $stale = ($old.command -match '(?i)\\python(?:\d*)?\.exe$') -or ($oldArgs -match 'ida_pro_mcp|server\.py')
    if ($stale) { Write-Info "检测到旧 mrexodia 版条目（command=$($old.command)），改写为官方 ida-mcp" }
    if ($stale -or $old.requestTimeoutMs -ne 420000 -or $old.command -ne $Uvx) {
        # 文本级替换整个 "ida": { ... } 块，保留其余条目与注释原样
        $m = [regex]::Match($raw, '"ida"\s*:\s*\{(?:[^{}]|\{[^{}]*\})*\}')
        if ($m.Success) {
            $raw = $raw.Replace($m.Value, $idaBlock)     # 字面替换，避免 $ 被当分组引用
        } else {
            Write-Warn '定位 ida 块失败，跳过自动改写'
        }
    } else {
        Write-Ok 'ida 条目已是官方写法且超时正确，无需改写'
    }
} elseif ($parsed) {
    Write-Warn 'mcp.json 里没有 ida 条目 —— 请手工加入（见脚本末尾模板）'
} else {
    # 5b. 占位符形态（模板原文）：整条替换
    $raw = $raw.Replace('<UVX>', (Esc-JsonPath $Uvx))
    $m = [regex]::Match($raw, '"ida"\s*:\s*\{(?:[^{}]|\{[^{}]*\})*\}')
    if ($m.Success) {
        $raw = $raw.Replace($m.Value, $idaBlock)
        Write-Info '按模板文本改写 ida 条目'
    }
    $raw = $raw.Replace('<IDA_ROOT>', (Esc-JsonPath $found))
    $raw = $raw.Replace('<IDA_PYTHON>', (Esc-JsonPath $idaPy))
}

if ($raw -ne $before) {
    try {
        $null = $raw | ConvertFrom-Json      # 只在仍是合法 JSON 时落盘
    } catch {
        Write-Warn '改写后 JSON 不合法，已放弃写入（原文件未动）'
        exit 1
    }
    [System.IO.File]::WriteAllText($McpJson, $raw, (New-Object System.Text.UTF8Encoding($false)))
    Write-Ok 'mcp.json 已更新'
    Write-Info "  UVX         = $Uvx"
    Write-Info "  IDA_ROOT    = $found"
    Write-Info "  IDA_PYTHON  = $(if ($idaPy) { $idaPy } else { '(none)' })"
} else {
    Write-Ok 'mcp.json 无需变更'
}

Write-Host @'

    官方 ida 条目长这样（command 必须是 uvx 的**绝对路径**）：
      "ida": {
        "command": "C:\\...\\Scripts\\uvx.exe",
        "args": ["ida-mcp", "stdio", "--agent=pi"],
        "env": { "PYTHONIOENCODING": "utf-8" },
        "transport": "stdio", "lifecycle": "eager",
        "requestTimeoutMs": 420000
      }
    requestTimeoutMs 必须 >= 420000：execute_python 默认超时 360s，旧值 180000 必然截断。
'@ -ForegroundColor DarkGray

Write-Host '    自检：powershell -File ..\Tool\scripts\ida_ensure_ready.ps1 -Status' -ForegroundColor Yellow
Write-Host '    握手：powershell -File ..\Tool\scripts\ida_ensure_ready.ps1 -Target "<二进制绝对路径>"' -ForegroundColor Yellow
Write-Host "    提示：重启 pi / 在 Qoder 里执行 /mcp reload 使配置生效" -ForegroundColor Yellow
exit 0
