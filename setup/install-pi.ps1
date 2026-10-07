#Requires -Version 5.1
<#
  Seep 工作台 —— 一键配置 Pi Agent 运行环境 (加强版)
  包含：
    1. 备份原 ~/.pi/agent 配置
    2. 同步 9 个 Skill
    3. 同步提示词与安全放行扩展
    4. 增量合并 mcp.json（保护已有用户配置，UTF-8 No BOM，反斜杠安全转义）
    5. 配置 settings.json
#>
[CmdletBinding()]
param(
    [switch]$SkipPackages
)

$ErrorActionPreference = 'Continue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = Split-Path -Parent $ScriptDir
$NormalizedRoot = $Root.Replace('\', '/')
$ToolDir   = Join-Path $Root 'Tool'
$AgentDir  = Join-Path $env:USERPROFILE '.pi\agent'
$SkillsDir = Join-Path $AgentDir 'skills'
$ExtDir    = Join-Path $AgentDir 'extensions'

function Write-Ok($m)   { Write-Host "    [OK] $m" -ForegroundColor Green }
function Write-Warn($m) { Write-Host "    [!!] $m" -ForegroundColor Yellow }
function Write-Info($m) { Write-Host "    [..] $m" -ForegroundColor Gray }

Write-Host "`n  === Pi Agent 环境配置 ===" -ForegroundColor Cyan

# ---------------------------------------------------------------- 1. 目录与备份
foreach ($d in @($AgentDir, $SkillsDir, $ExtDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

$backup = Join-Path $AgentDir ("backup-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$needBackup = @('SYSTEM.md', 'AGENTS.md', 'mcp.json', 'settings.json')
$hasOld = $false
foreach ($f in $needBackup) {
    if (Test-Path (Join-Path $AgentDir $f)) { $hasOld = $true; break }
}
if ($hasOld) {
    New-Item -ItemType Directory -Path $backup -Force | Out-Null
    $n = 0
    foreach ($f in $needBackup) {
        $p = Join-Path $AgentDir $f
        if (Test-Path $p) { Copy-Item $p $backup -Force; $n++ }
    }
    Write-Ok "已安全备份原有配置 ($n 个文件) -> $backup"
}

# ---------------------------------------------------------------- 2. Skill 同步
$srcSkills = Join-Path $ToolDir 'skill'
if (Test-Path $srcSkills) {
    # ⚠️ 同名冲突修复（2026-09-27）：
    # Tool/skill/ida-reverse/ 与 Tool/skill/safe-skills/ida-reverse/ 都要装到
    # ~/.pi/agent/skills/ida-reverse/。Get-ChildItem 按字母序返回，'ida-reverse' <
    # 'safe-skills'，所以旧版 safe-skills 那一份会**后**复制并把官方版删掉覆盖掉。
    # 结果：每次 install 都用旧的 mrexodia/idalib-mcp HTTP 手册覆盖了官方 ida-mcp 战术文档。
    # 规则：顶层 Tool/skill/<name>/ 是本地维护的权威版，优先；safe-skills 只补空缺。
    $claimed = @{}
    foreach ($s in (Get-ChildItem $srcSkills -Directory)) {
        if ($s.Name -eq 'safe-skills') { continue }
        $dst = Join-Path $SkillsDir $s.Name
        if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
        Copy-Item $s.FullName $dst -Recurse -Force
        $claimed[$s.Name] = $s.FullName
        Write-Ok "skill: $($s.Name)"
    }
    $ss = Join-Path $srcSkills 'safe-skills'
    if (Test-Path $ss) {
        $skipped = @()
        foreach ($sub in (Get-ChildItem $ss -Directory)) {
            if ($claimed.ContainsKey($sub.Name)) {
                $skipped += $sub.Name
                continue
            }
            $dst = Join-Path $SkillsDir $sub.Name
            if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
            Copy-Item $sub.FullName $dst -Recurse -Force
            $claimed[$sub.Name] = $sub.FullName
        }
        Write-Ok ('safe-skills -> skills/（安装 ' + ($claimed.Count - $skipped.Count) + ' 个）')
        if ($skipped.Count -gt 0) {
            Write-Warn ("safe-skills 与顶层同名，已保留顶层版: " + ($skipped -join ', ') +
                        '（顶层 Tool/skill/ 为权威版）')
        }
    }
} else { Write-Warn "未找到 $srcSkills" }

# ---------------------------------------------------------------- 3. 提示词 + 扩展
$srcPrompt = Join-Path $ToolDir 'prompts'
foreach ($f in @('SYSTEM.md', 'AGENTS.md')) {
    $src = Join-Path $srcPrompt $f
    if (Test-Path $src) { Copy-Item $src (Join-Path $AgentDir $f) -Force; Write-Ok "prompt: $f" }
    else { Write-Warn "未找到 $f" }
}
$srcExt = Join-Path $srcPrompt 'extensions'
if (Test-Path $srcExt) {
    foreach ($f in (Get-ChildItem $srcExt -Filter '*.ts')) {
        Copy-Item $f.FullName (Join-Path $ExtDir $f.Name) -Force
        Write-Ok "extension: $($f.Name)"
    }
}

# ---------------------------------------------------------------- 4. 增量安全合并 mcp.json (UTF-8 No BOM, 无覆盖隐患)
$dstMcp = Join-Path $AgentDir 'mcp.json'
$existingConfig = [PSCustomObject]@{ mcpServers = [PSCustomObject]@{} }

if (Test-Path $dstMcp) {
    try {
        $rawMcp = [System.IO.File]::ReadAllText($dstMcp, [System.Text.Encoding]::UTF8)
        # 注意：不能用 $rawMcp.StartsWith([char]0xFEFF)。
        # .NET 默认 StartsWith 使用文化敏感比较，而 U+FEFF（BOM）是可忽略字符，
        # 等价于空字符串，会导致任何字符串都“以 BOM 开头”，从而误删首字符并破坏 JSON。
        if ($rawMcp.Length -gt 0 -and [int]$rawMcp[0] -eq 0xFEFF) { $rawMcp = $rawMcp.Substring(1) }
        $existingConfig = $rawMcp | ConvertFrom-Json
    } catch {
        Write-Warn "现有 mcp.json 语法异常，正在安全初始化..."
        $existingConfig = [PSCustomObject]@{ mcpServers = [PSCustomObject]@{} }
    }
}

if (-not $existingConfig.mcpServers) {
    $existingConfig | Add-Member -NotePropertyName 'mcpServers' -NotePropertyValue ([PSCustomObject]@{}) -Force
}

# 探测 uvx —— 官方 ida-mcp 由 `uvx ida-mcp stdio` 启动，command 必须是绝对路径
# （裸 'uvx' 在 Windows 上是 uvx.cmd，MCP 客户端用 CreateProcess 直接拉起会 WinError 2）
$uvx = $null
foreach ($c in @('uvx', 'uvx.exe')) {
    $gUvx = Get-Command $c -ErrorAction SilentlyContinue
    if ($gUvx) { $uvx = $gUvx.Source; break }
}
if (-not $uvx) {
    $uPats = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python*\Scripts\uvx.exe'),
        (Join-Path $env:USERPROFILE '.local\bin\uvx.exe'),
        'C:\Program Files\Python*\Scripts\uvx.exe'
    )
    foreach ($p in $uPats) {
        $hit = Get-ChildItem $p -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { $uvx = $hit.FullName; break }
    }
}
if ($uvx) {
    Write-Ok "探测到 uvx（IDA MCP）: $uvx"
} else {
    $uvx = 'uvx'
    Write-Warn '未探测到 uvx —— ida 条目保留裸 "uvx"，请 pip install uv 后重跑，或见 MANUAL\IDA-PRO.md'
}

# 探测 Node.js —— playwright / js-reverse 若配 "command": "npx"，npx 在 Windows 上是 npx.cmd，
# CreateProcess 直拉会 WinError 2，且 `npx -y` 每次启动都要联网去 registry 取包。工作台已自带
# 这两个包（含 node_modules），所以用绝对路径的 node.exe 直跑本地入口脚本。
$nodeExe = $null
$nCand = @(
    $env:NODE_HOME | ForEach-Object { Join-Path $_ 'node.exe' }
    'C:\Program Files\nodejs\node.exe'
)
$gNode = Get-Command node -ErrorAction SilentlyContinue
if ($gNode) { $nCand = @($gNode.Source) + $nCand }
foreach ($c in $nCand) { if ($c -and (Test-Path $c)) { $nodeExe = $c; break } }
if ($nodeExe) {
    Write-Ok "探测到 Node.js: $nodeExe"
} else {
    $nodeExe = 'node'
    Write-Warn '未探测到 Node.js（nvm/绝对路径均无），mcp.json 里保留裸 "node"，请自行安装 Node LTS'
}

# 挂载核心 seep MCP
$seepServerPy = "$NormalizedRoot/Tool/mcp/seep_mcp_server.py"
$seepEntry = [PSCustomObject]@{
    command = "python"
    args    = @($seepServerPy)
    env     = [PSCustomObject]@{
        PYTHONIOENCODING = "utf-8"
    }
    transport = "stdio"
}
$existingConfig.mcpServers | Add-Member -NotePropertyName 'seep' -NotePropertyValue $seepEntry -Force

# 挂载 ida（官方 Hex-Rays ida-mcp：靠 ida-nexus 注册、端口每次随机，无头 idalib 也能干活）
$idaEntry = [PSCustomObject]@{
    command          = $uvx
    args             = @('ida-mcp', 'stdio', '--agent=pi')
    env              = [PSCustomObject]@{ PYTHONIOENCODING = 'utf-8' }
    transport        = 'stdio'
    lifecycle        = 'eager'
    requestTimeoutMs = 420000
}
$existingConfig.mcpServers | Add-Member -NotePropertyName 'ida' -NotePropertyValue $idaEntry -Force

# IDA 本体探测（只用于提示；无头 idalib 模式无需 GUI 常驻）
$idaRoot = $null
$idaCands = @('C:\Program Files', 'D:\Program Files', 'D:\Tool\IDA Pro', 'C:\Program Files\IDA Pro', 'C:\IDA Pro')
$idaCands += @(Get-ChildItem -Path $Root -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'IDA*' } | ForEach-Object { $_.FullName })
foreach ($cand in $idaCands) {
    if (Test-Path (Join-Path $cand 'ida.exe')) { $idaRoot = $cand; break }
    $hitIda = Get-ChildItem -Path $cand -Directory -Filter 'IDA*' -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName 'ida.exe' } |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($hitIda) { $idaRoot = Split-Path $hitIda -Parent; break }
}
if ($idaRoot) {
    Write-Ok "探测到 IDA: $idaRoot"
    Write-Info '继续跑 install-ida.ps1 可自动装 GUI 插件 + ida-nexus'
} else {
    Write-Warn '未探测到 IDA Pro（无 IDA 时 seep MCP 的 r2 八件套仍可用，见 MANUAL\IDA-PRO.md）'
}

# 挂载 js-reverse（走本地构建入口，避开 npx 的 WinError 2 与每次联网）
$jsReverseJs = "$NormalizedRoot/Tool/mcp/Tool/safe/js-reverse-mcp/build/src/index.js"
if (-not (Test-Path $jsReverseJs)) {
    Write-Warn 'js-reverse-mcp 尚未构建，请先运行: powershell -File setup\extract-deps.ps1'
}
$jsReverseEntry = [PSCustomObject]@{
    command   = $nodeExe
    args      = @($jsReverseJs)
    transport = "stdio"
    lifecycle = "lazy"
}
$existingConfig.mcpServers | Add-Member -NotePropertyName 'js-reverse' -NotePropertyValue $jsReverseEntry -Force

# 挂载 playwright (若不存在才添加模板，不冲掉用户现有 Token)
if (-not $existingConfig.mcpServers.playwright) {
    $playwrightEntry = [PSCustomObject]@{
        command   = $nodeExe
        args      = @("$NormalizedRoot/Tool/mcp/Tool/safe/playwright-mcp/cli.js", "--extension")
        env       = [PSCustomObject]@{
            PLAYWRIGHT_MCP_EXTENSION_TOKEN = "<YOUR_PLAYWRIGHT_TOKEN>"
        }
        transport = "stdio"
        lifecycle = "eager"
    }
    $existingConfig.mcpServers | Add-Member -NotePropertyName 'playwright' -NotePropertyValue $playwrightEntry -Force
}

# 序列化为 UTF-8 No BOM 格式写入
$finalMcpJson = $existingConfig | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($dstMcp, $finalMcpJson, (New-Object System.Text.UTF8Encoding $false))
Write-Ok "mcp.json 已增量合并完成（保护已有第三方配置，UTF-8 无BOM格式）"

# ---------------------------------------------------------------- 5. settings.json (增量合并 packages)
$dstSettings = Join-Path $AgentDir 'settings.json'
$packages = @(
    'npm:pi-open-tui',
    'npm:pi-web-access',
    'npm:@juicesharp/rpiv-todo',
    'npm:@narumitw/pi-btw',
    'npm:@narumitw/pi-plan-mode',
    'npm:@narumitw/pi-usage',
    'npm:pi-mcp-extension',
    'npm:@smoose/pi-themes',
    'npm:pi-tool-display',
    'npm:@juicesharp/rpiv-ask-user-question',
    'npm:pi-playwright',
    'npm:pi-goal-x'
)

$settings = [PSCustomObject]@{}
if (Test-Path $dstSettings) {
    try {
        $rawSet = [System.IO.File]::ReadAllText($dstSettings, [System.Text.Encoding]::UTF8)
        # 同上：必须用序数/字符比较，避免文化敏感比较误判 BOM
        if ($rawSet.Length -gt 0 -and [int]$rawSet[0] -eq 0xFEFF) { $rawSet = $rawSet.Substring(1) }
        $settings = $rawSet | ConvertFrom-Json
    } catch { $settings = [PSCustomObject]@{} }
}

$currentPackages = @()
if ($settings.packages) { $currentPackages = @($settings.packages) }
foreach ($pkg in $packages) {
    if ($currentPackages -notcontains $pkg) { $currentPackages += $pkg }
}

$settings | Add-Member -NotePropertyName 'packages' -NotePropertyValue $currentPackages -Force
$finalSettingsJson = $settings | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($dstSettings, $finalSettingsJson, (New-Object System.Text.UTF8Encoding $false))
Write-Ok "settings.json 已安全同步（$($currentPackages.Count) 个 packages）"

# ---------------------------------------------------------------- 6. 安装扩展包
if (-not $SkipPackages) {
    $pi = Get-Command pi -ErrorAction SilentlyContinue
    if ($pi) {
        Write-Info 'pi update --extensions ...'
        & pi update --extensions 2>&1 | ForEach-Object { Write-Info $_ }
        if ($LASTEXITCODE -eq 0) { Write-Ok 'pi 扩展包已更新' }
        else { Write-Warn 'pi update 失败，可稍后手动执行：pi update --extensions' }
    } else {
        Write-Warn '未找到 pi 命令，跳过扩展包更新'
    }
}

exit 0
