#Requires -Version 5.1
<#
  Seep 工作台 —— pi 环境配置
  1. 备份现有配置
  2. 复制 Skill / 提示词 / 扩展
  3. 生成 mcp.json（替换占位符）
  4. 写 settings.json（packages 列表）
  5. 安装 pi 扩展包
#>
[CmdletBinding()]
param(
    [switch]$NoBackup,
    [switch]$SkipPackages
)

$ErrorActionPreference = 'Continue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = Split-Path -Parent $ScriptDir
$ToolDir   = Join-Path $Root 'Tool'
$AgentDir  = Join-Path $env:USERPROFILE '.pi\agent'
$SkillsDir = Join-Path $AgentDir 'skills'
$ExtDir    = Join-Path $AgentDir 'extensions'

function Write-Ok($m)   { Write-Host "    [OK] $m" -ForegroundColor Green }
function Write-Warn($m) { Write-Host "    [!!] $m" -ForegroundColor Yellow }
function Write-Info($m) { Write-Host "    [..] $m" -ForegroundColor Gray }

New-Item -ItemType Directory -Force -Path $AgentDir, $SkillsDir, $ExtDir | Out-Null

# ---------------------------------------------------------------- 1. 备份
if (-not $NoBackup) {
    $stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backup = Join-Path $AgentDir "_backup_$stamp"
    New-Item -ItemType Directory -Force -Path $backup | Out-Null
    $n = 0
    foreach ($f in @('SYSTEM.md', 'AGENTS.md', 'mcp.json', 'settings.json')) {
        $src = Join-Path $AgentDir $f
        if (Test-Path $src) { Copy-Item $src (Join-Path $backup $f) -Force; $n++ }
    }
    if (Test-Path $ExtDir) {
        $eb = Join-Path $backup 'extensions'
        New-Item -ItemType Directory -Force -Path $eb | Out-Null
        Get-ChildItem $ExtDir -Filter '*.ts' -ErrorAction SilentlyContinue |
            ForEach-Object { Copy-Item $_.FullName $eb -Force; $n++ }
    }
    Write-Ok "已备份 $n 个文件 -> $backup"
}

# ---------------------------------------------------------------- 2. Skill
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

# ---------------------------------------------------------------- 4. mcp.json
$tpl = Join-Path $ToolDir 'mcp\mcp.json.template'
if (Test-Path $tpl) {
    $content = Get-Content $tpl -Raw -Encoding UTF8

    # 修复：Windows 路径含单反斜杠，直接塞进 JSON 字符串会产生 "\Downloads"
    # 这类非法转义，导致整个 mcp.json 无法被严格 JSON 解析器读取。必须转义。
    function Esc-JsonPath([string]$s) { if ($null -eq $s) { return $s } return $s.Replace('\', '\\') }

    $content = $content.Replace('<SEEP_ROOT>', (Esc-JsonPath $Root))

    # 修复：playwright / js-reverse 原来配的是 "command": "npx"。npx 在 Windows 上是
    # npx.cmd，MCP 客户端用 CreateProcess 直接拉起会 WinError 2 找不到文件；而且
    # `npx -y` 每次启动都要联网去 registry 取包。工作台已经自带这两个包（含
    # node_modules），所以改为用绝对路径的 node.exe 直跑本地入口脚本。
    $nodeExe = $null
    $nCand = @(
        $env:NODE_HOME | ForEach-Object { Join-Path $_ 'node.exe' }
        'C:\Program Files\nodejs\node.exe'
    )
    $g = Get-Command node -ErrorAction SilentlyContinue
    if ($g) { $nCand = @($g.Source) + $nCand }
    foreach ($c in $nCand) { if ($c -and (Test-Path $c)) { $nodeExe = $c; break } }
    if ($nodeExe) {
        $content = $content.Replace('<NODE_EXE>', (Esc-JsonPath $nodeExe))
        Write-Ok "探测到 Node.js: $nodeExe"
    } else {
        $content = $content.Replace('<NODE_EXE>', 'node')
        Write-Warn '未探测到 Node.js（nvm/绝对路径均无），mcp.json 里保留裸 "node"，请自行安装 Node LTS'
    }
    $jrEntry = Join-Path $Root 'Tool\mcp\Tool\safe\js-reverse-mcp\build\src\index.js'
    if (-not (Test-Path $jrEntry)) {
        Write-Warn 'js-reverse-mcp 尚未构建，请先运行: powershell -File setup\extract-deps.ps1'
    }

    # 探测 uvx —— 官方 ida-mcp 由 `uvx ida-mcp stdio` 启动，command 必须是**绝对路径**
    # （裸 'uvx' 在 Windows 上 WinError 2；旧写法 IDA Python + ida_pro_mcp\server.py 已废弃）
    $uvx = $null
    foreach ($c in @('uvx', 'uvx.exe')) {
        $g = Get-Command $c -ErrorAction SilentlyContinue
        if ($g) { $uvx = $g.Source; break }
    }
    if (-not $uvx) {
        $uPats = @(
            (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python*\Scripts\uvx.exe'),
            (Join-Path $env:USERPROFILE '.local\bin\uvx.exe'),
            'D:\Program Files\Python\Python*\Scripts\uvx.exe',
            'C:\Program Files\Python*\Scripts\uvx.exe'
        )
        foreach ($p in $uPats) {
            $hit = Get-ChildItem $p -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($hit) { $uvx = $hit.FullName; break }
        }
    }
    if ($uvx) {
        $content = $content.Replace('<UVX>', (Esc-JsonPath $uvx))
        Write-Ok "探测到 uvx（IDA MCP）: $uvx"
    } else {
        $content = $content.Replace('<UVX>', 'uvx')
        Write-Warn '未探测到 uvx —— ida 条目保留裸 "uvx"，请 pip install uv 后重跑，或见 MANUAL\IDA-PRO.md'
    }

    # 顺带探测 IDA 本体（只用于提示；无头 idalib 模式无需 GUI 常驻）
    $idaRoot = $null
    $idaCands = @('D:\Program Files', 'C:\Program Files', 'D:\Tool\IDA Pro', 'C:\Program Files\IDA Pro', 'C:\IDA Pro')
    # 兼容把 IDA 直接放在工作台根目录下的情况（如 "<Root>\IDA Pro 9.4"）
    $idaCands += @(Get-ChildItem -Path $Root -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'IDA*' } | ForEach-Object { $_.FullName })
    foreach ($cand in $idaCands) {
        if (Test-Path (Join-Path $cand 'ida.exe')) { $idaRoot = $cand; break }
        $sub = Get-ChildItem -Path $cand -Directory -Filter 'IDA*' -ErrorAction SilentlyContinue |
            ForEach-Object { Join-Path $_.FullName 'ida.exe' } |
            Where-Object { Test-Path $_ } | Select-Object -First 1
        if ($sub) { $idaRoot = Split-Path $sub -Parent; break }
    }
    if ($idaRoot) {
        Write-Ok "探测到 IDA: $idaRoot"
        Write-Info '继续跑 install-ida.ps1 可自动装 GUI 插件 + ida-nexus'
    } else {
        Write-Warn '未探测到 IDA Pro（无 IDA 时 seep MCP 的 r2 八件套仍可用，见 MANUAL\IDA-PRO.md）'
    }

    $dstMcp = Join-Path $AgentDir 'mcp.json'
    # 修复：PowerShell 5.1 的 -Encoding UTF8 会写 BOM，严格 JSON 解析器不接受。
    [System.IO.File]::WriteAllText($dstMcp, $content, (New-Object System.Text.UTF8Encoding($false)))
    Write-Ok "mcp.json 已生成 -> $dstMcp"

    if ($content -match '<YOUR_PLAYWRIGHT_TOKEN>') {
        Write-Info 'playwright token 仍为占位符（不用浏览器自动化可忽略）'
    }
} else { Write-Warn "未找到 $tpl" }

# ---------------------------------------------------------------- 5. settings.json
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

$settings = $null
if (Test-Path $dstSettings) {
    try { $settings = Get-Content $dstSettings -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $settings = $null }
}
if ($null -eq $settings) { $settings = [pscustomobject]@{} }

$settings | Add-Member -NotePropertyName 'packages' -NotePropertyValue $packages -Force
$settings | ConvertTo-Json -Depth 10 | Set-Content -Path $dstSettings -Encoding UTF8
Write-Ok "settings.json 已写入 $($packages.Count) 个 packages"

# ---------------------------------------------------------------- 6. 安装扩展包
if (-not $SkipPackages) {
    $pi = Get-Command pi -ErrorAction SilentlyContinue
    if ($pi) {
        Write-Info 'pi update --extensions ...'
        & pi update --extensions 2>&1 | ForEach-Object { Write-Info $_ }
        if ($LASTEXITCODE -eq 0) { Write-Ok 'pi 扩展包已更新' }
        else { Write-Warn 'pi update 失败，可稍后手动执行：pi update --extensions' }
    } else {
        Write-Warn '未找到 pi 命令，跳过扩展包安装'
        Write-Info '安装 pi 后手动执行：pi update --extensions'
    }
}

Write-Host "`n    提示：需重启 pi 使 Skill / 提示词 / MCP 生效" -ForegroundColor Yellow
exit 0
