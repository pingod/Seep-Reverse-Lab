#Requires -Version 5.1
<#
  首次运行：解压 node_modules.zip / venv.zip（从 GitHub clone 后执行一次）
  用法：powershell -ExecutionPolicy Bypass -File .\extract-deps.ps1
#>
$ErrorActionPreference = 'Continue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = Split-Path -Parent $ScriptDir
$SafeDir   = Join-Path $Root 'Tool\mcp\Tool\safe'

# 修复：这些 zip 包内部**已经带了一层目录**（node_modules/、.venv/）。
# 原来把 DestinationPath 直接指到 ".../node_modules"，解压结果就成了
# node_modules/node_modules/*，Node 的模块解析找不到任何依赖，
# js-reverse-mcp / playwright-mcp 两个 MCP 全部起不来（verify.ps1 只看目录
# 是否存在，所以当时仍是 PASS）。现在一律解压到包的根目录。
$zips = @(
    @{ Zip = "$SafeDir\js-reverse-mcp\node_modules.zip";  Dest = "$SafeDir\js-reverse-mcp" }
    @{ Zip = "$SafeDir\playwright-mcp\node_modules.zip";  Dest = "$SafeDir\playwright-mcp" }
    @{ Zip = "$SafeDir\ida-pro-mcp\venv.zip";             Dest = "$SafeDir\ida-pro-mcp" }   # 旧 mrexodia 版，可选；官方 ida-mcp 用 uvx 免解压
)

function Repair-NestedDir {
    # 自愈：把历史遗留的 <parent>\<leaf>\<leaf>\* 提一层上来
    param([string]$Parent, [string]$Leaf)
    $outer = Join-Path $Parent $Leaf
    $inner = Join-Path $outer $Leaf
    if (-not (Test-Path $inner)) { return }
    Write-Host "  [FIX] 检出 $Leaf/$Leaf 双层嵌套，正在提升一层 ..." -ForegroundColor Yellow
    $others = @(Get-ChildItem -Path $outer -Force | Where-Object { $_.Name -ne $Leaf })
    if ($others.Count -gt 0) {
        Write-Host "  [SKIP] $outer 下还有其他文件，未自动合并，请手工处理" -ForegroundColor Yellow
        return
    }
    foreach ($item in Get-ChildItem -Path $inner -Force) {
        Move-Item -LiteralPath $item.FullName -Destination $outer -Force
    }
    Remove-Item -LiteralPath $inner -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] 已修正 $Leaf" -ForegroundColor Green
}

foreach ($z in $zips) {
    $zipPath = $z.Zip
    $destParent = $z.Dest
    $leaf = Split-Path $zipPath -Leaf
    # node_modules.zip -> node_modules；venv.zip -> .venv
    $inner = if ($leaf -eq 'venv.zip') { '.venv' } else { 'node_modules' }
    $marker = Join-Path $destParent $inner

    Repair-NestedDir -Parent $destParent -Leaf $inner

    if (Test-Path $marker) {
        Write-Host "  [SKIP] $leaf (已存在于 $destParent)" -ForegroundColor Green
        continue
    }
    if (-not (Test-Path $zipPath)) {
        Write-Host "  [WARN] $zipPath 不存在" -ForegroundColor Yellow
        continue
    }
    Write-Host "  [..] 解压 $leaf -> $destParent ..." -NoNewline
    New-Item -ItemType Directory -Path $destParent -Force | Out-Null
    Expand-Archive -Path $zipPath -DestinationPath $destParent -Force
    Repair-NestedDir -Parent $destParent -Leaf $inner
    Write-Host " 完成" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# js-reverse-mcp 仓库里只带 TypeScript 源码，必须先编译出 build/src/index.js
# 才能被 mcp.json 里的 `node .../build/src/index.js` 直接启动。
# ---------------------------------------------------------------------------
$jr = Join-Path $SafeDir 'js-reverse-mcp'
$jrEntry = Join-Path $jr 'build\src\index.js'
$jrTsc = Join-Path $jr 'node_modules\typescript\bin\tsc'
if (-not (Test-Path $jrEntry) -and (Test-Path $jrTsc) -and (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host '  [..] 编译 js-reverse-mcp (tsc) ...'
    Push-Location $jr
    try {
        & node $jrTsc 2>&1 | Select-Object -Last 5
        if (Test-Path $jrEntry) { Write-Host "  [OK] 已生成 build\src\index.js" -ForegroundColor Green }
        else { Write-Host '  [WARN] tsc 未产出 build/src/index.js，请手工执行 npm run build' -ForegroundColor Yellow }
    } finally { Pop-Location }
} elseif (-not (Test-Path $jrEntry)) {
    Write-Host '  [WARN] 缺少 typescript 或 node，js-reverse-mcp 无法本地构建（见 MANUAL/PREREQUISITES.md）' -ForegroundColor Yellow
}

Write-Host '  依赖解压检查结束。' -ForegroundColor Cyan
