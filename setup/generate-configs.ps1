#Requires -Version 5.1
<#
  Seep 工作台 — 各 Agent 配置一键自愈与绝对路径展开生成器 (Config Generator)
  用于解决 DSH、OpenCode、Claude Code 用户手工替换 <SEEP_ROOT> 出错的问题。
#>
[CmdletBinding()]
param(
    [switch]$PrintOnly
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = Split-Path -Parent $ScriptDir
$NormalizedRoot = $Root.Replace('\', '/')
$ToolDir   = Join-Path $Root 'Tool'
$McpServerPy = "$NormalizedRoot/Tool/mcp/seep_mcp_server.py"

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "          Seep Reverse Lab — 多 Agent 配置文件生成与自愈器" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  检测到工作台物理根目录: $Root" -ForegroundColor White
Write-Host "  标准化 POSIX 路径表示: $NormalizedRoot" -ForegroundColor Gray

# -----------------------------------------------------------------------------
# 1. 生成 Claude Code 项目级 .mcp.json (若不存在或修复)
# -----------------------------------------------------------------------------
Write-Host "`n[1/3] 正在生成 Claude Code 项目级配置 (.mcp.json)..." -ForegroundColor White
$claudeMcpJson = @"
{
  "mcpServers": {
    "seep": {
      "command": "python",
      "args": [
        "$McpServerPy"
      ],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
"@
$claudeDest = Join-Path $Root '.mcp.json'
if (-not $PrintOnly) {
    [System.IO.File]::WriteAllText($claudeDest, $claudeMcpJson, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "  [√] 已更新: $claudeDest" -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# 2. 生成 OpenCode / Codex 工作区配置 (opencode.jsonc)
# -----------------------------------------------------------------------------
Write-Host "`n[2/3] 正在生成 OpenCode 工作区配置 (opencode.jsonc)..." -ForegroundColor White
$openCodeJsonc = @"
{
  "`$schema": "https://opencode.ai/config.json",
  "mcpServers": {
    "seep": {
      "command": "python",
      "args": [
        "$McpServerPy"
      ],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
"@
$openCodeDest = Join-Path $Root 'opencode.jsonc'
if (-not $PrintOnly) {
    [System.IO.File]::WriteAllText($openCodeDest, $openCodeJsonc, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "  [√] 已更新: $openCodeDest" -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# 3. 生成 DeepSeek Harness 可直接粘贴的 YAML 配置 (cordis.generated.yml)
# -----------------------------------------------------------------------------
Write-Host "`n[3/3] 正在生成 DeepSeek Harness (DSH) 插件配置 (cordis.generated.yml)..." -ForegroundColor White
$dshYaml = @"
# ==============================================================================
# DeepSeek Harness (Cordis) 插件配置 — 可直接复制粘贴进 profile 或 cordis.yml
# 生成基准目录: $NormalizedRoot
# ==============================================================================
plugins:
  - id: seep-mcp
    name: '@deepseek-ai/dsh-mcp-client'
    config:
      serverName: seep
      transport: stdio
      command: python
      args:
        - '$McpServerPy'
      env:
        PYTHONIOENCODING: utf-8
"@
$dshDest = Join-Path $ScriptDir 'cordis.generated.yml'
if (-not $PrintOnly) {
    [System.IO.File]::WriteAllText($dshDest, $dshYaml, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "  [√] 已生成: $dshDest" -ForegroundColor Green
}

Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host "  🎉 所有 Agent 配置文件生成完毕！无任何 <SEEP_ROOT> 占位符残留！" -ForegroundColor Green
Write-Host "  DSH 用户可直接打开 setup/cordis.generated.yml 复制 YAML 插件配置。" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
