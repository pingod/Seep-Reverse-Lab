# build.ps1 -- 项目L 案例归档：语法自检、脱敏走查与完整性清单生成
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File build.ps1
#   powershell -ExecutionPolicy Bypass -File build.ps1 -Denylist <path-to-denylist>
#
# 脱敏走查需要一份"禁止出现在归档里的真实字面值"清单。该清单本身含有目标身份，
# 因此**不随包发布**：默认查找同目录的 redaction.txt（已被 .gitignore 排除），
# 也可用 -Denylist 指向本地私有目录里的清单，或设置环境变量 SEEP_DENYLIST_PROJECTL。
# 清单缺失时本脚本仍会执行**通用**走查（本机用户目录、二进制/证据/私钥产物隔离），
# 并明确报告目标专属清单未加载。
#
# 清单格式：每行 `名称<TAB>正则`；`#` 开头为注释；匹配不区分大小写。

param(
    [string]$Denylist = ''
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  项目L -- 案例归档打包 / 完整性校验" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# ---- 1. Python 脚本语法自检 ----
$py = Join-Path $root 'src\keygen.py'
$pyc = Join-Path $root 'src\__pycache__'
if ((Get-Command python -ErrorAction SilentlyContinue) -and (Test-Path $py)) {
    & python -m py_compile $py (Join-Path $root 'src\selftest.py') (Join-Path $root 'src\verify_package.py')
    if ($LASTEXITCODE -ne 0) { throw 'python syntax error' }
    Write-Host '  [OK] src\keygen.py + src\selftest.py + src\verify_package.py syntax' -ForegroundColor Green
    Remove-Item $pyc -Recurse -Force -ErrorAction SilentlyContinue
} else {
    Write-Host '  [SKIP] python not found, skipping syntax check' -ForegroundColor Yellow
}

# ---- 2. PowerShell 脚本语法自检 ----
foreach ($rel in @('src\restore.ps1', 'build.ps1')) {
    $full = Join-Path $root $rel
    if (-not (Test-Path $full)) { continue }
    $errs = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$null, [ref]$errs)
    if ($errs -and $errs.Count -gt 0) { throw "$rel parse error: $($errs[0])" }
    Write-Host ('  [OK] ' + $rel + ' syntax') -ForegroundColor Green
}

# ---- 3. 占位保护自检：脱敏版必须**拒绝**在占位值未填写时运行 ----
if (Get-Command python -ErrorAction SilentlyContinue) {
    Push-Location $root
    try {
        $out = & python src\keygen.py --check-config 2>&1 | Out-String
    } finally { Pop-Location }
    if ($out -notmatch '\[config\]') { throw 'keygen.py --check-config produced no verdict' }
    if ($out -notmatch 'BAKED_PUBKEY_HEX') {
        throw 'keygen.py --check-config does not report the redacted placeholders'
    }
    Write-Host '  [OK] placeholder guard active (unfilled redacted values are reported)' -ForegroundColor Green
    Remove-Item $pyc -Recurse -Force -ErrorAction SilentlyContinue

    # ---- 3b. 逻辑自检：合成样本上跑一次完整签发，无需真实目标 ----
    Push-Location $root
    try {
        $st = & python src\selftest.py 2>&1 | Out-String
        $code = $LASTEXITCODE
    } finally { Pop-Location }
    if ($code -ne 0) {
        Write-Host $st -ForegroundColor Red
        throw 'src\selftest.py failed -- the shipped PoC is not functional'
    }
    if ($st -notmatch '(\d+)/\1 checks passed') { throw 'src\selftest.py reported no check tally' }
    Write-Host ('  [OK] synthetic-fixture self-test: ' + $Matches[1] + '/' + $Matches[1] + ' checks passed') -ForegroundColor Green
    Remove-Item $pyc -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- 4. 脱敏走查 ----
Write-Host ''
Write-Host '  脱敏走查 (redaction scan)' -ForegroundColor Cyan

# 通用项：随包发布，不含目标身份
$patterns = [ordered]@{
    'local user profile' = 'C:\\Users\\[^<]'
    'home dir leak'      = '/home/[a-z0-9._-]{3,}'
    'drive-letter workdir' = '[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\(Desktop|Downloads|Documents)'
}

if (-not $Denylist) {
    $local = Join-Path $root 'redaction.txt'
    if (Test-Path $local) { $Denylist = $local }
    elseif ($env:SEEP_DENYLIST_PROJECTL) { $Denylist = $env:SEEP_DENYLIST_PROJECTL }
}

$scannedWithFile = $false
if ($Denylist -and (Test-Path $Denylist)) {
    $n = 0
    foreach ($line in (Get-Content $Denylist -Encoding UTF8)) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $parts = $t -split "`t", 2
        if ($parts.Count -lt 2) { $parts = $t -split '\s{2,}', 2 }
        if ($parts.Count -lt 2) { Write-Host "  [WARN] unparsed denylist line: $t" -ForegroundColor Yellow; continue }
        $patterns[$parts[0].Trim()] = $parts[1].Trim()
        $n++
    }
    $scannedWithFile = $true
    Write-Host ('  [INFO] target denylist loaded: ' + $n + ' pattern(s)') -ForegroundColor Green
} else {
    Write-Host '  [WARN] target-specific denylist NOT loaded -- generic checks only.' -ForegroundColor Yellow
    Write-Host '         Pass -Denylist <path> (kept out of the archive on purpose).' -ForegroundColor Yellow
}

# 扫描范围：归档内所有文本文件（本脚本自带的脱敏项除外）
$allText = Get-ChildItem -Path $root -Recurse -File -Include *.cs, *.ps1, *.py, *.md, *.txt, *.nfo, *.json, *.yaml, *.yml, *.cmd, *.bat |
           Where-Object { $_.Name -ne 'SHA256SUMS.txt' -and $_.Name -ne 'redaction.txt' }
$files = $allText | Where-Object { $_.Name -ne 'build.ps1' }
$leak = 0
foreach ($k in $patterns.Keys) {
    $hits = $files | Select-String -Pattern $patterns[$k] -ErrorAction SilentlyContinue
    if ($hits) {
        $leak++
        Write-Host ('  [LEAK] ' + $k) -ForegroundColor Red
        $hits | Select-Object -First 3 | ForEach-Object { Write-Host ('         ' + $_.Filename + ':' + $_.LineNumber + '  ' + $_.Line.Trim()) }
    } else {
        Write-Host ('  [OK]   ' + $k + ' not present') -ForegroundColor Green
    }
}
if ($leak -gt 0) { throw "redaction scan failed: $leak pattern group(s) leaked" }

# ---- 5. 产物隔离：二进制 / 证据 / 私钥 / 运行期生成物不得入包 ----
Write-Host ''
Write-Host '  产物隔离 (artifact isolation)' -ForegroundColor Cyan
$forbiddenNames = @('__pycache__', 'mint_keys.json', 'license.sig', 'license.ini', 'SHA256SUMS.tmp')
$forbiddenExt   = @('*.exe', '*.dll', '*.dmp', '*.bin', '*.orig', '*.patched', '*.bak-*', '*.idb', '*.i64', '*.frida')
$bad = @()
foreach ($d in @('samples', 'evidence', 'out')) {
    if (Test-Path (Join-Path $root $d)) { $bad += (Join-Path $root $d) }
}
foreach ($f in (Get-ChildItem $root -Recurse -Force -File -Include $forbiddenNames -ErrorAction SilentlyContinue)) {
    $bad += $f.FullName
}
foreach ($f in (Get-ChildItem $root -Recurse -Force -File -Include $forbiddenExt -ErrorAction SilentlyContinue)) {
    $bad += $f.FullName
}
$bad = @($bad | ForEach-Object { $_.Substring($root.Length + 1) } | Sort-Object -Unique)
if ($bad.Count -gt 0) {
    $bad | ForEach-Object { Write-Host ('  [LEAK] ' + $_) -ForegroundColor Red }
    throw 'artifact isolation failed: sample binaries / evidence / key material must not be packaged'
}
Write-Host '  [OK]   no sample binary, evidence dir, minted license or private key inside the case' -ForegroundColor Green

# ---- 6. 生成 SHA256SUMS.txt ----
Write-Host ''
Write-Host '  生成 SHA256SUMS.txt' -ForegroundColor Cyan
$sumFile = Join-Path $root 'SHA256SUMS.txt'
$lines = @()
foreach ($f in ($allText | Sort-Object FullName)) {
    $rel = $f.FullName.Substring($root.Length + 1).Replace('\', '/')
    $hash = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
    $lines += ($hash + '  ' + $rel)
}
[System.IO.File]::WriteAllLines($sumFile, $lines, (New-Object System.Text.UTF8Encoding($false)))
Write-Host ('  [OK] ' + $lines.Count + ' entries -> SHA256SUMS.txt') -ForegroundColor Green

# ---- 7. 包内一致性：文档引用的地址 / 常量 / 计数必须与源码和清单一致 ----
Write-Host ''
Write-Host '  包内一致性 (package consistency)' -ForegroundColor Cyan
if (Get-Command python -ErrorAction SilentlyContinue) {
    $vpArgs = @()
    if ($Denylist -and (Test-Path $Denylist)) {
        $vpArgs = @('--denylist', $Denylist)
    }
    Push-Location $root
    try {
        $vp = & python src\verify_package.py @vpArgs 2>&1 | Out-String
        $vc = $LASTEXITCODE
    } finally { Pop-Location }
    if ($vc -ne 0) {
        Write-Host $vp -ForegroundColor Red
        throw 'src\verify_package.py failed -- docs and sources disagree, or the manifest is stale'
    }
    if ($vp -notmatch '(\d+)/\1 package checks passed') { throw 'src\verify_package.py reported no check tally' }
    Write-Host ('  [OK] package consistency: ' + $Matches[1] + '/' + $Matches[1] + ' checks passed') -ForegroundColor Green
    Remove-Item $pyc -Recurse -Force -ErrorAction SilentlyContinue
} else {
    Write-Host '  [SKIP] python not found' -ForegroundColor Yellow
}

Write-Host ''
Write-Host "================================================================================" -ForegroundColor Cyan
if ($scannedWithFile) {
    Write-Host '  项目L 归档自检通过（含目标专属脱敏清单）' -ForegroundColor Green
} else {
    Write-Host '  项目L 归档自检通过（通用走查；目标专属清单未加载）' -ForegroundColor Yellow
}
Write-Host "================================================================================" -ForegroundColor Cyan
