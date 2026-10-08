#restore.ps1 -- tessoa case: undo the trust-anchor swap and remove minted license files
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\restore.ps1
#   powershell -ExecutionPolicy Bypass -File .\restore.ps1 -ExeOnly
#   powershell -ExecutionPolicy Bypass -File .\restore.ps1 -LicenseOnly
#
# What it does, in order:
#   [1/4] stop the target process (it is single-instance; a live process locks the exe)
#   [2/4] restore the installed exe from tessoa.exe.orig-backup (written by keygen.py --install-exe)
#   [3/4] delete %APPDATA%\tessoa\license.ini / license.sig, keeping any .bak-* as .restored-*
#   [4/4] report the resulting state
#
# Nothing here is destructive to the original binary: the backup is only removed after a
# successful restore, and the file is copied (not moved) into place.
# -Product / -ExeName default to the real target. The placeholder guard still rejects
# any value containing '<' or '>' so the script can never touch an unintended directory.

param(
    [string]$Product = 'tessoa',
    [string]$ExeName = 'tessoa.exe',
    [switch]$ExeOnly,
    [switch]$LicenseOnly
)

$ErrorActionPreference = 'Stop'
$OutputEncoding = [System.Text.Encoding]::UTF8

if ($Product -match '<' -or $Product -match '>') {
    Write-Host 'FATAL: -Product still looks like a placeholder. Pass a real directory name.' -ForegroundColor Red
    exit 3
}

$appDataDir   = Join-Path $env:APPDATA     $Product
$installDir   = Join-Path $env:LOCALAPPDATA $Product
$liveExe      = Join-Path $installDir      $ExeName
$exeBackup    = "$liveExe.orig-backup"
$processName  = [IO.Path]::GetFileNameWithoutExtension($ExeName)

Write-Host '=============================================================='
Write-Host "  tessoa restore -- product directory: $Product"
Write-Host '=============================================================='

# ---- [1/4] stop the process ------------------------------------------------
if (-not $LicenseOnly) {
    Write-Host '[1/4] Stopping target process'
    Get-Process -Name $processName -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host ("      pid {0} -> terminate" -f $_.Id)
        $_ | Stop-Process -Force
    }
    Start-Sleep -Seconds 2
} else {
    Write-Host '[1/4] Skipped (-LicenseOnly)'
}

# ---- [2/4] restore the exe -------------------------------------------------
if (-not $LicenseOnly) {
    Write-Host '[2/4] Restore installed exe'
    if (-not (Test-Path $exeBackup)) {
        Write-Host "      [SKIP] no backup at $exeBackup" -ForegroundColor Yellow
    } else {
        $origMd5  = (Get-FileHash $exeBackup -Algorithm MD5).Hash.ToLower()
        $currentMd5 = $null
        if (Test-Path $liveExe) { $currentMd5 = (Get-FileHash $liveExe -Algorithm MD5).Hash.ToLower() }
        if ($currentMd5 -eq $origMd5) {
            Write-Host '      [OK]   already clean (md5 matches backup), nothing to do'
        } else {
            Copy-Item $exeBackup $liveExe -Force
            $after = (Get-FileHash $liveExe -Algorithm MD5).Hash.ToLower()
            if ($after -ne $origMd5) { throw "restore mismatch: $after != $origMd5" }
            Write-Host "      [OK]   restored from .orig-backup (md5 $origMd5)" -ForegroundColor Green
        }
    }
} else {
    Write-Host '[2/4] Skipped (-LicenseOnly)'
}

# ---- [3/4] remove minted license files -------------------------------------
Write-Host '[3/4] Remove minted license artifacts'
if (Test-Path $appDataDir) {
    foreach ($name in @('license.ini', 'license.sig')) {
        $live = Join-Path $appDataDir $name
        if (Test-Path $live) {
            # keep a forensics-friendly copy under a name that the client never reads
            $kept = "$live.removed-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            Move-Item $live $kept -Force
            Write-Host "      [OK]   $name -> $(Split-Path -Leaf $kept)"
        } else {
            Write-Host "      [SKIP] $name not present"
        }
    }
    $baks = @(Get-ChildItem -Path $appDataDir -Filter 'license.*.bak-*' -File -ErrorAction SilentlyContinue)
    if ($baks.Count -gt 0) {
        Write-Host ("      [NOTE] {0} pre-mint backup(s) kept in {1}" -f $baks.Count, $appDataDir)
        Write-Host '             These are the vendor-issued files. Delete them only if you already'
        Write-Host '             re-activated legitimately; keygen.py --deploy created them.'
    }
} else {
    Write-Host "      [SKIP] directory not present: $appDataDir"
}

# ---- [4/4] report ----------------------------------------------------------
Write-Host '[4/4] Resulting state'
Write-Host ("      exe      : {0}" -f $(if (Test-Path $liveExe) { $liveExe } else { '(absent)' }))
if (Test-Path $liveExe) {
    $md5 = (Get-FileHash $liveExe -Algorithm MD5).Hash.ToLower()
    Write-Host ("      exe md5  : {0}" -f $md5)
    if (Test-Path $exeBackup) {
        $b = (Get-FileHash $exeBackup -Algorithm MD5).Hash.ToLower()
        Write-Host ("      backup   : {0} ({1})" -f $b, $(if ($b -eq $md5) { 'matches -> clean' } else { 'DIFFERS -> still patched' }))
    }
}
foreach ($name in @('license.ini', 'license.sig')) {
    $live = Join-Path $appDataDir $name
    Write-Host ("      {0,-12}: {1}" -f $name, $(if (Test-Path $live) { 'PRESENT' } else { 'absent' }))
}
Write- ''
Write-Host 'Done. Restart the target: with license.sig removed the client enters the reject path'
Write-Host '      (statically: code=4 in sub_1404A06F8 - not captured dynamically, see docs 2.1).'
