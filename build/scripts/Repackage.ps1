# repoRoot\build\Repackage.ps1
# Runs: CleanUp.ps1 -> BuildLibraries.ps1 -> PackageNuGet.ps1 -> ExpandPackages.ps1

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Resolve paths relative to this script (works from any CWD)
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$BuildDir  = Split-Path -Parent $ScriptDir
$RepoRoot  = Split-Path -Parent $BuildDir

# Pick a PowerShell engine (prefer pwsh; fallback to Windows PowerShell)
$PSExe = $null
foreach ($cand in @('pwsh','powershell')) {
  $cmd = Get-Command $cand -ErrorAction SilentlyContinue
  if ($cmd) { $PSExe = $cmd.Source; break }
}
if (-not $PSExe) { throw "Neither 'pwsh' nor 'powershell' was found on PATH." }

function RunStep {
  param(
    [Parameter(Mandatory)][string]$Title,
    [Parameter(Mandatory)][string]$ScriptName
  )
  $sep = '=' * 70
  Write-Host "`n$sep`n$Title`n$sep"
  $scriptPath = Join-Path $ScriptDir $ScriptName
  if (-not (Test-Path -LiteralPath $scriptPath)) {
    throw "Missing script: $scriptPath"
  }
  & $PSExe -NoProfile -ExecutionPolicy Bypass -File $scriptPath
  if ($LASTEXITCODE -ne 0) {
    throw "Step failed: $Title (exit code $LASTEXITCODE)"
  }
}

RunStep -Title "1/4 Clean up"         -ScriptName 'CleanUp.ps1'
RunStep -Title "2/4 Build libraries"  -ScriptName 'BuildLibraries.ps1'
RunStep -Title "3/4 Package NuGet"    -ScriptName 'PackageNuGet.ps1'
RunStep -Title "4/4 Expand packages"  -ScriptName 'ExpandPackages.ps1'

Write-Host "`nAll steps completed successfully." -ForegroundColor Green
