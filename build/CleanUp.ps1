# repoRoot\build\CleanUp.ps1
# Deletes *.nupkg in build/, removes build\_pkgView, clears NuGet caches,
# and wipes repoRoot\lib\SocketLibraryCPP contents.
# Logs to build\logs\CleanUp_YYYYMMDD-HHMMSS.log

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# -- Resolve paths relative to this script (works from any CWD) --
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$RepoRoot  = Split-Path -Parent $ScriptDir
$BuildDir  = $ScriptDir
$LogsDir   = Join-Path $RepoRoot 'build\logs'
New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null

$RunStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunLog   = Join-Path $LogsDir ("CleanUp_{0}.log" -f $RunStamp)

# -- Logging helpers --
function Write-Log([string]$msg) {
  $msg | Out-File -FilePath $RunLog -Append -Encoding UTF8
  Write-Host $msg
}
function Section($title) {
  $sep = '─' * 70
  Write-Log ""
  Write-Log $sep
  Write-Log $title
  Write-Log $sep
}

# -- Find nuget.exe (prefer PATH, then common repo locations) --
function Get-NuGetExe {
  $cmd = Get-Command nuget.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  $candidates = @(
    (Join-Path $BuildDir 'nuget.exe'),
    (Join-Path $RepoRoot 'nuget.exe'),
    (Join-Path $RepoRoot '.nuget\nuget.exe')
  )
  foreach ($c in $candidates) { if (Test-Path -LiteralPath $c) { return $c } }
  return $null
}

# -- Optional dotnet fallback if nuget.exe isn't available --
function Get-DotNet {
  $cmd = Get-Command dotnet -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  return $null
}

# ---- Run header ----
"======================================================================" | Out-File -FilePath $RunLog -Encoding UTF8
"CleanUp run: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"              | Out-File -FilePath $RunLog -Append
"RepoRoot : $RepoRoot"                                                  | Out-File -FilePath $RunLog -Append
"BuildDir : $BuildDir"                                                  | Out-File -FilePath $RunLog -Append
"======================================================================" | Out-File -FilePath $RunLog -Append

# ---- Delete *.nupkg in build/ ----
Section "Deleting *.nupkg files in $BuildDir"
$nupkgs = @(Get-ChildItem -LiteralPath $BuildDir -Filter *.nupkg -File -ErrorAction SilentlyContinue)
if ($nupkgs.Count -gt 0) {
  foreach ($f in $nupkgs) {
    Write-Log ("Deleting: {0}" -f $f.FullName)
    Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Continue
  }
  Write-Log ("Deleted {0} file(s)." -f $nupkgs.Count)
} else {
  Write-Log "No .nupkg files found."
}

# ---- Remove build\_pkgView entirely ----
$PkgViewDir = Join-Path $BuildDir '_pkgView'
Section "Removing package view folder $PkgViewDir"
if (Test-Path -LiteralPath $PkgViewDir) {
  try {
    Remove-Item -LiteralPath $PkgViewDir -Recurse -Force -ErrorAction Stop
    Write-Log "Removed: $PkgViewDir"
  } catch {
    Write-Log ("ERROR removing {0}: {1}" -f $PkgViewDir, $_.Exception.Message)
  }
} else {
  Write-Log "No _pkgView folder found. (Nothing to remove.)"
}

# ---- Purge repoRoot\lib\SocketLibraryCPP contents (preserve the folder) ----
$LibOutDir = Join-Path $RepoRoot 'lib\SocketLibraryCPP'
Section "Purging contents of $LibOutDir"
if (Test-Path -LiteralPath $LibOutDir) {
  $items = @(Get-ChildItem -LiteralPath $LibOutDir -Force -ErrorAction SilentlyContinue)
  if ($items.Count -gt 0) {
    foreach ($it in $items) {
      Write-Log ("Removing: {0}" -f $it.FullName)
      Remove-Item -LiteralPath $it.FullName -Recurse -Force -ErrorAction Continue
    }
    Write-Log ("Removed {0} item(s)." -f $items.Count)
  } else {
    Write-Log "Directory exists but is already empty."
  }
} else {
  Write-Log "Directory not found. (Nothing to purge.)"
}

# ---- Clear NuGet caches ----
Section "Clearing NuGet caches"
$nugetExe = Get-NuGetExe
if ($nugetExe) {
  Write-Log "Using nuget.exe: $nugetExe"

  & $nugetExe locals all -list  *>&1 | Tee-Object -FilePath $RunLog -Append
  Write-Log "Running: nuget locals all -clear"
  & $nugetExe locals all -clear *>&1 | Tee-Object -FilePath $RunLog -Append
  Write-Log "After clear:"
  & $nugetExe locals all -list  *>&1 | Tee-Object -FilePath $RunLog -Append

} else {
  $dotnet = Get-DotNet
  if ($dotnet) {
    Write-Log "nuget.exe not found. Falling back to dotnet."
    Write-Log "Using dotnet: $dotnet"

    & $dotnet nuget locals all --list  *>&1 | Tee-Object -FilePath $RunLog -Append
    Write-Log "Running: dotnet nuget locals all --clear"
    & $dotnet nuget locals all --clear *>&1 | Tee-Object -FilePath $RunLog -Append
    Write-Log "After clear:"
    & $dotnet nuget locals all --list  *>&1 | Tee-Object -FilePath $RunLog -Append
  } else {
    Write-Log "ERROR: Neither nuget.exe nor dotnet was found. Skipping cache clear."
  }
}

Write-Log ""
Write-Log "Cleanup complete. Log: $RunLog"
