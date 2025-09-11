# repoRoot\build\ViewNupkgs.ps1
# Expand all .nupkg files under build/ into build/_pkgView/<Id.Version>/ and show a tree for each.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# -- Resolve paths relative to this script (works from any CWD) --
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$RepoRoot  = Split-Path -Parent $ScriptDir
$BuildDir  = $ScriptDir
$ViewRoot  = Join-Path $BuildDir '_pkgView'
$LogsDir   = Join-Path $RepoRoot 'build\logs'

New-Item -ItemType Directory -Force -Path $LogsDir  | Out-Null
New-Item -ItemType Directory -Force -Path $ViewRoot | Out-Null

$RunStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunLog   = Join-Path $LogsDir ("ViewNupkgs_{0}.log" -f $RunStamp)

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

# ---- Run header ----
"======================================================================" | Out-File -FilePath $RunLog -Encoding UTF8
"ViewNupkgs run: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"           | Out-File -FilePath $RunLog -Append
"RepoRoot : $RepoRoot"                                                  | Out-File -FilePath $RunLog -Append
"BuildDir : $BuildDir"                                                  | Out-File -FilePath $RunLog -Append
"ViewRoot : $ViewRoot"                                                  | Out-File -FilePath $RunLog -Append
"======================================================================" | Out-File -FilePath $RunLog -Append

# ---- Find .nupkg(s) ----
$nupkgs = @(Get-ChildItem -LiteralPath $BuildDir -Filter *.nupkg -File -ErrorAction SilentlyContinue)
if ($nupkgs.Count -eq 0) {
  Write-Log "No .nupkg files found in $BuildDir. Nothing to expand."
  Write-Host "Done. Log: $RunLog"
  exit 0
}

# ---- Expand and show tree for each package ----
foreach ($pkg in ($nupkgs | Sort-Object Name)) {
  $baseName = [System.IO.Path]::GetFileNameWithoutExtension($pkg.Name)   # "Id.Version"
  $destDir  = Join-Path $ViewRoot $baseName

  Section "Expanding: $($pkg.FullName)"
  Write-Log ("Target dir: {0}" -f $destDir)

  # Clean target dir for a fresh view
  if (Test-Path -LiteralPath $destDir) {
    Write-Log "Removing existing view directory..."
    Remove-Item -LiteralPath $destDir -Recurse -Force -ErrorAction Continue
  }
  New-Item -ItemType Directory -Force -Path $destDir | Out-Null

  # Expand the .nupkg (zip format)
  try {
    Expand-Archive -LiteralPath $pkg.FullName -DestinationPath $destDir -Force
  } catch {
    # Extremely rare: if Expand-Archive rejects extension, fall back to copy-as-zip
    $zipTemp = "$($pkg.FullName).zip"
    Copy-Item -LiteralPath $pkg.FullName -Destination $zipTemp -Force
    Expand-Archive -LiteralPath $zipTemp -DestinationPath $destDir -Force
    Remove-Item -LiteralPath $zipTemp -Force
  }

  # Show a tree of the extracted package
    Section "Tree for: $baseName"
    if (Get-Command tree -ErrorAction SilentlyContinue) {
    # /F = include files, /A = ASCII characters (better for logs)
    & tree /F /A $destDir *>&1 | Tee-Object -FilePath $RunLog -Append
    } else {
    Write-Log "(No 'tree' command available; listing files instead)"
    Get-ChildItem -LiteralPath $destDir -Recurse |
        Select-Object FullName |
        Format-Table -AutoSize | Out-String -Width 4096 |
        Tee-Object -FilePath $RunLog -Append | Out-Host
    }
}

Write-Host "`nAll packages expanded under: $ViewRoot"
Write-Host "Log: $RunLog"
