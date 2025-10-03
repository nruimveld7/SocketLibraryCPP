# repoRoot\build\scripts\BuildLibraries.ps1
# Build every Configuration|Platform in the vcxproj and write ONE timestamped log per run.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# -- Resolve paths relative to this script (works from any CWD) --
$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$BuildDir = Split-Path -Parent $ScriptDir
$RepoRoot  = Split-Path -Parent $BuildDir
$ProjPath  = Join-Path $RepoRoot 'src\SocketLibraryCPP\SocketLibraryCPP.vcxproj'
if (-not (Test-Path -LiteralPath $ProjPath)) { throw "Project not found: $ProjPath" }

# -- Find MSBuild via vswhere; fallback to PATH --
function Get-MSBuildPath {
  $vswhere = Join-Path "${env:ProgramFiles(x86)}" 'Microsoft Visual Studio\Installer\vswhere.exe'
  if (Test-Path -LiteralPath $vswhere) {
    $vs = & $vswhere -latest -requires Microsoft.Component.MSBuild -products * -format json | ConvertFrom-Json
    if ($vs -and $vs.installationPath) {
      $msbuild = Join-Path $vs.installationPath 'MSBuild\Current\Bin\MSBuild.exe'
      if (Test-Path -LiteralPath $msbuild) { return $msbuild }
    }
  }
  $cmd = Get-Command msbuild.exe -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  throw "MSBuild not found. Install Visual Studio (or Build Tools) or add MSBuild.exe to PATH."
}
$MSBuild = Get-MSBuildPath
Write-Host "Using MSBuild: $MSBuild"

# -- Discover Configuration|Platform pairs from the vcxproj (namespace-safe) --
[xml]$xml = Get-Content -LiteralPath $ProjPath
$pcNodes = $xml.SelectNodes("//*[local-name()='ItemGroup' and @Label='ProjectConfigurations']/*[local-name()='ProjectConfiguration']")
if (-not $pcNodes -or $pcNodes.Count -eq 0) { throw "No ProjectConfiguration nodes found in $ProjPath" }

$pairsRaw = foreach ($n in $pcNodes) {
  $include = $n.GetAttribute('Include')  # e.g., "Debug|Win32"
  if (-not $include) { continue }
  $cp = $include -split '\|'
  if ($cp.Count -ne 2) { continue }
  [pscustomobject]@{ Configuration = $cp[0]; Platform = $cp[1] }
}
if (-not $pairsRaw -or $pairsRaw.Count -eq 0) { throw "No Configuration|Platform pairs discovered in $ProjPath" }
$pairs = $pairsRaw | Sort-Object Platform, Configuration -Unique

# -- Single run log setup --
$LogsDir  = Join-Path $RepoRoot 'build\logs'
New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null
$RunStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunLog   = Join-Path $LogsDir ("BuildLibs_{0}.log" -f $RunStamp)

# Header
"======================================================================" | Out-File -FilePath $RunLog -Encoding UTF8
"BuildLibs run: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"            | Out-File -FilePath $RunLog -Append
"RepoRoot: $RepoRoot"                                                   | Out-File -FilePath $RunLog -Append
"Project : $ProjPath"                                                   | Out-File -FilePath $RunLog -Append
"MSBuild : $MSBuild"                                                    | Out-File -FilePath $RunLog -Append
$pairList = ($pairs | ForEach-Object { "$($_.Configuration)|$($_.Platform)" }) -join ', '
"Pairs   : $pairList"                                                   | Out-File -FilePath $RunLog -Append
"======================================================================" | Out-File -FilePath $RunLog -Append

# -- Build loop (append all output to the same file) --
$errors = @()
foreach ($p in $pairs) {
  $cfg   = $p.Configuration
  $plt   = $p.Platform
  $label = "$cfg|$plt"

  $sep = '─' * 70
  Write-Host "`n$sep`nBuilding $label`n$sep"
  @(
    ""
    $sep
    "BEGIN BUILD: $label"
    "Start: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"
    $sep
    ""
  ) | Out-File -FilePath $RunLog -Append

  & $MSBuild $ProjPath `
    /nologo `
    /m `
    /v:m `
    /t:Build `
    /p:Configuration=$cfg `
    /p:Platform=$plt `
    /p:SolutionDir="$RepoRoot\" *>&1 | Tee-Object -FilePath $RunLog -Append

  if ($LASTEXITCODE) {
    $msg = "BUILD FAILED: $label (see $RunLog)"
    $errors += $msg
    @(
      ""
      "RESULT: FAILED ($label)"
      "End:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"
      $sep
    ) | Out-File -FilePath $RunLog -Append
    Write-Host $msg -ForegroundColor Red
    break
  } else {
    @(
      ""
      "RESULT: SUCCESS ($label)"
      "End:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"
      $sep
    ) | Out-File -FilePath $RunLog -Append
  }
}

if ($errors.Count -gt 0) {
  Write-Host "`nOne or more builds failed." -ForegroundColor Red
  Write-Host "Log: $RunLog"
  exit 1
}

Write-Host "`nAll configurations built successfully." -ForegroundColor Green
Write-Host "Log: $RunLog"
