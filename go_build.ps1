# go_build.ps1
# Build Go binary as static, stripped binary for Baota (Linux amd64 by default)
# Features:
#   - Reads required Go version from go.mod
#   - Auto-detects service name from cmd/ subdirectories containing main.go
#   - Local module cache (.gocache, .gomodcache)
#   - Optional UPX compression

param(
    [string]$ServiceName,                     # Name of the service (subdir under cmd/). Auto-detected if omitted.
    [string]$GoOS = "linux",
    [string]$GoArch = "amd64",
    [switch]$CompressWithUpx,
    [string]$LdFlags = "-s -w"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------
function Fail-Build {
    param([string]$Message)
    Write-Host "ERROR: $Message" -ForegroundColor Red
    exit 1
}

function Quote-ProcessArgument {
    param([string]$Argument)

    if ($null -eq $Argument -or $Argument.Length -eq 0) {
        return '""'
    }
    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    $result = '"'
    $backslashes = 0
    foreach ($char in $Argument.ToCharArray()) {
        if ($char -eq '\') {
            $backslashes++
            continue
        }
        if ($char -eq '"') {
            if ($backslashes -gt 0) {
                $result += ('\' * ($backslashes * 2))
            }
            $result += '\"'
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            $result += ('\' * $backslashes)
            $backslashes = 0
        }
        $result += $char
    }
    if ($backslashes -gt 0) {
        $result += ('\' * ($backslashes * 2))
    }
    $result += '"'

    return $result
}

function Invoke-GoCapture {
    param([string[]]$Arguments)

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = "go"
    $startInfo.Arguments = ($Arguments | ForEach-Object { Quote-ProcessArgument $_ }) -join " "
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo

    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        $output = (($stdout, $stderr) -join "").Trim()
        $exitCode = $process.ExitCode
    } finally {
        $process.Dispose()
    }

    [pscustomobject]@{
        ExitCode = $exitCode
        Output   = $output
    }
}

function Get-GoVersionFromText {
    param([string]$VersionOutput)

    if ($VersionOutput -notmatch "go version go(?<Version>\d+\.\d+(?:\.\d+)?)") {
        return $null
    }
    return [version]$Matches.Version
}

# -----------------------------------------------------------------------------
# Parse go.mod
# -----------------------------------------------------------------------------
$goModPath = Join-Path $PSScriptRoot "go.mod"
if (-not (Test-Path $goModPath)) {
    Fail-Build "go.mod not found in $PSScriptRoot"
}

Write-Host "Parsing go.mod ..." -ForegroundColor Cyan

$goModContent = Get-Content $goModPath -Raw

# Extract module name (optional, for information only)
$moduleMatch = [regex]::Match($goModContent, '^module\s+(\S+)', 'Multiline')
$moduleName = if ($moduleMatch.Success) { $moduleMatch.Groups[1].Value } else { "<unknown>" }

# Extract required Go version
$goVersionMatch = [regex]::Match($goModContent, '^go\s+(\d+\.\d+(?:\.\d+)?)', 'Multiline')
if (-not $goVersionMatch.Success) {
    Fail-Build "go.mod does not specify a Go version (missing 'go 1.x' directive)."
}
$requiredGoVersion = [version]$goVersionMatch.Groups[1].Value
Write-Host "Module: $moduleName" -ForegroundColor Gray
Write-Host "Requires Go >= $requiredGoVersion" -ForegroundColor Gray

# -----------------------------------------------------------------------------
# Detect service name from cmd/
# -----------------------------------------------------------------------------
$cmdPath = Join-Path $PSScriptRoot "cmd"
if (-not (Test-Path $cmdPath)) {
    Fail-Build "cmd/ directory not found at $cmdPath"
}

# Force array by wrapping with @(...) to avoid Count property error when only one service exists
$availableServices = @(Get-ChildItem $cmdPath -Directory | Where-Object {
    Test-Path (Join-Path $_.FullName "main.go")
} | ForEach-Object { $_.Name })

if ($availableServices.Count -eq 0) {
    Fail-Build "No service found under cmd/ (no subdirectory contains a main.go file)."
}

if ([string]::IsNullOrEmpty($ServiceName)) {
    if ($availableServices.Count -eq 1) {
        $ServiceName = $availableServices[0]
        Write-Host "Auto-detected service: $ServiceName" -ForegroundColor Yellow
    } else {
        Write-Host "Available services: $($availableServices -join ', ')" -ForegroundColor Yellow
        Fail-Build "Multiple services found. Please specify -ServiceName parameter."
    }
} else {
    if ($availableServices -notcontains $ServiceName) {
        Write-Host "Available services: $($availableServices -join ', ')" -ForegroundColor Yellow
        Fail-Build "Service '$ServiceName' not found under cmd/ (no main.go in cmd/$ServiceName)."
    }
}

$outputName = $ServiceName   # binary output name

# -----------------------------------------------------------------------------
# Prepare local caches
# -----------------------------------------------------------------------------
Write-Host "[1/5] Preparing local Go caches..." -ForegroundColor Cyan
$env:GOCACHE = Join-Path $PSScriptRoot ".gocache"
$env:GOMODCACHE = Join-Path $PSScriptRoot ".gomodcache"
New-Item -ItemType Directory -Force -Path $env:GOCACHE | Out-Null
New-Item -ItemType Directory -Force -Path $env:GOMODCACHE | Out-Null

# -----------------------------------------------------------------------------
# Check Go toolchain version
# -----------------------------------------------------------------------------
Write-Host "[2/5] Checking Go toolchain..." -ForegroundColor Cyan
$goToolchainResult = Invoke-GoCapture @("env", "GOTOOLCHAIN")
if ($goToolchainResult.ExitCode -ne 0) {
    Fail-Build "Unable to read GOTOOLCHAIN. Output: $($goToolchainResult.Output)"
}
$goToolchain = $goToolchainResult.Output

$goVersionResult = Invoke-GoCapture @("version")
if ($goVersionResult.ExitCode -ne 0) {
    Fail-Build "Unable to run go version. Install Go $requiredGoVersion or newer, or allow GOTOOLCHAIN=auto to select it. Output: $($goVersionResult.Output)"
}

$goVersionText = $goVersionResult.Output
$currentGoVersion = Get-GoVersionFromText $goVersionText
if ($null -eq $currentGoVersion) {
    Fail-Build "Unable to parse Go version from: $goVersionText"
}

if ($currentGoVersion -lt $requiredGoVersion) {
    Fail-Build "Detected $goVersionText with GOTOOLCHAIN=$goToolchain.`nThis build requires Go $requiredGoVersion or newer; install a newer Go toolchain or set GOTOOLCHAIN=auto."
}

Write-Host "Using $goVersionText (GOTOOLCHAIN=$goToolchain)" -ForegroundColor Gray

# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------
Write-Host "[3/5] Building Go binary for $GoOS/$GoArch ..." -ForegroundColor Cyan

$env:GOOS = $GoOS
$env:GOARCH = $GoArch
$env:CGO_ENABLED = "0"

$entryPoint = "./cmd/$ServiceName"
$buildArgs = @(
    "build",
    "-trimpath",
    "-buildvcs=false",
    "-ldflags=$LdFlags",
    "-o", $outputName,
    $entryPoint
)

Write-Host "Running: go $($buildArgs -join ' ')" -ForegroundColor Gray
$buildResult = Invoke-GoCapture $buildArgs
if ($buildResult.Output) {
    Write-Host $buildResult.Output
}
if ($buildResult.ExitCode -ne 0) {
    Fail-Build "Build failed"
}

Write-Host "[4/5] Build succeeded: $outputName" -ForegroundColor Green

$fileInfo = Get-Item $outputName
Write-Host "File size: $([math]::Round($fileInfo.Length / 1MB, 2)) MB" -ForegroundColor Yellow

# -----------------------------------------------------------------------------
# Optional UPX compression
# -----------------------------------------------------------------------------
if ($CompressWithUpx) {
    Write-Host "[5/5] Compressing with UPX..." -ForegroundColor Cyan
    if (Get-Command upx -ErrorAction SilentlyContinue) {
        upx --best --lzma $outputName
        $compressedInfo = Get-Item $outputName
        Write-Host "Compressed size: $([math]::Round($compressedInfo.Length / 1MB, 2)) MB" -ForegroundColor Green
    } else {
        Write-Host "Warning: UPX not found. Skipping compression." -ForegroundColor Yellow
    }
} else {
    Write-Host "[5/5] Skipping UPX compression." -ForegroundColor Gray
}

Write-Host "Done. Binary: $outputName" -ForegroundColor Cyan