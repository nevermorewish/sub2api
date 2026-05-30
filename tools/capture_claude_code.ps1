param(
    [string]$Model = "claude-haiku-4-5-20251001",
    [string]$Prompt = "hello",
    [string]$Name = "",
    [int]$Port = 8080,
    [int]$TimeoutSeconds = 120,
    [string]$CaptureRoot = "captures\claude-code-headers",
    [string]$ProxyCaCert = ".mitmproxy\mitmproxy-ca-cert.pem",
    [switch]$Interactive,
    [switch]$KeepProcesses,
    [string]$SetBeta = "",
    [string]$AppendBeta = "",
    [string]$BetaTag = "",
    [switch]$BlockUpstream
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

function Quote-PSString {
    param([string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function Get-ProcessTreeIds {
    param([int]$RootProcessId)

    $ids = New-Object System.Collections.ArrayList
    [void]$ids.Add($RootProcessId)

    for ($index = 0; $index -lt $ids.Count; $index++) {
        $parent = [int]$ids[$index]
        $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$parent" -ErrorAction SilentlyContinue
        foreach ($child in $children) {
            $childId = [int]$child.ProcessId
            if (-not $ids.Contains($childId)) {
                [void]$ids.Add($childId)
            }
        }
    }

    return $ids
}

function Stop-StartedProcessTree {
    param([int[]]$RootProcessIds)

    $allIds = New-Object System.Collections.ArrayList
    foreach ($rootId in $RootProcessIds) {
        foreach ($id in Get-ProcessTreeIds -RootProcessId $rootId) {
            if (-not $allIds.Contains($id)) {
                [void]$allIds.Add($id)
            }
        }
    }

    foreach ($id in @($allIds | Sort-Object -Descending)) {
        Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
    }
}

function Get-CaptureSummary {
    param([string]$LatestPath)

    $capture = Get-Content $LatestPath -Raw | ConvertFrom-Json
    $bodyPreview = [string]$capture.body_preview
    $requestModel = $null
    if ($bodyPreview -match '"model"\s*:\s*"([^"]+)"') {
        $requestModel = $Matches[1]
    }

    $beta = [string]$capture.anthropic_beta
    return [pscustomobject]@{
        capture = $LatestPath
        captured_at = $capture.captured_at
        host = $capture.host
        path = $capture.path
        model = $requestModel
        user_agent = $capture.headers.'User-Agent'
        stainless_package = $capture.headers.'X-Stainless-Package-Version'
        stainless_runtime_version = $capture.headers.'X-Stainless-Runtime-Version'
        stainless_timeout = $capture.headers.'X-Stainless-Timeout'
        anthropic_beta = $beta
        has_oauth_2025_04_20 = $beta -like "*oauth-2025-04-20*"
        has_extended_cache_ttl_2025_04_11 = $beta -like "*extended-cache-ttl-2025-04-11*"
        body_bytes = $capture.body_bytes
    }
}

function Show-UsageHint {
    Write-Host "Examples:"
    Write-Host "  powershell -ExecutionPolicy Bypass -File tools\capture_claude_code.ps1"
    Write-Host "  powershell -ExecutionPolicy Bypass -File tools\capture_claude_code.ps1 -Model claude-haiku-4-5-20251001 -Prompt hello"
    Write-Host "  powershell -ExecutionPolicy Bypass -File tools\capture_claude_code.ps1 -Interactive -Name manual-haiku45"
    Write-Host ""
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$addonPath = Join-Path $repoRoot "tools\mitm_capture_claude.py"
$caPath = Join-Path $repoRoot $ProxyCaCert

if (-not (Get-Command mitmdump -ErrorAction SilentlyContinue)) {
    throw "mitmdump was not found in PATH."
}
if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
    throw "claude was not found in PATH."
}
if (-not (Test-Path $addonPath)) {
    throw "Missing mitmproxy addon: $addonPath"
}
if (-not (Test-Path $caPath)) {
    throw "Missing mitmproxy CA cert: $caPath"
}

$portOwner = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty OwningProcess
if ($portOwner) {
    throw "Port $Port is already in use by process $portOwner."
}

if ([string]::IsNullOrWhiteSpace($Name)) {
    $mode = if ($Interactive) { "interactive" } else { "prompt" }
    $safeModel = $Model -replace '[^a-zA-Z0-9._-]+', '-'
    $Name = "$safeModel-$mode-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
}

$captureDir = Join-Path $repoRoot (Join-Path $CaptureRoot $Name)
New-Item -ItemType Directory -Force -Path $captureDir | Out-Null

$oldCaptureDir = $env:CLAUDE_CAPTURE_DIR
$oldSetBeta = $env:CLAUDE_CAPTURE_SET_BETA
$oldAppendBeta = $env:CLAUDE_CAPTURE_APPEND_BETA
$oldBetaTag = $env:CLAUDE_CAPTURE_BETA_TAG
$oldBlockUpstream = $env:CLAUDE_CAPTURE_BLOCK_UPSTREAM

$mitm = $null
$claudeWindow = $null

try {
    $env:CLAUDE_CAPTURE_DIR = $captureDir
    $env:CLAUDE_CAPTURE_SET_BETA = $SetBeta
    $env:CLAUDE_CAPTURE_APPEND_BETA = $AppendBeta
    $env:CLAUDE_CAPTURE_BETA_TAG = $BetaTag
    $env:CLAUDE_CAPTURE_BLOCK_UPSTREAM = if ($BlockUpstream) { "1" } else { "" }

    $mitmArgs = @(
        "-p", [string]$Port,
        "--set", "confdir=.mitmproxy",
        "-s", "tools\mitm_capture_claude.py"
    )
    $mitm = Start-Process -FilePath "mitmdump" -ArgumentList $mitmArgs -WorkingDirectory $repoRoot -WindowStyle Hidden -PassThru

    Start-Sleep -Seconds 3

    $env:CLAUDE_CAPTURE_DIR = $oldCaptureDir
    $env:CLAUDE_CAPTURE_SET_BETA = $oldSetBeta
    $env:CLAUDE_CAPTURE_APPEND_BETA = $oldAppendBeta
    $env:CLAUDE_CAPTURE_BETA_TAG = $oldBetaTag
    $env:CLAUDE_CAPTURE_BLOCK_UPSTREAM = $oldBlockUpstream

    $proxy = "http://127.0.0.1:$Port"
    $claudeArgs = @("--model", $Model)
    if (-not $Interactive) {
        $claudeArgs += $Prompt
    }
    $claudeLine = "claude " + (($claudeArgs | ForEach-Object { Quote-PSString $_ }) -join " ")

    $windowTitle = "claude-capture-$Name"
    $claudeScript = @"
`$host.UI.RawUI.WindowTitle = $(Quote-PSString $windowTitle)
`$env:HTTP_PROXY = $(Quote-PSString $proxy)
`$env:HTTPS_PROXY = $(Quote-PSString $proxy)
`$env:NODE_EXTRA_CA_CERTS = $(Quote-PSString $caPath)
`$env:SSL_CERT_FILE = $(Quote-PSString $caPath)
Set-Location $(Quote-PSString $repoRoot)
$claudeLine
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($claudeScript))
    $claudeWindow = Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoExit", "-EncodedCommand", $encoded) -WorkingDirectory $repoRoot -PassThru

    $latestPath = Join-Path $captureDir "latest_request.redacted.json"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline -and -not (Test-Path $latestPath)) {
        Start-Sleep -Seconds 2
    }

    if (-not (Test-Path $latestPath)) {
        Show-UsageHint
        throw "Timed out waiting for latest_request.redacted.json. Capture dir: $captureDir"
    }

    Get-CaptureSummary -LatestPath $latestPath | ConvertTo-Json -Depth 4
}
finally {
    $env:CLAUDE_CAPTURE_DIR = $oldCaptureDir
    $env:CLAUDE_CAPTURE_SET_BETA = $oldSetBeta
    $env:CLAUDE_CAPTURE_APPEND_BETA = $oldAppendBeta
    $env:CLAUDE_CAPTURE_BETA_TAG = $oldBetaTag
    $env:CLAUDE_CAPTURE_BLOCK_UPSTREAM = $oldBlockUpstream

    if (-not $KeepProcesses) {
        $rootIds = @()
        if ($mitm -and $mitm.Id) {
            $rootIds += [int]$mitm.Id
        }
        if ($claudeWindow -and $claudeWindow.Id) {
            $rootIds += [int]$claudeWindow.Id
        }
        if ($rootIds.Count -gt 0) {
            Stop-StartedProcessTree -RootProcessIds $rootIds
        }
    }
}
