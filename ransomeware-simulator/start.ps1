param(
    [int]$BackendPort = 5001,
    [int]$FrontendPort = 3000
)

$ErrorActionPreference = "Stop"

function Stop-PortProcess {
    param([int]$Port)

    $connections = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if (-not $connections) {
        return
    }

    $pids = $connections | Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($pid in $pids) {
        $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Host "Stopping process on port ${Port}: $($proc.ProcessName) (PID $pid)"
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        }
    }
}

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = Join-Path $projectRoot "backend"
$frontendDir = Join-Path $projectRoot "frontend"

if (-not (Test-Path $backendDir) -or -not (Test-Path $frontendDir)) {
    throw "Run this script from the ransomware-simulator project root."
}

Stop-PortProcess -Port $BackendPort
Stop-PortProcess -Port $FrontendPort

$pythonCmd = "python"
$venvPython = Join-Path $backendDir "venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    $pythonCmd = $venvPython
}

Write-Host "Starting backend on port $BackendPort..."
$backendArgs = "-NoExit", "-Command", "Set-Location '$backendDir'; `$env:RANSOMWARE_BACKEND_PORT='$BackendPort'; & '$pythonCmd' app.py"
Start-Process powershell -ArgumentList $backendArgs

Write-Host "Starting frontend on port $FrontendPort..."
$frontendArgs = "-NoExit", "-Command", "Set-Location '$frontendDir'; `$env:PORT='$FrontendPort'; npm start"
Start-Process powershell -ArgumentList $frontendArgs

Write-Host "RansomWatch is launching:"
Write-Host "Backend  -> http://localhost:$BackendPort"
Write-Host "Frontend -> http://localhost:$FrontendPort"
