param(
    [int]$Port = 5000
)

$ErrorActionPreference = "Stop"

function Stop-PortProcess {
    param([int]$TargetPort)

    $connections = Get-NetTCPConnection -LocalPort $TargetPort -State Listen -ErrorAction SilentlyContinue
    if (-not $connections) {
        return
    }

    $pids = $connections | Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($pid in $pids) {
        $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Host "Stopping process on port ${TargetPort}: $($proc.ProcessName) (PID $pid)"
            Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        }
    }
}

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectDir

Stop-PortProcess -TargetPort $Port

$pythonCmd = "python"
$venvPython = Join-Path $projectDir "env\Scripts\python.exe"
if (Test-Path $venvPython) {
    $pythonCmd = $venvPython
}

Write-Host "Starting phishing backend on port $Port..."
$backendArgs = "-NoExit", "-Command", "Set-Location '$projectDir'; & '$pythonCmd' app.py"
Start-Process powershell -ArgumentList $backendArgs

Start-Sleep -Seconds 2
Write-Host "Opening dashboard: http://localhost:$Port"
Start-Process "http://localhost:$Port"
