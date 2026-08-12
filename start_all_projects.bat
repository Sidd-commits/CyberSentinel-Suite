@echo off
setlocal

set "ROOT=%~dp0"

echo Starting all projects...

REM DDoS project (static page)
if exist "%ROOT%DdosDos\index.html" (
    start "DDoS" "%ROOT%DdosDos\index.html"
) else (
    echo [WARN] DdosDos\index.html not found
)

REM SQL Injection project (open dashboard)
if exist "%ROOT%sql_injection\dashboard.html" (
    start "SQL Injection" "%ROOT%sql_injection\dashboard.html"
) else if exist "%ROOT%sql_injection\index.html" (
    echo [WARN] dashboard.html not found, opening index.html instead
    start "SQL Injection" "%ROOT%sql_injection\index.html"
) else (
    echo [WARN] sql_injection project page not found
)

REM Ransomware simulator (uses existing launcher)
if exist "%ROOT%ransomware-simulator\ransomware-simulator\start.bat" (
    start "Ransomware" /d "%ROOT%ransomware-simulator\ransomware-simulator" cmd /k call start.bat
) else (
    echo [WARN] ransomware start.bat not found
)

REM Phishing project (uses existing launcher)
if exist "%ROOT%Phishing\start.bat" (
    start "Phishing" /d "%ROOT%Phishing" cmd /k call start.bat
) else (
    echo [WARN] Phishing\start.bat not found
)

echo Done. Windows for each project should be opening.
endlocal