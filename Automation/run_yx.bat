@echo off
cd /d "%~dp0"

:: =================== Speed Test Config ===================
:: Test count (default: 10)
set TEST_COUNT=10
:: Download speed limit MB/s (default: 0.2)
set SPEED_LIMIT=0.2
:: Max average latency ms (default: 1000)
set DELAY_LIMIT=1000
:: Port (default: 443)
set TEST_PORT=443
:: Sample IP count from official pool (default: 300)
set SAMPLE_COUNT=300
:: Colo airport code, e.g. HKG,SIN (leave empty for all)
set TEST_COLO=
:: Max output count: -1 = keep all, positive number (e.g. 5) = keep top N
set MAX_OUTPUT=-1
:: =========================================================

set "EXTRA_ARGS="
if not "%TEST_COLO%"=="" (
    set "EXTRA_ARGS=-colo %TEST_COLO%"
)

echo [1/4] Running speed test...
yx_windows_amd64.exe test -http -n %TEST_COUNT% -sl %SPEED_LIMIT% -tl %DELAY_LIMIT% -port %TEST_PORT% -c %SAMPLE_COUNT% %EXTRA_ARGS%

if not exist "result.csv" (
    echo [ERROR] result.csv not found!
    goto END
)

echo [2/4] Converting result.csv to cloudflare_ips.txt (MaxOutput: %MAX_OUTPUT%)...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0convert.ps1" -MaxOutput %MAX_OUTPUT%

if not exist "cloudflare_ips.txt" (
    echo [ERROR] Conversion failed!
    goto END
)

echo [3/4] Copying results...
set "REPO_DIR=%~dp0.."
set "TARGET_DIR=%REPO_DIR%\results"

if not exist "%TARGET_DIR%" (
    mkdir "%TARGET_DIR%"
)

copy /y "cloudflare_ips.txt" "%TARGET_DIR%\cloudflare_ips.txt" >nul

echo [4/4] Committing and pushing to GitHub...
cd /d "%REPO_DIR%"
git pull origin main --rebase
git add results/cloudflare_ips.txt Automation/run_yx.bat Automation/convert.ps1
git commit -m "update: local speed test results"
git push origin main

if %errorlevel% equ 0 (
    echo Push successful!
) else (
    echo [ERROR] Push failed.
)

:END
echo.
pause