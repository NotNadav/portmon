@echo off
cd /d "%~dp0"
set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"

if exist "target\release\portmon.exe" goto :launch

echo Building PortMon (first run only, may take a few minutes)...
cargo build --release
if errorlevel 1 (
    echo.
    echo Build failed. Make sure Rust is installed: https://rustup.rs/
    pause
    exit /b 1
)

:launch
start "" "target\release\portmon.exe"
