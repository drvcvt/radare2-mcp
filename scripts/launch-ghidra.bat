@echo off
REM Launch Ghidra headless with a binary, import it into a project, and start the HTTP server
REM Usage: launch-ghidra.bat <binary_path> [project_name]
REM
REM The GhidraMCP extension must be installed in Ghidra.
REM This script:
REM   1. Creates/opens a Ghidra project
REM   2. Imports and analyzes the binary (headless)
REM   3. Then opens Ghidra GUI with the project so the HTTP bridge is active

setlocal enabledelayedexpansion

set GHIDRA_HOME=C:\Users\matti\ghidra\ghidra_11.3.2_PUBLIC
set GHIDRA_PROJECTS=C:\Users\matti\ghidra\projects
set ANALYZE_HEADLESS=%GHIDRA_HOME%\support\analyzeHeadless.bat
set GHIDRA_RUN=%GHIDRA_HOME%\ghidraRun.bat

if "%~1"=="" (
    echo Usage: launch-ghidra.bat ^<binary_path^> [project_name]
    echo.
    echo Example: launch-ghidra.bat C:\Users\matti\binaries\malware.exe malware_analysis
    exit /b 1
)

set BINARY_PATH=%~f1
set BINARY_NAME=%~n1

if "%~2"=="" (
    set PROJECT_NAME=%BINARY_NAME%_project
) else (
    set PROJECT_NAME=%~2
)

if not exist "%BINARY_PATH%" (
    echo Error: Binary not found: %BINARY_PATH%
    exit /b 1
)

if not exist "%GHIDRA_PROJECTS%" mkdir "%GHIDRA_PROJECTS%"

echo [*] Ghidra Headless Analysis
echo     Binary:  %BINARY_PATH%
echo     Project: %PROJECT_NAME%
echo     Dir:     %GHIDRA_PROJECTS%
echo.

REM Step 1: Headless import + analysis
echo [1/2] Running headless analysis (this may take a while)...
call "%ANALYZE_HEADLESS%" "%GHIDRA_PROJECTS%" "%PROJECT_NAME%" -import "%BINARY_PATH%" -overwrite -analysisTimeoutPerFile 300 2>&1

if errorlevel 1 (
    echo [!] Headless analysis failed or binary already imported, trying to open existing project...
)

echo.
echo [2/2] Opening Ghidra GUI with project...
echo       The GhidraMCP HTTP bridge will be available on http://127.0.0.1:8080/
echo       Wait for Ghidra to fully load before using the MCP.
echo.

REM Step 2: Open Ghidra GUI (so the GhidraMCP HTTP server plugin starts)
start "" "%GHIDRA_RUN%" "%GHIDRA_PROJECTS%\%PROJECT_NAME%.gpr"

echo [*] Ghidra is starting. Once loaded, open the binary from the project.
echo [*] The MCP bridge will be active on http://127.0.0.1:8080/
echo [*] You can now use Claude with both Ghidra and radare2 MCPs.
