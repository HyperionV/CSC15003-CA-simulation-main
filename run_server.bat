@echo off
echo Starting CA Management System Server...

for /r "%~dp0" %%f in (ca_server.exe) do (
    if exist "%%f" (
        echo Found server at: %%f
        set SERVER_PATH=%%f
        set SERVER_DIR=%%~dpf
        goto FOUND_SERVER
    )
)

echo ERROR: Could not find ca_server.exe in any subdirectory.
pause
exit /b 1

:FOUND_SERVER
start "CA Management System Server" cmd /k "cd /d build/bin/ && ca_server.exe && echo Server stopped."

exit   