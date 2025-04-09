@echo off
echo Starting CA Management System Client...

:FOUND_CLIENT
start "CA Management System Client" cmd /k "cd /d build/bin/ && ca_client.exe && echo Client stopped."

exit 