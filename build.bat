@echo off
echo Building CA Management System...

:: Create build directory if it doesn't exist
if not exist build mkdir build

:: Navigate to build directory
cd build

:: Generate build files
echo Generating build files with CMake...
cmake ..

:: Build the project
echo Building the project...
cmake --build . --config Release

:: Return to root directory
cd ..

echo Build completed. Executables are in build\bin directory.
echo Run run_server.bat to start the server.
echo Run run_client.bat to start the client.
pause 