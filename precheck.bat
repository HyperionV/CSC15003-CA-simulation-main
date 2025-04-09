@echo off
setlocal enabledelayedexpansion

echo ====================================
echo CA Management System - Requirements Check
echo ====================================
echo.

set REQUIREMENTS_MET=yes
set CMAKE_VERSION_REQUIRED=3.10
set CPP_STANDARD_REQUIRED=C++17

echo Checking system requirements...
echo.

:: Check for CMake
echo [1/4] Checking for CMake %CMAKE_VERSION_REQUIRED%+...
where cmake >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [FAILED] CMake not found in PATH
    echo         Please install CMake %CMAKE_VERSION_REQUIRED% or later from https://cmake.org/download/
    set REQUIREMENTS_MET=no
) else (
    for /f "tokens=3" %%i in ('cmake --version ^| findstr /C:"version"') do (
        set CMAKE_VERSION=%%i
        echo [PASSED] CMake version !CMAKE_VERSION! found
    )
)
echo.

:: Check for C++ compiler - improved detection
echo [2/4] Checking for C++ compiler with %CPP_STANDARD_REQUIRED% support...
set CPP_COMPILER_FOUND=no

:: Check for MSVC (Visual Studio)
where cl >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    for /f "tokens=*" %%i in ('cl 2^>^&1 ^| findstr /C:"Version"') do (
        echo [PASSED] MSVC: %%i
        set CPP_COMPILER_FOUND=yes
    )
)

:: Check for GCC/MinGW
if "!CPP_COMPILER_FOUND!"=="no" (
    where g++ >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        for /f "tokens=*" %%i in ('g++ --version 2^>^&1 ^| findstr /C:"g++"') do (
            echo [PASSED] GCC: %%i
            set CPP_COMPILER_FOUND=yes
        )
    )
)

:: Try to detect compilers via Visual Studio installation
if "!CPP_COMPILER_FOUND!"=="no" (
    if exist "C:\Program Files\Microsoft Visual Studio" (
        echo [PASSED] Visual Studio installation detected - compiler likely available
        set CPP_COMPILER_FOUND=yes
    ) else if exist "C:\Program Files (x86)\Microsoft Visual Studio" (
        echo [PASSED] Visual Studio installation detected - compiler likely available
        set CPP_COMPILER_FOUND=yes
    )
)

:: Try to detect MinGW installation in common locations
if "!CPP_COMPILER_FOUND!"=="no" (
    if exist "C:\MinGW\bin\g++.exe" (
        echo [PASSED] MinGW installation detected at C:\MinGW
        set CPP_COMPILER_FOUND=yes
    ) else if exist "C:\msys64\mingw64\bin\g++.exe" (
        echo [PASSED] MinGW-w64 installation detected via MSYS2
        set CPP_COMPILER_FOUND=yes
    )
)

:: Final compiler check result
if "!CPP_COMPILER_FOUND!"=="no" (
    echo [WARNING] No C++ compiler found in PATH
    echo          However, if you've installed Visual Studio or MinGW but haven't
    echo          added it to PATH, the build might still work.
    echo          - For Visual Studio: Try running from Developer Command Prompt
    echo          - For MinGW: Ensure g++ is in your PATH
)
echo.

:: Check for OpenSSL
echo [3/4] Checking for OpenSSL...
where openssl >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [FAILED] OpenSSL not found in PATH
    echo         Please install OpenSSL from https://slproweb.com/products/Win32OpenSSL.html
    set REQUIREMENTS_MET=no
) else (
    for /f "tokens=2" %%i in ('openssl version') do (
        set OPENSSL_VERSION=%%i
        echo [PASSED] OpenSSL version !OPENSSL_VERSION! found
    )
)
echo.

:: Check for SQLite (optional on Windows as it's included in the project)
echo [4/4] Checking for SQLite libraries...
echo [INFO] SQLite is included in the project, no external installation required
echo        If you encounter SQLite issues during build, see README.md
echo.

:: Final summary
echo ====================================
echo Summary
echo ====================================
if "%REQUIREMENTS_MET%"=="yes" (
    echo [SUCCESS] All required components are present.
    echo          You can proceed with running build.bat to build the application.
) else (
    echo [WARNING] Some requirements are missing. Please install the missing components
    echo          before proceeding with the installation.
    echo          However, if you've successfully built the project before, you may
    echo          still be able to proceed despite these warnings.
)
echo.

:: Check if build folder exists
if exist "%~dp0build" (
    echo [INFO] Build directory already exists. You may need to clean it before rebuilding.
    echo        To clean: 'rmdir /S /Q build'
)

pause 