@echo off
echo Building CA Management System...

if not exist build mkdir build
cd build

cmake ..
cmake --build . --config Release

echo Copying Release folder to root directory...
cd ..
if exist Release (
    echo Removing old Release folder...
    rmdir /S /Q Release
)
cd build
if exist Release (
    echo Copying new Release folder...
    xcopy /E /I /Y Release ..\Release
)

cd ..
echo Build completed. 