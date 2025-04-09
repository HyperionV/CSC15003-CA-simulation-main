# CA Management System - Installation Guide

This guide provides instructions for installing and setting up the CA Management System.

## System Requirements

- **CMake** (3.10+)
- **C++ Compiler** with C++17 support
- **OpenSSL** (1.1.1+)
- **SQLite3**

## Quick Start

### Windows
1. Run `precheck.bat` to verify system requirements
2. Run `setup_windows.bat` to build the application
3. Start server: `run_server.bat`
4. Start client: `run_client.bat`

### Linux
1. Run `./precheck.sh` to verify system requirements
2. Run `./setup_linux.sh` to build the application
3. Start server: `./ca_server`
4. Start client: `./ca_client`

### macOS
1. Run `./precheck.sh` to verify system requirements
2. Run `./setup_macos.sh` to build the application
3. Start server: `./ca_server`
4. Start client: `./ca_client`

## Detailed Installation

### Installing Prerequisites

#### CMake (3.10+)
- **Windows**: Download from [cmake.org](https://cmake.org/download/) and add to PATH
- **Linux**: `sudo apt install cmake` or `sudo yum install cmake`
- **macOS**: `brew install cmake`

#### C++ Compiler
- **Windows**: Visual Studio 2019+ or MinGW-w64 with GCC 7+
- **Linux**: GCC 7+ via `sudo apt install g++` or `sudo yum install gcc-c++`
- **macOS**: Xcode Command Line Tools: `xcode-select --install`

#### OpenSSL (1.1.1+)
- **Windows**: Download from [slproweb.com](https://slproweb.com/products/Win32OpenSSL.html) (Win64 OpenSSL)
- **Linux**: `sudo apt install libssl-dev` or `sudo yum install openssl-devel`
- **macOS**: `brew install openssl@1.1` and add to PATH

#### SQLite3
- **Windows**: Included in the project
- **Linux**: `sudo apt install libsqlite3-dev` or `sudo yum install sqlite-devel`
- **macOS**: `brew install sqlite3`

### Manual Build

#### Windows
```
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

#### Linux/macOS
```
mkdir -p build
cd build
cmake ..
cmake --build .
```

For macOS with Homebrew OpenSSL:
```
cmake -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@1.1) ..
```

## Directory Structure

```
project-root/
├── build/                  # Build files
├── data/                   # Data storage directory
│   ├── certs/              # Certificate storage
│   ├── keys/               # Key storage
│   └── db/                 # Database files
├── include/                # Header files
├── src/                    # Source files
├── lib/                    # External libraries
└── test/                   # Test files
```

## Troubleshooting

### OpenSSL Not Found
- Ensure OpenSSL is installed and in PATH
- Specify path manually: `cmake -DOPENSSL_ROOT_DIR="C:/OpenSSL-Win64" ..`

### Compiler Errors
- Verify C++17 support in your compiler
- Update compiler if needed

### Windows-Specific
- Ensure Windows SDK is installed for socket functionality
- OpenSSL bin directory must be in PATH

### SQLite Issues
- On Linux/macOS: Install SQLite development libraries
- On Windows: If needed, download precompiled binaries from [sqlite.org](https://www.sqlite.org/download.html)

For detailed help, run `precheck.bat` (Windows) or `./precheck.sh` (Linux/macOS) to identify specific issues.
