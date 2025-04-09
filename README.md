# Certificate Authority (CA) Management System

A simple certificate authority management system that allows for issuing, revoking, and managing digital certificates.

## Features

- User authentication and authorization
- Certificate signing request (CSR) submission and processing
- Certificate issuance and revocation
- Certificate validation and verification
- Certificate revocation list (CRL) generation
- Client-server architecture with socket communication

## System Requirements

- **CMake** (3.10+)
- **C++ Compiler** with C++17 support
- **OpenSSL** (1.1.1+)
- **SQLite3** (included in project for Windows)

## Quick Start

### Windows
1. Run `precheck.bat` to verify system requirements
2. Run `build.bat` to build the project
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

## Components

### Server Components

- **Database Manager**: Handles database operations for storing users, certificates, and logs
- **Authentication System**: Manages user authentication and session handling
- **OpenSSL Wrapper**: Provides a simplified interface to OpenSSL cryptographic functions
- **Certificate Authority**: Implements core CA functionality for certificate management
- **Server Console**: Provides a console-based user interface for server administration
- **Server Handler**: Handles client requests and communicates with other components

### Client Components

- **Client Console**: Provides a console-based user interface for client operations
- **Socket Communication**: Handles communication with the server

## Installing Prerequisites

### CMake (3.10+)
- **Windows**: Download from [cmake.org](https://cmake.org/download/) and add to PATH
- **Linux**: `sudo apt install cmake` or `sudo yum install cmake`
- **macOS**: `brew install cmake`

### C++ Compiler
- **Windows**: Visual Studio 2019+ or MinGW-w64 with GCC 7+
- **Linux**: GCC 7+ via `sudo apt install g++` or `sudo yum install gcc-c++`
- **macOS**: Xcode Command Line Tools: `xcode-select --install`

### OpenSSL (1.1.1+)
- **Windows**: Download from [slproweb.com](https://slproweb.com/products/Win32OpenSSL.html) (Win64 OpenSSL)
- **Linux**: `sudo apt install libssl-dev` or `sudo yum install openssl-devel`
- **macOS**: `brew install openssl@1.1` and add to PATH

### SQLite3
- **Windows**: Included in the project
- **Linux**: `sudo apt install libsqlite3-dev` or `sudo yum install sqlite-devel`
- **macOS**: `brew install sqlite3`

## Building and Running the Project

### Using CMake Directly

1. **Create and navigate to the build directory**:
   ```
   mkdir build
   cd build
   ```

2. **Generate build files**:
   ```
   cmake ..
   ```

3. **Build the project**:
   ```
   cmake --build . --config Release
   ```

4. **Run the server**:
   ```
   .\Release\ca_server.exe
   ```

5. **Run the client (in a separate terminal)**:
   ```
   .\Release\ca_client.exe
   ```

### Using Batch Files

The project includes several batch files to simplify building and running:

- **build.bat**: Builds the project using CMake.
  ```
  .\build.bat
  ```

- **run_server.bat**: Starts the CA server application.
  ```
  .\run_server.bat
  ```

- **run_client.bat**: Starts the CA client application.
  ```
  .\run_client.bat
  ```

**Workflow with batch files**:
1. Run `precheck.bat` to verify requirements
2. Run `build.bat` to build the project
3. Run `run_server.bat` to start the server
4. In a separate terminal, run `run_client.bat` to start the client

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

## Configuration

The CA configuration is stored in `data/ca_config.json`. This file is created automatically when the CA is initialized for the first time.

## Directory Structure

- `include/`: Header files
- `src/`: Source files
- `lib/`: External libraries
- `data/`: Data storage directory
  - `certs/`: Certificate storage
  - `keys/`: Key storage
  - `db/`: Database files

## License

This project is licensed under the MIT License - see the LICENSE file for details. 