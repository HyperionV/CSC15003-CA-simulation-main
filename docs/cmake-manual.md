# CA Management System - CMake Build Manual

This manual provides comprehensive instructions for building, compiling, and testing the CA Management System using CMake. It covers initial setup, troubleshooting, common errors, and best practices.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Project Structure](#project-structure)
3. [Basic Build Process](#basic-build-process)
4. [Advanced Configuration](#advanced-configuration)
5. [Troubleshooting Common Issues](#troubleshooting-common-issues)
6. [Testing](#testing)
7. [Development Workflow](#development-workflow)
8. [Platform-Specific Instructions](#platform-specific-instructions)

## Prerequisites

Before building the CA Management System, ensure you have the following installed:

- **CMake** (version 3.10 or later)
  - Windows: Download from [cmake.org](https://cmake.org/download/)
  - Linux: `sudo apt install cmake` (Ubuntu/Debian) or `sudo yum install cmake` (CentOS/Fedora)
  - macOS: `brew install cmake` (via Homebrew)

- **C++ Compiler** supporting C++17
  - Windows: Visual Studio 2019+ or MinGW-w64 (GCC 7+)
  - Linux: GCC 7+ (`sudo apt install g++`)
  - macOS: Clang (included with Xcode Command Line Tools)

- **Dependencies**
  - OpenSSL development libraries (1.1.1 or later)
    - Windows: Download from [slproweb.com](https://slproweb.com/products/Win32OpenSSL.html) (Developer version)
    - Linux: `sudo apt install libssl-dev` (Ubuntu/Debian)
    - macOS: `brew install openssl@1.1`
  
  - SQLite3 development libraries
    - Windows: Included in the project
    - Linux: `sudo apt install libsqlite3-dev`
    - macOS: `brew install sqlite3`

- **Build tools**
  - Windows: Visual Studio or Ninja
  - Linux/macOS: Make or Ninja

## Project Structure

The CA Management System has the following structure:

```
project-root/
├── CMakeLists.txt          # Main CMake configuration file
├── include/                # Header files
│   ├── auth_system.h
│   ├── certificate_authority.h
│   ├── client_console.h
│   ├── common.h
│   ├── database.h
│   ├── openssl_wrapper.h
│   ├── server_console.h
│   ├── server_handler.h    # Client-server communication handler
│   ├── socket_comm.h       # Socket communication
│   └── sqlite3.h
├── src/                    # Source files
│   ├── auth_system.cpp
│   ├── certificate_authority.cpp
│   ├── client_console.cpp
│   ├── client_main.cpp
│   ├── database.cpp
│   ├── main.cpp
│   ├── openssl_wrapper.cpp
│   ├── server_console.cpp
│   ├── server_handler.cpp  # Server handler implementation
│   ├── socket_comm.cpp     # Socket implementation
│   └── sqlite3.c
├── lib/                    # Third-party libraries
│   └── nlohmann/           # JSON library
├── data/                   # Data directory
│   └── ca_config.json      # CA configuration
└── build/                  # Build directory (created during build)
```

## Basic Build Process

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-username/ca-management-system.git
cd ca-management-system
```

### Step 2: Create Build Directory

```bash
mkdir -p build
cd build
```

### Step 3: Configure with CMake

```bash
cmake ..
```

### Step 4: Build the Project

```bash
cmake --build .
```

Or, specify a configuration for multi-configuration generators:

```bash
cmake --build . --config Release
```

### Step 5: Run the Server

```bash
./ca_server
```

### Step 6: Run the Client (in a separate terminal)

```bash
./ca_client
```

## Advanced Configuration

### Custom Build Types

You can specify the build type during configuration:

```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..  # Debug build with symbols
cmake -DCMAKE_BUILD_TYPE=Release .. # Optimized release build
```

### Visual Studio Configuration

For Visual Studio users:

```bash
cmake -G "Visual Studio 17 2022" -A x64 ..
```

You can then open the generated `.sln` file or build from the command line:

```bash
cmake --build . --config Release
```

### MinGW Configuration

For MinGW users:

```bash
cmake -G "MinGW Makefiles" ..
mingw32-make
```

### Specifying OpenSSL Path

If CMake cannot find OpenSSL, you can specify its path:

```bash
cmake -DOPENSSL_ROOT_DIR="C:/OpenSSL-Win64" ..  # Windows example
cmake -DOPENSSL_ROOT_DIR="/usr/local/opt/openssl@1.1" ..  # macOS example
```

### Build Options

The project supports various build options:

```bash
# Enable verbose build output
cmake --build . -- VERBOSE=1

# Build only the server
cmake --build . --target ca_server

# Build only the client
cmake --build . --target ca_client
```

## Troubleshooting Common Issues

### CMake Cannot Find OpenSSL

**Error Message:**
```
Could not find OpenSSL, try to set the path manually...
```

**Solutions:**

1. Install OpenSSL development libraries as mentioned in the Prerequisites section.

2. Specify the OpenSSL path manually:
   ```bash
   cmake -DOPENSSL_ROOT_DIR="/path/to/openssl" ..
   ```

3. On Windows, ensure the OpenSSL bin directory is in your PATH:
   ```
   SET PATH=%PATH%;C:\OpenSSL-Win64\bin
   ```

### Linker Errors with WinSock

**Error Message:**
```
undefined reference to `WSAStartup'
```

**Solution:**

Ensure that ws2_32 is linked. Check your CMakeLists.txt:

```cmake
if(WIN32)
    target_link_libraries(${TARGET_NAME} PRIVATE ws2_32)
endif()
```

### Cannot Open Include File WinSock2.h

**Error Message:**
```
fatal error C1083: Cannot open include file: 'WinSock2.h': No such file or directory
```

**Solution:**

This is Windows-specific. For cross-platform builds, modify socket_comm.h:

```cpp
#ifdef _WIN32
    #include <WinSock2.h>
    #include <WS2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif
```

### SQLite3 Errors

**Error Message:**
```
undefined reference to `sqlite3_open'
```

**Solution:**

Ensure sqlite3 is properly linked:

```cmake
target_link_libraries(${TARGET_NAME} PRIVATE ${SQLite3_LIBRARIES})
```

### Compiler Version Issues

**Error Message:**
```
The C++ compiler does not support C++17
```

**Solution:**

Upgrade your compiler or specify a compatible C++ standard:

```bash
# For GCC/Clang
cmake -DCMAKE_CXX_FLAGS="-std=c++14" ..

# For older CMake versions
cmake -DCMAKE_CXX_STANDARD=14 ..
```

### Rebuild After Changes

If you've made changes to the source code but aren't seeing them reflected:

1. Ensure you're rebuilding the project:
   ```bash
   cmake --build . --clean-first
   ```

2. If that doesn't work, try cleaning the build directory completely:
   ```bash
   cd build
   rm -rf *  # Be careful with this command!
   cmake ..
   cmake --build .
   ```

## Testing

### Running Basic Tests

```bash
cd build
ctest
```

Or run with verbose output:

```bash
ctest -V
```

### Testing the Client-Server Communication

1. Start the server:
   ```bash
   ./ca_server
   ```

2. In a separate terminal, run the client:
   ```bash
   ./ca_client
   ```

3. Test basic functionality:
   - Register a new user
   - Login with the created credentials
   - Request a certificate
   - View certificates
   - Revoke a certificate

### Performing Manual Tests

For manual testing, follow these steps:

1. **Server Connection Test**:
   - Start the server and client
   - Check console output for successful connection messages
   - If connection fails, verify port availability: `netstat -an | grep 8080`

2. **Authentication Test**:
   - Register with a new username and password
   - Try logging in with incorrect credentials (should fail)
   - Login with correct credentials
   - Verify session token is received

3. **Certificate Operations Test**:
   - Request a new certificate with valid details
   - View your certificates
   - Download a certificate
   - Revoke a certificate with a reason
   - Verify the certificate shows as revoked

4. **Error Handling Test**:
   - Kill the server while the client is connected
   - Observe how the client handles the disruption
   - Restart the server and reconnect

## Development Workflow

### Adding New Features

1. Make your code changes

2. Rebuild the project:
   ```bash
   cd build
   cmake --build .
   ```

3. If adding new files, update CMakeLists.txt:
   ```cmake
   set(SOURCES
       ${EXISTING_SOURCES}
       src/your_new_file.cpp
   )
   ```

4. Re-run CMake if you updated CMakeLists.txt:
   ```bash
   cmake ..
   cmake --build .
   ```

### Debugging

#### Visual Studio

1. Generate a Visual Studio solution:
   ```bash
   cmake -G "Visual Studio 17 2022" -A x64 ..
   ```

2. Open the solution in Visual Studio:
   ```bash
   start ca_management_system.sln
   ```

3. Set breakpoints and debug as usual

#### VS Code

1. Configure launch.json for debugging
2. Set breakpoints in the editor
3. Start debugging

#### GDB (Linux/macOS)

1. Build with debug symbols:
   ```bash
   cmake -DCMAKE_BUILD_TYPE=Debug ..
   cmake --build .
   ```

2. Run with GDB:
   ```bash
   gdb ./ca_server
   ```

3. Set breakpoints and debug:
   ```
   (gdb) break server_handler.cpp:155
   (gdb) run
   ```

## Platform-Specific Instructions

### Windows

1. Dependencies:
   - Visual Studio 2019 or newer
   - OpenSSL: Install from [slproweb.com](https://slproweb.com/products/Win32OpenSSL.html)
   - Add OpenSSL bin directory to PATH

2. Build:
   ```batch
   mkdir build
   cd build
   cmake -G "Visual Studio 17 2022" -A x64 -DOPENSSL_ROOT_DIR="C:/OpenSSL-Win64" ..
   cmake --build . --config Release
   ```

3. Run:
   ```batch
   .\Release\ca_server.exe
   ```

### Linux (Ubuntu/Debian)

1. Dependencies:
   ```bash
   sudo apt update
   sudo apt install cmake g++ libssl-dev libsqlite3-dev
   ```

2. Build:
   ```bash
   mkdir -p build
   cd build
   cmake -DCMAKE_BUILD_TYPE=Release ..
   cmake --build .
   ```

3. Run:
   ```bash
   ./ca_server
   ```

### macOS

1. Dependencies:
   ```bash
   brew install cmake openssl@1.1 sqlite3
   ```

2. Build:
   ```bash
   mkdir -p build
   cd build
   cmake -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@1.1) ..
   cmake --build .
   ```

3. Run:
   ```bash
   ./ca_server
   ```

## Final Notes

- Always back up your data directory before significant changes
- Keep your OpenSSL libraries updated for security patches
- The server requires proper shutdown to save all data
- If you encounter issues not covered in this manual, check the error.md file for additional troubleshooting

For further assistance, please open an issue on the GitHub repository or contact the project maintainers. 