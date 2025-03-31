# Certificate Authority (CA) Management System

A simple certificate authority management system that allows for issuing, revoking, and managing digital certificates.

## Features

- User authentication and authorization
- Certificate signing request (CSR) submission and processing
- Certificate issuance and revocation
- Certificate validation and verification
- Certificate revocation list (CRL) generation
- Client-server architecture with socket communication

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

## Requirements

- Visual Studio 2019 or later
- OpenSSL libraries
- SQLite
- CMake

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

6. **Run tests**:
   ```
   .\Release\ca_test.exe
   ```

7. **Rebuild after making changes**:
   ```
   cd build
   cmake --build . --config Release
   ```

### Using Batch Files

The project includes several batch files to simplify building and running:

- **build.bat**: Builds the project using CMake and copies the executable files to a Release folder in the root directory.
  ```
  .\build.bat
  ```
- To use both the server and the client, perform the following actions, each in one CMD window.
  - **run_server.bat**: Starts the CA server application from the Release folder.
    ```
    .\run_server.bat
    ```

  - **run_client.bat**: Starts the CA client application from the Release folder.
    ```
    .\run_client.bat
    ```

- **run_tests.bat**: Runs the test suite from the Release folder, for **quick testing** all essential features.
  ```
  .\run_tests.bat
  ```

**Workflow with batch files**:
1. Run `build.bat` to build the project
2. Run `run_server.bat` to start the server
3. In a separate CMD, run `run_client.bat` to start the client
4. After making code changes, run `build.bat` again to rebuild the project

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