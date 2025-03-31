# CA Management System Developer Guide

## Architecture

The CA Management System follows a client-server architecture with the following components:

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

## Database Schema

The database schema consists of the following tables:

### Users

- `userID`: Primary key
- `username`: Username (unique)
- `passwordHash`: Hashed password
- `email`: Email address
- `role`: User role (user/admin)
- `createdAt`: Creation timestamp

### Certificates

- `certificateID`: Primary key
- `version`: Certificate version
- `serialNumber`: Certificate serial number (unique)
- `signatureAlgorithm`: Signature algorithm
- `issuerName`: Issuer name
- `subjectName`: Subject name
- `validFrom`: Validity start date
- `validTo`: Validity end date
- `publicKey`: Public key
- `status`: Certificate status (valid/revoked)
- `ownerID`: Owner user ID (foreign key to Users)
- `certificateData`: Certificate data in PEM format
- `createdAt`: Creation timestamp

### CertificateRequests

- `requestID`: Primary key
- `subjectID`: Subject user ID (foreign key to Users)
- `publicKey`: Public key
- `csrData`: CSR data in PEM format
- `status`: Request status (pending/approved/rejected)
- `requestedAt`: Request timestamp
- `processedAt`: Processing timestamp
- `certificateID`: Certificate ID (foreign key to Certificates)

### RevokedCertificates

- `revokeID`: Primary key
- `certificateID`: Certificate ID (foreign key to Certificates)
- `serialNumber`: Certificate serial number
- `revocationDate`: Revocation timestamp
- `reason`: Revocation reason
- `revokedBy`: User ID who revoked the certificate (foreign key to Users)

### Logs

- `logID`: Primary key
- `timestamp`: Log timestamp
- `action`: Action performed
- `doneBy`: User ID who performed the action (foreign key to Users)
- `objectID`: ID of the object affected
- `details`: Additional details

## Class Descriptions

### DatabaseManager

The `DatabaseManager` class provides an interface to the SQLite database. It handles all database operations, including:

- User management
- Certificate management
- CSR management
- Logging

Key methods:
- `initialize()`: Initialize the database
- `addUser()`: Add a new user
- `getUserID()`: Get user ID by username
- `storeCSR()`: Store a CSR
- `storeCertificate()`: Store a certificate
- `revokeCertificate()`: Revoke a certificate
- `logActivity()`: Log an activity

### AuthenticationSystem

The `AuthenticationSystem` class handles user authentication and session management. It provides the following functionality:

- User registration
- User login
- Session creation and validation
- Password hashing and verification

Key methods:
- `registerUser()`: Register a new user
- `login()`: Login a user
- `createSession()`: Create a new session
- `validateSession()`: Validate a session
- `terminateSession()`: Terminate a session

### OpenSSLWrapper

The `OpenSSLWrapper` class provides a simplified interface to OpenSSL cryptographic functions. It handles:

- Key pair generation
- CSR generation and verification
- Certificate signing and verification
- CRL generation

Key methods:
- `generateRSAKeyPair()`: Generate a new RSA key pair
- `generateCSR()`: Generate a CSR
- `verifyCSR()`: Verify a CSR
- `signCSR()`: Sign a CSR to create a certificate
- `verifyCertificate()`: Verify a certificate against a CA certificate
- `generateCRL()`: Generate a CRL

### CertificateAuthority

The `CertificateAuthority` class implements the core CA functionality. It handles:

- CA initialization
- CSR processing
- Certificate issuance and revocation
- Certificate validation
- CRL generation

Key methods:
- `initialize()`: Initialize the CA
- `submitCSR()`: Submit a CSR
- `validateCSR()`: Validate a CSR
- `issueCertificate()`: Issue a certificate
- `revokeCertificate()`: Revoke a certificate
- `validateCertificate()`: Validate a certificate
- `generateCRL()`: Generate a CRL

### ServerConsole

The `ServerConsole` class provides a console-based user interface for server administration. It allows administrators to:

- View logs
- Manage users
- Perform certificate operations

Key methods:
- `run()`: Run the server console
- `displayMainMenu()`: Display the main menu
- `viewLogs()`: View logs
- `manageUsers()`: Manage users
- `certificateOperations()`: Perform certificate operations

### ServerHandler

The `ServerHandler` class handles client requests and communicates with other components. It:

- Listens for client connections
- Processes client requests
- Sends responses to clients

Key methods:
- `start()`: Start the server handler
- `stop()`: Stop the server handler
- `handleClient()`: Handle a client connection
- `processRequest()`: Process a client request

### ClientConsole

The `ClientConsole` class provides a console-based user interface for client operations. It allows users to:

- Register and login
- Request certificates
- View certificates
- Revoke certificates
- Download certificates
- Validate certificates

Key methods:
- `run()`: Run the client console
- `displayAuthMenu()`: Display the authentication menu
- `displayCertificateMenu()`: Display the certificate menu
- `login()`: Login
- `registerUser()`: Register a new user
- `requestCertificate()`: Request a certificate
- `viewCertificates()`: View certificates
- `revokeCertificate()`: Revoke a certificate
- `downloadCertificate()`: Download a certificate
- `validateCertificate()`: Validate a certificate

## Communication Protocol

The client and server communicate using a simple JSON-based protocol over TCP sockets. Each message consists of a JSON object with the following structure:

```json
{
    "action": "action_name",
    "payload": {
        "key1": "value1",
        "key2": "value2"
    },
    "token": "session_token"
}
```

The server responds with a JSON object with the following structure:

```json
{
    "status": "success|error",
    "message": "message text",
    "data": {
        "key1": "value1",
        "key2": "value2"
    }
}
```

### Actions

The following actions are supported:

- `login`: Login with username and password
- `register`: Register a new user
- `logout`: Logout
- `request_certificate`: Submit a CSR
- `get_certificates`: Get list of certificates
- `revoke_certificate`: Revoke a certificate
- `download_certificate`: Download a certificate
- `validate_certificate`: Validate a certificate

## Extending the System

### Adding New Features

To add a new feature to the system, follow these steps:

1. Identify the component(s) that need to be modified
2. Update the component(s) to implement the new feature
3. Update the communication protocol if necessary
4. Update the user interface to expose the new feature
5. Add tests for the new feature
6. Update the documentation

### Adding New Certificate Types

To add support for a new certificate type, modify the `OpenSSLWrapper` class to:

1. Add methods for generating the new certificate type
2. Add methods for validating the new certificate type
3. Update the `CertificateAuthority` class to use the new methods

### Improving Security

To improve the security of the system, consider:

1. Using stronger cryptographic algorithms
2. Implementing more robust authentication mechanisms
3. Adding support for hardware security modules (HSMs)
4. Implementing certificate transparency
5. Adding support for OCSP (Online Certificate Status Protocol)

## Testing

The system includes a test script (`test_ca_system.cpp`) that tests the core components of the system. To run the tests:

1. Build the test script
2. Run the test executable
3. Check the test results

To add new tests:

1. Add test functions to the test script
2. Call the test functions from the main function
3. Update the test results checking 