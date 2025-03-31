# CA Management System User Manual

## Server Administration

### Starting the Server

1. Run the server application (`ca_server.exe`)
2. The server will initialize the database and CA
3. The server console will be displayed

### Server Console

The server console provides the following options:

1. **View Logs**: View system logs with filtering and pagination
2. **Manage Users**: Create and manage user accounts
3. **Certificate Operations**: Manage certificate requests and certificates
4. **Exit**: Exit the server application

#### View Logs

- View system logs with filtering and pagination
- Filter logs by action or details
- Navigate through pages of logs

#### Manage Users

- View list of users
- Create new users
- Change user roles

#### Certificate Operations

- View pending certificate signing requests (CSRs)
- Approve or reject CSRs
- View all certificates
- Revoke certificates
- Generate certificate revocation list (CRL)

## Client Usage

### Starting the Client

1. Run the client application (`ca_client.exe`)
2. The client will display the authentication menu

### Authentication Menu

The authentication menu provides the following options:

1. **Login**: Login with existing credentials
2. **Register**: Register a new user account
3. **Exit**: Exit the client application

#### Login

- Enter username and password
- If credentials are valid, you will be logged in and taken to the certificate menu

#### Register

- Enter username, password, and email
- If registration is successful, you can login with the new credentials

### Certificate Menu

The certificate menu provides the following options:

1. **Request Certificate**: Submit a certificate signing request (CSR)
2. **View My Certificates**: View your certificates
3. **Revoke Certificate**: Revoke one of your certificates
4. **Download Certificate**: Download a certificate to a file
5. **Validate Certificate**: Validate a certificate against the CA
6. **Logout**: Logout and return to the authentication menu
7. **Exit**: Exit the client application

#### Request Certificate

- Enter subject information (common name, organization, country)
- A key pair will be generated
- A CSR will be generated and submitted to the server
- The private key will be saved to a file

#### View My Certificates

- View a list of your certificates
- See certificate details such as serial number, subject, status, and expiry date

#### Revoke Certificate

- Select a certificate to revoke
- Enter a reason for revocation
- The certificate will be revoked and added to the CRL

#### Download Certificate

- Select a certificate to download
- The certificate will be downloaded and saved to a file

#### Validate Certificate

- Enter the path to a certificate file
- The certificate will be validated against the CA
- The validation result will be displayed 