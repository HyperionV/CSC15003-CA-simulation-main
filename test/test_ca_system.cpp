#include "../include/common.h"
#include "../include/database.h"
#include "../include/auth_system.h"
#include "../include/openssl_wrapper.h"
#include "../include/certificate_authority.h"

// Test database functionality
bool testDatabase() {
    std::cout << "Testing database functionality..." << std::endl;
    
    DatabaseManager db;
    if (!db.initialize()) {
        std::cerr << "Failed to initialize database." << std::endl;
        return false;
    }
    
    // Test user creation
    if (!db.addUser("testuser", "testhash", "test@example.com")) {
        std::cerr << "Failed to add user." << std::endl;
        return false;
    }
    
    // Test user retrieval
    int userID = db.getUserID("testuser");
    if (userID <= 0) {
        std::cerr << "Failed to retrieve user ID." << std::endl;
        return false;
    }
    
    std::cout << "Database tests passed." << std::endl;
    return true;
}

// Test authentication functionality
bool testAuthentication() {
    std::cout << "Testing authentication functionality..." << std::endl;
    
    DatabaseManager db;
    if (!db.initialize()) {
        std::cerr << "Failed to initialize database." << std::endl;
        return false;
    }
    
    AuthenticationSystem auth(db);
    
    // Test user registration
    if (!auth.registerUser("testauth", "testpass", "testauth@example.com")) {
        std::cerr << "Failed to register user." << std::endl;
        return false;
    }
    
    // Test login
    if (!auth.login("testauth", "testpass")) {
        std::cerr << "Failed to login." << std::endl;
        return false;
    }
    
    // Test session management
    String token = auth.createSession("testauth");
    if (token.empty()) {
        std::cerr << "Failed to create session." << std::endl;
        return false;
    }
    
    if (!auth.validateSession(token)) {
        std::cerr << "Failed to validate session." << std::endl;
        return false;
    }
    
    if (auth.getUsernameFromToken(token) != "testauth") {
        std::cerr << "Failed to get username from token." << std::endl;
        return false;
    }
    
    if (!auth.terminateSession(token)) {
        std::cerr << "Failed to terminate session." << std::endl;
        return false;
    }
    
    std::cout << "Authentication tests passed." << std::endl;
    return true;
}

// Test OpenSSL wrapper functionality
bool testOpenSSLWrapper() {
    std::cout << "Testing OpenSSL wrapper functionality..." << std::endl;
    
    OpenSSLWrapper ssl;
    
    // Test key pair generation
    auto keyPair = ssl.generateRSAKeyPair(2048);
    if (keyPair.first.empty() || keyPair.second.empty()) {
        std::cerr << "Failed to generate key pair." << std::endl;
        return false;
    }
    
    // Test CSR generation
    String csrData = ssl.generateCSR(keyPair.first, "CN=Test Subject,O=Test Org,C=US");
    if (csrData.empty()) {
        std::cerr << "Failed to generate CSR." << std::endl;
        return false;
    }
    
    // Test CSR verification
    if (!ssl.verifyCSR(csrData)) {
        std::cerr << "Failed to verify CSR." << std::endl;
        return false;
    }
    
    std::cout << "OpenSSL wrapper tests passed." << std::endl;
    return true;
}

// Test certificate authority functionality
bool testCertificateAuthority() {
    std::cout << "Testing certificate authority functionality..." << std::endl;
    
    DatabaseManager db;
    if (!db.initialize()) {
        std::cerr << "Failed to initialize database." << std::endl;
        return false;
    }
    
    OpenSSLWrapper ssl;
    CertificateAuthority ca(db, ssl);
    
    // Initialize CA
    if (!ca.initialize(DATA_DIR + "ca_config.json")) {
        std::cerr << "Failed to initialize CA." << std::endl;
        return false;
    }
    
    // Test CSR submission
    auto keyPair = ssl.generateRSAKeyPair(2048);
    String csrData = ssl.generateCSR(keyPair.first, "CN=Test Subject,O=Test Org,C=US");
    
    int requestID = ca.submitCSR(csrData, "admin");
    if (requestID <= 0) {
        std::cerr << "Failed to submit CSR." << std::endl;
        return false;
    }
    
    // Test certificate issuance
    int certID = ca.issueCertificate(requestID, 365);
    if (certID <= 0) {
        std::cerr << "Failed to issue certificate." << std::endl;
        return false;
    }
    
    // Test certificate revocation
    if (!ca.revokeCertificate(certID, "Test revocation", "admin")) {
        std::cerr << "Failed to revoke certificate." << std::endl;
        return false;
    }
    
    std::cout << "Certificate authority tests passed." << std::endl;
    return true;
}

int main() {
    // Initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    bool allTestsPassed = true;
    
    allTestsPassed &= testDatabase();
    allTestsPassed &= testAuthentication();
    allTestsPassed &= testOpenSSLWrapper();
    allTestsPassed &= testCertificateAuthority();
    
    if (allTestsPassed) {
        std::cout << "\nAll tests passed!" << std::endl;
    } else {
        std::cout << "\nSome tests failed." << std::endl;
    }
    
    // Cleanup OpenSSL
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    
    return allTestsPassed ? 0 : 1;
} 