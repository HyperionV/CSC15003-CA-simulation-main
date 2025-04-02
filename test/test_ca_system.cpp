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

// Test PKCS#12 functionality
bool testPKCS12Functionality() {
    std::cout << "Testing PKCS#12 functionality..." << std::endl;
    
    OpenSSLWrapper ssl;
    
    // Generate a test key pair
    auto keyPair = ssl.generateRSAKeyPair(2048);
    String privateKey = keyPair.first;
    String publicKey = keyPair.second;
    
    if (privateKey.empty() || publicKey.empty()) {
        std::cerr << "Failed to generate test key pair." << std::endl;
        return false;
    }
    
    // Generate a self-signed certificate for testing
    String subject = "CN=PKCS12 Test,O=Test Organization,C=US";
    String csrData = ssl.generateCSR(privateKey, subject);
    
    if (csrData.empty()) {
        std::cerr << "Failed to generate CSR." << std::endl;
        return false;
    }
    
    // Self-sign the certificate
    String certPEM = ssl.signCSR(csrData, privateKey, "", 365);
    
    if (certPEM.empty()) {
        std::cerr << "Failed to self-sign certificate." << std::endl;
        return false;
    }
    
    std::cout << "  - Created test certificate and private key" << std::endl;
    
    // Test creating a PKCS#12 file
    const String testPassword = "testpassword";
    String pkcs12Data = ssl.createPKCS12(privateKey, certPEM, testPassword, "Test Certificate");
    
    if (pkcs12Data.empty()) {
        std::cerr << "Failed to create PKCS#12 data." << std::endl;
        return false;
    }
    
    std::cout << "  - Created PKCS#12 data successfully" << std::endl;
    
    // Test extracting from PKCS#12 file
    auto extractedPair = ssl.extractFromPKCS12(pkcs12Data, testPassword);
    String extractedKey = extractedPair.first;
    String extractedCert = extractedPair.second;
    
    if (extractedKey.empty() || extractedCert.empty()) {
        std::cerr << "Failed to extract from PKCS#12 data." << std::endl;
        return false;
    }
    
    std::cout << "  - Extracted private key and certificate from PKCS#12 data" << std::endl;
    
    // Test key matching functionality
    bool keyMatches = ssl.verifyKeyMatchesCertificate(extractedKey, extractedCert);
    if (!keyMatches) {
        std::cerr << "Extracted key does not match certificate." << std::endl;
        return false;
    }
    
    std::cout << "  - Verified extracted key matches certificate" << std::endl;
    
    // Test PKCS#12 with wrong password
    auto failedExtract = ssl.extractFromPKCS12(pkcs12Data, "wrongpassword");
    if (!failedExtract.first.empty() || !failedExtract.second.empty()) {
        std::cerr << "PKCS#12 extraction with wrong password should fail." << std::endl;
        return false;
    }
    
    std::cout << "  - PKCS#12 password protection verified" << std::endl;
    
    // Test save/load from file
    try {
        // Save PKCS#12 to file
        const String testFile = "test_cert.p12";
        std::ofstream p12File(testFile, std::ios::binary);
        p12File.write(pkcs12Data.data(), pkcs12Data.size());
        p12File.close();
        
        // Read from file
        std::ifstream readFile(testFile, std::ios::binary);
        std::stringstream p12Stream;
        p12Stream << readFile.rdbuf();
        String readData = p12Stream.str();
        readFile.close();
        
        // Extract again from file data
        auto fileExtracted = ssl.extractFromPKCS12(readData, testPassword);
        
        if (fileExtracted.first.empty() || fileExtracted.second.empty()) {
            std::cerr << "Failed to extract from PKCS#12 file." << std::endl;
            // Clean up test file
            std::remove(testFile.c_str());
            return false;
        }
        
        // Clean up test file
        std::remove(testFile.c_str());
        
        std::cout << "  - PKCS#12 file save/load test passed" << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception during file test: " << e.what() << std::endl;
        return false;
    }
    
    std::cout << "PKCS#12 functionality tests passed." << std::endl;
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
    allTestsPassed &= testPKCS12Functionality();
    
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