#include "../include/certificate_authority.h"
#include <fstream>

// For JSON parsing, we'll use a simple approach
// In a real project, you would use a dedicated JSON library like nlohmann/json
// Here we'll implement a very basic JSON parser for simplicity
class SimpleJSON {
public:
    static std::map<String, String> parse(const String& jsonStr) {
        std::map<String, String> result;
        size_t pos = 0;
        
        // Find opening brace
        pos = jsonStr.find('{', pos);
        if (pos == String::npos) return result;
        
        while (true) {
            // Find key
            pos = jsonStr.find('"', pos + 1);
            if (pos == String::npos) break;
            
            size_t keyStart = pos + 1;
            pos = jsonStr.find('"', pos + 1);
            if (pos == String::npos) break;
            
            String key = jsonStr.substr(keyStart, pos - keyStart);
            
            // Find colon
            pos = jsonStr.find(':', pos + 1);
            if (pos == String::npos) break;
            
            // Find value
            pos = jsonStr.find_first_not_of(" \t\r\n", pos + 1);
            if (pos == String::npos) break;
            
            String value;
            if (jsonStr[pos] == '"') {
                // String value
                size_t valueStart = pos + 1;
                pos = jsonStr.find('"', pos + 1);
                if (pos == String::npos) break;
                value = jsonStr.substr(valueStart, pos - valueStart);
            } else if (isdigit(jsonStr[pos]) || jsonStr[pos] == '-') {
                // Number value
                size_t valueStart = pos;
                pos = jsonStr.find_first_of(",}", pos + 1);
                if (pos == String::npos) break;
                value = jsonStr.substr(valueStart, pos - valueStart);
                // Adjust position to point to the delimiter
                pos--;
            } else {
                // Unknown value type
                break;
            }
            
            result[key] = value;
            
            // Find comma or closing brace
            pos = jsonStr.find_first_of(",}", pos + 1);
            if (pos == String::npos || jsonStr[pos] == '}') break;
        }
        
        return result;
    }
    
    static String serialize(const std::map<String, String>& data, bool prettyPrint = false) {
        String result = "{";
        if (prettyPrint) result += "\n";
        
        bool first = true;
        for (const auto& entry : data) {
            if (!first) {
                result += ",";
                if (prettyPrint) result += "\n";
            }
            if (prettyPrint) result += "    ";
            result += "\"" + entry.first + "\": ";
            
            // Check if value is a number
            bool isNumber = true;
            for (char c : entry.second) {
                if (!isdigit(c) && c != '-' && c != '.') {
                    isNumber = false;
                    break;
                }
            }
            
            if (isNumber) {
                result += entry.second;
            } else {
                result += "\"" + entry.second + "\"";
            }
            
            first = false;
        }
        
        if (prettyPrint) result += "\n";
        result += "}";
        return result;
    }
};

CertificateAuthority::CertificateAuthority(DatabaseManager& dbManager, OpenSSLWrapper& sslWrapper)
    : db(dbManager), ssl(sslWrapper), defaultValidityDays(365) {
}

bool CertificateAuthority::initialize(const String& configPath) {
    // Create directories if they don't exist
    std::filesystem::create_directories(CERT_DIR);
    std::filesystem::create_directories(KEY_DIR);
    
    // Try to load existing CA keys
    if (loadCAKeys(configPath)) {
        std::cout << "Loaded existing CA keys" << std::endl;
        return true;
    }
    
    // If loading fails, create a new self-signed CA
    std::cout << "Creating new self-signed CA..." << std::endl;
    return createSelfSignedCA();
}

bool CertificateAuthority::loadCAKeys(const String& configPath) {
    try {
        // Read config file
        std::ifstream configFile(configPath);
        if (!configFile.is_open()) {
            return false;
        }
        
        // Read the entire file into a string
        std::stringstream configStream;
        configStream << configFile.rdbuf();
        String configStr = configStream.str();
        
        // Parse config
        auto config = SimpleJSON::parse(configStr);
        
        // Get paths from config
        String caKeyPath = config["caKeyPath"];
        String caCertPath = config["caCertPath"];
        caSubject = config["caSubject"];
        defaultValidityDays = std::stoi(config["defaultValidityDays"]);
        
        // Read CA private key
        std::ifstream keyFile(caKeyPath);
        if (!keyFile.is_open()) {
            return false;
        }
        std::stringstream keyStream;
        keyStream << keyFile.rdbuf();
        caPrivateKey = keyStream.str();
        
        // Read CA certificate
        std::ifstream certFile(caCertPath);
        if (!certFile.is_open()) {
            return false;
        }
        std::stringstream certStream;
        certStream << certFile.rdbuf();
        caCertificate = certStream.str();
        
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Error loading CA keys: " << e.what() << std::endl;
        return false;
    }
}

bool CertificateAuthority::createSelfSignedCA() {
    try {
        // Default CA subject if not specified
        if (caSubject.empty()) {
            caSubject = "CN=CA Management System,O=University Project,C=US";
        }
        
        // Default validity if not specified
        if (defaultValidityDays <= 0) {
            defaultValidityDays = 365;
        }
        
        // Generate CA key pair
        auto keyPair = ssl.generateRSAKeyPair(4096);
        caPrivateKey = keyPair.first;
        
        // Save private key
        std::ofstream keyFile(KEY_DIR + "ca_private.key");
        keyFile << caPrivateKey;
        keyFile.close();
        
        // Create self-signed certificate
        // Generate a CSR for the CA
        String csrData = ssl.generateCSR(caPrivateKey, caSubject);
        
        // Self-sign the CSR with a longer validity (10 years)
        caCertificate = ssl.signCSR(csrData, caPrivateKey, "", 3650);
        
        // Save certificate
        std::ofstream certFile(CERT_DIR + "ca_cert.pem");
        certFile << caCertificate;
        certFile.close();
        
        // Create config file
        std::map<String, String> config;
        config["caKeyPath"] = KEY_DIR + "ca_private.key";
        config["caCertPath"] = CERT_DIR + "ca_cert.pem";
        config["caSubject"] = caSubject;
        config["defaultValidityDays"] = std::to_string(defaultValidityDays);
        
        std::ofstream configFile(DATA_DIR + "ca_config.json");
        configFile << SimpleJSON::serialize(config, true);
        configFile.close();
        
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Error creating self-signed CA: " << e.what() << std::endl;
        return false;
    }
}

int CertificateAuthority::submitCSR(const String& csrData, const String& username) {
    // Validate CSR format
    if (!validateCSR(csrData)) {
        return -1;
    }
    
    // Extract public key from CSR
    BIO* csrBio = BIO_new_mem_buf(csrData.c_str(), -1);
    X509_REQ* req = PEM_read_bio_X509_REQ(csrBio, nullptr, nullptr, nullptr);
    EVP_PKEY* pubKey = X509_REQ_get_pubkey(req);
    
    // Convert public key to PEM
    BIO* pubKeyBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pubKeyBio, pubKey);
    String publicKeyPEM = ssl.bioToString(pubKeyBio);
    
    // Cleanup
    BIO_free(csrBio);
    BIO_free(pubKeyBio);
    EVP_PKEY_free(pubKey);
    X509_REQ_free(req);
    
    // Get user ID
    int userID = db.getUserID(username);
    if (userID < 0) {
        return -1;
    }
    
    // Store CSR in database
    return db.storeCSR(userID, publicKeyPEM, csrData);
}

bool CertificateAuthority::validateCSR(const String& csrData) {
    return ssl.verifyCSR(csrData);
}

int CertificateAuthority::issueCertificate(int requestID, int validityDays) {
    // Get CSR data from database
    auto csrInfo = db.getCSRInfo(requestID);
    if (csrInfo.csrData.empty() || csrInfo.status != "pending") {
        return -1;
    }
    
    // Use configured validity days if not specified
    if (validityDays <= 0) {
        validityDays = defaultValidityDays;
    }
    
    // Sign the CSR
    String certPEM = ssl.signCSR(csrInfo.csrData, caPrivateKey, caCertificate, validityDays);
    
    // Parse the certificate to extract information
    BIO* bio = BIO_new_mem_buf(certPEM.c_str(), -1);
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!cert) {
        return -1;
    }
    
    // Extract certificate information
    int version = X509_get_version(cert) + 1;
    
    // Get serial number as string
    ASN1_INTEGER* serialASN1 = X509_get_serialNumber(cert);
    BIGNUM* bn = ASN1_INTEGER_to_BN(serialASN1, nullptr);
    char* serialStr = BN_bn2hex(bn);
    String serialNumber = serialStr;
    OPENSSL_free(serialStr);
    BN_free(bn);
    
    // Get signature algorithm
    int sig_nid = X509_get_signature_nid(cert);
    String signatureAlgorithm = OBJ_nid2ln(sig_nid);
    
    // Get issuer and subject names
    char issuerStr[256];
    char subjectStr[256];
    X509_NAME_oneline(X509_get_issuer_name(cert), issuerStr, sizeof(issuerStr));
    X509_NAME_oneline(X509_get_subject_name(cert), subjectStr, sizeof(subjectStr));
    String issuerName = issuerStr;
    String subjectName = subjectStr;
    
    // Get validity period
    const ASN1_TIME* notBefore = X509_get_notBefore(cert);
    const ASN1_TIME* notAfter = X509_get_notAfter(cert);
    
    // Convert ASN1_TIME to time_t (simplified)
    struct tm tm_before = {0};
    struct tm tm_after = {0};
    
    // Extract year, month, day from ASN1_TIME
    // This is a simplification - OpenSSL has better functions for this
    if (notBefore->type == V_ASN1_UTCTIME) {
        tm_before.tm_year = (notBefore->data[0] - '0') * 10 + (notBefore->data[1] - '0');
        if (tm_before.tm_year < 50) tm_before.tm_year += 100; // 2000+
        tm_before.tm_mon = (notBefore->data[2] - '0') * 10 + (notBefore->data[3] - '0') - 1;
        tm_before.tm_mday = (notBefore->data[4] - '0') * 10 + (notBefore->data[5] - '0');
    }
    
    if (notAfter->type == V_ASN1_UTCTIME) {
        tm_after.tm_year = (notAfter->data[0] - '0') * 10 + (notAfter->data[1] - '0');
        if (tm_after.tm_year < 50) tm_after.tm_year += 100; // 2000+
        tm_after.tm_mon = (notAfter->data[2] - '0') * 10 + (notAfter->data[3] - '0') - 1;
        tm_after.tm_mday = (notAfter->data[4] - '0') * 10 + (notAfter->data[5] - '0');
    }
    
    time_t validFrom = mktime(&tm_before);
    time_t validTo = mktime(&tm_after);
    
    // Store certificate in database
    int certID = db.storeCertificate(serialNumber, version, signatureAlgorithm,
                                    issuerName, subjectName, validFrom, validTo,
                                    csrInfo.publicKey, csrInfo.subjectID, certPEM);
    
    // Update CSR status
    if (certID > 0) {
        db.updateCSRStatus(requestID, "approved", certID);
    }
    
    X509_free(cert);
    return certID;
}

bool CertificateAuthority::revokeCertificate(int certificateID, const String& reason, const String& username) {
    // Get certificate info
    auto certInfo = db.getCertificateInfo(certificateID);
    if (certInfo.serialNumber.empty()) {
        return false;
    }
    
    // Check if user is authorized (owner or admin)
    int userID = db.getUserID(username);
    String userRole = db.getUserRole(username);
    
    if (userID != certInfo.ownerID && userRole != "admin") {
        return false;
    }
    
    // Revoke certificate
    return db.revokeCertificate(certificateID, certInfo.serialNumber, reason, userID);
}

bool CertificateAuthority::validateCertificate(const String& certData) {
    // Verify certificate against CA certificate
    return ssl.verifyCertificate(certData, caCertificate);
}

String CertificateAuthority::generateCRL() {
    // Get list of revoked certificates
    auto revokedCerts = db.getRevokedCertificates();
    
    // Generate CRL
    String crlPEM = ssl.generateCRL(revokedCerts, caPrivateKey, caCertificate);
    
    // Save CRL to file
    std::ofstream crlFile(CERT_DIR + "ca.crl");
    crlFile << crlPEM;
    crlFile.close();
    
    return crlPEM;
}

int CertificateAuthority::getPendingCSRCount() {
    return db.getPendingCSRCount();
} 