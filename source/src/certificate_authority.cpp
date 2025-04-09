#include "../include/certificate_authority.h"
#include <fstream>

class SimpleJSON {
public:
    static map<String, String> parse(const String& jsonStr) {
        map<String, String> result;
        size_t pos = 0;
        
        pos = jsonStr.find('{', pos);
        if (pos == String::npos) return result;
        
        while (true) {
            pos = jsonStr.find('"', pos + 1);
            if (pos == String::npos) break;
            
            size_t keyStart = pos + 1;
            pos = jsonStr.find('"', pos + 1);
            if (pos == String::npos) break;
            
            String key = jsonStr.substr(keyStart, pos - keyStart);
            pos = jsonStr.find(':', pos + 1);
            if (pos == String::npos) break;
            
            pos = jsonStr.find_first_not_of(" \t\r\n", pos + 1);
            if (pos == String::npos) break;
            
            String value;
            if (jsonStr[pos] == '"') {
                size_t valueStart = pos + 1;
                pos = jsonStr.find('"', pos + 1);
                if (pos == String::npos) break;
                value = jsonStr.substr(valueStart, pos - valueStart);
            } else if (isdigit(jsonStr[pos]) || jsonStr[pos] == '-') {
                size_t valueStart = pos;
                pos = jsonStr.find_first_of(",}", pos + 1);
                if (pos == String::npos) break;
                value = jsonStr.substr(valueStart, pos - valueStart);
                pos--;
            } else {
                break;
            }
            
            result[key] = value;
            
            pos = jsonStr.find_first_of(",}", pos + 1);
            if (pos == String::npos || jsonStr[pos] == '}') break;
        }
        
        return result;
    }
    
    static String serialize(const map<String, String>& data, bool prettyPrint = false) {
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
    : db(dbManager), ssl(sslWrapper), defaultValidityDays(365), usePKCS12(false) {
}

bool CertificateAuthority::initialize(const String& configPath) {
    filesystem::create_directories(CERT_DIR);
    filesystem::create_directories(KEY_DIR);
    
    if (loadCAKeys(configPath)) {
        cout << "Loaded existing CA keys" << endl;
        return true;
    }
    cout << "Creating new self-signed CA..." << endl;
    return createSelfSignedCA();
}

bool CertificateAuthority::loadCAKeys(const String& configPath) {
    try {
        ifstream configFile(configPath);
        if (!configFile.is_open()) {
            return false;
        }
        
        stringstream configStream;
        configStream << configFile.rdbuf();
        String configStr = configStream.str();
        
        auto config = SimpleJSON::parse(configStr);
        
        usePKCS12 = false;
        if (config.find("usePKCS12") != config.end()) {
            usePKCS12 = (config["usePKCS12"] == "true");
        }
        
        if (usePKCS12) {
            String p12Path = config["caP12Path"];
            caPassword = config["caPassword"];
            caSubject = config["caSubject"];
            defaultValidityDays = stoi(config["defaultValidityDays"]);
            
            return loadCAKeysFromPKCS12(p12Path);
        } else {
            String caKeyPath = config["caKeyPath"];
            String caCertPath = config["caCertPath"];
            caSubject = config["caSubject"];
            defaultValidityDays = stoi(config["defaultValidityDays"]);
            
            ifstream keyFile(caKeyPath);
            if (!keyFile.is_open()) {
                return false;
            }
            stringstream keyStream;
            keyStream << keyFile.rdbuf();
            caPrivateKey = keyStream.str();
            
            ifstream certFile(caCertPath);
            if (!certFile.is_open()) {
                return false;
            }
            stringstream certStream;
            certStream << certFile.rdbuf();
            caCertificate = certStream.str();
            
            return true;
        }
    }
    catch (const exception& e) {
        cerr << "Error loading CA keys: " << e.what() << endl;
        return false;
    }
}

bool CertificateAuthority::loadCAKeysFromPKCS12(const String& p12Path) {
    try {
        ifstream p12File(p12Path, ios::binary);
        if (!p12File.is_open()) {
            cerr << "Failed to open PKCS#12 file: " << p12Path << endl;
            return false;
        }
        
        stringstream p12Stream;
        p12Stream << p12File.rdbuf();
        String p12Data = p12Stream.str();
        
        auto keyAndCert = ssl.extractFromPKCS12(p12Data, caPassword);
        caPrivateKey = keyAndCert.first;
        caCertificate = keyAndCert.second;
        
        if (caPrivateKey.empty() || caCertificate.empty()) {
            cerr << "Failed to extract key and certificate from PKCS#12 file" << endl;
            return false;
        }
        
        return true;
    }
    catch (const exception& e) {
        cerr << "Error loading CA keys from PKCS#12: " << e.what() << endl;
        return false;
    }
}

bool CertificateAuthority::createSelfSignedCA() {
    try {
        if (caSubject.empty()) {
            caSubject = "CN=CA Management System,O=University Project,C=US";
        }
        
        if (defaultValidityDays <= 0) {
            defaultValidityDays = 365;
        }
        
        auto keyPair = ssl.generateRSAKeyPair(4096);
        caPrivateKey = keyPair.first;
        
        ofstream keyFile(KEY_DIR + "ca_private.key");
        keyFile << caPrivateKey;
        keyFile.close();
        
        String csrData = ssl.generateCSR(caPrivateKey, caSubject);
        
        caCertificate = ssl.signCSR(csrData, caPrivateKey, "", 3650, true);
        
        ofstream certFile(CERT_DIR + "ca_cert.pem");
        certFile << caCertificate;
        certFile.close();
        
        if (usePKCS12) {
            storeCAKeysAsPKCS12();
        }
        
        map<String, String> config;
        
        if (usePKCS12) {
            config["caP12Path"] = CERT_DIR + "ca_cert.p12";
            config["caPassword"] = caPassword;
            config["usePKCS12"] = "true";
        } else {
            config["caKeyPath"] = KEY_DIR + "ca_private.key";
            config["caCertPath"] = CERT_DIR + "ca_cert.pem";
            config["usePKCS12"] = "false";
        }
        
        config["caSubject"] = caSubject;
        config["defaultValidityDays"] = to_string(defaultValidityDays);
        
        ofstream configFile(DATA_DIR + "ca_config.json");
        configFile << SimpleJSON::serialize(config, true);
        configFile.close();
        
        return true;
    }
    catch (const exception& e) {
        cerr << "Error creating self-signed CA: " << e.what() << endl;
        return false;
    }
}

bool CertificateAuthority::storeCAKeysAsPKCS12() {
    try {
        if (caPassword.empty()) {
            cout << "Enter password for CA PKCS#12 file: ";
            getline(cin, caPassword);
            
            if (caPassword.empty()) {
                cerr << "Password cannot be empty for PKCS#12 format." << endl;
                return false;
            }
        }
        
        String p12Data = ssl.createPKCS12(caPrivateKey, caCertificate, caPassword, "CA Certificate");
        
        if (p12Data.empty()) {
            cerr << "Failed to create PKCS#12 file for CA" << endl;
            return false;
        }
        
        ofstream p12File(CERT_DIR + "ca_cert.p12", ios::binary);
        p12File.write(p12Data.data(), p12Data.size());
        p12File.close();
        
        cout << "CA keys stored in PKCS#12 format." << endl;
        return true;
    }
    catch (const exception& e) {
        cerr << "Error storing CA keys as PKCS#12: " << e.what() << endl;
        return false;
    }
}

int CertificateAuthority::submitCSR(const String& csrData, const String& username) {
    if (!validateCSR(csrData)) {
        return -1;
    }
    
    BIO* csrBio = BIO_new_mem_buf(csrData.c_str(), -1);
    X509_REQ* req = PEM_read_bio_X509_REQ(csrBio, nullptr, nullptr, nullptr);
    EVP_PKEY* pubKey = X509_REQ_get_pubkey(req);
    
    BIO* pubKeyBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pubKeyBio, pubKey);
    String publicKeyPEM = ssl.bioToString(pubKeyBio);
    
    BIO_free(csrBio);
    BIO_free(pubKeyBio);
    EVP_PKEY_free(pubKey);
    X509_REQ_free(req);
    
    int userID = db.getUserID(username);
    if (userID < 0) {
        return -1;
    }
    
    return db.storeCSR(userID, publicKeyPEM, csrData);
}

bool CertificateAuthority::validateCSR(const String& csrData) {
    return ssl.verifyCSR(csrData);
}

int CertificateAuthority::issueCertificate(int requestID, int validityDays) {
    auto csrInfo = db.getCSRInfo(requestID);
    if (csrInfo.csrData.empty() || csrInfo.status != "pending") {
        return -1;
    }
    
    if (validityDays <= 0) {
        validityDays = defaultValidityDays;
    }
    String certPEM = ssl.signCSR(csrInfo.csrData, caPrivateKey, caCertificate, validityDays);
    
    BIO* bio = BIO_new_mem_buf(certPEM.c_str(), -1);
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!cert) {
        return -1;
    }
    
    int version = X509_get_version(cert) + 1;
    
    ASN1_INTEGER* serialASN1 = X509_get_serialNumber(cert);
    BIGNUM* bn = ASN1_INTEGER_to_BN(serialASN1, nullptr);
    char* serialStr = BN_bn2hex(bn);
    String serialNumber = serialStr;
    OPENSSL_free(serialStr);
    BN_free(bn);
    
    int sig_nid = X509_get_signature_nid(cert);
    String signatureAlgorithm = OBJ_nid2ln(sig_nid);
    
    char issuerStr[256];
    char subjectStr[256];
    X509_NAME_oneline(X509_get_issuer_name(cert), issuerStr, sizeof(issuerStr));
    X509_NAME_oneline(X509_get_subject_name(cert), subjectStr, sizeof(subjectStr));
    String issuerName = issuerStr;
    String subjectName = subjectStr;
    
    const ASN1_TIME* notBefore = X509_get_notBefore(cert);
    const ASN1_TIME* notAfter = X509_get_notAfter(cert);
    
    struct tm tm_before = {0};
    struct tm tm_after = {0};
    

    if (notBefore->type == V_ASN1_UTCTIME) {
        tm_before.tm_year = (notBefore->data[0] - '0') * 10 + (notBefore->data[1] - '0');
        if (tm_before.tm_year < 50) tm_before.tm_year += 100; 
        tm_before.tm_mon = (notBefore->data[2] - '0') * 10 + (notBefore->data[3] - '0') - 1;
        tm_before.tm_mday = (notBefore->data[4] - '0') * 10 + (notBefore->data[5] - '0');
    }
    
    if (notAfter->type == V_ASN1_UTCTIME) {
        tm_after.tm_year = (notAfter->data[0] - '0') * 10 + (notAfter->data[1] - '0');
        if (tm_after.tm_year < 50) tm_after.tm_year += 100; 
        tm_after.tm_mon = (notAfter->data[2] - '0') * 10 + (notAfter->data[3] - '0') - 1;
        tm_after.tm_mday = (notAfter->data[4] - '0') * 10 + (notAfter->data[5] - '0');
    }
    
    time_t validFrom = mktime(&tm_before);
    time_t validTo = mktime(&tm_after);
    
    int certID = db.storeCertificate(serialNumber, version, signatureAlgorithm,
                                    issuerName, subjectName, validFrom, validTo,
                                    csrInfo.publicKey, csrInfo.subjectID, certPEM);
    
    if (certID > 0) {
        db.updateCSRStatus(requestID, "approved", certID);
    }
    
    X509_free(cert);
    return certID;
}

bool CertificateAuthority::revokeCertificate(int certificateID, const String& reason, const String& username) {
    auto certInfo = db.getCertificateInfo(certificateID);
    if (certInfo.serialNumber.empty()) {
        return false;
    }
    
    int userID = db.getUserID(username);
    String userRole = db.getUserRole(username);
    
    if (userID != certInfo.ownerID && userRole != "admin") {
        return false;
    }
    return db.revokeCertificate(certificateID, certInfo.serialNumber, reason, userID);
}

bool CertificateAuthority::validateCertificate(const String& certData) {
    bool valid = ssl.verifyCertificate(certData, caCertificate);
    
    if (!valid) {
        return false;
    }
    
    try {
        BIO* certBio = BIO_new_mem_buf(certData.c_str(), -1);
        X509* cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
        BIO_free(certBio);
        
        if (!cert) {
            return false;
        }
        
        ASN1_INTEGER* serialASN1 = X509_get_serialNumber(cert);
        BIGNUM* bn = ASN1_INTEGER_to_BN(serialASN1, nullptr);
        char* serialStr = BN_bn2hex(bn);
        String serialNumber = serialStr;
        OPENSSL_free(serialStr);
        BN_free(bn);
        X509_free(cert);
        
        auto revokedCerts = db.getRevokedCertificates();
        for (const auto& revokedCert : revokedCerts) {
            if (revokedCert.first == serialNumber) {
                return false; 
            }
        }
        
        return true; 
    }
    catch (const exception& e) {
        cerr << "Error validating certificate: " << e.what() << endl;
        return false;
    }
}

String CertificateAuthority::generateCRL() {
    auto revokedCerts = db.getRevokedCertificates();
    String crlPEM = ssl.generateCRL(revokedCerts, caPrivateKey, caCertificate);
    ofstream crlFile(CERT_DIR + "ca.crl");
    crlFile << crlPEM;
    crlFile.close();
    return crlPEM;
}

int CertificateAuthority::getPendingCSRCount() {
    return db.getPendingCSRCount();
} 