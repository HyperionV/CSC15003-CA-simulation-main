#include "../include/openssl_wrapper.h"
#include <openssl/pkcs12.h>

OpenSSLWrapper::OpenSSLWrapper() {
    // Initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

OpenSSLWrapper::~OpenSSLWrapper() {
    // Cleanup OpenSSL
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

// Generate RSA key pair
std::pair<String, String> OpenSSLWrapper::generateRSAKeyPair(int keySize) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    // Replace deprecated RSA_generate_key with RSA_generate_key_ex
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, keySize, bn, nullptr);
    // Use EVP_PKEY_assign_RSA with additional check
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        // Handle error
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        BN_free(bn);
        return {"", ""};
    }
    BN_free(bn);
    
    // Extract private key to PEM
    BIO* privateBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(privateBio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    
    // Extract public key to PEM
    BIO* publicBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(publicBio, pkey);
    
    // Read BIOs to strings
    String privateKey = bioToString(privateBio);
    String publicKey = bioToString(publicBio);
    
    // Cleanup
    BIO_free(privateBio);
    BIO_free(publicBio);
    EVP_PKEY_free(pkey);
    
    return {privateKey, publicKey};
}

// Generate CSR
String OpenSSLWrapper::generateCSR(const String& privateKeyPEM, const String& subjectName) {
    // Parse private key
    BIO* keyBio = BIO_new_mem_buf(privateKeyPEM.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
    BIO_free(keyBio);
    
    if (!pkey) {
        std::cerr << "Failed to parse private key" << std::endl;
        return "";
    }
    
    // Create X509_REQ
    X509_REQ* req = X509_REQ_new();
    X509_REQ_set_pubkey(req, pkey);
    
    // Set subject name
    X509_NAME* name = X509_REQ_get_subject_name(req);
    parseAndAddSubject(name, subjectName);
    
    // Sign the request
    X509_REQ_sign(req, pkey, EVP_sha256());
    
    // Write to PEM
    BIO* csrBio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(csrBio, req);
    String csrPEM = bioToString(csrBio);
    
    // Cleanup
    BIO_free(csrBio);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    
    return csrPEM;
}

// Verify CSR
bool OpenSSLWrapper::verifyCSR(const String& csrPEM) {
    BIO* bio = BIO_new_mem_buf(csrPEM.c_str(), -1);
    X509_REQ* req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!req) {
        std::cerr << "Failed to parse CSR" << std::endl;
        return false;
    }
    
    // Verify CSR signature
    EVP_PKEY* pkey = X509_REQ_get_pubkey(req);
    int result = X509_REQ_verify(req, pkey);
    EVP_PKEY_free(pkey);
    X509_REQ_free(req);
    
    return (result > 0);
}

// Sign CSR to create certificate
String OpenSSLWrapper::signCSR(const String& csrPEM, const String& caKeyPEM,
                              const String& caCertPEM, int validityDays, bool isCA) {
    // Parse CSR
    BIO* csrBio = BIO_new_mem_buf(csrPEM.c_str(), -1);
    X509_REQ* req = PEM_read_bio_X509_REQ(csrBio, nullptr, nullptr, nullptr);
    BIO_free(csrBio);
    
    if (!req) {
        std::cerr << "Failed to parse CSR" << std::endl;
        return "";
    }
    
    // Parse CA private key
    BIO* caKeyBio = BIO_new_mem_buf(caKeyPEM.c_str(), -1);
    EVP_PKEY* caKey = PEM_read_bio_PrivateKey(caKeyBio, nullptr, nullptr, nullptr);
    BIO_free(caKeyBio);
    
    if (!caKey) {
        std::cerr << "Failed to parse CA private key" << std::endl;
        X509_REQ_free(req);
        return "";
    }
    
    // Create new certificate
    X509* cert = X509_new();
    
    // Set version (X509v3)
    X509_set_version(cert, 2);
    
    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(cert), generateSerialNumber());
    
    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * validityDays);
    
    // Set subject from CSR
    X509_set_subject_name(cert, X509_REQ_get_subject_name(req));
    
    // Parse CA certificate if provided, otherwise use self-signed
    X509* caCert = nullptr;
    if (!caCertPEM.empty()) {
        BIO* caCertBio = BIO_new_mem_buf(caCertPEM.c_str(), -1);
        caCert = PEM_read_bio_X509(caCertBio, nullptr, nullptr, nullptr);
        BIO_free(caCertBio);
        
        if (!caCert) {
            std::cerr << "Failed to parse CA certificate" << std::endl;
            EVP_PKEY_free(caKey);
            X509_REQ_free(req);
            X509_free(cert);
            return "";
        }
        
        // Set issuer from CA cert
        X509_set_issuer_name(cert, X509_get_subject_name(caCert));
    } else {
        // Self-signed: issuer = subject
        X509_set_issuer_name(cert, X509_REQ_get_subject_name(req));
    }
    
    // Set public key from CSR
    EVP_PKEY* reqPubKey = X509_REQ_get_pubkey(req);
    X509_set_pubkey(cert, reqPubKey);
    EVP_PKEY_free(reqPubKey);
    
    // Add extensions based on whether this is a CA certificate or not
    if (isCA) {
        if (caCert) {
            addCAExtensions(cert, caCert);
        } else {
            // Self-signed CA: use cert as its own CA
            addCAExtensions(cert, cert);
        }
    } else {
        if (caCert) {
            addExtensions(cert, caCert);
        } else {
            // Self-signed: use cert as its own CA
            addExtensions(cert, cert);
        }
    }
    
    // Sign the certificate
    X509_sign(cert, caKey, EVP_sha256());
    
    // Write to PEM
    BIO* certBio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(certBio, cert);
    String certPEM = bioToString(certBio);
    
    // Cleanup
    BIO_free(certBio);
    X509_free(cert);
    if (caCert) X509_free(caCert);
    EVP_PKEY_free(caKey);
    X509_REQ_free(req);
    
    return certPEM;
}

// Verify certificate against CA
bool OpenSSLWrapper::verifyCertificate(const String& certPEM, const String& caCertPEM) {
    // Parse certificate
    BIO* certBio = BIO_new_mem_buf(certPEM.c_str(), -1);
    X509* cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
    BIO_free(certBio);
    
    if (!cert) {
        std::cerr << "Failed to parse certificate" << std::endl;
        return false;
    }
    
    // Parse CA certificate
    BIO* caCertBio = BIO_new_mem_buf(caCertPEM.c_str(), -1);
    X509* caCert = PEM_read_bio_X509(caCertBio, nullptr, nullptr, nullptr);
    BIO_free(caCertBio);
    
    if (!caCert) {
        std::cerr << "Failed to parse CA certificate" << std::endl;
        X509_free(cert);
        return false;
    }
    
    // Check certificate expiration dates
    time_t currentTime = time(nullptr);
    const ASN1_TIME* notBefore = X509_get_notBefore(cert);
    const ASN1_TIME* notAfter = X509_get_notAfter(cert);
    
    bool validTime = true;
    
    // Convert ASN1_TIME to time_t and compare
    int pday = 0, psec = 0;
    if (!ASN1_TIME_diff(&pday, &psec, NULL, notBefore) || (pday > 0 || psec > 0)) {
        std::cerr << "Certificate is not yet valid" << std::endl;
        validTime = false;
    }
    
    pday = 0;
    psec = 0;
    if (!ASN1_TIME_diff(&pday, &psec, NULL, notAfter) || (pday < 0 || psec < 0)) {
        std::cerr << "Certificate has expired" << std::endl;
        validTime = false;
    }
    
    if (!validTime) {
        X509_free(cert);
        X509_free(caCert);
        return false;
    }
    
    // Create certificate store
    X509_STORE* store = X509_STORE_new();
    X509_STORE_add_cert(store, caCert);
    
    // Set verification flags to check all certificate attributes
    X509_STORE_set_flags(store, X509_V_FLAG_CHECK_SS_SIGNATURE);
    
    // Create verification context
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, nullptr);
    
    // Verify certificate
    int result = X509_verify_cert(ctx);
    
    // If verification failed, get the error code and log it
    if (result <= 0) {
        int error = X509_STORE_CTX_get_error(ctx);
        std::cerr << "Certificate verification failed: " 
                  << X509_verify_cert_error_string(error) << std::endl;
    }
    
    // Cleanup
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);
    X509_free(caCert);
    
    return (result > 0);
}

bool OpenSSLWrapper::validateCertificateChain(const std::vector<String>& certChain) {
    if (certChain.empty()) {
        return false;
    }
    
    // Create certificate store
    X509_STORE* store = X509_STORE_new();
    
    // Parse all certificates
    std::vector<X509*> certs;
    for (const auto& certPEM : certChain) {
        BIO* certBio = BIO_new_mem_buf(certPEM.c_str(), -1);
        X509* cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
        BIO_free(certBio);
        
        if (!cert) {
            // Cleanup
            for (auto c : certs) {
                X509_free(c);
            }
            X509_STORE_free(store);
            return false;
        }
        
        certs.push_back(cert);
    }
    
    // Add all certificates except the first one to the store
    for (size_t i = 1; i < certs.size(); i++) {
        X509_STORE_add_cert(store, certs[i]);
    }
    
    // Create verification context
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, certs[0], nullptr);
    
    // Verify certificate chain
    int result = X509_verify_cert(ctx);
    
    // Cleanup
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    for (auto cert : certs) {
        X509_free(cert);
    }
    
    return (result > 0);
}

bool OpenSSLWrapper::checkCertificateRevocation(const String& certPEM, const String& crlPEM) {
    // Parse certificate
    BIO* certBio = BIO_new_mem_buf(certPEM.c_str(), -1);
    X509* cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
    BIO_free(certBio);
    
    if (!cert) {
        return false;
    }
    
    // Parse CRL
    BIO* crlBio = BIO_new_mem_buf(crlPEM.c_str(), -1);
    X509_CRL* crl = PEM_read_bio_X509_CRL(crlBio, nullptr, nullptr, nullptr);
    BIO_free(crlBio);
    
    if (!crl) {
        X509_free(cert);
        return false;
    }
    
    // Check if certificate is in CRL
    int idx = X509_CRL_get_ext_by_NID(crl, NID_crl_number, -1);
    if (idx == -1) {
        X509_free(cert);
        X509_CRL_free(crl);
        return false;
    }
    
    // Get certificate serial number
    ASN1_INTEGER* cert_serial = X509_get_serialNumber(cert);
    
    // Check if certificate is revoked
    bool revoked = false;
    for (int i = 0; i < sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl)); i++) {
        X509_REVOKED* rev = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
        const ASN1_INTEGER* rev_serial = X509_REVOKED_get0_serialNumber(rev);
        if (ASN1_INTEGER_cmp(rev_serial, cert_serial) == 0) {
            revoked = true;
            break;
        }
    }
    
    // Cleanup
    X509_free(cert);
    X509_CRL_free(crl);
    
    return revoked;
}

// Generate CRL
String OpenSSLWrapper::generateCRL(const std::vector<std::pair<String, String>>& revokedCerts,
                                 const String& caKeyPEM, const String& caCertPEM) {
    // Parse CA private key
    BIO* caKeyBio = BIO_new_mem_buf(caKeyPEM.c_str(), -1);
    EVP_PKEY* caKey = PEM_read_bio_PrivateKey(caKeyBio, nullptr, nullptr, nullptr);
    BIO_free(caKeyBio);
    
    if (!caKey) {
        std::cerr << "Failed to parse CA private key" << std::endl;
        return "";
    }
    
    // Parse CA certificate
    BIO* caCertBio = BIO_new_mem_buf(caCertPEM.c_str(), -1);
    X509* caCert = PEM_read_bio_X509(caCertBio, nullptr, nullptr, nullptr);
    BIO_free(caCertBio);
    
    if (!caCert) {
        std::cerr << "Failed to parse CA certificate" << std::endl;
        EVP_PKEY_free(caKey);
        return "";
    }
    
    // Create new CRL
    X509_CRL* crl = X509_CRL_new();
    
    // Set issuer
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(caCert));
    
    // Set last update and next update
    X509_CRL_set_lastUpdate(crl, X509_get_notBefore(caCert)); // Current time
    X509_CRL_set_nextUpdate(crl, X509_get_notAfter(caCert));  // +1 day
    
    // Add revoked certificates
    for (const auto& entry : revokedCerts) {
        // serialNumber, reason
        const String& serialNumber = entry.first;
        const String& reason = entry.second;
        
        BIGNUM* bn = nullptr;
        BN_hex2bn(&bn, serialNumber.c_str());
        
        X509_REVOKED* revoked = X509_REVOKED_new();
        
        // Set serial number
        ASN1_INTEGER* serialASN1 = BN_to_ASN1_INTEGER(bn, nullptr);
        X509_REVOKED_set_serialNumber(revoked, serialASN1);
        ASN1_INTEGER_free(serialASN1);
        BN_free(bn);
        
        // Set revocation time to now
        ASN1_TIME* revocationTime = ASN1_TIME_new();
        X509_gmtime_adj(revocationTime, 0);
        X509_REVOKED_set_revocationDate(revoked, revocationTime);
        ASN1_TIME_free(revocationTime);
        
        // Add reason extension if provided
        if (!reason.empty()) {
            const char* reasonStr = reason.c_str();
            
            // Convert reason string to OpenSSL code
            int reasonCode = CRL_REASON_UNSPECIFIED;
            if (reason == "keyCompromise") reasonCode = CRL_REASON_KEY_COMPROMISE;
            else if (reason == "caCompromise") reasonCode = CRL_REASON_CA_COMPROMISE;
            else if (reason == "affiliationChanged") reasonCode = CRL_REASON_AFFILIATION_CHANGED;
            else if (reason == "superseded") reasonCode = CRL_REASON_SUPERSEDED;
            else if (reason == "cessationOfOperation") reasonCode = CRL_REASON_CESSATION_OF_OPERATION;
            else if (reason == "certificateHold") reasonCode = CRL_REASON_CERTIFICATE_HOLD;
            
            // Add reason extension
            ASN1_ENUMERATED* reasonEnum = ASN1_ENUMERATED_new();
            ASN1_ENUMERATED_set(reasonEnum, reasonCode);
            
            X509_EXTENSION* ext = X509_EXTENSION_create_by_NID(nullptr, NID_crl_reason, 
                                                              0, reasonEnum);
            X509_REVOKED_add_ext(revoked, ext, -1);
            
            X509_EXTENSION_free(ext);
            ASN1_ENUMERATED_free(reasonEnum);
        }
        
        // Add to CRL
        X509_CRL_add0_revoked(crl, revoked);
    }
    
    // Sort entries
    X509_CRL_sort(crl);
    
    // Sign the CRL
    X509_CRL_sign(crl, caKey, EVP_sha256());
    
    // Write to PEM
    BIO* crlBio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_CRL(crlBio, crl);
    String crlPEM = bioToString(crlBio);
    
    // Cleanup
    BIO_free(crlBio);
    X509_CRL_free(crl);
    X509_free(caCert);
    EVP_PKEY_free(caKey);
    
    return crlPEM;
}

// Utility to convert BIO to string
String OpenSSLWrapper::bioToString(BIO* bio) {
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    String result(mem->data, mem->length);
    return result;
}

// Generate a unique serial number
long OpenSSLWrapper::generateSerialNumber() {
    // In a real implementation, this should use a secure random number
    // and track used serials to ensure uniqueness
    std::vector<unsigned char> buffer(8);
    RAND_bytes(buffer.data(), buffer.size());
    
    long serialNumber = 0;
    for (int i = 0; i < 8; i++) {
        serialNumber = (serialNumber << 8) | buffer[i];
    }
    return std::abs(serialNumber);
}

// Helper to parse subject string
void OpenSSLWrapper::parseAndAddSubject(X509_NAME* name, const String& subject) {
    // Simple parser for DN format (e.g., "CN=John Doe,O=Example Inc,C=US")
    std::istringstream ss(subject);
    String token;
    
    while (std::getline(ss, token, ',')) {
        size_t pos = token.find('=');
        if (pos != String::npos) {
            String field = token.substr(0, pos);
            String value = token.substr(pos + 1);
            X509_NAME_add_entry_by_txt(name, field.c_str(), MBSTRING_ASC, 
                                      (unsigned char*)value.c_str(), -1, -1, 0);
        }
    }
}

// Helper to add X.509v3 extensions
void OpenSSLWrapper::addExtensions(X509* cert, X509* caCert) {
    // Create extension context
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, caCert, cert, nullptr, nullptr, 0);
    
    // Add basic constraints
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                                             NID_basic_constraints, "critical,CA:FALSE");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    
    // Add key usage
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                             NID_key_usage, "critical,digitalSignature,keyEncipherment");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    
    // Add extended key usage
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                             NID_ext_key_usage, "serverAuth,clientAuth");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    
    // Add subject key identifier
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                             NID_subject_key_identifier, "hash");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    
    // Add authority key identifier
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                             NID_authority_key_identifier, "keyid:always,issuer");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
}

// Helper to add CA-specific X.509v3 extensions
void OpenSSLWrapper::addCAExtensions(X509* cert, X509* caCert) {
    // Create extension context
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, caCert, cert, nullptr, nullptr, 0);
    
    // Add basic constraints with CA:TRUE
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                                             NID_basic_constraints, "critical,CA:TRUE");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    
    // Add key usage appropriate for a CA
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                             NID_key_usage, "critical,keyCertSign,cRLSign");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    
    // Add subject key identifier
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                             NID_subject_key_identifier, "hash");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    
    // Add authority key identifier if not self-signed
    if (caCert != cert) {
        ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                                 NID_authority_key_identifier, "keyid:always,issuer");
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
}

// Create a PKCS#12 file from a private key and certificate
String OpenSSLWrapper::createPKCS12(const String& privateKeyPEM, const String& certificatePEM, 
                                   const String& password, const String& friendlyName) {
    // Parse private key
    BIO* keyBio = BIO_new_mem_buf(privateKeyPEM.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
    BIO_free(keyBio);
    
    if (!pkey) {
        std::cerr << "Failed to parse private key for PKCS#12" << std::endl;
        return "";
    }
    
    // Parse certificate
    BIO* certBio = BIO_new_mem_buf(certificatePEM.c_str(), -1);
    X509* cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
    BIO_free(certBio);
    
    if (!cert) {
        std::cerr << "Failed to parse certificate for PKCS#12" << std::endl;
        EVP_PKEY_free(pkey);
        return "";
    }
    
    // Create PKCS#12 structure
    PKCS12* p12 = PKCS12_create(
        password.c_str(),   // Password for PKCS#12 file
        friendlyName.empty() ? "Certificate" : friendlyName.c_str(), // Friendly name
        pkey,               // Private key
        cert,               // Certificate
        nullptr,            // CA certificate chain (none in this case)
        0,                  // Key encryption algorithm (0 = default)
        0,                  // Cert encryption algorithm (0 = default)
        0,                  // Iteration count (0 = default)
        0,                  // MAC iteration count (0 = default)
        0                   // Key type flags (0 = default)
    );
    
    if (!p12) {
        std::cerr << "Failed to create PKCS#12 structure" << std::endl;
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return "";
    }
    
    // Write PKCS#12 to memory BIO
    BIO* p12Bio = BIO_new(BIO_s_mem());
    i2d_PKCS12_bio(p12Bio, p12);
    
    // Convert to string (base64 encoded)
    BUF_MEM* bptr;
    BIO_get_mem_ptr(p12Bio, &bptr);
    String result(bptr->data, bptr->length);
    
    // Cleanup
    PKCS12_free(p12);
    BIO_free(p12Bio);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    
    return result;
}

// Extract a private key and certificate from a PKCS#12 file
std::pair<String, String> OpenSSLWrapper::extractFromPKCS12(const String& pkcs12Data, const String& password) {
    // Create BIO from PKCS#12 data
    BIO* p12Bio = BIO_new_mem_buf(pkcs12Data.c_str(), pkcs12Data.size());
    PKCS12* p12 = d2i_PKCS12_bio(p12Bio, nullptr);
    BIO_free(p12Bio);
    
    if (!p12) {
        std::cerr << "Failed to parse PKCS#12 data" << std::endl;
        return {"", ""};
    }
    
    // Parse PKCS#12
    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;
    STACK_OF(X509)* ca = nullptr;
    
    if (!PKCS12_parse(p12, password.c_str(), &pkey, &cert, &ca)) {
        std::cerr << "Failed to parse PKCS#12 with provided password" << std::endl;
        PKCS12_free(p12);
        return {"", ""};
    }
    
    // Extract private key to PEM
    BIO* keyBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(keyBio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    String privateKey = bioToString(keyBio);
    BIO_free(keyBio);
    
    // Extract certificate to PEM
    BIO* certBio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(certBio, cert);
    String certificate = bioToString(certBio);
    BIO_free(certBio);
    
    // Cleanup
    PKCS12_free(p12);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    if (ca) sk_X509_pop_free(ca, X509_free);
    
    return {privateKey, certificate};
}

// Extract subject from certificate
String OpenSSLWrapper::extractSubjectFromCertificate(const String& certPEM) {
    // Parse certificate
    BIO* certBio = BIO_new_mem_buf(certPEM.c_str(), -1);
    X509* cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
    BIO_free(certBio);
    
    if (!cert) {
        std::cerr << "Failed to parse certificate for subject extraction" << std::endl;
        return "";
    }
    
    // Extract subject
    X509_NAME* name = X509_get_subject_name(cert);
    char* subjectStr = X509_NAME_oneline(name, nullptr, 0);
    String subject;
    
    if (subjectStr) {
        subject = subjectStr;
        OPENSSL_free(subjectStr);
    }
    
    X509_free(cert);
    return subject;
}

// Extract Common Name (CN) from subject string
String OpenSSLWrapper::extractCNFromSubject(const String& subject) {
    size_t cnPos = subject.find("CN=");
    if (cnPos == String::npos) {
        return "";
    }
    
    cnPos += 3; // Skip "CN="
    size_t cnEnd = subject.find(',', cnPos);
    
    if (cnEnd != String::npos) {
        return subject.substr(cnPos, cnEnd - cnPos);
    } else {
        return subject.substr(cnPos);
    }
}

// Find a private key that matches a certificate
String OpenSSLWrapper::findMatchingPrivateKey(const String& certificatePEM, const String& directory,
                                            bool interactiveSelection) {
    // First extract subject info from the certificate
    String subject = extractSubjectFromCertificate(certificatePEM);
    String commonName = extractCNFromSubject(subject);
    
    if (subject.empty()) {
        std::cerr << "Could not extract subject from certificate" << std::endl;
        return "";
    }
    
    // Get list of key files in the directory (files with .key extension)
    std::vector<String> keyFiles;
    try {
        for (const auto& entry : std::filesystem::directory_iterator(directory)) {
            if (entry.is_regular_file() && entry.path().extension() == ".key") {
                keyFiles.push_back(entry.path().string());
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error reading directory for key files: " << e.what() << std::endl;
        return "";
    }
    
    // Check if any key files were found
    if (keyFiles.empty()) {
        std::cerr << "No private key files found in the directory: " << directory << std::endl;
        return "";
    }
    
    // Try to find a key file with matching name based on CN
    if (!commonName.empty()) {
        for (const auto& keyPath : keyFiles) {
            String fileName = std::filesystem::path(keyPath).stem().string();
            
            // Check if filename contains or matches CN
            if (fileName.find(commonName) != String::npos || commonName.find(fileName) != String::npos) {
                // Try to read this key file
                try {
                    std::ifstream keyFile(keyPath);
                    if (!keyFile.is_open()) continue;
                    
                    std::stringstream keyStream;
                    keyStream << keyFile.rdbuf();
                    String keyPEM = keyStream.str();
                    
                    // Verify that this key matches the certificate
                    if (verifyKeyMatchesCertificate(keyPEM, certificatePEM)) {
                        return keyPEM;
                    }
                } catch (...) {
                    continue;
                }
            }
        }
    }
    
    // If no match found by name, try each key to see if it matches the certificate
    for (const auto& keyPath : keyFiles) {
        try {
            std::ifstream keyFile(keyPath);
            if (!keyFile.is_open()) continue;
            
            std::stringstream keyStream;
            keyStream << keyFile.rdbuf();
            String keyPEM = keyStream.str();
            
            // Verify that this key matches the certificate
            if (verifyKeyMatchesCertificate(keyPEM, certificatePEM)) {
                return keyPEM;
            }
        } catch (...) {
            continue;
        }
    }
    
    // If interactive selection is enabled and no automatic match was found
    if (interactiveSelection) {
        std::cout << "No matching private key found automatically." << std::endl;
        std::cout << "Available private key files:" << std::endl;
        std::cout << "---------------------------" << std::endl;
        
        for (size_t i = 0; i < keyFiles.size(); i++) {
            std::cout << i + 1 << ". " << std::filesystem::path(keyFiles[i]).filename().string() << std::endl;
        }
        std::cout << "---------------------------" << std::endl;
        
        std::cout << "Select a private key file to use (0 to cancel): ";
        int selection;
        std::cin >> selection;
        std::cin.ignore(); // Clear newline
        
        if (selection <= 0 || selection > static_cast<int>(keyFiles.size())) {
            return "";
        }
        
        // Read the selected key file
        try {
            std::ifstream keyFile(keyFiles[selection - 1]);
            if (!keyFile.is_open()) {
                std::cerr << "Failed to open key file: " << keyFiles[selection - 1] << std::endl;
                return "";
            }
            
            std::stringstream keyStream;
            keyStream << keyFile.rdbuf();
            return keyStream.str();
        } catch (const std::exception& e) {
            std::cerr << "Error reading key file: " << e.what() << std::endl;
            return "";
        }
    }
    
    // No match found
    return "";
}

// Verify that a private key matches a certificate
bool OpenSSLWrapper::verifyKeyMatchesCertificate(const String& privateKeyPEM, const String& certPEM) {
    // Parse private key
    BIO* keyBio = BIO_new_mem_buf(privateKeyPEM.c_str(), -1);
    EVP_PKEY* privKey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
    BIO_free(keyBio);
    
    if (!privKey) {
        return false;
    }
    
    // Parse certificate
    BIO* certBio = BIO_new_mem_buf(certPEM.c_str(), -1);
    X509* cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
    BIO_free(certBio);
    
    if (!cert) {
        EVP_PKEY_free(privKey);
        return false;
    }
    
    // Get public key from certificate
    EVP_PKEY* pubKey = X509_get_pubkey(cert);
    
    // Check if the public key in the certificate matches the private key
    bool result = false;
    if (pubKey) {
        // Note: EVP_PKEY_cmp is deprecated but still widely available
        result = (EVP_PKEY_cmp(pubKey, privKey) == 1);
        EVP_PKEY_free(pubKey);
    }
    
    EVP_PKEY_free(privKey);
    X509_free(cert);
    
    return result;
}