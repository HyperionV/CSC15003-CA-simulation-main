#include "../include/openssl_wrapper.h"
#include <openssl/pkcs12.h>

OpenSSLWrapper::OpenSSLWrapper() {
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

OpenSSLWrapper::~OpenSSLWrapper() {
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

pair<String, String> OpenSSLWrapper::generateRSAKeyPair(int keySize) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, keySize, bn, nullptr);
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        BN_free(bn);
        return {"", ""};
    }
    BN_free(bn);
    BIO* privateBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(privateBio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    BIO* publicBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(publicBio, pkey);
    String privateKey = bioToString(privateBio);
    String publicKey = bioToString(publicBio);
    BIO_free(privateBio);
    BIO_free(publicBio);
    EVP_PKEY_free(pkey);
    
    return {privateKey, publicKey};
}

String OpenSSLWrapper::generateCSR(const String& privateKeyPEM, const String& subjectName) {
    BIO* keyBio = BIO_new_mem_buf(privateKeyPEM.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
    BIO_free(keyBio);
    
    if (!pkey) {
        cerr << "Failed to parse private key" << endl;
        return "";
    }

    X509_REQ* req = X509_REQ_new();
    X509_REQ_set_pubkey(req, pkey);
    X509_NAME* name = X509_REQ_get_subject_name(req);
    parseAndAddSubject(name, subjectName);
    X509_REQ_sign(req, pkey, EVP_sha256());
    BIO* csrBio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(csrBio, req);
    String csrPEM = bioToString(csrBio);
    BIO_free(csrBio);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    return csrPEM;
}

bool OpenSSLWrapper::verifyCSR(const String& csrPEM) {
    BIO* bio = BIO_new_mem_buf(csrPEM.c_str(), -1);
    X509_REQ* req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!req) {
        cerr << "Failed to parse CSR" << endl;
        return false;
    }
    
    EVP_PKEY* pkey = X509_REQ_get_pubkey(req);
    int result = X509_REQ_verify(req, pkey);
    EVP_PKEY_free(pkey);
    X509_REQ_free(req);
    return (result > 0);
}

String OpenSSLWrapper::signCSR(const String& csrPEM, const String& caKeyPEM,
                              const String& caCertPEM, int validityDays, bool isCA) {
    BIO* csrBio = BIO_new_mem_buf(csrPEM.c_str(), -1);
    X509_REQ* req = PEM_read_bio_X509_REQ(csrBio, nullptr, nullptr, nullptr);
    BIO_free(csrBio);
    if (!req) {
        cerr << "Failed to parse CSR" << endl;
        return "";
    }
    BIO* caKeyBio = BIO_new_mem_buf(caKeyPEM.c_str(), -1);
    EVP_PKEY* caKey = PEM_read_bio_PrivateKey(caKeyBio, nullptr, nullptr, nullptr);
    BIO_free(caKeyBio);
    
    if (!caKey) {
        cerr << "Failed to parse CA private key" << endl;
        X509_REQ_free(req);
        return "";
    }
    X509* cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), generateSerialNumber());
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 60 * 60 * 24 * validityDays);
    X509_set_subject_name(cert, X509_REQ_get_subject_name(req));
    X509* caCert = nullptr;
    if (!caCertPEM.empty()) {
        BIO* caCertBio = BIO_new_mem_buf(caCertPEM.c_str(), -1);
        caCert = PEM_read_bio_X509(caCertBio, nullptr, nullptr, nullptr);
        BIO_free(caCertBio);
        
        if (!caCert) {
            cerr << "Failed to parse CA certificate" << endl;
            EVP_PKEY_free(caKey);
            X509_REQ_free(req);
            X509_free(cert);
            return "";
        }
        X509_set_issuer_name(cert, X509_get_subject_name(caCert));
    } else {
        X509_set_issuer_name(cert, X509_REQ_get_subject_name(req));
    }

    EVP_PKEY* reqPubKey = X509_REQ_get_pubkey(req);
    X509_set_pubkey(cert, reqPubKey);
    EVP_PKEY_free(reqPubKey);

    if (isCA) {
        if (caCert) {
            addCAExtensions(cert, caCert);
        } else {
            addCAExtensions(cert, cert);
        }
    } else {
        if (caCert) {
        addExtensions(cert, caCert);
        } else {
            addExtensions(cert, cert);
        }
    }
    X509_sign(cert, caKey, EVP_sha256());
    BIO* certBio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(certBio, cert);
    String certPEM = bioToString(certBio);
    BIO_free(certBio);
    X509_free(cert);
    if (caCert) X509_free(caCert);
    EVP_PKEY_free(caKey);
    X509_REQ_free(req);
    
    return certPEM;
}

bool OpenSSLWrapper::verifyCertificate(const String& certPEM, const String& caCertPEM) {
    BIO* certBio = BIO_new_mem_buf(certPEM.c_str(), -1);
    X509* cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
    BIO_free(certBio);
    
    if (!cert) {
        cerr << "Failed to parse certificate" << endl;
        return false;
    }
    BIO* caCertBio = BIO_new_mem_buf(caCertPEM.c_str(), -1);
    X509* caCert = PEM_read_bio_X509(caCertBio, nullptr, nullptr, nullptr);
    BIO_free(caCertBio);
    
    if (!caCert) {
        cerr << "Failed to parse CA certificate" << endl;
        X509_free(cert);
        return false;
    }
    time_t currentTime = time(nullptr);
    const ASN1_TIME* notBefore = X509_get_notBefore(cert);
    const ASN1_TIME* notAfter = X509_get_notAfter(cert);
    
    bool validTime = true;
    int pday = 0, psec = 0;
    if (!ASN1_TIME_diff(&pday, &psec, NULL, notBefore) || (pday > 0 || psec > 0)) {
        cerr << "Certificate is not yet valid" << endl;
        validTime = false;
    }
    
    pday = 0;
    psec = 0;
    if (!ASN1_TIME_diff(&pday, &psec, NULL, notAfter) || (pday < 0 || psec < 0)) {
        cerr << "Certificate has expired" << endl;
        validTime = false;
    }
    
    if (!validTime) {
        X509_free(cert);
        X509_free(caCert);
        return false;
    }
    X509_STORE* store = X509_STORE_new();
    X509_STORE_add_cert(store, caCert);
    X509_STORE_set_flags(store, X509_V_FLAG_CHECK_SS_SIGNATURE);
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, nullptr);
    int result = X509_verify_cert(ctx);
    if (result <= 0) {
        int error = X509_STORE_CTX_get_error(ctx);
        cerr << "Certificate verification failed: " 
                  << X509_verify_cert_error_string(error) << endl;
    }
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);
    X509_free(caCert);
    
    return (result > 0);
}

bool OpenSSLWrapper::validateCertificateChain(const vector<String>& certChain) {
    if (certChain.empty()) {
        return false;
    }
    X509_STORE* store = X509_STORE_new();
    vector<X509*> certs;
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
    for (size_t i = 1; i < certs.size(); i++) {
        X509_STORE_add_cert(store, certs[i]);
    }
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, certs[0], nullptr);
    int result = X509_verify_cert(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    for (auto cert : certs) {
        X509_free(cert);
    }
    
    return (result > 0);
}

bool OpenSSLWrapper::checkCertificateRevocation(const String& certPEM, const String& crlPEM) {
    BIO* certBio = BIO_new_mem_buf(certPEM.c_str(), -1);
    X509* cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
    BIO_free(certBio);
    
    if (!cert) {
        return false;
    }
    BIO* crlBio = BIO_new_mem_buf(crlPEM.c_str(), -1);
    X509_CRL* crl = PEM_read_bio_X509_CRL(crlBio, nullptr, nullptr, nullptr);
    BIO_free(crlBio);
    
    if (!crl) {
        X509_free(cert);
        return false;
    }
    int idx = X509_CRL_get_ext_by_NID(crl, NID_crl_number, -1);
    if (idx == -1) {
        X509_free(cert);
        X509_CRL_free(crl);
        return false;
    }
    ASN1_INTEGER* cert_serial = X509_get_serialNumber(cert);
    bool revoked = false;
    for (int i = 0; i < sk_X509_REVOKED_num(X509_CRL_get_REVOKED(crl)); i++) {
        X509_REVOKED* rev = sk_X509_REVOKED_value(X509_CRL_get_REVOKED(crl), i);
        const ASN1_INTEGER* rev_serial = X509_REVOKED_get0_serialNumber(rev);
        if (ASN1_INTEGER_cmp(rev_serial, cert_serial) == 0) {
            revoked = true;
            break;
        }
    }
    X509_free(cert);
    X509_CRL_free(crl);
    
    return revoked;
}


String OpenSSLWrapper::generateCRL(const vector<pair<String, String>>& revokedCerts,
                                 const String& caKeyPEM, const String& caCertPEM) {
    BIO* caKeyBio = BIO_new_mem_buf(caKeyPEM.c_str(), -1);
    EVP_PKEY* caKey = PEM_read_bio_PrivateKey(caKeyBio, nullptr, nullptr, nullptr);
    BIO_free(caKeyBio);
    
    if (!caKey) {
        cerr << "Failed to parse CA private key" << endl;
        return "";
    }
    
    BIO* caCertBio = BIO_new_mem_buf(caCertPEM.c_str(), -1);
    X509* caCert = PEM_read_bio_X509(caCertBio, nullptr, nullptr, nullptr);
    BIO_free(caCertBio);
    
    if (!caCert) {
        cerr << "Failed to parse CA certificate" << endl;
        EVP_PKEY_free(caKey);
        return "";
    }
    
    X509_CRL* crl = X509_CRL_new();
    
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(caCert));
    
    X509_CRL_set_lastUpdate(crl, X509_get_notBefore(caCert)); 
    X509_CRL_set_nextUpdate(crl, X509_get_notAfter(caCert));
    
    for (const auto& entry : revokedCerts) {
        const String& serialNumber = entry.first;
        const String& reason = entry.second;
        
        BIGNUM* bn = nullptr;
        BN_hex2bn(&bn, serialNumber.c_str());
        
        X509_REVOKED* revoked = X509_REVOKED_new();
        
        ASN1_INTEGER* serialASN1 = BN_to_ASN1_INTEGER(bn, nullptr);
        X509_REVOKED_set_serialNumber(revoked, serialASN1);
        ASN1_INTEGER_free(serialASN1);
        BN_free(bn);
        
        ASN1_TIME* revocationTime = ASN1_TIME_new();
        X509_gmtime_adj(revocationTime, 0);
        X509_REVOKED_set_revocationDate(revoked, revocationTime);
        ASN1_TIME_free(revocationTime);
        
        if (!reason.empty()) {
            const char* reasonStr = reason.c_str();
            
            int reasonCode = CRL_REASON_UNSPECIFIED;
            if (reason == "keyCompromise") reasonCode = CRL_REASON_KEY_COMPROMISE;
            else if (reason == "caCompromise") reasonCode = CRL_REASON_CA_COMPROMISE;
            else if (reason == "affiliationChanged") reasonCode = CRL_REASON_AFFILIATION_CHANGED;
            else if (reason == "superseded") reasonCode = CRL_REASON_SUPERSEDED;
            else if (reason == "cessationOfOperation") reasonCode = CRL_REASON_CESSATION_OF_OPERATION;
            else if (reason == "certificateHold") reasonCode = CRL_REASON_CERTIFICATE_HOLD;
            
            ASN1_ENUMERATED* reasonEnum = ASN1_ENUMERATED_new();
            ASN1_ENUMERATED_set(reasonEnum, reasonCode);
            
            X509_EXTENSION* ext = X509_EXTENSION_create_by_NID(nullptr, NID_crl_reason, 
                                                              0, reasonEnum);
            X509_REVOKED_add_ext(revoked, ext, -1);
            
            X509_EXTENSION_free(ext);
            ASN1_ENUMERATED_free(reasonEnum);
        }
        
        X509_CRL_add0_revoked(crl, revoked);
    }
    
    X509_CRL_sort(crl);
    
    X509_CRL_sign(crl, caKey, EVP_sha256());
    
    BIO* crlBio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_CRL(crlBio, crl);
    String crlPEM = bioToString(crlBio);
    
    BIO_free(crlBio);
    X509_CRL_free(crl);
    X509_free(caCert);
    EVP_PKEY_free(caKey);
    
    return crlPEM;
}

String OpenSSLWrapper::bioToString(BIO* bio) {
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    String result(mem->data, mem->length);
    return result;
}

long OpenSSLWrapper::generateSerialNumber() {
    vector<unsigned char> buffer(8);
    RAND_bytes(buffer.data(), buffer.size());
    
    long serialNumber = 0;
    for (int i = 0; i < 8; i++) {
        serialNumber = (serialNumber << 8) | buffer[i];
    }
    return abs(serialNumber);
}

void OpenSSLWrapper::parseAndAddSubject(X509_NAME* name, const String& subject) {
    istringstream ss(subject);
    String token;
    
    while (getline(ss, token, ',')) {
        size_t pos = token.find('=');
        if (pos != String::npos) {
            String field = token.substr(0, pos);
            String value = token.substr(pos + 1);
            X509_NAME_add_entry_by_txt(name, field.c_str(), MBSTRING_ASC, 
                                      (unsigned char*)value.c_str(), -1, -1, 0);
        }
    }
}

void OpenSSLWrapper::addExtensions(X509* cert, X509* caCert) {
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, caCert, cert, nullptr, nullptr, 0);
    
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                                             NID_basic_constraints, "critical,CA:FALSE");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                             NID_key_usage, "critical,digitalSignature,keyEncipherment");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                             NID_ext_key_usage, "serverAuth,clientAuth");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                             NID_subject_key_identifier, "hash");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                             NID_authority_key_identifier, "keyid:always,issuer");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
}

void OpenSSLWrapper::addCAExtensions(X509* cert, X509* caCert) {
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, caCert, cert, nullptr, nullptr, 0);
    
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                                             NID_basic_constraints, "critical,CA:TRUE");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                             NID_key_usage, "critical,keyCertSign,cRLSign");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    
    ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                             NID_subject_key_identifier, "hash");
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    
    if (caCert != cert) {
        ext = X509V3_EXT_conf_nid(nullptr, &ctx, 
                                 NID_authority_key_identifier, "keyid:always,issuer");
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }
}

String OpenSSLWrapper::createPKCS12(const String& privateKeyPEM, const String& certificatePEM, 
                                   const String& password, const String& friendlyName) {
    BIO* keyBio = BIO_new_mem_buf(privateKeyPEM.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
    BIO_free(keyBio);
    
    if (!pkey) {
        cerr << "Failed to parse private key for PKCS#12" << endl;
        return "";
    }
    
    BIO* certBio = BIO_new_mem_buf(certificatePEM.c_str(), -1);
    X509* cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
    BIO_free(certBio);
    
    if (!cert) {
        cerr << "Failed to parse certificate for PKCS#12" << endl;
        EVP_PKEY_free(pkey);
        return "";
    }
    
    PKCS12* p12 = PKCS12_create(
        password.c_str(),   
        friendlyName.empty() ? "Certificate" : friendlyName.c_str(), 
        pkey, cert, nullptr, 0, 0, 0, 0, 0                   
    );
    
    if (!p12) {
        cerr << "Failed to create PKCS#12 structure" << endl;
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return "";
    }
    BIO* p12Bio = BIO_new(BIO_s_mem());
    i2d_PKCS12_bio(p12Bio, p12);
    BUF_MEM* bptr;
    BIO_get_mem_ptr(p12Bio, &bptr);
    String result(bptr->data, bptr->length);
    PKCS12_free(p12);
    BIO_free(p12Bio);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    
    return result;
}

pair<String, String> OpenSSLWrapper::extractFromPKCS12(const String& pkcs12Data, const String& password) {
    BIO* p12Bio = BIO_new_mem_buf(pkcs12Data.c_str(), pkcs12Data.size());
    PKCS12* p12 = d2i_PKCS12_bio(p12Bio, nullptr);
    BIO_free(p12Bio);
    
    if (!p12) {
        cerr << "Failed to parse PKCS#12 data" << endl;
        return {"", ""};
    }
    EVP_PKEY* pkey = nullptr;
    X509* cert = nullptr;
    STACK_OF(X509)* ca = nullptr;
    
    if (!PKCS12_parse(p12, password.c_str(), &pkey, &cert, &ca)) {
        cerr << "Failed to parse PKCS#12 with provided password" << endl;
        PKCS12_free(p12);
        return {"", ""};
    }
    BIO* keyBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(keyBio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    String privateKey = bioToString(keyBio);
    BIO_free(keyBio);
    BIO* certBio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(certBio, cert);
    String certificate = bioToString(certBio);
    BIO_free(certBio);
    PKCS12_free(p12);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    if (ca) sk_X509_pop_free(ca, X509_free);
    
    return {privateKey, certificate};
}

String OpenSSLWrapper::extractSubjectFromCertificate(const String& certPEM) {
    BIO* certBio = BIO_new_mem_buf(certPEM.c_str(), -1);
    X509* cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
    BIO_free(certBio);
    
    if (!cert) {
        cerr << "Failed to parse certificate for subject extraction" << endl;
        return "";
    }

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

String OpenSSLWrapper::extractCNFromSubject(const String& subject) {
    size_t cnPos = subject.find("CN=");
    if (cnPos == String::npos) {
        return "";
    }
    
    cnPos += 3; 
    size_t cnEnd = subject.find(',', cnPos);
    
    if (cnEnd != String::npos) {
        return subject.substr(cnPos, cnEnd - cnPos);
    } else {
        return subject.substr(cnPos);
    }
}

String OpenSSLWrapper::findMatchingPrivateKey(const String& certificatePEM, const String& directory,
                                            bool interactiveSelection) {
    String subject = extractSubjectFromCertificate(certificatePEM);
    String commonName = extractCNFromSubject(subject);
    
    if (subject.empty()) {
        cerr << "Could not extract subject from certificate" << endl;
        return "";
    }
    vector<String> keyFiles;
    try {
        for (const auto& entry : filesystem::directory_iterator(directory)) {
            if (entry.is_regular_file() && entry.path().extension() == ".key") {
                keyFiles.push_back(entry.path().string());
            }
        }
    } catch (const exception& e) {
        cerr << "Error reading directory for key files: " << e.what() << endl;
        return "";
    }
    
    if (keyFiles.empty()) {
        cerr << "No private key files found in the directory: " << directory << endl;
        return "";
    }
    
    if (!commonName.empty()) {
        for (const auto& keyPath : keyFiles) {
            String fileName = filesystem::path(keyPath).stem().string();
            if (fileName.find(commonName) != String::npos || commonName.find(fileName) != String::npos) {
                try {
                    ifstream keyFile(keyPath);
                    if (!keyFile.is_open()) continue;
                    
                    stringstream keyStream;
                    keyStream << keyFile.rdbuf();
                    String keyPEM = keyStream.str();
                    
                    if (verifyKeyMatchesCertificate(keyPEM, certificatePEM)) {
                        return keyPEM;
                    }
                } catch (...) {
                    continue;
                }
            }
        }
    }
    for (const auto& keyPath : keyFiles) {
        try {
            ifstream keyFile(keyPath);
            if (!keyFile.is_open()) continue;
            
            stringstream keyStream;
            keyStream << keyFile.rdbuf();
            String keyPEM = keyStream.str();
            if (verifyKeyMatchesCertificate(keyPEM, certificatePEM)) {
                return keyPEM;
            }
        } catch (...) {
            continue;
        }
    }
        if (interactiveSelection) {
        cout << "No matching private key found automatically." << endl;
        cout << "Available private key files:" << endl;
        cout << "---------------------------" << endl;
        
        for (size_t i = 0; i < keyFiles.size(); i++) {
            cout << i + 1 << ". " << filesystem::path(keyFiles[i]).filename().string() << endl;
        }
        cout << "---------------------------" << endl;
        
        cout << "Select a private key file to use (0 to cancel): ";
        int selection;
        cin >> selection;
        cin.ignore(); 
        
        if (selection <= 0 || selection > static_cast<int>(keyFiles.size())) {
            return "";
        }
                try {
            ifstream keyFile(keyFiles[selection - 1]);
            if (!keyFile.is_open()) {
                cerr << "Failed to open key file: " << keyFiles[selection - 1] << endl;
                return "";
            }
            
            stringstream keyStream;
            keyStream << keyFile.rdbuf();
            return keyStream.str();
        } catch (const exception& e) {
            cerr << "Error reading key file: " << e.what() << endl;
            return "";
        }
    }
    return "";
}

bool OpenSSLWrapper::verifyKeyMatchesCertificate(const String& privateKeyPEM, const String& certPEM) {
    BIO* keyBio = BIO_new_mem_buf(privateKeyPEM.c_str(), -1);
    EVP_PKEY* privKey = PEM_read_bio_PrivateKey(keyBio, nullptr, nullptr, nullptr);
    BIO_free(keyBio);
    
    if (!privKey) {
        return false;
    }
    BIO* certBio = BIO_new_mem_buf(certPEM.c_str(), -1);
    X509* cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
    BIO_free(certBio);
    
    if (!cert) {
        EVP_PKEY_free(privKey);
        return false;
    }
    
    EVP_PKEY* pubKey = X509_get_pubkey(cert);

    bool result = false;
    if (pubKey) {
        result = (EVP_PKEY_cmp(pubKey, privKey) == 1);
        EVP_PKEY_free(pubKey);
    }
    
    EVP_PKEY_free(privKey);
    X509_free(cert);
    
    return result;
}