#pragma once
#include "common.h"
#include "database.h"
#include "openssl_wrapper.h"

class CertificateAuthority {
public:
    CertificateAuthority(DatabaseManager& dbManager, OpenSSLWrapper& sslWrapper);
    
    bool initialize(const String& configPath = DATA_DIR + "ca_config.json");
    
    // CSR operations
    int submitCSR(const String& csrData, const String& username);
    bool validateCSR(const String& csrData);
    
    // Certificate operations
    int issueCertificate(int requestID, int validityDays = 0);
    bool revokeCertificate(int certificateID, const String& reason, const String& username);
    bool validateCertificate(const String& certData);
    
    // CRL operations
    String generateCRL();
    
    // Utility functions
    int getPendingCSRCount();
    
private:
    DatabaseManager& db;
    OpenSSLWrapper& ssl;
    
    // CA configuration
    String caPrivateKey;
    String caCertificate;
    String caSubject;
    int defaultValidityDays;
    String caPassword;        // Password for PKCS#12 file
    bool usePKCS12;           // Whether to use PKCS#12 format
    
    bool loadCAKeys(const String& configPath);
    bool createSelfSignedCA();
    bool storeCAKeysAsPKCS12();
    bool loadCAKeysFromPKCS12(const String& p12Path);
}; 