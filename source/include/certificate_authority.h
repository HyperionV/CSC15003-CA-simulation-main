#pragma once
#include "common.h"
#include "database.h"
#include "openssl_wrapper.h"

class CertificateAuthority {
public:
    CertificateAuthority(DatabaseManager& dbManager, OpenSSLWrapper& sslWrapper);
    
    bool initialize(const String& configPath = DATA_DIR + "ca_config.json");
    
    int submitCSR(const String& csrData, const String& username);
    bool validateCSR(const String& csrData);
    
    int issueCertificate(int requestID, int validityDays = 0);
    bool revokeCertificate(int certificateID, const String& reason, const String& username);
    bool validateCertificate(const String& certData);
    
    String generateCRL();
    
    int getPendingCSRCount();
    
private:
    DatabaseManager& db;
    OpenSSLWrapper& ssl;
    
    String caPrivateKey;
    String caCertificate;
    String caSubject;
    int defaultValidityDays;
    String caPassword;        
    bool usePKCS12;           
    
    bool loadCAKeys(const String& configPath);
    bool createSelfSignedCA();
    bool storeCAKeysAsPKCS12();
    bool loadCAKeysFromPKCS12(const String& p12Path);
}; 