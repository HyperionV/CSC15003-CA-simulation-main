#pragma once
#include "common.h"

class OpenSSLWrapper {
public:
    OpenSSLWrapper();
    ~OpenSSLWrapper();
    
    // Key generation
    std::pair<String, String> generateRSAKeyPair(int keySize = 2048);
    
    // CSR operations
    String generateCSR(const String& privateKeyPEM, const String& subjectName);
    bool verifyCSR(const String& csrPEM);
    
    // Certificate operations
    String signCSR(const String& csrPEM, const String& caKeyPEM,
                  const String& caCertPEM, int validityDays);
    bool verifyCertificate(const String& certPEM, const String& caCertPEM);
    
    // CRL operations
    String generateCRL(const std::vector<std::pair<String, String>>& revokedCerts,
                      const String& caKeyPEM, const String& caCertPEM);
    
    // Utility functions
    String bioToString(BIO* bio);
    long generateSerialNumber();
    
private:
    void parseAndAddSubject(X509_NAME* name, const String& subject);
    void addExtensions(X509* cert, X509* caCert);
}; 