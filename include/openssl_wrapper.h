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
                  const String& caCertPEM, int validityDays, bool isCA = false);
    bool verifyCertificate(const String& certPEM, const String& caCertPEM);
    
    // CRL operations
    String generateCRL(const std::vector<std::pair<String, String>>& revokedCerts,
                      const String& caKeyPEM, const String& caCertPEM);
    
    // PKCS#12 operations
    String createPKCS12(const String& privateKeyPEM, const String& certificatePEM, 
                      const String& password, const String& friendlyName = "");
    std::pair<String, String> extractFromPKCS12(const String& pkcs12Data, const String& password);
    
    // Certificate validation methods
    bool validateCertificateChain(const std::vector<String>& certChain);
    bool checkCertificateRevocation(const String& certPEM, const String& crlPEM);
    
    // Certificate and key utilities
    String extractSubjectFromCertificate(const String& certPEM);
    String extractCNFromSubject(const String& subject);
    String findMatchingPrivateKey(const String& certificatePEM, const String& directory = ".",
                                 bool interactiveSelection = false);
    bool verifyKeyMatchesCertificate(const String& privateKeyPEM, const String& certPEM);
    
    // Utility functions
    String bioToString(BIO* bio);
    long generateSerialNumber();
    
private:
    void parseAndAddSubject(X509_NAME* name, const String& subject);
    void addExtensions(X509* cert, X509* caCert);
    void addCAExtensions(X509* cert, X509* caCert);
}; 