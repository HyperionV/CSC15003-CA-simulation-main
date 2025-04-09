#pragma once
#include "common.h"

class OpenSSLWrapper {
public:
    OpenSSLWrapper();
    ~OpenSSLWrapper();
    
    pair<String, String> generateRSAKeyPair(int keySize = 2048);
    String generateCSR(const String& privateKeyPEM, const String& subjectName);
    bool verifyCSR(const String& csrPEM);
    String signCSR(const String& csrPEM, const String& caKeyPEM,
                  const String& caCertPEM, int validityDays, bool isCA = false);
    bool verifyCertificate(const String& certPEM, const String& caCertPEM);
    String generateCRL(const vector<pair<String, String>>& revokedCerts,
                      const String& caKeyPEM, const String& caCertPEM);
String createPKCS12(const String& privateKeyPEM, const String& certificatePEM, 
                      const String& password, const String& friendlyName = "");
    pair<String, String> extractFromPKCS12(const String& pkcs12Data, const String& password);
    bool validateCertificateChain(const vector<String>& certChain);
    bool checkCertificateRevocation(const String& certPEM, const String& crlPEM);
    String extractSubjectFromCertificate(const String& certPEM);
    String extractCNFromSubject(const String& subject);
    String findMatchingPrivateKey(const String& certificatePEM, const String& directory = ".",
                                 bool interactiveSelection = false);
    bool verifyKeyMatchesCertificate(const String& privateKeyPEM, const String& certPEM);
    String bioToString(BIO* bio);
    long generateSerialNumber();
    
private:
    void parseAndAddSubject(X509_NAME* name, const String& subject);
    void addExtensions(X509* cert, X509* caCert);
    void addCAExtensions(X509* cert, X509* caCert);
}; 