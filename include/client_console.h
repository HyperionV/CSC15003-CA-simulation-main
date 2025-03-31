#pragma once
#include "common.h"
#include "openssl_wrapper.h"

class ClientConsole {
public:
    ClientConsole(OpenSSLWrapper& sslWrapper);
    
    void run();
    
private:
    OpenSSLWrapper& ssl;
    bool running;
    bool loggedIn;
    String sessionToken;
    String currentUsername;
    
    // Server communication
    bool connectToServer();
    String sendRequest(const String& action, const std::map<String, String>& payload);
    String simulateServerResponse(const String& request);
    
    // Menu functions
    void displayMainMenu();
    void displayAuthMenu();
    void displayCertificateMenu();
    
    // Authentication functions
    bool login();
    bool registerUser();
    void logout();
    
    // Certificate functions
    void requestCertificate();
    void viewCertificates();
    void revokeCertificate();
    void downloadCertificate();
    void validateCertificate();
    
    // Helper functions
    String getInput(const String& prompt);
    int getIntInput(const String& prompt);
    void waitForEnter();
    void displayMessage(const String& message);
}; 