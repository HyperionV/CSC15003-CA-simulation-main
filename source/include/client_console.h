#pragma once
#include "common.h"
#include "socket_comm.h"
#include "openssl_wrapper.h"

class ClientConsole {
public:
    ClientConsole();
    ClientConsole(OpenSSLWrapper& sslWrapper);
    
    void run();
    
private:
    // Session state
    bool loggedIn;
    bool running;
    String sessionToken;
    String currentUsername;
    OpenSSLWrapper ssl;
    
    // UI methods
    void showMainMenu();
    void handleMainMenuChoice(int choice);
    void displayMessage(const String& message);
    void displayAuthMenu();
    void displayCertificateMenu();
    
    // Menu actions
    bool registerUser();
    bool login();
    void logout();
    void requestCertificate();
    void viewCertificates();
    void downloadCertificate();
    void revokeCertificate();
    void validateCertificate();
    
    // Helper methods
    String getInput(const String& prompt);
    int getIntInput(const String& prompt);
    String maskInput(const String& prompt);
    void waitForEnter();
    String sendRequest(const String& action, const std::map<String, String>& payload);
    String simulateServerResponse(const String& request);
    
    // PKCS#12 helper methods
    String findMatchingPrivateKey(const String& certificateData, const String& subjectName = "");
}; 