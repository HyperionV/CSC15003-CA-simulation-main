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
    bool loggedIn;
    bool running;
    String sessionToken;
    String currentUsername;
    OpenSSLWrapper ssl;
    
    void showMainMenu();
    void handleMainMenuChoice(int choice);
    void displayMessage(const String& message);
    void displayAuthMenu();
    void displayCertificateMenu();
    
    bool registerUser();
    bool login();
    void logout();
    void requestCertificate();
    void viewCertificates();
    void downloadCertificate();
    void revokeCertificate();
    void validateCertificate();
    
    String getInput(const String& prompt);
    int getIntInput(const String& prompt);
    String maskInput(const String& prompt);
    void waitForEnter();
    String sendRequest(const String& action, const map<String, String>& payload);
    String simulateServerResponse(const String& request);
    String findMatchingPrivateKey(const String& certificateData, const String& subjectName = "");
}; 