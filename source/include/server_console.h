#pragma once
#include "common.h"
#include "auth_system.h"
#include "certificate_authority.h"
#include "database.h"

class ServerConsole {
public:
    ServerConsole(AuthenticationSystem& authSystem, 
                 CertificateAuthority& ca, 
                 DatabaseManager& dbManager);
    
    void run();
    
private:
    AuthenticationSystem& auth;
    CertificateAuthority& ca;
    DatabaseManager& db;
    bool running;
    
    void displayMainMenu();
    void viewLogs();
    void manageUsers();
    void certificateOperations();
    
    void listCertificates();
    void viewCertificateDetails();
    void approveCertificateRequest();
    void revokeCertificate();

    void displayServerStatus();
    String getInput(const String& prompt);
    int getIntInput(const String& prompt);
    void waitForEnter();
}; 