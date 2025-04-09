#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "common.h"
#include "socket_comm.h"
#include "auth_system.h"
#include "certificate_authority.h"
#include "database.h"
#include "../lib/nlohmann/json.hpp"

using json = nlohmann::json;

class ServerHandler {
public:
    ServerHandler(AuthenticationSystem& authSystem, 
                 CertificateAuthority& ca, 
                 DatabaseManager& dbManager);
    
    bool start(int port = 8080);
    void stop();
    
private:
    AuthenticationSystem& auth;
    CertificateAuthority& ca;
    DatabaseManager& db;
    ServerSocket serverSocket;
    bool running;
    
    void handleClient(SOCKET clientSocket);
    String processRequest(const String& request);
    json handleLogin(const json& payload);
    json handleRegister(const json& payload);
    json handleLogout(const json& payload, const String& token);
    json handleRequestCertificate(const json& payload, const String& token);
    json handleGetCertificates(const json& payload, const String& token);
    json handleRevokeCertificate(const json& payload, const String& token);
    json handleDownloadCertificate(const json& payload, const String& token);
    json handleValidateCertificate(const json& payload, const String& token);
}; 