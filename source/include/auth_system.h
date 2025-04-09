#pragma once
#include "common.h"
#include "database.h"

class AuthenticationSystem {
public:
    AuthenticationSystem(DatabaseManager& dbManager);
    bool registerUser(const String& username, const String& password, const String& email, const String& role = "user");
    bool login(const String& username, const String& password);
    String createSession(const String& username);
    bool validateSession(const String& token);
    String getUsernameFromToken(const String& token);
    bool terminateSession(const String& token);
    String hashPassword(const String& password, const String& salt);
    String generateSalt(size_t length = 16);
    
private:
    DatabaseManager& db;
    map<String, String> activeSessions; 
}; 