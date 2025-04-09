#include "../include/auth_system.h"

AuthenticationSystem::AuthenticationSystem(DatabaseManager& dbManager) : db(dbManager) {
}

bool AuthenticationSystem::registerUser(const String& username, const String& password, 
                                      const String& email, const String& role) {
    String salt = generateSalt();
    String passwordHash = hashPassword(password, salt);
    
    String storedHash = passwordHash + ":" + salt;
    return db.addUser(username, storedHash, email, role);
}

bool AuthenticationSystem::login(const String& username, const String& password) {
    String storedHash = db.getUserPasswordHash(username);
    if (storedHash.empty()) {
        return false; 
    }
    size_t separatorPos = storedHash.find(':');
    if (separatorPos == String::npos) {
        return false;
    }
    
    String hash = storedHash.substr(0, separatorPos);
    String salt = storedHash.substr(separatorPos + 1);
    
    String computedHash = hashPassword(password, salt);
    return (computedHash == hash);
}

String AuthenticationSystem::createSession(const String& username) {
    vector<unsigned char> buffer(32);
    RAND_bytes(buffer.data(), buffer.size());
    
    stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << hex << setw(2) << setfill('0') << (int)buffer[i];
    }
    
    String token = ss.str();
    
    activeSessions[token] = username;
    
    return token;
}

bool AuthenticationSystem::validateSession(const String& token) {
    return activeSessions.find(token) != activeSessions.end();
}

String AuthenticationSystem::getUsernameFromToken(const String& token) {
    auto it = activeSessions.find(token);
    if (it != activeSessions.end()) {
        return it->second;
    }
    return "";
}

bool AuthenticationSystem::terminateSession(const String& token) {
    auto it = activeSessions.find(token);
    if (it != activeSessions.end()) {
        activeSessions.erase(it);
        return true;
    }
    return false;
}

String AuthenticationSystem::hashPassword(const String& password, const String& salt) {
    String combined = password + salt;
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, combined.c_str(), combined.length());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    
    return ss.str();
}

String AuthenticationSystem::generateSalt(size_t length) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    
    String salt;
    salt.reserve(length);
    vector<unsigned char> buffer(length);
    RAND_bytes(buffer.data(), length);
    
    for (size_t i = 0; i < length; i++) {
        salt += alphanum[buffer[i] % (sizeof(alphanum) - 1)];
    }
    
    return salt;
} 