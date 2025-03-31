#include "../include/auth_system.h"

AuthenticationSystem::AuthenticationSystem(DatabaseManager& dbManager) : db(dbManager) {
}

bool AuthenticationSystem::registerUser(const String& username, const String& password, 
                                      const String& email, const String& role) {
    // Generate salt and hash password
    String salt = generateSalt();
    String passwordHash = hashPassword(password, salt);
    
    // Store hash with salt appended (in a real system, salt would be stored separately)
    String storedHash = passwordHash + ":" + salt;
    
    // Add user to database
    return db.addUser(username, storedHash, email, role);
}

bool AuthenticationSystem::login(const String& username, const String& password) {
    // Get stored password hash
    String storedHash = db.getUserPasswordHash(username);
    if (storedHash.empty()) {
        return false; // User not found
    }
    
    // Extract salt from stored hash
    size_t separatorPos = storedHash.find(':');
    if (separatorPos == String::npos) {
        return false; // Invalid hash format
    }
    
    String hash = storedHash.substr(0, separatorPos);
    String salt = storedHash.substr(separatorPos + 1);
    
    // Verify password
    String computedHash = hashPassword(password, salt);
    return (computedHash == hash);
}

String AuthenticationSystem::createSession(const String& username) {
    // Generate a random token
    std::vector<unsigned char> buffer(32);
    RAND_bytes(buffer.data(), buffer.size());
    
    // Convert to hex string
    std::stringstream ss;
    for (int i = 0; i < 32; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i];
    }
    
    String token = ss.str();
    
    // Store session
    activeSessions[token] = username;
    
    return token;
}

bool AuthenticationSystem::validateSession(const String& token) {
    // Check if token exists in active sessions
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
    // Combine password and salt
    String combined = password + salt;
    
    // Create SHA-256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, combined.c_str(), combined.length());
    SHA256_Final(hash, &sha256);
    
    // Convert to hex string
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
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
    
    // Use secure random number generator
    std::vector<unsigned char> buffer(length);
    RAND_bytes(buffer.data(), length);
    
    for (size_t i = 0; i < length; i++) {
        salt += alphanum[buffer[i] % (sizeof(alphanum) - 1)];
    }
    
    return salt;
} 