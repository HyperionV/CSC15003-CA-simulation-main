#pragma once
#include "common.h"

class DatabaseManager {
public:
    DatabaseManager();
    ~DatabaseManager();
    
    bool initialize();
    
    // Basic database operations
    bool executeQuery(const String& query);
    bool executeQueryWithParams(const String& query, const std::vector<String>& params);
    
    // User management
    bool addUser(const String& username, const String& passwordHash, const String& email, const String& role = "user");
    bool authenticateUser(const String& username, const String& passwordHash);
    int getUserID(const String& username);
    String getUserPasswordHash(const String& username);
    String getUserRole(const String& username);
    
    // Certificate operations
    int storeCSR(int userID, const String& publicKey, const String& csrData);
    bool storeCertificate(const String& serialNumber, int version,
                          const String& signatureAlgorithm,
                          const String& issuerName, const String& subjectName,
                          time_t validFrom, time_t validTo,
                          const String& publicKey, int ownerID,
                          const String& certificateData);
    bool revokeCertificate(int certificateID, const String& serialNumber, 
                           const String& reason, int revokedBy);
    String getCertificateData(int certificateID);
    
    // CSR information structures
    struct CSRInfo {
        String csrData;
        String publicKey;
        int subjectID;
        String status;
    };

    struct CertificateInfo {
        String serialNumber;
        int ownerID;
    };
    
    // Additional structures for the server console
    struct UserInfo {
        int userID;
        String username;
        String email;
        String role;
    };

    struct LogEntry {
        int logID;
        String action;
        int doneBy;
        int objectID;
        String details;
        String timestamp;
    };

    struct CSREntry {
        int requestID;
        String subjectName;
        String requestedAt;
    };

    struct CertificateEntry {
        int certificateID;
        String serialNumber;
        String subjectName;
        String status;
        String validTo;
    };
    
    // CSR and Certificate retrieval
    CSRInfo getCSRInfo(int requestID);
    bool updateCSRStatus(int requestID, const String& status, int certificateID = -1);
    CertificateInfo getCertificateInfo(int certificateID);
    int getPendingCSRCount();
    
    // Log operations
    bool logActivity(const String& action, int doneBy, int objectID, const String& details);
    
    // Additional methods for the server console
    std::vector<UserInfo> getUsers();
    std::vector<LogEntry> getLogs(const String& filter, int offset, int limit);
    std::vector<CSREntry> getPendingCSRs();
    std::vector<CertificateEntry> getAllCertificates();
    bool updateUserRole(int userID, const String& newRole);
    std::vector<CertificateEntry> getUserCertificates(int userID);
    
    // Revoked certificates methods
    std::vector<std::pair<String, String>> getRevokedCertificates();
    
private:
    sqlite3* db;
    bool createTables();
}; 