#pragma once
#include "common.h"

class DatabaseManager {
public:
    DatabaseManager();
    ~DatabaseManager();
    
    bool initialize();
    
    bool executeQuery(const String& query);
    bool executeQueryWithParams(const String& query, const vector<String>& params);
    
    bool addUser(const String& username, const String& passwordHash, const String& email, const String& role = "user");
    bool authenticateUser(const String& username, const String& passwordHash);
    int getUserID(const String& username);
    String getUserPasswordHash(const String& username);
    String getUserRole(const String& username);
    
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
    
    CSRInfo getCSRInfo(int requestID);
    bool updateCSRStatus(int requestID, const String& status, int certificateID = -1);
    CertificateInfo getCertificateInfo(int certificateID);
    int getPendingCSRCount();
    
    bool logActivity(const String& action, int doneBy, int objectID, const String& details);
    
    vector<UserInfo> getUsers();
    vector<LogEntry> getLogs(const String& filter, int offset, int limit);
    vector<CSREntry> getPendingCSRs();
    vector<CertificateEntry> getAllCertificates();
    bool updateUserRole(int userID, const String& newRole);
    vector<CertificateEntry> getUserCertificates(int userID);
    
    vector<pair<String, String>> getRevokedCertificates();
    
private:
    sqlite3* db;
    bool createTables();
}; 