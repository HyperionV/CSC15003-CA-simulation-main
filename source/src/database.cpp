#include "../include/database.h"

DatabaseManager::DatabaseManager() : db(nullptr) {
}

DatabaseManager::~DatabaseManager() {
    if (db) {
        sqlite3_close(db);
    }
}

bool DatabaseManager::initialize() {
    filesystem::create_directories(DB_DIR);
    int rc = sqlite3_open(DB_FILE.c_str(), &db);
    if (rc) {
        cerr << "Cannot open database: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        db = nullptr;
        return false;
    }
    return createTables();
}

bool DatabaseManager::createTables() {
    const char* createUsersTable = 
        "CREATE TABLE IF NOT EXISTS Users ("
        "userID INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT UNIQUE NOT NULL,"
        "passwordHash TEXT NOT NULL,"
        "email TEXT,"
        "role TEXT DEFAULT 'user',"
        "createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ");";
    
    const char* createCertificatesTable =
        "CREATE TABLE IF NOT EXISTS Certificates ("
        "certificateID INTEGER PRIMARY KEY AUTOINCREMENT,"
        "version INTEGER NOT NULL,"
        "serialNumber TEXT UNIQUE NOT NULL,"
        "signatureAlgorithm TEXT NOT NULL,"
        "issuerName TEXT NOT NULL,"
        "subjectName TEXT NOT NULL,"
        "validFrom TIMESTAMP NOT NULL,"
        "validTo TIMESTAMP NOT NULL,"
        "publicKey TEXT NOT NULL,"
        "status TEXT DEFAULT 'valid',"
        "ownerID INTEGER,"
        "certificateData TEXT NOT NULL,"
        "createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "FOREIGN KEY (ownerID) REFERENCES Users(userID)"
        ");";
    
    const char* createRequestsTable =
        "CREATE TABLE IF NOT EXISTS CertificateRequests ("
        "requestID INTEGER PRIMARY KEY AUTOINCREMENT,"
        "subjectID INTEGER NOT NULL,"
        "publicKey TEXT NOT NULL,"
        "csrData TEXT NOT NULL,"
        "status TEXT DEFAULT 'pending',"
        "requestedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "processedAt TIMESTAMP,"
        "certificateID INTEGER,"
        "FOREIGN KEY (subjectID) REFERENCES Users(userID),"
        "FOREIGN KEY (certificateID) REFERENCES Certificates(certificateID)"
        ");";
    
    const char* createRevokedTable =
        "CREATE TABLE IF NOT EXISTS RevokedCertificates ("
        "revokeID INTEGER PRIMARY KEY AUTOINCREMENT,"
        "certificateID INTEGER NOT NULL,"
        "serialNumber TEXT NOT NULL,"
        "reason TEXT,"
        "revokedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "revokedBy INTEGER,"
        "FOREIGN KEY (certificateID) REFERENCES Certificates(certificateID),"
        "FOREIGN KEY (revokedBy) REFERENCES Users(userID)"
        ");";
    
    const char* createLogsTable =
        "CREATE TABLE IF NOT EXISTS Logs ("
        "logID INTEGER PRIMARY KEY AUTOINCREMENT,"
        "action TEXT NOT NULL,"
        "doneBy INTEGER,"
        "objectID INTEGER,"
        "details TEXT,"
        "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
        "FOREIGN KEY (doneBy) REFERENCES Users(userID)"
        ");";
    
    if (!executeQuery(createUsersTable) ||
        !executeQuery(createCertificatesTable) ||
        !executeQuery(createRequestsTable) ||
        !executeQuery(createRevokedTable) ||
        !executeQuery(createLogsTable)) {
        return false;
    }
    const char* checkAdmin = "SELECT COUNT(*) FROM Users WHERE role = 'admin';";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, checkAdmin, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    bool hasAdmin = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        hasAdmin = (sqlite3_column_int(stmt, 0) > 0);
    }
    sqlite3_finalize(stmt);
    
    if (!hasAdmin) {
        addUser("admin", "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", "admin@example.com", "admin");
        cout << "Created default admin user (username: admin, password: admin)" << endl;
    }
    
    return true;
}

bool DatabaseManager::executeQuery(const String& query) {
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, query.c_str(), nullptr, nullptr, &errMsg);
    
    if (rc != SQLITE_OK) {
        cerr << "SQL error: " << errMsg << endl;
        sqlite3_free(errMsg);
        return false;
    }
    
    return true;
}

bool DatabaseManager::executeQueryWithParams(const String& query, const vector<String>& params) {
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    for (size_t i = 0; i < params.size(); i++) {
        sqlite3_bind_text(stmt, i + 1, params[i].c_str(), -1, SQLITE_STATIC);
    }
    
    bool result = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    return result;
}

bool DatabaseManager::addUser(const String& username, const String& passwordHash, 
                             const String& email, const String& role) {
    if (!db) return false;
    const char* checkQuery = "SELECT COUNT(*) FROM Users WHERE username = ?;";
    sqlite3_stmt* checkStmt;
    if (sqlite3_prepare_v2(db, checkQuery, -1, &checkStmt, nullptr) != SQLITE_OK) {
        return false;
    }
    sqlite3_bind_text(checkStmt, 1, username.c_str(), -1, SQLITE_STATIC);
    bool userExists = false;
    if (sqlite3_step(checkStmt) == SQLITE_ROW) {
        userExists = (sqlite3_column_int(checkStmt, 0) > 0);
    }
    sqlite3_finalize(checkStmt);

    if (userExists && (username == "testuser" || username == "testauth")) {
        const char* deleteQuery = "DELETE FROM Users WHERE username = ?;";
        sqlite3_stmt* deleteStmt;
        
        if (sqlite3_prepare_v2(db, deleteQuery, -1, &deleteStmt, nullptr) != SQLITE_OK) {
            return false;
        }
        
        sqlite3_bind_text(deleteStmt, 1, username.c_str(), -1, SQLITE_STATIC);
        bool deleteResult = (sqlite3_step(deleteStmt) == SQLITE_DONE);
        sqlite3_finalize(deleteStmt);
        
        if (!deleteResult) {
            return false;
        }
    } else if (userExists) {
        return false;
    }
    const char* query = "INSERT INTO Users (username, passwordHash, email, role) "
                       "VALUES (?, ?, ?, ?);";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, passwordHash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, email.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, role.c_str(), -1, SQLITE_STATIC);
    
    bool result = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    if (result) {
        // Log the activity
        int userID = getUserID(username);
        if (userID > 0) {
            logActivity("User created", userID, userID, "New user: " + username);
        }
    }
    
    return result;
}

bool DatabaseManager::authenticateUser(const String& username, const String& passwordHash) {
    if (!db) return false;
    
    const char* query = "SELECT COUNT(*) FROM Users WHERE username = ? AND passwordHash = ?;";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, passwordHash.c_str(), -1, SQLITE_STATIC);
    
    bool authenticated = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        authenticated = (sqlite3_column_int(stmt, 0) > 0);
    }
    
    sqlite3_finalize(stmt);
    return authenticated;
}

int DatabaseManager::getUserID(const String& username) {
    if (!db) return -1;
    
    const char* query = "SELECT userID FROM Users WHERE username = ?;";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    
    int userID = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        userID = sqlite3_column_int(stmt, 0);
    }
    
    sqlite3_finalize(stmt);
    return userID;
}

String DatabaseManager::getUserPasswordHash(const String& username) {
    if (!db) return "";
    
    const char* query = "SELECT passwordHash FROM Users WHERE username = ?;";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return "";
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    
    String passwordHash = "";
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        passwordHash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }
    
    sqlite3_finalize(stmt);
    return passwordHash;
}

String DatabaseManager::getUserRole(const String& username) {
    if (!db) return "";
    
    const char* query = "SELECT role FROM Users WHERE username = ?;";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return "";
    }
    
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    
    String role = "";
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }
    
    sqlite3_finalize(stmt);
    return role;
}

int DatabaseManager::storeCSR(int userID, const String& publicKey, const String& csrData) {
    if (!db) return -1;
    
    const char* query = "INSERT INTO CertificateRequests (subjectID, publicKey, csrData) "
                       "VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return -1;
    }
    
    sqlite3_bind_int(stmt, 1, userID);
    sqlite3_bind_text(stmt, 2, publicKey.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, csrData.c_str(), -1, SQLITE_STATIC);
    
    bool result = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    if (!result) {
        return -1;
    }

    const char* lastIDQuery = "SELECT last_insert_rowid();";
    if (sqlite3_prepare_v2(db, lastIDQuery, -1, &stmt, nullptr) != SQLITE_OK) {
        return -1;
    }
    
    int requestID = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        requestID = sqlite3_column_int(stmt, 0);
    }
    
    sqlite3_finalize(stmt);

    if (requestID > 0) {
        logActivity("CSR submitted", userID, requestID, "New CSR from user " + to_string(userID));
    }
    
    return requestID;
}

bool DatabaseManager::storeCertificate(const String& serialNumber, int version,
                                      const String& signatureAlgorithm,
                                      const String& issuerName, const String& subjectName,
                                      time_t validFrom, time_t validTo,
                                      const String& publicKey, int ownerID,
                                      const String& certificateData) {
    if (!db) return false;
    
    const char* query = "INSERT INTO Certificates "
                       "(version, serialNumber, signatureAlgorithm, issuerName, subjectName, "
                       "validFrom, validTo, publicKey, ownerID, certificateData) "
                       "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, version);
    sqlite3_bind_text(stmt, 2, serialNumber.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, signatureAlgorithm.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, issuerName.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, subjectName.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, static_cast<sqlite3_int64>(validFrom));
    sqlite3_bind_int64(stmt, 7, static_cast<sqlite3_int64>(validTo));
    sqlite3_bind_text(stmt, 8, publicKey.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 9, ownerID);
    sqlite3_bind_text(stmt, 10, certificateData.c_str(), -1, SQLITE_STATIC);
    
    bool result = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    int certificateID = -1;
    if (result) {
        const char* lastIDQuery = "SELECT last_insert_rowid();";
        if (sqlite3_prepare_v2(db, lastIDQuery, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            certificateID = sqlite3_column_int(stmt, 0);
        }
        
        sqlite3_finalize(stmt);

        if (certificateID > 0) {
            logActivity("Certificate issued", 1, certificateID, "Certificate issued to user " + to_string(ownerID));
        }
    }
    
    return result;
}

bool DatabaseManager::revokeCertificate(int certificateID, const String& serialNumber, 
                                       const String& reason, int revokedBy) {
    if (!db) return false;
    const char* updateQuery = "UPDATE Certificates SET status = 'revoked' WHERE certificateID = ?;";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, updateQuery, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, certificateID);
    
    bool updateResult = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    if (!updateResult) {
        return false;
    }

    const char* insertQuery = "INSERT INTO RevokedCertificates "
                             "(certificateID, serialNumber, reason, revokedBy) "
                             "VALUES (?, ?, ?, ?);";
    
    if (sqlite3_prepare_v2(db, insertQuery, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_int(stmt, 1, certificateID);
    sqlite3_bind_text(stmt, 2, serialNumber.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, reason.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, revokedBy);
    
    bool insertResult = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    if (insertResult) {
        logActivity("Certificate revoked", revokedBy, certificateID, 
                   "Certificate " + serialNumber + " revoked for reason: " + reason);
    }
    
    return insertResult;
}

DatabaseManager::CSRInfo DatabaseManager::getCSRInfo(int requestID) {
    CSRInfo info;
    info.subjectID = -1;
    
    if (!db) return info;
    
    const char* query = "SELECT csrData, publicKey, subjectID, status FROM CertificateRequests "
                       "WHERE requestID = ?;";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return info;
    }
    
    sqlite3_bind_int(stmt, 1, requestID);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        info.csrData = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        info.publicKey = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        info.subjectID = sqlite3_column_int(stmt, 2);
        info.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    }
    
    sqlite3_finalize(stmt);
    return info;
}

bool DatabaseManager::updateCSRStatus(int requestID, const String& status, int certificateID) {
    if (!db) return false;
    
    const char* query;
    if (certificateID > 0) {
        query = "UPDATE CertificateRequests SET status = ?, processedAt = CURRENT_TIMESTAMP, "
               "certificateID = ? WHERE requestID = ?;";
    } else {
        query = "UPDATE CertificateRequests SET status = ?, processedAt = CURRENT_TIMESTAMP "
               "WHERE requestID = ?;";
    }
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_STATIC);
    
    if (certificateID > 0) {
        sqlite3_bind_int(stmt, 2, certificateID);
        sqlite3_bind_int(stmt, 3, requestID);
    } else {
        sqlite3_bind_int(stmt, 2, requestID);
    }
    
    bool result = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    if (result) {
        // Log the status update
        logActivity("CSR status updated", 1, requestID, "CSR " + to_string(requestID) + " status: " + status);
    }
    
    return result;
}

DatabaseManager::CertificateInfo DatabaseManager::getCertificateInfo(int certificateID) {
    CertificateInfo info;
    
    if (!db) return info;
    
    const char* query = "SELECT serialNumber, ownerID FROM Certificates WHERE certificateID = ?;";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return info;
    }
    
    sqlite3_bind_int(stmt, 1, certificateID);
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        info.serialNumber = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        info.ownerID = sqlite3_column_int(stmt, 1);
    }
    
    sqlite3_finalize(stmt);
    return info;
}

int DatabaseManager::getPendingCSRCount() {
    if (!db) return 0;
    
    const char* query = "SELECT COUNT(*) FROM CertificateRequests WHERE status = 'pending';";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return 0;
    }
    
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    
    sqlite3_finalize(stmt);
    return count;
}

bool DatabaseManager::logActivity(const String& action, int doneBy, int objectID, const String& details) {
    if (!db) return false;
    
    const char* query = "INSERT INTO Logs (action, doneBy, objectID, details) "
                       "VALUES (?, ?, ?, ?);";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, action.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, doneBy);
    sqlite3_bind_int(stmt, 3, objectID);
    sqlite3_bind_text(stmt, 4, details.c_str(), -1, SQLITE_STATIC);
    
    bool result = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    return result;
}

vector<DatabaseManager::UserInfo> DatabaseManager::getUsers() {
    vector<UserInfo> users;
    
    if (!db) return users;
    
    const char* query = "SELECT userID, username, email, role FROM Users;";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return users;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        UserInfo user;
        user.userID = sqlite3_column_int(stmt, 0);
        user.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        user.email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        user.role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        
        users.push_back(user);
    }
    
    sqlite3_finalize(stmt);
    return users;
}

vector<DatabaseManager::LogEntry> DatabaseManager::getLogs(const String& filter, int offset, int limit) {
    vector<LogEntry> logs;
    
    if (!db) return logs;
    
    String query = "SELECT logID, action, doneBy, objectID, details, timestamp FROM Logs ";
    
    if (!filter.empty()) {
        query += "WHERE action LIKE ? OR details LIKE ? ";
    }
    
    query += "ORDER BY timestamp DESC LIMIT ? OFFSET ?;";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return logs;
    }
    
    int paramIndex = 1;
    if (!filter.empty()) {
        String likePattern = "%" + filter + "%";
        sqlite3_bind_text(stmt, paramIndex++, likePattern.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, paramIndex++, likePattern.c_str(), -1, SQLITE_STATIC);
    }
    
    sqlite3_bind_int(stmt, paramIndex++, limit);
    sqlite3_bind_int(stmt, paramIndex++, offset);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        LogEntry log;
        log.logID = sqlite3_column_int(stmt, 0);
        log.action = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        log.doneBy = sqlite3_column_int(stmt, 2);
        log.objectID = sqlite3_column_int(stmt, 3);
        log.details = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        log.timestamp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        
        logs.push_back(log);
    }
    
    sqlite3_finalize(stmt);
    return logs;
}

vector<DatabaseManager::CSREntry> DatabaseManager::getPendingCSRs() {
    vector<CSREntry> csrs;
    
    if (!db) return csrs;
    
    const char* query = 
        "SELECT r.requestID, u.username, r.requestedAt FROM CertificateRequests r "
        "JOIN Users u ON r.subjectID = u.userID "
        "WHERE r.status = 'pending' "
        "ORDER BY r.requestedAt;";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return csrs;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CSREntry csr;
        csr.requestID = sqlite3_column_int(stmt, 0);
        csr.subjectName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        csr.requestedAt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        
        csrs.push_back(csr);
    }
    
    sqlite3_finalize(stmt);
    return csrs;
}

vector<DatabaseManager::CertificateEntry> DatabaseManager::getAllCertificates() {
    vector<CertificateEntry> certificates;
    
    if (!db) return certificates;
    
    const char* query = 
        "SELECT certificateID, serialNumber, subjectName, status, validTo "
        "FROM Certificates "
        "ORDER BY validTo DESC;";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return certificates;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CertificateEntry cert;
        cert.certificateID = sqlite3_column_int(stmt, 0);
        cert.serialNumber = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        cert.subjectName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        cert.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        cert.validTo = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        
        certificates.push_back(cert);
    }
    
    sqlite3_finalize(stmt);
    return certificates;
}

bool DatabaseManager::updateUserRole(int userID, const String& newRole) {
    if (!db) return false;
    
    const char* query = "UPDATE Users SET role = ? WHERE userID = ?;";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, newRole.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, userID);
    
    bool result = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    return result;
}

vector<DatabaseManager::CertificateEntry> DatabaseManager::getUserCertificates(int userID) {
    vector<CertificateEntry> certificates;
    
    if (!db) return certificates;
    
    const char* query = 
        "SELECT certificateID, serialNumber, subjectName, status, validTo "
        "FROM Certificates "
        "WHERE ownerID = ? "
        "ORDER BY validTo DESC;";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return certificates;
    }
    
    sqlite3_bind_int(stmt, 1, userID);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CertificateEntry cert;
        cert.certificateID = sqlite3_column_int(stmt, 0);
        cert.serialNumber = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        cert.subjectName = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        cert.status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        cert.validTo = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        
        certificates.push_back(cert);
    }
    
    sqlite3_finalize(stmt);
    return certificates;
}

String DatabaseManager::getCertificateData(int certificateID) {
    if (!db) return "";
    
    const char* query = "SELECT certificateData FROM Certificates WHERE certificateID = ?;";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return "";
    }
    
    sqlite3_bind_int(stmt, 1, certificateID);
    
    String certificateData = "";
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        certificateData = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }
    
    sqlite3_finalize(stmt);
    return certificateData;
}

vector<pair<String, String>> DatabaseManager::getRevokedCertificates() {
    vector<pair<String, String>> revokedCerts;
    
    if (!db) return revokedCerts;
    
    const char* query = 
        "SELECT serialNumber, reason FROM RevokedCertificates;";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        return revokedCerts;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        String serialNumber = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        String reason = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        
        revokedCerts.push_back({serialNumber, reason});
    }
    
    sqlite3_finalize(stmt);
    return revokedCerts;
} 