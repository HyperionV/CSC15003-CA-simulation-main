#include "../include/server_console.h"
#include <iomanip>
#include <ctime>

ServerConsole::ServerConsole(AuthenticationSystem& authSystem, 
                           CertificateAuthority& ca, 
                           DatabaseManager& dbManager)
    : auth(authSystem), ca(ca), db(dbManager), running(true) {
}

void ServerConsole::run() {
    while (running) {
        displayMainMenu();
        
        int choice = getIntInput("Enter your choice: ");
        
        switch (choice) {
            case 1:
                viewLogs();
                break;
            case 2:
                manageUsers();
                break;
            case 3:
                certificateOperations();
                break;
            case 0:
                if (getInput("Are you sure you want to exit? (y/n): ") == "y") {
                    running = false;
                }
                break;
            default:
                cout << "Invalid choice. Please try again." << endl;
                waitForEnter();
                break;
        }
    }
}

void ServerConsole::displayMainMenu() {
    system("cls");
    
    displayServerStatus();
    
    cout << "\n=== CA Server Console ===" << endl;
    cout << "1. View Logs" << endl;
    cout << "2. Manage Users" << endl;
    cout << "3. Certificate Operations" << endl;
    cout << "0. Exit" << endl;
}

void ServerConsole::displayServerStatus() {
    auto now = chrono::system_clock::now();
    time_t now_time = chrono::system_clock::to_time_t(now);
    
    cout << "CA Management System - Server" << endl;
    cout << "Current time: " << ctime(&now_time);
    cout << "Pending CSRs: " << ca.getPendingCSRCount() << endl;
}

void ServerConsole::viewLogs() {
    system("cls");
    cout << "=== Log Viewer ===" << endl;
    
    int page = 0;
    int logsPerPage = 10;
    String filter = "";
    bool viewingLogs = true;
    
    while (viewingLogs) {
        auto logs = db.getLogs(filter, page * logsPerPage, logsPerPage);
        
        system("cls");
        cout << "=== Log Viewer ===" << endl;
        cout << "Filter: " << (filter.empty() ? "None" : filter) << endl;
        cout << "\n";
        
        if (logs.empty()) {
            cout << "No logs found.\n";
        } else {
            for (const auto& log : logs) {
                cout << log.timestamp << " | " << log.action 
                          << " | User: " << log.doneBy << endl;
                cout << "  Details: " << log.details << endl;
                cout << "-------------------\n";
            }
        }
        
        cout << "\n";
        cout << "Page " << (page + 1) << "\n";
        cout << "1. Next Page\n";
        cout << "2. Previous Page\n";
        cout << "3. Set Filter\n";
        cout << "0. Back\n";
        
        int choice = getIntInput("Enter your choice: ");
        
        switch (choice) {
            case 0:
                viewingLogs = false;
                break;
            case 1:
                page++;
                break;
            case 2:
                if (page > 0) {
                    page--;
                }
                break;
            case 3:
                filter = getInput("Enter filter (empty for none): ");
                page = 0;
                break;
            default:
                cout << "Invalid choice." << endl;
                waitForEnter();
                break;
        }
    }
}

void ServerConsole::manageUsers() {
    system("cls");
    cout << "=== User Management ===" << endl;
    
    bool managingUsers = true;
    
    while (managingUsers) {
        auto users = db.getUsers();
        
        system("cls");
        cout << "=== User Management ===" << endl;
        cout << "\nUser List:\n";
        cout << "------------------------------------\n";
        cout << left << setw(5) << "ID" << " | " 
                  << setw(20) << "Username" << " | " 
                  << setw(20) << "Email" << " | " 
                  << "Role" << endl;
        cout << "------------------------------------\n";
        
        for (const auto& user : users) {
            cout << left << setw(5) << user.userID << " | " 
                      << setw(20) << user.username << " | " 
                      << setw(20) << user.email << " | " 
                      << user.role << endl;
        }
        
        cout << "\n";
        cout << "1. Create New User\n";
        cout << "2. Change User Role\n";
        cout << "0. Back\n";
        
        int choice = getIntInput("Enter your choice: ");
        
        switch (choice) {
            case 0:
                managingUsers = false;
                break;
            case 1: {
                String username = getInput("Enter username: ");
                String password = getInput("Enter password: ");
                String email = getInput("Enter email: ");
                String role = getInput("Enter role (user/admin): ");
                
                if (auth.registerUser(username, password, email, role)) {
                    cout << "User created successfully." << endl;
                } else {
                    cout << "Failed to create user." << endl;
                }
                waitForEnter();
                break;
            }
            case 2: {
                int userID = getIntInput("Enter user ID: ");
                String newRole = getInput("Enter new role (user/admin): ");
                
                if (db.updateUserRole(userID, newRole)) {
                    cout << "User role updated successfully." << endl;
                } else {
                    cout << "Failed to update user role." << endl;
                }
                waitForEnter();
                break;
            }
            default:
                cout << "Invalid choice." << endl;
                waitForEnter();
                break;
        }
    }
}

void ServerConsole::certificateOperations() {
    while (true) {
        system("cls");
        cout << "Certificate Operations" << endl;
        cout << "=====================" << endl;
        cout << "1. List All Certificates" << endl;
        cout << "2. View Certificate Details" << endl;
        cout << "3. Approve Certificate Request" << endl;
        cout << "4. Revoke Certificate" << endl;
        cout << "5. Generate CRL" << endl;
        cout << "0. Back" << endl;
        
        int choice = getIntInput("Enter your choice: ");
        
        switch (choice) {
            case 0:
                return;
            case 1:
                listCertificates();
                break;
            case 2:
                viewCertificateDetails();
                break;
            case 3:
                approveCertificateRequest();
                break;
            case 4:
                revokeCertificate();
                break;
            case 5: {
                cout << "Generating Certificate Revocation List (CRL)..." << endl;
                String crlData = ca.generateCRL();
                if (!crlData.empty()) {
                    cout << "CRL generated successfully." << endl;
                    cout << "Saved to: " << CERT_DIR << "ca.crl" << endl;
                } else {
                    cout << "Failed to generate CRL." << endl;
                }
                waitForEnter();
                break;
            }
            default:
                cout << "Invalid choice. Please try again." << endl;
                waitForEnter();
                break;
        }
    }
}

void ServerConsole::listCertificates() {
    auto certificates = db.getAllCertificates();
    
    system("cls");
    cout << "=== All Certificates ===" << endl;
    cout << "------------------------------------\n";
    cout << left << setw(5) << "ID" << " | " 
              << setw(15) << "Serial" << " | " 
              << setw(20) << "Subject" << " | " 
              << setw(10) << "Status" << " | " 
              << "Expiry" << endl;
    cout << "------------------------------------\n";
    
    for (const auto& cert : certificates) {
        cout << left << setw(5) << cert.certificateID << " | " 
                  << setw(15) << cert.serialNumber.substr(0, 12) + "..." << " | " 
                  << setw(20) << cert.subjectName << " | " 
                  << setw(10) << cert.status << " | " 
                  << cert.validTo << endl;
    }
    
    waitForEnter();
}

void ServerConsole::viewCertificateDetails() {
    int certID = getIntInput("Enter certificate ID: ");
    
    auto certInfo = db.getCertificateInfo(certID);
    String certData = db.getCertificateData(certID);
    
    if (certData.empty()) {
        cout << "Certificate not found." << endl;
        waitForEnter();
        return;
    }
    
    system("cls");
    cout << "=== Certificate Details ===" << endl;
    cout << "ID: " << certID << endl;
    cout << "Serial Number: " << certInfo.serialNumber << endl;
    cout << "Owner ID: " << certInfo.ownerID << endl;
    cout << "\nCertificate Data:\n" << certData << endl;
    
    waitForEnter();
}

void ServerConsole::approveCertificateRequest() {
    system("cls");
    cout << "=== Approve Certificate Request ===" << endl;
    
    auto pendingCSRs = db.getPendingCSRs();
    
    if (pendingCSRs.empty()) {
        cout << "No pending certificate requests found." << endl;
        waitForEnter();
        return;
    }
    
    cout << "Pending Certificate Requests:" << endl;
    cout << "--------------------------------------------------" << endl;
    cout << "| ID | Requester | Request Date |" << endl;
    cout << "--------------------------------------------------" << endl;
    
    for (const auto& csr : pendingCSRs) {
        cout << "| " << setw(2) << csr.requestID 
                  << " | " << setw(9) << csr.subjectName 
                  << " | " << setw(12) << csr.requestedAt << " |" << endl;
    }
    cout << "--------------------------------------------------" << endl;
    cout << endl;
    
    int requestID = getIntInput("Enter CSR ID from the list to approve: ");

    bool validID = false;
    for (const auto& csr : pendingCSRs) {
        if (csr.requestID == requestID) {
            validID = true;
            break;
        }
    }
    
    if (!validID) {
        cout << "Invalid CSR ID. Please select an ID from the list." << endl;
        waitForEnter();
        return;
    }
    
    int validityDays = getIntInput("Enter validity period in days (default: 365): ");
    
    int certID = ca.issueCertificate(requestID, validityDays);
    if (certID > 0) {
        cout << "Certificate issued successfully. ID: " << certID << endl;
    } else {
        cout << "Failed to issue certificate." << endl;
    }
    waitForEnter();
}

void ServerConsole::revokeCertificate() {
    int certID = getIntInput("Enter certificate ID to revoke: ");
    String reason = getInput("Enter revocation reason: ");
    
    if (ca.revokeCertificate(certID, reason, "admin")) {
        cout << "Certificate revoked successfully." << endl;
    } else {
        cout << "Failed to revoke certificate." << endl;
    }
    waitForEnter();
}

String ServerConsole::getInput(const String& prompt) {
    String input;
    cout << prompt;
    getline(cin, input);
    return input;
}

int ServerConsole::getIntInput(const String& prompt) {
    String input = getInput(prompt);
    try {
        return stoi(input);
    } catch (...) {
        return -1;
    }
}

void ServerConsole::waitForEnter() {
    cout << "\nPress Enter to continue...";
    cin.get();
} 