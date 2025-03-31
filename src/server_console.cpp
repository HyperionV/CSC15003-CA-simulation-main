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
                std::cout << "Invalid choice. Please try again." << std::endl;
                waitForEnter();
                break;
        }
    }
}

void ServerConsole::displayMainMenu() {
    system("cls"); // Clear screen (Windows)
    
    displayServerStatus();
    
    std::cout << "\n=== CA Server Console ===" << std::endl;
    std::cout << "1. View Logs" << std::endl;
    std::cout << "2. Manage Users" << std::endl;
    std::cout << "3. Certificate Operations" << std::endl;
    std::cout << "0. Exit" << std::endl;
}

void ServerConsole::displayServerStatus() {
    // Get current time
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    
    std::cout << "CA Management System - Server" << std::endl;
    std::cout << "Current time: " << std::ctime(&now_time);
    std::cout << "Pending CSRs: " << ca.getPendingCSRCount() << std::endl;
}

void ServerConsole::viewLogs() {
    system("cls");
    std::cout << "=== Log Viewer ===" << std::endl;
    
    int page = 0;
    int logsPerPage = 10;
    String filter = "";
    bool viewingLogs = true;
    
    while (viewingLogs) {
        // Get logs with pagination and filtering
        auto logs = db.getLogs(filter, page * logsPerPage, logsPerPage);
        
        system("cls");
        std::cout << "=== Log Viewer ===" << std::endl;
        std::cout << "Filter: " << (filter.empty() ? "None" : filter) << std::endl;
        std::cout << "\n";
        
        if (logs.empty()) {
            std::cout << "No logs found.\n";
        } else {
            for (const auto& log : logs) {
                std::cout << log.timestamp << " | " << log.action 
                          << " | User: " << log.doneBy << std::endl;
                std::cout << "  Details: " << log.details << std::endl;
                std::cout << "-------------------\n";
            }
        }
        
        std::cout << "\n";
        std::cout << "Page " << (page + 1) << "\n";
        std::cout << "1. Next Page\n";
        std::cout << "2. Previous Page\n";
        std::cout << "3. Set Filter\n";
        std::cout << "0. Back\n";
        
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
                page = 0;  // Reset to first page
                break;
            default:
                std::cout << "Invalid choice." << std::endl;
                waitForEnter();
                break;
        }
    }
}

void ServerConsole::manageUsers() {
    system("cls");
    std::cout << "=== User Management ===" << std::endl;
    
    bool managingUsers = true;
    
    while (managingUsers) {
        // Get user list
        auto users = db.getUsers();
        
        system("cls");
        std::cout << "=== User Management ===" << std::endl;
        std::cout << "\nUser List:\n";
        std::cout << "------------------------------------\n";
        std::cout << std::left << std::setw(5) << "ID" << " | " 
                  << std::setw(20) << "Username" << " | " 
                  << std::setw(20) << "Email" << " | " 
                  << "Role" << std::endl;
        std::cout << "------------------------------------\n";
        
        for (const auto& user : users) {
            std::cout << std::left << std::setw(5) << user.userID << " | " 
                      << std::setw(20) << user.username << " | " 
                      << std::setw(20) << user.email << " | " 
                      << user.role << std::endl;
        }
        
        std::cout << "\n";
        std::cout << "1. Create New User\n";
        std::cout << "2. Change User Role\n";
        std::cout << "0. Back\n";
        
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
                    std::cout << "User created successfully." << std::endl;
                } else {
                    std::cout << "Failed to create user." << std::endl;
                }
                waitForEnter();
                break;
            }
            case 2: {
                int userID = getIntInput("Enter user ID: ");
                String newRole = getInput("Enter new role (user/admin): ");
                
                if (db.updateUserRole(userID, newRole)) {
                    std::cout << "User role updated successfully." << std::endl;
                } else {
                    std::cout << "Failed to update user role." << std::endl;
                }
                waitForEnter();
                break;
            }
            default:
                std::cout << "Invalid choice." << std::endl;
                waitForEnter();
                break;
        }
    }
}

void ServerConsole::certificateOperations() {
    while (true) {
        system("cls");
        std::cout << "Certificate Operations" << std::endl;
        std::cout << "=====================" << std::endl;
        std::cout << "1. List All Certificates" << std::endl;
        std::cout << "2. View Certificate Details" << std::endl;
        std::cout << "3. Approve Certificate Request" << std::endl;
        std::cout << "4. Revoke Certificate" << std::endl;
        std::cout << "5. Generate CRL" << std::endl;
        std::cout << "0. Back" << std::endl;
        
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
                std::cout << "Generating Certificate Revocation List (CRL)..." << std::endl;
                String crlData = ca.generateCRL();
                if (!crlData.empty()) {
                    std::cout << "CRL generated successfully." << std::endl;
                    std::cout << "Saved to: " << CERT_DIR << "ca.crl" << std::endl;
                } else {
                    std::cout << "Failed to generate CRL." << std::endl;
                }
                waitForEnter();
                break;
            }
            default:
                std::cout << "Invalid choice. Please try again." << std::endl;
                waitForEnter();
                break;
        }
    }
}

void ServerConsole::listCertificates() {
    auto certificates = db.getAllCertificates();
    
    system("cls");
    std::cout << "=== All Certificates ===" << std::endl;
    std::cout << "------------------------------------\n";
    std::cout << std::left << std::setw(5) << "ID" << " | " 
              << std::setw(15) << "Serial" << " | " 
              << std::setw(20) << "Subject" << " | " 
              << std::setw(10) << "Status" << " | " 
              << "Expiry" << std::endl;
    std::cout << "------------------------------------\n";
    
    for (const auto& cert : certificates) {
        std::cout << std::left << std::setw(5) << cert.certificateID << " | " 
                  << std::setw(15) << cert.serialNumber.substr(0, 12) + "..." << " | " 
                  << std::setw(20) << cert.subjectName << " | " 
                  << std::setw(10) << cert.status << " | " 
                  << cert.validTo << std::endl;
    }
    
    waitForEnter();
}

void ServerConsole::viewCertificateDetails() {
    int certID = getIntInput("Enter certificate ID: ");
    
    auto certInfo = db.getCertificateInfo(certID);
    String certData = db.getCertificateData(certID);
    
    if (certData.empty()) {
        std::cout << "Certificate not found." << std::endl;
        waitForEnter();
        return;
    }
    
    system("cls");
    std::cout << "=== Certificate Details ===" << std::endl;
    std::cout << "ID: " << certID << std::endl;
    std::cout << "Serial Number: " << certInfo.serialNumber << std::endl;
    std::cout << "Owner ID: " << certInfo.ownerID << std::endl;
    std::cout << "\nCertificate Data:\n" << certData << std::endl;
    
    waitForEnter();
}

void ServerConsole::approveCertificateRequest() {
    int requestID = getIntInput("Enter CSR ID to approve: ");
    int validityDays = getIntInput("Enter validity period in days (default: 365): ");
    
    int certID = ca.issueCertificate(requestID, validityDays);
    if (certID > 0) {
        std::cout << "Certificate issued successfully. ID: " << certID << std::endl;
    } else {
        std::cout << "Failed to issue certificate." << std::endl;
    }
    waitForEnter();
}

void ServerConsole::revokeCertificate() {
    int certID = getIntInput("Enter certificate ID to revoke: ");
    String reason = getInput("Enter revocation reason: ");
    
    if (ca.revokeCertificate(certID, reason, "admin")) {
        std::cout << "Certificate revoked successfully." << std::endl;
    } else {
        std::cout << "Failed to revoke certificate." << std::endl;
    }
    waitForEnter();
}

String ServerConsole::getInput(const String& prompt) {
    String input;
    std::cout << prompt;
    std::getline(std::cin, input);
    return input;
}

int ServerConsole::getIntInput(const String& prompt) {
    String input = getInput(prompt);
    try {
        return std::stoi(input);
    } catch (...) {
        return -1;
    }
}

void ServerConsole::waitForEnter() {
    std::cout << "\nPress Enter to continue...";
    std::cin.get();
} 