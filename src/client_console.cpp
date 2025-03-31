#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "../include/client_console.h"
#include "../include/socket_comm.h"
#include "../lib/nlohmann/json.hpp"

using json = nlohmann::json;

ClientConsole::ClientConsole(OpenSSLWrapper& sslWrapper)
    : ssl(sslWrapper), running(true), loggedIn(false) {
    // Initialize socket
    SocketManager::initialize();
}

void ClientConsole::run() {
    while (running) {
        if (!loggedIn) {
            displayAuthMenu();
        } else {
            displayCertificateMenu();
        }
    }
}

void ClientConsole::displayAuthMenu() {
    system("cls");
    std::cout << "CA Management System - Client" << std::endl;
    std::cout << "============================" << std::endl;
    std::cout << "1. Login" << std::endl;
    std::cout << "2. Register" << std::endl;
    std::cout << "0. Exit" << std::endl;
    
    int choice = getIntInput("Enter your choice: ");
    
    switch (choice) {
        case 0:
            running = false;
            break;
        case 1:
            login();
            break;
        case 2:
            registerUser();
            break;
        default:
            displayMessage("Invalid choice. Please try again.");
            break;
    }
}

void ClientConsole::displayCertificateMenu() {
    while (true) {
        system("cls");
        std::cout << "CA Management System - Client" << std::endl;
        std::cout << "============================" << std::endl;
        std::cout << "Logged in as: " << currentUsername << std::endl;
        std::cout << "\n";
        std::cout << "1. Request Certificate" << std::endl;
        std::cout << "2. View My Certificates" << std::endl;
        std::cout << "3. Revoke Certificate" << std::endl;
        std::cout << "4. Download Certificate" << std::endl;
        std::cout << "5. Validate Certificate" << std::endl;
        std::cout << "6. Logout" << std::endl;
        std::cout << "0. Exit" << std::endl;
        
        int choice = getIntInput("Enter your choice: ");
        
        switch (choice) {
            case 0:
                running = false;
                return;
            case 1:
                requestCertificate();
                break;
            case 2:
                viewCertificates();
                break;
            case 3:
                revokeCertificate();
                break;
            case 4:
                downloadCertificate();
                break;
            case 5:
                validateCertificate();
                break;
            case 6:
                logout();
                return;
            default:
                displayMessage("Invalid choice. Please try again.");
                break;
        }
    }
}

bool ClientConsole::login() {
    system("cls");
    std::cout << "=== Login ===" << std::endl;
    
    String username = getInput("Username: ");
    String password = getInput("Password: ");
    
    std::map<String, String> payload;
    payload["username"] = username;
    payload["password"] = password;
    
    String response = sendRequest("login", payload);
    
    try {
        json responseJson = json::parse(response);
        
        if (responseJson["status"] == "success") {
            sessionToken = responseJson["data"]["token"];
            currentUsername = username;
            loggedIn = true;
            displayMessage("Login successful.");
            return true;
        } else {
            displayMessage("Login failed: " + responseJson["message"].get<String>());
            return false;
        }
    }
    catch (const std::exception& e) {
        displayMessage("Error parsing response: " + String(e.what()));
        return false;
    }
}

bool ClientConsole::registerUser() {
    system("cls");
    std::cout << "=== Register ===" << std::endl;
    
    String username = getInput("Username: ");
    String password = getInput("Password: ");
    String email = getInput("Email: ");
    
    std::map<String, String> payload;
    payload["username"] = username;
    payload["password"] = password;
    payload["email"] = email;
    
    String response = sendRequest("register", payload);
    
    try {
        json responseJson = json::parse(response);
        
        if (responseJson["status"] == "success") {
            displayMessage("Registration successful. You can now login.");
            return true;
        } else {
            displayMessage("Registration failed: " + responseJson["message"].get<String>());
            return false;
        }
    }
    catch (const std::exception& e) {
        displayMessage("Error parsing response: " + String(e.what()));
        return false;
    }
}

void ClientConsole::logout() {
    if (!loggedIn) {
        return;
    }
    
    std::map<String, String> payload;
    String response = sendRequest("logout", payload);
    
    // Even if server response fails, we'll log out locally
    sessionToken = "";
    currentUsername = "";
    loggedIn = false;
    
    displayMessage("Logged out successfully.");
}

void ClientConsole::requestCertificate() {
    system("cls");
    std::cout << "=== Request Certificate ===" << std::endl;
    
    // Get subject information
    std::cout << "Enter subject information:" << std::endl;
    String commonName = getInput("Common Name (CN): ");
    String organization = getInput("Organization (O): ");
    String country = getInput("Country (C): ");
    
    // Build subject string
    String subject = "CN=" + commonName + ",O=" + organization + ",C=" + country;
    
    // Generate key pair
    std::cout << "Generating key pair..." << std::endl;
    auto keyPair = ssl.generateRSAKeyPair(2048);
    String privateKey = keyPair.first;
    String publicKey = keyPair.second;
    
    // Generate CSR
    std::cout << "Generating certificate signing request..." << std::endl;
    String csrData = ssl.generateCSR(privateKey, subject);
    
    // Save private key to file
    String keyFilename = commonName + ".key";
    std::ofstream keyFile(keyFilename);
    keyFile << privateKey;
    keyFile.close();
    
    std::cout << "Private key saved to " << keyFilename << std::endl;
    std::cout << "IMPORTANT: Keep this file secure!" << std::endl;
    
    // Submit CSR to server
    std::map<String, String> payload;
    payload["csr"] = csrData;
    
    String response = sendRequest("request_certificate", payload);
    
    try {
        json responseJson = json::parse(response);
        
        if (responseJson["status"] == "success") {
            int requestID = responseJson["data"]["requestID"];
            displayMessage("Certificate request submitted successfully. Request ID: " + 
                          std::to_string(requestID));
        } else {
            displayMessage("Certificate request failed: " + responseJson["message"].get<String>());
        }
    }
    catch (const std::exception& e) {
        displayMessage("Error parsing response: " + String(e.what()));
    }
}

void ClientConsole::viewCertificates() {
    system("cls");
    std::cout << "=== My Certificates ===" << std::endl;
    
    std::map<String, String> payload;
    String response = sendRequest("get_certificates", payload);
    
    try {
        json responseJson = json::parse(response);
        
        if (responseJson["status"] == "success") {
            auto certificates = responseJson["data"]["certificates"];
            
            if (certificates.empty()) {
                std::cout << "You don't have any certificates." << std::endl;
            } else {
                std::cout << "------------------------------------\n";
                std::cout << std::left << std::setw(5) << "ID" << " | " 
                          << std::setw(15) << "Serial" << " | " 
                          << std::setw(20) << "Subject" << " | " 
                          << std::setw(10) << "Status" << " | " 
                          << "Expiry" << std::endl;
                std::cout << "------------------------------------\n";
                
                for (const auto& cert : certificates) {
                    std::cout << std::left << std::setw(5) << cert["certificateID"].get<int>() << " | " 
                              << std::setw(15) << cert["serialNumber"].get<String>().substr(0, 12) + "..." << " | " 
                              << std::setw(20) << cert["subjectName"].get<String>() << " | " 
                              << std::setw(10) << cert["status"].get<String>() << " | " 
                              << cert["validTo"].get<String>() << std::endl;
                }
            }
        } else {
            std::cout << "Failed to retrieve certificates: " << responseJson["message"].get<String>() << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cout << "Error parsing response: " << e.what() << std::endl;
    }
    
    waitForEnter();
}

void ClientConsole::revokeCertificate() {
    system("cls");
    std::cout << "=== Revoke Certificate ===" << std::endl;
    
    // First, get the list of certificates
    viewCertificates();
    
    int certID = getIntInput("Enter certificate ID to revoke (0 to cancel): ");
    if (certID <= 0) {
        return;
    }
    
    String reason = getInput("Enter revocation reason: ");
    
    std::map<String, String> payload;
    payload["certificateID"] = std::to_string(certID);
    payload["reason"] = reason;
    
    String response = sendRequest("revoke_certificate", payload);
    
    try {
        json responseJson = json::parse(response);
        
        if (responseJson["status"] == "success") {
            displayMessage("Certificate revoked successfully.");
        } else {
            displayMessage("Failed to revoke certificate: " + responseJson["message"].get<String>());
        }
    }
    catch (const std::exception& e) {
        displayMessage("Error parsing response: " + String(e.what()));
    }
}

void ClientConsole::downloadCertificate() {
    system("cls");
    std::cout << "=== Download Certificate ===" << std::endl;
    
    // First, get the list of certificates
    viewCertificates();
    
    int certID = getIntInput("Enter certificate ID to download (0 to cancel): ");
    if (certID <= 0) {
        return;
    }
    
    std::map<String, String> payload;
    payload["certificateID"] = std::to_string(certID);
    
    String response = sendRequest("download_certificate", payload);
    
    try {
        json responseJson = json::parse(response);
        
        if (responseJson["status"] == "success") {
            String certificateData = responseJson["data"]["certificateData"];
            String filename = "certificate_" + std::to_string(certID) + ".pem";
            
            std::ofstream certFile(filename);
            certFile << certificateData;
            certFile.close();
            
            displayMessage("Certificate downloaded successfully to " + filename);
        } else {
            displayMessage("Failed to download certificate: " + responseJson["message"].get<String>());
        }
    }
    catch (const std::exception& e) {
        displayMessage("Error parsing response: " + String(e.what()));
    }
}

void ClientConsole::validateCertificate() {
    system("cls");
    std::cout << "=== Validate Certificate ===" << std::endl;
    
    String filename = getInput("Enter certificate file path: ");
    
    // Read certificate file
    std::ifstream certFile(filename);
    if (!certFile.is_open()) {
        displayMessage("Failed to open certificate file.");
        return;
    }
    
    std::stringstream certStream;
    certStream << certFile.rdbuf();
    String certificateData = certStream.str();
    certFile.close();
    
    // Send validation request
    json payload;
    payload["certificateData"] = certificateData;
    
    String response = sendRequest("validate_certificate", payload);
    
    try {
        json responseJson = json::parse(response);
        
        if (responseJson["status"] == "success") {
            bool valid = responseJson["data"]["valid"];
            if (valid) {
                displayMessage("Certificate is valid.");
            } else {
                displayMessage("Certificate is invalid or has been revoked.");
            }
        } else {
            displayMessage("Failed to validate certificate: " + responseJson["message"].get<String>());
        }
    }
    catch (const std::exception& e) {
        displayMessage("Error parsing response: " + String(e.what()));
    }
}

String ClientConsole::sendRequest(const String& action, const std::map<String, String>& payload) {
    // Build request JSON
    json request;
    request["action"] = action;
    
    // Add payload
    json payloadJson = json::object();
    for (const auto& pair : payload) {
        payloadJson[pair.first] = pair.second;
    }
    request["payload"] = payloadJson;
    
    // Add session token if logged in
    if (loggedIn && !sessionToken.empty()) {
        request["token"] = sessionToken;
    }
    
    // Convert to string
    String requestStr = request.dump();
    
    // Connect to server
    ClientSocket socket;
    if (!socket.connect("localhost", 8080)) {
        json errorResponse;
        errorResponse["status"] = "error";
        errorResponse["message"] = "Failed to connect to server";
        return errorResponse.dump();
    }
    
    // Send request
    if (!socket.send(requestStr)) {
        json errorResponse;
        errorResponse["status"] = "error";
        errorResponse["message"] = "Failed to send request to server";
        return errorResponse.dump();
    }
    
    // Receive response
    String response = socket.receive();
    
    // Close connection
    socket.close();
    
    return response;
}

String ClientConsole::simulateServerResponse(const String& request) {
    // This is a placeholder function that simulates server responses
    // In a real implementation, this would be replaced with actual server communication
    
    try {
        json requestJson = json::parse(request);
        String action = requestJson["action"];
        
        // Simulate different server responses based on action
        if (action == "login") {
            String username = requestJson["payload"]["username"];
            String password = requestJson["payload"]["password"];
            
            // Simulate successful login for "admin" user with password "admin"
            if (username == "admin" && password == "admin") {
                json response;
                response["status"] = "success";
                response["data"]["token"] = "simulated_session_token";
                response["message"] = "Login successful";
                return response.dump();
            } else {
                json response;
                response["status"] = "error";
                response["message"] = "Invalid credentials";
                return response.dump();
            }
        }
        else if (action == "register") {
            // Simulate successful registration
            json response;
            response["status"] = "success";
            response["message"] = "Registration successful";
            return response.dump();
        }
        else if (action == "logout") {
            // Simulate successful logout
            json response;
            response["status"] = "success";
            response["message"] = "Logout successful";
            return response.dump();
        }
        else if (action == "request_certificate") {
            // Simulate successful CSR submission
            json response;
            response["status"] = "success";
            response["data"]["requestID"] = 123;
            response["message"] = "CSR submitted successfully";
            return response.dump();
        }
        else if (action == "get_certificates") {
            // Simulate certificate list
            json response;
            response["status"] = "success";
            
            json certificates = json::array();
            
            // Add a sample certificate
            json cert1;
            cert1["certificateID"] = 1;
            cert1["serialNumber"] = "ABCDEF1234567890";
            cert1["subjectName"] = "CN=Sample Certificate";
            cert1["status"] = "valid";
            cert1["validTo"] = "2023-12-31";
            certificates.push_back(cert1);
            
            response["data"]["certificates"] = certificates;
            response["message"] = "Certificates retrieved";
            return response.dump();
        }
        else if (action == "revoke_certificate") {
            // Simulate certificate revocation
            json response;
            response["status"] = "success";
            response["message"] = "Certificate revoked successfully";
            return response.dump();
        }
        else if (action == "download_certificate") {
            // Simulate certificate download
            json response;
            response["status"] = "success";
            response["data"]["certificateData"] = "-----BEGIN CERTIFICATE-----\nSample certificate data\n-----END CERTIFICATE-----";
            response["message"] = "Certificate downloaded";
            return response.dump();
        }
        else {
            // Unknown action
            json response;
            response["status"] = "error";
            response["message"] = "Unknown action: " + action;
            return response.dump();
        }
    }
    catch (const std::exception& e) {
        json response;
        response["status"] = "error";
        response["message"] = "Error processing request: " + String(e.what());
        return response.dump();
    }
}

String ClientConsole::getInput(const String& prompt) {
    String input;
    std::cout << prompt;
    std::getline(std::cin, input);
    return input;
}

int ClientConsole::getIntInput(const String& prompt) {
    String input = getInput(prompt);
    try {
        return std::stoi(input);
    } catch (...) {
        return -1;
    }
}

void ClientConsole::waitForEnter() {
    std::cout << "\nPress Enter to continue...";
    std::cin.get();
}

void ClientConsole::displayMessage(const String& message) {
    std::cout << "\n" << message << std::endl;
    waitForEnter();
} 