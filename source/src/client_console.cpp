#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "../include/client_console.h"
#include "../include/socket_comm.h"
#include "../lib/nlohmann/json.hpp"

using json = nlohmann::json;

ClientConsole::ClientConsole(OpenSSLWrapper& sslWrapper)
    : ssl(sslWrapper), running(true), loggedIn(false) {
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
    cout << "CA Management System - Client" << endl;
    cout << "============================" << endl;
    cout << "1. Login" << endl;
    cout << "2. Register" << endl;
    cout << "0. Exit" << endl;
    
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
        cout << "CA Management System - Client" << endl;
        cout << "============================" << endl;
        cout << "Logged in as: " << currentUsername << endl;
        cout << "\n";
        cout << "1. Request Certificate" << endl;
        cout << "2. View My Certificates" << endl;
        cout << "3. Revoke Certificate" << endl;
        cout << "4. Download Certificate" << endl;
        cout << "5. Validate Certificate" << endl;
        cout << "6. Logout" << endl;
        cout << "0. Exit" << endl;
        
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
    cout << "=== Login ===" << endl;
    
    String username = getInput("Username: ");
    String password = getInput("Password: ");
    
    map<String, String> payload;
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
    catch (const exception& e) {
        displayMessage("Error parsing response: " + String(e.what()));
        return false;
    }
}

bool ClientConsole::registerUser() {
    system("cls");
    cout << "=== Register ===" << endl;
    
    String username = getInput("Username: ");
    String password = getInput("Password: ");
    String email = getInput("Email: ");
    
    map<String, String> payload;
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
    catch (const exception& e) {
        displayMessage("Error parsing response: " + String(e.what()));
        return false;
    }
}

void ClientConsole::logout() {
    if (!loggedIn) {
        return;
    }
    
    map<String, String> payload;
    String response = sendRequest("logout", payload);
    
    // Even if server response fails, we'll log out locally
    sessionToken = "";
    currentUsername = "";
    loggedIn = false;
    
    displayMessage("Logged out successfully.");
}

void ClientConsole::requestCertificate() {
    system("cls");
    cout << "=== Request Certificate ===" << endl;
    
    // Get subject information
    cout << "Enter subject information:" << endl;
    String commonName = getInput("Common Name (CN): ");
    String organization = getInput("Organization (O): ");
    String country = getInput("Country (C): ");
    
    // Build subject string
    String subject = "CN=" + commonName + ",O=" + organization + ",C=" + country;
    
    // Generate key pair
    cout << "Generating key pair..." << endl;
    auto keyPair = ssl.generateRSAKeyPair(2048);
    String privateKey = keyPair.first;
    String publicKey = keyPair.second;
    
    // Generate CSR
    cout << "Generating certificate signing request..." << endl;
    String csrData = ssl.generateCSR(privateKey, subject);
    
    // Save private key to file
    String keyFilename = commonName + ".key";
    ofstream keyFile(keyFilename);
    keyFile << privateKey;
    keyFile.close();
    
    cout << "Private key saved to " << keyFilename << endl;
    cout << "IMPORTANT: Keep this file secure!" << endl;
    
    // Submit CSR to server
    map<String, String> payload;
    payload["csr"] = csrData;
    
    String response = sendRequest("request_certificate", payload);
    
    try {
        json responseJson = json::parse(response);
        
        if (responseJson["status"] == "success") {
            int requestID = responseJson["data"]["requestID"];
            displayMessage("Certificate request submitted successfully. Request ID: " + 
                          to_string(requestID));
        } else {
            displayMessage("Certificate request failed: " + responseJson["message"].get<String>());
        }
    }
    catch (const exception& e) {
        displayMessage("Error parsing response: " + String(e.what()));
    }
}

void ClientConsole::viewCertificates() {
    system("cls");
    cout << "=== My Certificates ===" << endl;
    
    map<String, String> payload;
    String response = sendRequest("get_certificates", payload);
    
    try {
        json responseJson = json::parse(response);
        
        if (responseJson["status"] == "success") {
            auto certificates = responseJson["data"]["certificates"];
            
            if (certificates.empty()) {
                cout << "You don't have any certificates." << endl;
            } else {
                cout << "------------------------------------\n";
                cout << left << setw(5) << "ID" << " | " 
                          << setw(15) << "Serial" << " | " 
                          << setw(20) << "Subject" << " | " 
                          << setw(10) << "Status" << " | " 
                          << "Expiry" << endl;
                cout << "------------------------------------\n";
                
                for (const auto& cert : certificates) {
                    cout << left << setw(5) << cert["certificateID"].get<int>() << " | " 
                              << setw(15) << cert["serialNumber"].get<String>().substr(0, 12) + "..." << " | " 
                              << setw(20) << cert["subjectName"].get<String>() << " | " 
                              << setw(10) << cert["status"].get<String>() << " | " 
                              << cert["validTo"].get<String>() << endl;
                }
            }
        } else {
            cout << "Failed to retrieve certificates: " << responseJson["message"].get<String>() << endl;
        }
    }
    catch (const exception& e) {
        cout << "Error parsing response: " << e.what() << endl;
    }
    
    waitForEnter();
}

void ClientConsole::revokeCertificate() {
    system("cls");
    cout << "=== Revoke Certificate ===" << endl;
    
    // First, get the list of certificates
    viewCertificates();
    
    int certID = getIntInput("Enter certificate ID to revoke (0 to cancel): ");
    if (certID <= 0) {
        return;
    }
    
    String reason = getInput("Enter revocation reason: ");
    
    map<String, String> payload;
    payload["certificateID"] = to_string(certID);
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
    catch (const exception& e) {
        displayMessage("Error parsing response: " + String(e.what()));
    }
}

void ClientConsole::downloadCertificate() {
    system("cls");
    cout << "=== Download Certificate ===" << endl;
    
    // First, get the list of certificates
    viewCertificates();
    
    int certID = getIntInput("Enter certificate ID to download (0 to cancel): ");
    if (certID <= 0) {
        return;
    }
    
    // Ask for format choice
    cout << "\nChoose format:" << endl;
    cout << "1. PEM (certificate only)" << endl;
    cout << "2. PKCS#12 (certificate and private key bundled, password protected)" << endl;
    
    int formatChoice = getIntInput("Enter your choice: ");
    if (formatChoice != 1 && formatChoice != 2) {
        displayMessage("Invalid selection. Downloading as PEM format.");
        formatChoice = 1;
    }
    
    // Request certificate from server
    map<String, String> payload;
    payload["certificateID"] = to_string(certID);
    
    String response = sendRequest("download_certificate", payload);
    
    try {
        json responseJson = json::parse(response);
        
        if (responseJson["status"] == "success") {
            String certificateData = responseJson["data"]["certificateData"];
            String subjectName = responseJson["data"]["subjectName"];
            
            const String certsDir = "Certs";
            filesystem::create_directories(certsDir);
            
            if (formatChoice == 1) {
                // Save as PEM format
                String filename = certsDir + "/certificate_" + to_string(certID) + ".pem";
                ofstream certFile(filename);
                certFile << certificateData;
                certFile.close();
                
                displayMessage("Certificate downloaded successfully to " + filename);
            }
            else {
                String privateKey = findMatchingPrivateKey(certificateData, subjectName);
                if (privateKey.empty()) {
                    displayMessage("Failed to find matching private key. PKCS#12 format requires a private key.");
                    return;
                }
                
                String password = maskInput("Enter password to protect the PKCS#12 file: ");
                if (password.empty()) {
                    displayMessage("Password cannot be empty for PKCS#12 format.");
                    return;
                }
                
                String friendlyName = "Certificate_" + to_string(certID);
                if (!subjectName.empty()) {
                    size_t cnPos = subjectName.find("CN=");
                    if (cnPos != String::npos) {
                        cnPos += 3;
                        size_t cnEnd = subjectName.find(',', cnPos);
                        friendlyName = (cnEnd != String::npos) ? 
                            subjectName.substr(cnPos, cnEnd - cnPos) : subjectName.substr(cnPos);
                    }
                }
                
                String p12Data = ssl.createPKCS12(privateKey, certificateData, password, friendlyName);
                
                if (p12Data.empty()) {
                    displayMessage("Failed to create PKCS#12 file.");
                    return;
                }
                
                String filename = certsDir + "/certificate_" + to_string(certID) + ".p12";
                ofstream p12File(filename, ios::binary);
                p12File.write(p12Data.data(), p12Data.size());
                p12File.close();
                
                displayMessage("Certificate and private key saved in PKCS#12 format to " + filename);
            }
        } else {
            displayMessage("Failed to download certificate: " + responseJson["message"].get<String>());
        }
    }
    catch (const exception& e) {
        displayMessage("Error parsing response: " + String(e.what()));
    }
}

void ClientConsole::validateCertificate() {
    system("cls");
    cout << "=== Validate Certificate ===" << endl;
    
    const String certsDir = "Certs";
    filesystem::create_directories(certsDir);
    
    vector<String> certFiles;
    try {
        for (const auto& entry : filesystem::directory_iterator(certsDir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".pem") {
                certFiles.push_back(entry.path().string());
            }
        }
    } catch (const exception& e) {
        displayMessage("Error reading certificate directory: " + String(e.what()));
        return;
    }
    
    if (certFiles.empty()) {
        displayMessage("No certificate files found in the Certs folder. Please download certificates first.");
        return;
    }
    
    cout << "Available Certificate Files:" << endl;
    cout << "----------------------------" << endl;
    for (size_t i = 0; i < certFiles.size(); i++) {
        // Extract just the filename for display
        String displayName = filesystem::path(certFiles[i]).filename().string();
        cout << i + 1 << ". " << displayName << endl;
    }
    cout << "----------------------------" << endl;
    cout << endl;
    
    int selection = getIntInput("Enter the number of the certificate to validate (0 to cancel): ");
    if (selection <= 0 || selection > static_cast<int>(certFiles.size())) {
        if (selection != 0) {
            displayMessage("Invalid selection.");
        }
        return;
    }
    
    String filename = certFiles[selection - 1];
    
    ifstream certFile(filename);
    if (!certFile.is_open()) {
        displayMessage("Failed to open certificate file: " + filename);
        return;
    }
    
    stringstream certStream;
    certStream << certFile.rdbuf();
    String certificateData = certStream.str();
    certFile.close();
    
    cout << "\nValidating certificate: " << filesystem::path(filename).filename().string() << endl;
    cout << "----------------------------" << endl;
    
    json payload;
    payload["certificateData"] = certificateData;
    
    String response = sendRequest("validate_certificate", payload);
    
    try {
        json responseJson = json::parse(response);
        
        if (responseJson["status"] == "success") {
            bool valid = responseJson["data"]["valid"];
            
            cout << "Validation result: ";
            if (valid) {
                cout << "VALID" << endl;
                cout << "The certificate is valid and issued by a trusted CA." << endl;
                cout << "It has not been revoked and is within its validity period." << endl;
            } else {
                cout << "INVALID" << endl;
                cout << "The certificate is invalid or has been revoked." << endl;
                
                if (responseJson["data"].contains("error")) {
                    cout << "Error: " << responseJson["data"]["error"].get<String>() << endl;
                }
            }
            
            cout << "----------------------------" << endl;
            waitForEnter();
        } else {
            displayMessage("Failed to validate certificate: " + responseJson["message"].get<String>());
        }
    }
    catch (const exception& e) {
        displayMessage("Error parsing response: " + String(e.what()));
    }
}

String ClientConsole::sendRequest(const String& action, const map<String, String>& payload) {
    json request;
    request["action"] = action;
    
    json payloadJson = json::object();
    for (const auto& pair : payload) {
        payloadJson[pair.first] = pair.second;
    }
    request["payload"] = payloadJson;
    
    if (loggedIn && !sessionToken.empty()) {
        request["token"] = sessionToken;
    }
    
    String requestStr = request.dump();
    
    ClientSocket socket;
    if (!socket.connect("localhost", 8080)) {
        json errorResponse;
        errorResponse["status"] = "error";
        errorResponse["message"] = "Failed to connect to server";
        return errorResponse.dump();
    }
    
    if (!socket.send(requestStr)) {
        json errorResponse;
        errorResponse["status"] = "error";
        errorResponse["message"] = "Failed to send request to server";
        return errorResponse.dump();
    }
    
    String response = socket.receive();
    
    socket.close();
    
    return response;
}

String ClientConsole::simulateServerResponse(const String& request) {

    try {
        json requestJson = json::parse(request);
        String action = requestJson["action"];
        
        if (action == "login") {
            String username = requestJson["payload"]["username"];
            String password = requestJson["payload"]["password"];
            
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
            json response;
            response["status"] = "success";
            response["message"] = "Registration successful";
            return response.dump();
        }
        else if (action == "logout") {
            json response;
            response["status"] = "success";
            response["message"] = "Logout successful";
            return response.dump();
        }
        else if (action == "request_certificate") {
            json response;
            response["status"] = "success";
            response["data"]["requestID"] = 123;
            response["message"] = "CSR submitted successfully";
            return response.dump();
        }
        else if (action == "get_certificates") {
            json response;
            response["status"] = "success";
            
            json certificates = json::array();
            
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
            json response;
            response["status"] = "success";
            response["message"] = "Certificate revoked successfully";
            return response.dump();
        }
        else if (action == "download_certificate") {
            json response;
            response["status"] = "success";
            response["data"]["certificateData"] = "-----BEGIN CERTIFICATE-----\nSample certificate data\n-----END CERTIFICATE-----";
            response["message"] = "Certificate downloaded";
            return response.dump();
        }
        else {
            json response;
            response["status"] = "error";
            response["message"] = "Unknown action: " + action;
            return response.dump();
        }
    }
    catch (const exception& e) {
        json response;
        response["status"] = "error";
        response["message"] = "Error processing request: " + String(e.what());
        return response.dump();
    }
}

String ClientConsole::getInput(const String& prompt) {
    String input;
    cout << prompt;
    getline(cin, input);
    return input;
}

int ClientConsole::getIntInput(const String& prompt) {
    String input = getInput(prompt);
    try {
        return stoi(input);
    } catch (...) {
        return -1;
    }
}

void ClientConsole::waitForEnter() {
    cout << "\nPress Enter to continue...";
    cin.get();
}

void ClientConsole::displayMessage(const String& message) {
    cout << "\n" << message << endl;
    waitForEnter();
}

String ClientConsole::findMatchingPrivateKey(const String& certificateData, const String& subjectName) {
    String privateKey = ssl.findMatchingPrivateKey(
        certificateData,   
        ".",             
        true              
    );
    
    return privateKey;
}

String ClientConsole::maskInput(const String& prompt) {
    String input;
    cout << prompt;
    getline(cin, input);
    return input;
} 