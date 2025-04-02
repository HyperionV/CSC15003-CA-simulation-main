#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "../include/server_handler.h"
#include <vector>

ServerHandler::ServerHandler(AuthenticationSystem& authSystem, 
                           CertificateAuthority& ca, 
                           DatabaseManager& dbManager)
    : auth(authSystem), ca(ca), db(dbManager), serverSocket(8080), running(false) {
}

bool ServerHandler::start(int port) {
    // Initialize socket
    if (!SocketManager::initialize()) {
        std::cerr << "Failed to initialize socket manager" << std::endl;
        return false;
    }
    
    // Bind socket
    serverSocket = ServerSocket(port);
    if (!serverSocket.bind()) {
        std::cerr << "Failed to bind server socket" << std::endl;
        return false;
    }
    
    // Listen for connections
    if (!serverSocket.listen()) {
        std::cerr << "Failed to listen on server socket" << std::endl;
        return false;
    }
    
    std::cout << "Server started on port " << port << std::endl;
    
    running = true;
    
    // Accept and handle client connections
    while (running) {
        SOCKET clientSocket = serverSocket.accept();
        if (clientSocket != INVALID_SOCKET) {
            // In a real server, we would create a thread for each client
            // For simplicity, we'll handle clients sequentially
            handleClient(clientSocket);
        }
    }
    
    return true;
}

void ServerHandler::stop() {
    running = false;
    serverSocket.close();
    SocketManager::cleanup();
}

void ServerHandler::handleClient(SOCKET clientSocket) {
    // Receive and process client messages
    bool connected = true;
    
    while (connected) {
        // First receive the length prefix
        uint32_t length = 0;
        int bytesReceived = recv(clientSocket, (char*)&length, sizeof(length), 0);
        
        // Now receive the exact message length
        std::vector<char> buffer(length + 1, 0);
        bytesReceived = recv(clientSocket, buffer.data(), length, 0);
        
        
        // Null-terminate the received data and process it
        buffer[bytesReceived] = '\0';
        String request(buffer.data(), bytesReceived);
        String response = processRequest(request);
        
        // Send response to client
        // First send the length prefix
        length = response.length();
        if (send(clientSocket, (char*)&length, sizeof(length), 0) == SOCKET_ERROR) {
            std::cerr << "Send length failed: " << WSAGetLastError() << std::endl;
            break;
        }
        
        // Then send the actual response
        if (send(clientSocket, response.c_str(), length, 0) == SOCKET_ERROR) {
            std::cerr << "Send response failed: " << WSAGetLastError() << std::endl;
            break;
        }
    }
    
    // Close the client socket
    closesocket(clientSocket);
}

String ServerHandler::processRequest(const String& request) {
    try {
        // Parse JSON request
        json requestJson = json::parse(request);
        
        // Extract action and payload
        String action = requestJson["action"];
        json payload = requestJson["payload"];
        
        // Check if request includes a session token
        String token = "";
        if (requestJson.contains("token")) {
            token = requestJson["token"];
        }
        
        // Process based on action
        json responseJson;
        
        if (action == "login") {
            responseJson = handleLogin(payload);
        }
        else if (action == "register") {
            responseJson = handleRegister(payload);
        }
        else if (action == "logout") {
            responseJson = handleLogout(payload, token);
        }
        else if (action == "request_certificate") {
            responseJson = handleRequestCertificate(payload, token);
        }
        else if (action == "get_certificates") {
            responseJson = handleGetCertificates(payload, token);
        }
        else if (action == "revoke_certificate") {
            responseJson = handleRevokeCertificate(payload, token);
        }
        else if (action == "download_certificate") {
            responseJson = handleDownloadCertificate(payload, token);
        }
        else if (action == "validate_certificate") {
            responseJson = handleValidateCertificate(payload, token);
        }
        else {
            responseJson["status"] = "error";
            responseJson["message"] = "Unknown action: " + action;
        }
        
        // Return JSON response
        return responseJson.dump();
    }
    catch (const std::exception& e) {
        // Handle parsing errors
        json errorResponse;
        errorResponse["status"] = "error";
        errorResponse["message"] = "Error processing request: " + String(e.what());
        return errorResponse.dump();
    }
}

json ServerHandler::handleLogin(const json& payload) {
    json response;
    
    String username = payload["username"];
    String password = payload["password"];
    
    if (auth.login(username, password)) {
        String token = auth.createSession(username);
        
        response["status"] = "success";
        response["data"]["token"] = token;
        response["message"] = "Login successful";
        
        // Log the login
        db.logActivity("User login", db.getUserID(username), 0, "User logged in: " + username);
    } else {
        response["status"] = "error";
        response["message"] = "Invalid credentials";
    }
    
    return response;
}

json ServerHandler::handleRegister(const json& payload) {
    json response;
    
    String username = payload["username"];
    String password = payload["password"];
    String email = payload["email"];
    
    if (auth.registerUser(username, password, email)) {
        response["status"] = "success";
        response["message"] = "Registration successful";
    } else {
        response["status"] = "error";
        response["message"] = "Registration failed";
    }
    
    return response;
}

json ServerHandler::handleLogout(const json& payload, const String& token) {
    json response;
    
    if (auth.terminateSession(token)) {
        response["status"] = "success";
        response["message"] = "Logout successful";
    } else {
        response["status"] = "error";
        response["message"] = "Invalid session";
    }
    
    return response;
}

json ServerHandler::handleRequestCertificate(const json& payload, const String& token) {
    json response;
    
    // Validate session
    if (!auth.validateSession(token)) {
        response["status"] = "error";
        response["message"] = "Authentication required";
        return response;
    }
    
    String username = auth.getUsernameFromToken(token);
    String csrData = payload["csr"];
    
    int requestID = ca.submitCSR(csrData, username);
    
    if (requestID > 0) {
        response["status"] = "success";
        response["data"]["requestID"] = requestID;
        response["message"] = "CSR submitted successfully";
    } else {
        response["status"] = "error";
        response["message"] = "Failed to submit CSR";
    }
    
    return response;
}

json ServerHandler::handleGetCertificates(const json& payload, const String& token) {
    json response;
    
    // Validate session
    if (!auth.validateSession(token)) {
        response["status"] = "error";
        response["message"] = "Authentication required";
        return response;
    }
    
    String username = auth.getUsernameFromToken(token);
    int userID = db.getUserID(username);
    
    auto certificates = db.getUserCertificates(userID);
    
    response["status"] = "success";
    response["data"]["certificates"] = json::array();
    
    for (const auto& cert : certificates) {
        json certJson;
        certJson["certificateID"] = cert.certificateID;
        certJson["serialNumber"] = cert.serialNumber;
        certJson["subjectName"] = cert.subjectName;
        certJson["status"] = cert.status;
        certJson["validTo"] = cert.validTo;
        
        response["data"]["certificates"].push_back(certJson);
    }
    
    response["message"] = "Certificates retrieved";
    
    return response;
}

json ServerHandler::handleRevokeCertificate(const json& payload, const String& token) {
    json response;
    
    // Validate session
    if (!auth.validateSession(token)) {
        response["status"] = "error";
        response["message"] = "Authentication required";
        return response;
    }
    
    String username = auth.getUsernameFromToken(token);
    int certificateID = std::stoi(payload["certificateID"].get<String>());
    String reason = payload["reason"];
    
    if (ca.revokeCertificate(certificateID, reason, username)) {
        response["status"] = "success";
        response["message"] = "Certificate revoked successfully";
    } else {
        response["status"] = "error";
        response["message"] = "Failed to revoke certificate";
    }
    
    return response;
}

json ServerHandler::handleDownloadCertificate(const json& payload, const String& token) {
    json response;
    
    // Validate session
    if (!auth.validateSession(token)) {
        response["status"] = "error";
        response["message"] = "Authentication required";
        return response;
    }
    
    String username = auth.getUsernameFromToken(token);
    int certificateID = std::stoi(payload["certificateID"].get<String>());
    
    // Get certificate data
    auto certData = db.getCertificateData(certificateID);
    
    if (!certData.empty()) {
        response["status"] = "success";
        response["data"]["certificateData"] = certData;
        response["message"] = "Certificate downloaded";
    } else {
        response["status"] = "error";
        response["message"] = "Failed to download certificate";
    }
    
    return response;
}

json ServerHandler::handleValidateCertificate(const json& payload, const String& token) {
    json response;
    
    // Validate session
    if (!auth.validateSession(token)) {
        response["status"] = "error";
        response["message"] = "Authentication required";
        return response;
    }
    
    String certificateData = payload["certificateData"];
    
    // First, try to parse the certificate to check its basic format
    BIO* certBio = BIO_new_mem_buf(certificateData.c_str(), -1);
    X509* cert = PEM_read_bio_X509(certBio, nullptr, nullptr, nullptr);
    BIO_free(certBio);
    
    if (!cert) {
        response["status"] = "success";
        response["data"]["valid"] = false;
        response["data"]["error"] = "Invalid certificate format";
        response["message"] = "Certificate validation failed";
        return response;
    }
    
    // Certificate is valid format, now check its validity against CA
    bool valid = ca.validateCertificate(certificateData);
    
    // Clean up the X509 object
    X509_free(cert);
    
    if (valid) {
        response["status"] = "success";
        response["data"]["valid"] = true;
        response["message"] = "Certificate is valid";
    } else {
        response["status"] = "success";
        response["data"]["valid"] = false;
        
        // Get specific error detail from certificate authority
        // For now, we'll provide a generic message, but in a real implementation
        // the CA could return specific error details (expiration, revocation, etc.)
        response["data"]["error"] = "The certificate is not trusted, has expired, or has been revoked";
        response["message"] = "Certificate is invalid";
    }
    
    return response;
} 