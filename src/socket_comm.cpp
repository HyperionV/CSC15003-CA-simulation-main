#include "../include/socket_comm.h"

bool SocketManager::initialize() {
    WSADATA wsaData;
    return (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);
}

void SocketManager::cleanup() {
    WSACleanup();
}

ServerSocket::ServerSocket(int port) : serverSocket(INVALID_SOCKET), port(port), bound(false) {
}

ServerSocket::~ServerSocket() {
    close();
}

bool ServerSocket::bind() {
    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Error creating socket: " << WSAGetLastError() << std::endl;
        return false;
    }
    
    // Set up server address
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);
    
    // Bind socket
    if (::bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed: " << WSAGetLastError() << std::endl;
        closesocket(serverSocket);
        serverSocket = INVALID_SOCKET;
        return false;
    }
    
    bound = true;
    return true;
}

bool ServerSocket::listen(int backlog) {
    if (!bound || serverSocket == INVALID_SOCKET) {
        return false;
    }
    
    if (::listen(serverSocket, backlog) == SOCKET_ERROR) {
        std::cerr << "Listen failed: " << WSAGetLastError() << std::endl;
        return false;
    }
    
    return true;
}

SOCKET ServerSocket::accept() {
    if (!bound || serverSocket == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }
    
    sockaddr_in clientAddr;
    int clientAddrSize = sizeof(clientAddr);
    
    SOCKET clientSocket = ::accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrSize);
    
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Accept failed: " << WSAGetLastError() << std::endl;
    }
    
    return clientSocket;
}

void ServerSocket::close() {
    if (serverSocket != INVALID_SOCKET) {
        closesocket(serverSocket);
        serverSocket = INVALID_SOCKET;
    }
    bound = false;
}

ClientSocket::ClientSocket() : clientSocket(INVALID_SOCKET), connected(false) {
}

ClientSocket::~ClientSocket() {
    close();
}

bool ClientSocket::connect(const String& host, int port) {
    // Create socket
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Error creating socket: " << WSAGetLastError() << std::endl;
        return false;
    }
    
    // Set up server address
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    
    // Convert host to IP
    inet_pton(AF_INET, host.c_str(), &serverAddr.sin_addr);
    
    // Connect to server
    if (::connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connect failed: " << WSAGetLastError() << std::endl;
        closesocket(clientSocket);
        clientSocket = INVALID_SOCKET;
        return false;
    }
    
    connected = true;
    return true;
}

bool ClientSocket::send(const String& message) {
    if (!connected || clientSocket == INVALID_SOCKET) {
        return false;
    }
    
    // Add message length prefix
    uint32_t length = message.length();
    if (::send(clientSocket, (char*)&length, sizeof(length), 0) == SOCKET_ERROR) {
        std::cerr << "Send length failed: " << WSAGetLastError() << std::endl;
        return false;
    }
    
    // Send message
    if (::send(clientSocket, message.c_str(), length, 0) == SOCKET_ERROR) {
        std::cerr << "Send message failed: " << WSAGetLastError() << std::endl;
        return false;
    }
    
    return true;
}

String ClientSocket::receive() {
    if (!connected || clientSocket == INVALID_SOCKET) {
        return "";
    }
    
    // Receive message length
    uint32_t length = 0;
    int bytesReceived = ::recv(clientSocket, (char*)&length, sizeof(length), 0);
    
    if (bytesReceived <= 0) {
        if (bytesReceived == 0) {
            // Connection closed
            close();
        } else {
            std::cerr << "Receive length failed: " << WSAGetLastError() << std::endl;
        }
        return "";
    }
    
    // Receive message
    std::vector<char> buffer(length + 1, 0);
    bytesReceived = ::recv(clientSocket, buffer.data(), length, 0);
    
    if (bytesReceived <= 0) {
        if (bytesReceived == 0) {
            // Connection closed
            close();
        } else {
            std::cerr << "Receive message failed: " << WSAGetLastError() << std::endl;
        }
        return "";
    }
    
    return String(buffer.data(), bytesReceived);
}

void ClientSocket::close() {
    if (clientSocket != INVALID_SOCKET) {
        closesocket(clientSocket);
        clientSocket = INVALID_SOCKET;
    }
    connected = false;
} 