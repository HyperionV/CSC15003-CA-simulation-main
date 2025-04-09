#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

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
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        cerr << "Error creating socket: " << WSAGetLastError() << endl;
        return false;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (::bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Bind failed: " << WSAGetLastError() << endl;
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
        cerr << "Listen failed: " << WSAGetLastError() << endl;
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
        cerr << "Accept failed: " << WSAGetLastError() << endl;
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
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        cerr << "Error creating socket: " << WSAGetLastError() << endl;
        return false;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);

    int result = inet_pton(AF_INET, host.c_str(), &serverAddr.sin_addr);
    if (result <= 0) {
        if (host == "localhost") {
            inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);
        } else {
            cerr << "Invalid address: " << host << ", error: " << (result == 0 ? "Not a valid address" : "Conversion error") << endl;
            closesocket(clientSocket);
            clientSocket = INVALID_SOCKET;
            return false;
        }
    }
    

    if (::connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Connect failed: " << WSAGetLastError() << endl;
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
    
    uint32_t length = message.length();
    if (::send(clientSocket, (char*)&length, sizeof(length), 0) == SOCKET_ERROR) {
        cerr << "Send length failed: " << WSAGetLastError() << endl;
        return false;
    }

    if (::send(clientSocket, message.c_str(), length, 0) == SOCKET_ERROR) {
        cerr << "Send message failed: " << WSAGetLastError() << endl;
        return false;
    }
    
    return true;
}

String ClientSocket::receive() {
    if (!connected || clientSocket == INVALID_SOCKET) {
        return "";
    }

    uint32_t length = 0;
    int bytesReceived = ::recv(clientSocket, (char*)&length, sizeof(length), 0);
    
    if (bytesReceived <= 0) {
        if (bytesReceived == 0) {
            close();
        } else {
            cerr << "Receive length failed: " << WSAGetLastError() << endl;
        }
        return "";
    }

    vector<char> buffer(length + 1, 0);
    bytesReceived = ::recv(clientSocket, buffer.data(), length, 0);
    
    if (bytesReceived <= 0) {
        if (bytesReceived == 0) {
            close();
        } else {
            cerr << "Receive message failed: " << WSAGetLastError() << endl;
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