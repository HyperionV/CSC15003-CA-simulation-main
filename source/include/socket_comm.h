#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "common.h"
#include <WinSock2.h>
#include <WS2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

class SocketManager {
public:
    static bool initialize();
    static void cleanup();
};

class ServerSocket {
public:
    ServerSocket(int port);
    ~ServerSocket();
    
    bool bind();
    bool listen(int backlog = 5);
    SOCKET accept();
    void close();
    
private:
    SOCKET serverSocket;
    int port;
    bool bound;
};

class ClientSocket {
public:
    ClientSocket();
    ~ClientSocket();
    
    bool connect(const String& host, int port);
    bool send(const String& message);
    String receive();
    void close();
    
private:
    SOCKET clientSocket;
    bool connected;
}; 