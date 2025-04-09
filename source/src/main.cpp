#include "../include/common.h"
#include "../include/database.h"
#include "../include/auth_system.h"
#include "../include/openssl_wrapper.h"
#include "../include/certificate_authority.h"
#include "../include/server_console.h"
#include "../include/server_handler.h"
#include <thread>

void runServerHandler(ServerHandler& handler) {
    handler.start(8080);
}

int main() {
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    DatabaseManager dbManager;
    if (!dbManager.initialize()) {
        cerr << "Failed to initialize database. Exiting." << endl;
        return 1;
    }
    AuthenticationSystem authSystem(dbManager);
    OpenSSLWrapper sslWrapper;
    CertificateAuthority ca(dbManager, sslWrapper);
    if (!ca.initialize(DATA_DIR + "ca_config.json")) {
        cerr << "Failed to initialize CA. Exiting." << endl;
        return 1;
    }
    cout << "CA Management System initialized successfully." << endl;
    ServerHandler serverHandler(authSystem, ca, dbManager);
    thread serverThread(runServerHandler, ref(serverHandler));
    ServerConsole console(authSystem, ca, dbManager);
    console.run();
    serverHandler.stop();
    if (serverThread.joinable()) {
        serverThread.join();
    }
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    
    return 0;
} 