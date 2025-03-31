#include "../include/common.h"
#include "../include/database.h"
#include "../include/auth_system.h"
#include "../include/openssl_wrapper.h"
#include "../include/certificate_authority.h"
#include "../include/server_console.h"

int main() {
    // Initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Initialize database
    DatabaseManager dbManager;
    if (!dbManager.initialize()) {
        std::cerr << "Failed to initialize database. Exiting." << std::endl;
        return 1;
    }
    
    // Initialize authentication system
    AuthenticationSystem authSystem(dbManager);
    
    // Initialize OpenSSL wrapper
    OpenSSLWrapper sslWrapper;
    
    // Initialize certificate authority
    CertificateAuthority ca(dbManager, sslWrapper);
    if (!ca.initialize(DATA_DIR + "ca_config.json")) {
        std::cerr << "Failed to initialize CA. Exiting." << std::endl;
        return 1;
    }
    
    std::cout << "CA Management System initialized successfully." << std::endl;
    
    // Start server console
    ServerConsole console(authSystem, ca, dbManager);
    console.run();
    
    // Cleanup OpenSSL
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    
    return 0;
} 