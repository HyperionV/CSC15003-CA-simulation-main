#include "../include/common.h"
#include "../include/openssl_wrapper.h"
#include "../include/client_console.h"

int main() {
    // Initialize OpenSSL
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Initialize OpenSSL wrapper
    OpenSSLWrapper sslWrapper;
    
    // Start client console
    ClientConsole console(sslWrapper);
    console.run();
    
    // Cleanup OpenSSL
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    
    return 0;
} 