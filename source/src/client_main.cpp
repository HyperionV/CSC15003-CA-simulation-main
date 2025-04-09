#include "../include/common.h"
#include "../include/openssl_wrapper.h"
#include "../include/client_console.h"

int main() {
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    OpenSSLWrapper sslWrapper;
    ClientConsole console(sslWrapper);
    console.run();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    
    return 0;
} 