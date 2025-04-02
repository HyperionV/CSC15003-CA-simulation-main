#pragma once
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <memory>
#include <stdexcept>
#include <filesystem>
#include <iomanip>


#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/pkcs12.h>



#include "sqlite3.h"

// Common typedefs and constants
typedef std::string String;
typedef unsigned int uint;

// Simple error handling macro - commented out for now
/*
#define CHECK_SSL_ERROR(expr) if(!(expr)) { \
    unsigned long err = ERR_get_error(); \
    char* err_msg = ERR_error_string(err, nullptr); \
    std::cerr << "OpenSSL error: " << err_msg << std::endl; \
    return false; \
}
*/

// Project paths
const String DATA_DIR = "./data/";
const String CERT_DIR = DATA_DIR + "certs/";
const String KEY_DIR = DATA_DIR + "keys/";
const String DB_DIR = DATA_DIR + "db/";
const String DB_FILE = DB_DIR + "ca.db"; 