#include <iostream>
#include "../include/sqlite3.h"

int main() {
    std::cout << "Placeholder to verify SQLite is working correctly." << std::endl;
    std::cout << "SQLite version: " << sqlite3_libversion() << std::endl;
    return 0;
} 