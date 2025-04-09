#include <iostream>
#include "../include/sqlite3.h"

int main() {
    cout << "Placeholder to verify SQLite is working correctly." << endl;
    cout << "SQLite version: " << sqlite3_libversion() << endl;
    return 0;
} 