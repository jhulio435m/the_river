#include <iostream>
#include <sqlite3.h>

int main() {
    sqlite3* db;
    if (sqlite3_open("secure_river.db", &db) != SQLITE_OK) {
        std::cerr << "Error abriendo DB" << std::endl;
        return 1;
    }

    const char* sql = "SELECT username, first_login, hwid FROM users;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, 0);

    std::cout << "USER | FIRST_LOGIN | HWID" << std::endl;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* user = (const char*)sqlite3_column_text(stmt, 0);
        int fl = sqlite3_column_int(stmt, 1);
        const char* hwid = (const char*)sqlite3_column_text(stmt, 2);
        std::cout << (user?user:"NULL") << " | " << fl << " | " << (hwid?hwid:"NULL") << std::endl;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}
