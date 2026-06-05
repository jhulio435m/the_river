#include "server/user_repository.h"

#include <ctime>
#include <iostream>

#include "common/security_utils.h"
#include "common/shared_config.h"

UserRepository::~UserRepository() {
    Close();
}

bool UserRepository::Open(const std::string& dbPath) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ != nullptr) return true;
    return sqlite3_open(dbPath.c_str(), &db_) == SQLITE_OK;
}

void UserRepository::Close() {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ != nullptr) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool UserRepository::ExecSQLLocked(const std::string& sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        if (err != nullptr) {
            std::cerr << "[DB] " << err << std::endl;
            sqlite3_free(err);
        }
        return false;
    }
    return true;
}

bool UserRepository::EnsureDefaultAdminLocked() {
    sqlite3_stmt* st = nullptr;
    sqlite3_prepare_v2(
        db_,
        "INSERT OR IGNORE INTO users (username, password_hash, first_login, hwid, is_admin) "
        "VALUES (?, ?, 0, NULL, 1);",
        -1, &st, nullptr);
    std::string adminHash = MakePasswordHash(river::AdminDefaultPassword());
    const std::string adminUsername = river::AdminUsername();
    sqlite3_bind_text(st, 1, adminUsername.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, adminHash.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

bool UserRepository::InitSchema() {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr) return false;

    if (!ExecSQLLocked(
            "CREATE TABLE IF NOT EXISTS users ("
            "username TEXT PRIMARY KEY,"
            "password_hash TEXT NOT NULL,"
            "first_login INTEGER DEFAULT 1,"
            "hwid TEXT,"
            "is_admin INTEGER DEFAULT 0"
            ");")) return false;

    if (!ExecSQLLocked(
            "CREATE TABLE IF NOT EXISTS banned_hwids ("
            "hwid TEXT PRIMARY KEY,"
            "reason TEXT,"
            "banned_at INTEGER"
            ");")) return false;

    char* alterErr = nullptr;
    int alterRc = sqlite3_exec(db_, "ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0;", nullptr, nullptr, &alterErr);
    if (alterRc != SQLITE_OK && alterErr != nullptr) {
        std::string msg = alterErr;
        if (msg.find("duplicate column name") == std::string::npos) {
            std::cerr << "[DB] " << msg << std::endl;
            sqlite3_free(alterErr);
            return false;
        }
        sqlite3_free(alterErr);
    }

    return EnsureDefaultAdminLocked();
}

UserRecord UserRepository::FindUserByCredentials(const std::string& username, const std::string& password) {
    std::lock_guard<std::mutex> lk(mutex_);
    UserRecord record;
    if (db_ == nullptr) return record;

    sqlite3_stmt* st = nullptr;
    sqlite3_prepare_v2(
        db_,
        "SELECT password_hash, first_login, hwid, is_admin FROM users WHERE username=?;",
        -1, &st, nullptr);
    sqlite3_bind_text(st, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char* hash = sqlite3_column_text(st, 0);
        const std::string storedHash = hash ? reinterpret_cast<const char*>(hash) : "";
        if (VerifyPasswordHash(password, storedHash)) {
            record.found = true;
            record.firstLogin = sqlite3_column_int(st, 1);
            const unsigned char* hwid = sqlite3_column_text(st, 2);
            record.hwid = hwid ? reinterpret_cast<const char*>(hwid) : "";
            record.isAdmin = sqlite3_column_int(st, 3) == 1;
        }
    }
    sqlite3_finalize(st);
    return record;
}

UserRecord UserRepository::FindUserByUsername(const std::string& username) {
    std::lock_guard<std::mutex> lk(mutex_);
    UserRecord record;
    if (db_ == nullptr) return record;

    sqlite3_stmt* st = nullptr;
    sqlite3_prepare_v2(
        db_,
        "SELECT first_login, hwid, is_admin FROM users WHERE username=?;",
        -1, &st, nullptr);
    sqlite3_bind_text(st, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        record.found = true;
        record.firstLogin = sqlite3_column_int(st, 0);
        const unsigned char* hwid = sqlite3_column_text(st, 1);
        record.hwid = hwid ? reinterpret_cast<const char*>(hwid) : "";
        record.isAdmin = sqlite3_column_int(st, 2) == 1;
    }
    sqlite3_finalize(st);
    return record;
}

bool UserRepository::UpdateUserHwid(const std::string& username, const std::string& hwid) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr) return false;

    sqlite3_stmt* st = nullptr;
    sqlite3_prepare_v2(db_, "UPDATE users SET hwid=? WHERE username=?;", -1, &st, nullptr);
    sqlite3_bind_text(st, 1, hwid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

bool UserRepository::IsHwidBanned(const std::string& hwid) {
    if (hwid.empty()) return false;

    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr) return false;

    sqlite3_stmt* st = nullptr;
    sqlite3_prepare_v2(db_, "SELECT 1 FROM banned_hwids WHERE hwid=?;", -1, &st, nullptr);
    sqlite3_bind_text(st, 1, hwid.c_str(), -1, SQLITE_TRANSIENT);
    bool banned = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return banned;
}

bool UserRepository::BanHwid(const std::string& hwid, const std::string& reason) {
    if (hwid.empty()) return false;

    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr) return false;

    sqlite3_stmt* st = nullptr;
    sqlite3_prepare_v2(
        db_,
        "INSERT OR REPLACE INTO banned_hwids (hwid, reason, banned_at) VALUES (?, ?, ?);",
        -1, &st, nullptr);
    sqlite3_bind_text(st, 1, hwid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, reason.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)time(nullptr));
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

bool UserRepository::UnbanHwid(const std::string& hwid) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr) return false;

    sqlite3_stmt* st = nullptr;
    sqlite3_prepare_v2(db_, "DELETE FROM banned_hwids WHERE hwid=?;", -1, &st, nullptr);
    sqlite3_bind_text(st, 1, hwid.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

bool UserRepository::UserExistsLocked(const std::string& username) {
    sqlite3_stmt* st = nullptr;
    sqlite3_prepare_v2(db_, "SELECT 1 FROM users WHERE username=?;", -1, &st, nullptr);
    sqlite3_bind_text(st, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    bool exists = sqlite3_step(st) == SQLITE_ROW;
    sqlite3_finalize(st);
    return exists;
}

bool UserRepository::UserExists(const std::string& username) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr) return false;
    return UserExistsLocked(username);
}

bool UserRepository::GetPasswordHash(const std::string& username, std::string& passwordHash) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr) return false;
    sqlite3_stmt* st = nullptr;
    sqlite3_prepare_v2(db_, "SELECT password_hash FROM users WHERE username=?;", -1, &st, nullptr);
    sqlite3_bind_text(st, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    bool found = false;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char* hash = sqlite3_column_text(st, 0);
        passwordHash = hash ? reinterpret_cast<const char*>(hash) : "";
        found = !passwordHash.empty();
    }
    sqlite3_finalize(st);
    return found;
}

std::string UserRepository::NextSequentialUsernameLocked() {
    sqlite3_stmt* st = nullptr;
    sqlite3_prepare_v2(
        db_,
        "SELECT COALESCE(MAX(CAST(SUBSTR(username, 5) AS INTEGER)), 0) "
        "FROM users WHERE username GLOB 'user[0-9]*';",
        -1, &st, nullptr);
    int nextId = 1;
    if (sqlite3_step(st) == SQLITE_ROW)
        nextId = sqlite3_column_int(st, 0) + 1;
    sqlite3_finalize(st);
    return "user" + std::to_string(nextId);
}

bool UserRepository::CreateNextUser(std::string& createdUsername) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr) return false;

    createdUsername = NextSequentialUsernameLocked();
    sqlite3_stmt* st = nullptr;
    std::string passwordHash = MakePasswordHash(river::DefaultUserPassword());
    sqlite3_prepare_v2(
        db_,
        "INSERT INTO users (username, password_hash, first_login, hwid, is_admin) "
        "VALUES (?, ?, 1, NULL, 0);",
        -1, &st, nullptr);
    sqlite3_bind_text(st, 1, createdUsername.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, passwordHash.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

bool UserRepository::ResetUserPassword(const std::string& username, const std::string& newPassword) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr || username.empty() || newPassword.empty()) return false;

    sqlite3_stmt* st = nullptr;
    std::string passwordHash = MakePasswordHash(newPassword);
    sqlite3_prepare_v2(
        db_,
        "UPDATE users SET password_hash=?, first_login=0 WHERE username=?;",
        -1, &st, nullptr);
    sqlite3_bind_text(st, 1, passwordHash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, username.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db_) > 0;
    sqlite3_finalize(st);
    return ok;
}

bool UserRepository::CompleteFirstLogin(const std::string& oldUsername,
                                        const std::string& newUsername,
                                        const std::string& newPassword) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr || oldUsername.empty() || newUsername.empty() || newPassword.empty()) return false;
    if (newUsername != oldUsername && UserExistsLocked(newUsername)) return false;

    sqlite3_stmt* st = nullptr;
    std::string passwordHash = MakePasswordHash(newPassword);
    sqlite3_prepare_v2(
        db_,
        "UPDATE users SET username=?, password_hash=?, first_login=0 "
        "WHERE username=? AND is_admin=0;",
        -1, &st, nullptr);
    sqlite3_bind_text(st, 1, newUsername.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, passwordHash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, oldUsername.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db_) > 0;
    sqlite3_finalize(st);
    return ok;
}
