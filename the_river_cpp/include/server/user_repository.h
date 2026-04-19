#pragma once

#include <mutex>
#include <string>

#include <sqlite3.h>

struct UserRecord {
    bool found = false;
    bool isAdmin = false;
    int firstLogin = 0;
    std::string hwid;
};

class UserRepository {
public:
    UserRepository() = default;
    ~UserRepository();

    bool Open(const std::string& dbPath);
    void Close();
    bool InitSchema();

    UserRecord FindUserByCredentials(const std::string& username, const std::string& password);
    bool UpdateUserHwid(const std::string& username, const std::string& hwid);
    bool IsHwidBanned(const std::string& hwid);
    bool BanHwid(const std::string& hwid, const std::string& reason);
    bool UnbanHwid(const std::string& hwid);
    bool CreateNextUser(std::string& createdUsername);
    bool ResetUserPassword(const std::string& username, const std::string& newPassword);
    bool CompleteFirstLogin(const std::string& oldUsername,
                            const std::string& newUsername,
                            const std::string& newPassword);

private:
    bool ExecSQLLocked(const std::string& sql);
    bool EnsureDefaultAdminLocked();
    bool UserExistsLocked(const std::string& username);
    std::string NextSequentialUsernameLocked();

    sqlite3* db_ = nullptr;
    std::mutex mutex_;
};
