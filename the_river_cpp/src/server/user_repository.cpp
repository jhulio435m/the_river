#include "server/user_repository.h"

#include <ctime>
#include <iostream>

#include "common/scram.h"
#include "common/secure_envelope.h"
#include "common/security_utils.h"
#include "common/shared_config.h"

namespace {

// RAII wrapper so every early return finalizes the statement.
class Stmt {
public:
    Stmt(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &st_, nullptr) != SQLITE_OK) {
            sqlite3_finalize(st_);
            st_ = nullptr;
        }
    }
    ~Stmt() { sqlite3_finalize(st_); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;
    bool ok() const { return st_ != nullptr; }
    sqlite3_stmt* get() const { return st_; }
    void Text(int idx, const std::string& v) { sqlite3_bind_text(st_, idx, v.c_str(), -1, SQLITE_TRANSIENT); }
    void Int64(int idx, long long v) { sqlite3_bind_int64(st_, idx, static_cast<sqlite3_int64>(v)); }
    int Step() { return st_ ? sqlite3_step(st_) : SQLITE_ERROR; }
    std::string ColText(int col) const {
        const unsigned char* t = sqlite3_column_text(st_, col);
        return t ? reinterpret_cast<const char*>(t) : "";
    }
    long long ColInt64(int col) const { return static_cast<long long>(sqlite3_column_int64(st_, col)); }

private:
    sqlite3_stmt* st_ = nullptr;
};

std::string MakeScramCredentialString(const std::string& password) {
    river::scram::Credential credential;
    if (!river::scram::MakeCredential(password, credential)) return "";
    return river::scram::Serialize(credential);
}

}  // namespace

UserRepository::~UserRepository() {
    Close();
}

bool UserRepository::Open(const std::string& dbPath) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ != nullptr) return true;
    if (sqlite3_open(dbPath.c_str(), &db_) != SQLITE_OK) {
        if (db_ != nullptr) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return false;
    }
    // Tolerate brief concurrent access (e.g. check_db or backups) instead of failing instantly.
    sqlite3_busy_timeout(db_, 3000);
    return true;
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

int UserRepository::SchemaVersionLocked() {
    sqlite3_stmt* st = nullptr;
    int version = 0;
    if (sqlite3_prepare_v2(db_, "PRAGMA user_version;", -1, &st, nullptr) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) {
        version = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return version;
}

bool UserRepository::SetSchemaVersionLocked(int version) {
    return ExecSQLLocked("PRAGMA user_version = " + std::to_string(version) + ";");
}

bool UserRepository::EnsureDefaultAdminLocked() {
    const std::string adminUsername = river::AdminUsername();
    if (UserExistsLocked(adminUsername)) return true;  // INSERT OR IGNORE semantics, skip PBKDF2
    const std::string adminCredential = MakeScramCredentialString(river::AdminDefaultPassword());
    if (adminCredential.empty()) return false;
    Stmt st(db_,
            "INSERT OR IGNORE INTO users (username, password_hash, first_login, hwid, is_admin) "
            "VALUES (?, ?, 0, NULL, 1);");
    if (!st.ok()) return false;
    st.Text(1, adminUsername);
    st.Text(2, adminCredential);
    return st.Step() == SQLITE_DONE;
}

bool UserRepository::MigrateV1CredentialsLocked() {
    // v1 stored "pbkdf2-sha256$iter$saltHex$hashHex" where hashHex is exactly the
    // SCRAM SaltedPassword, so every row converts without user action.
    std::vector<std::pair<std::string, std::string>> rows;
    {
        Stmt st(db_, "SELECT username, password_hash FROM users WHERE password_hash LIKE 'pbkdf2-sha256$%';");
        if (!st.ok()) return false;
        int rc;
        while ((rc = st.Step()) == SQLITE_ROW) rows.emplace_back(st.ColText(0), st.ColText(1));
        if (rc != SQLITE_DONE) return false;
    }
    for (const auto& [username, v1Hash] : rows) {
        river::scram::Credential credential;
        if (!river::scram::CredentialFromV1Hash(v1Hash, credential)) {
            // Leave the row untouched: that account cannot log in until an admin
            // runs /passwd, but one bad row must not keep the server down.
            std::cerr << "[DB] No se pudo migrar la credencial v1 de '" << username
                      << "'; requiere /passwd." << std::endl;
            continue;
        }
        const std::string serialized = river::scram::Serialize(credential);
        if (serialized.empty()) continue;
        Stmt up(db_, "UPDATE users SET password_hash=? WHERE username=?;");
        if (!up.ok()) return false;
        up.Text(1, serialized);
        up.Text(2, username);
        if (up.Step() != SQLITE_DONE) return false;
    }
    return true;
}

bool UserRepository::InitSchema() {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr) return false;

    if (!ExecSQLLocked("BEGIN IMMEDIATE;")) return false;

    if (!ExecSQLLocked(
            "CREATE TABLE IF NOT EXISTS users ("
            "username TEXT PRIMARY KEY,"
            "password_hash TEXT NOT NULL,"
            "first_login INTEGER DEFAULT 1,"
            "hwid TEXT,"
            "is_admin INTEGER DEFAULT 0"
            ");")) {
        ExecSQLLocked("ROLLBACK;");
        return false;
    }

    if (!ExecSQLLocked(
            "CREATE TABLE IF NOT EXISTS banned_hwids ("
            "hwid TEXT PRIMARY KEY,"
            "reason TEXT,"
            "banned_at INTEGER"
            ");")) {
        ExecSQLLocked("ROLLBACK;");
        return false;
    }

    const int schemaVersion = SchemaVersionLocked();
    if (schemaVersion < 1) {
        char* alterErr = nullptr;
        int alterRc = sqlite3_exec(db_, "ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0;", nullptr, nullptr, &alterErr);
        if (alterRc != SQLITE_OK) {
            std::string msg = alterErr != nullptr ? alterErr : "unknown alter table error";
            if (alterErr != nullptr) sqlite3_free(alterErr);
            if (msg.find("duplicate column name") == std::string::npos) {
                std::cerr << "[DB] " << msg << std::endl;
                ExecSQLLocked("ROLLBACK;");
                return false;
            }
        } else if (alterErr != nullptr) {
            sqlite3_free(alterErr);
        }

        if (!SetSchemaVersionLocked(1)) {
            ExecSQLLocked("ROLLBACK;");
            return false;
        }
    }

    if (!ExecSQLLocked(
            "CREATE TABLE IF NOT EXISTS user_keys ("
            "username TEXT PRIMARY KEY,"
            "pubkey TEXT NOT NULL,"
            "updated_at INTEGER NOT NULL"
            ");") ||
        !ExecSQLLocked(
            "CREATE TABLE IF NOT EXISTS room_history ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "ts INTEGER NOT NULL,"
            "from_user TEXT NOT NULL,"
            "body TEXT NOT NULL"
            ");") ||
        !ExecSQLLocked(
            "CREATE TABLE IF NOT EXISTS offline_pm ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "to_user TEXT NOT NULL,"
            "from_user TEXT NOT NULL,"
            "ts INTEGER NOT NULL,"
            "envelope TEXT NOT NULL"
            ");") ||
        !ExecSQLLocked("CREATE INDEX IF NOT EXISTS idx_offline_pm_to ON offline_pm(to_user, id);")) {
        ExecSQLLocked("ROLLBACK;");
        return false;
    }

    if (SchemaVersionLocked() < 2) {
        if (!MigrateV1CredentialsLocked() || !SetSchemaVersionLocked(2)) {
            ExecSQLLocked("ROLLBACK;");
            return false;
        }
    }

    if (!EnsureDefaultAdminLocked()) {
        ExecSQLLocked("ROLLBACK;");
        return false;
    }
    return ExecSQLLocked("COMMIT;");
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

bool UserRepository::GetCredential(const std::string& username, river::scram::Credential& credential) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr) return false;
    Stmt st(db_, "SELECT password_hash FROM users WHERE username=?;");
    if (!st.ok()) return false;
    st.Text(1, username);
    if (st.Step() != SQLITE_ROW) return false;
    return river::scram::Parse(st.ColText(0), credential);
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
    std::string passwordHash = MakeScramCredentialString(river::DefaultUserPassword());
    if (passwordHash.empty()) return false;
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
    std::string passwordHash = MakeScramCredentialString(newPassword);
    if (passwordHash.empty()) return false;
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

bool UserRepository::CompleteFirstLoginWithCredential(const std::string& oldUsername,
                                                      const std::string& newUsername,
                                                      int iterations,
                                                      const std::string& saltHex,
                                                      const std::string& storedKeyHex,
                                                      const std::string& serverKeyHex) {
    river::scram::Credential credential;
    if (!river::scram::CredentialFromParts(iterations, saltHex, storedKeyHex, serverKeyHex, credential))
        return false;
    const std::string serialized = river::scram::Serialize(credential);
    if (serialized.empty()) return false;

    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr || oldUsername.empty() || newUsername.empty()) return false;
    if (newUsername != oldUsername && UserExistsLocked(newUsername)) return false;

    if (!ExecSQLLocked("BEGIN IMMEDIATE;")) return false;
    bool ok = false;
    {
        Stmt st(db_,
                "UPDATE users SET username=?, password_hash=?, first_login=0 "
                "WHERE username=? AND is_admin=0;");
        if (st.ok()) {
            st.Text(1, newUsername);
            st.Text(2, serialized);
            st.Text(3, oldUsername);
            ok = st.Step() == SQLITE_DONE && sqlite3_changes(db_) > 0;
        }
    }
    // The renamed account starts fresh: nothing keyed by either name carries over.
    for (const char* sql : {"DELETE FROM user_keys WHERE username=?;", "DELETE FROM offline_pm WHERE to_user=?;"}) {
        for (const std::string* name : {&oldUsername, &newUsername}) {
            if (!ok) break;
            Stmt st(db_, sql);
            if (!st.ok()) { ok = false; break; }
            st.Text(1, *name);
            ok = st.Step() == SQLITE_DONE;
        }
    }
    if (!ok) {
        ExecSQLLocked("ROLLBACK;");
        return false;
    }
    return ExecSQLLocked("COMMIT;");
}

bool UserRepository::ResetUserHwid(const std::string& username) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr || username.empty()) return false;

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_, "UPDATE users SET hwid=NULL WHERE username=?;", -1, &st, nullptr) != SQLITE_OK) {
        sqlite3_finalize(st);
        return false;
    }
    sqlite3_bind_text(st, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(db_) > 0;
    sqlite3_finalize(st);
    return ok;
}

bool UserRepository::DeleteUser(const std::string& username) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr || username.empty()) return false;

    if (!ExecSQLLocked("BEGIN IMMEDIATE;")) return false;
    bool ok = false;
    {
        Stmt st(db_, "DELETE FROM users WHERE username=? AND is_admin=0;");
        if (st.ok()) {
            st.Text(1, username);
            ok = st.Step() == SQLITE_DONE && sqlite3_changes(db_) > 0;
        }
    }
    for (const char* sql : {"DELETE FROM user_keys WHERE username=?;", "DELETE FROM offline_pm WHERE to_user=?;"}) {
        if (!ok) break;
        Stmt st(db_, sql);
        if (!st.ok()) { ok = false; break; }
        st.Text(1, username);
        ok = st.Step() == SQLITE_DONE;
    }
    if (!ok) {
        ExecSQLLocked("ROLLBACK;");
        return false;
    }
    return ExecSQLLocked("COMMIT;");
}

std::vector<BannedHwidRecord> UserRepository::ListBannedHwids() {
    std::lock_guard<std::mutex> lk(mutex_);
    std::vector<BannedHwidRecord> records;
    if (db_ == nullptr) return records;

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT hwid, COALESCE(reason, ''), COALESCE(banned_at, 0) "
                           "FROM banned_hwids ORDER BY banned_at DESC;",
                           -1, &st, nullptr) != SQLITE_OK) {
        sqlite3_finalize(st);
        return records;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        BannedHwidRecord record;
        const unsigned char* hwid = sqlite3_column_text(st, 0);
        const unsigned char* reason = sqlite3_column_text(st, 1);
        record.hwid = hwid ? reinterpret_cast<const char*>(hwid) : "";
        record.reason = reason ? reinterpret_cast<const char*>(reason) : "";
        record.bannedAt = static_cast<long long>(sqlite3_column_int64(st, 2));
        records.push_back(record);
    }
    sqlite3_finalize(st);
    return records;
}

std::vector<UserSummary> UserRepository::ListUsers() {
    std::lock_guard<std::mutex> lk(mutex_);
    std::vector<UserSummary> users;
    if (db_ == nullptr) return users;

    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(db_,
                           "SELECT username, is_admin, first_login, "
                           "CASE WHEN hwid IS NULL OR hwid = '' THEN 0 ELSE 1 END "
                           "FROM users ORDER BY username;",
                           -1, &st, nullptr) != SQLITE_OK) {
        sqlite3_finalize(st);
        return users;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        UserSummary summary;
        const unsigned char* name = sqlite3_column_text(st, 0);
        summary.username = name ? reinterpret_cast<const char*>(name) : "";
        summary.isAdmin = sqlite3_column_int(st, 1) == 1;
        summary.firstLoginPending = sqlite3_column_int(st, 2) == 1;
        summary.hwidBound = sqlite3_column_int(st, 3) == 1;
        users.push_back(summary);
    }
    sqlite3_finalize(st);
    return users;
}

KeySetResult UserRepository::SetUserKey(const std::string& username, const std::string& pubKeyB64) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr || username.empty() || pubKeyB64.empty()) return KeySetResult::Error;

    std::string previous;
    bool hadKey = false;
    {
        Stmt st(db_, "SELECT pubkey FROM user_keys WHERE username=?;");
        if (!st.ok()) return KeySetResult::Error;
        st.Text(1, username);
        const int rc = st.Step();
        if (rc == SQLITE_ROW) {
            previous = st.ColText(0);
            hadKey = true;
        } else if (rc != SQLITE_DONE) {
            return KeySetResult::Error;
        }
    }
    if (hadKey && previous == pubKeyB64) return KeySetResult::Unchanged;

    Stmt st(db_,
            "INSERT INTO user_keys (username, pubkey, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(username) DO UPDATE SET pubkey=excluded.pubkey, updated_at=excluded.updated_at;");
    if (!st.ok()) return KeySetResult::Error;
    st.Text(1, username);
    st.Text(2, pubKeyB64);
    st.Int64(3, static_cast<long long>(time(nullptr)));
    return st.Step() == SQLITE_DONE ? KeySetResult::Changed : KeySetResult::Error;
}

bool UserRepository::GetUserKey(const std::string& username, std::string& pubKeyB64) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr) return false;
    Stmt st(db_, "SELECT pubkey FROM user_keys WHERE username=?;");
    if (!st.ok()) return false;
    st.Text(1, username);
    if (st.Step() != SQLITE_ROW) return false;
    pubKeyB64 = st.ColText(0);
    return !pubKeyB64.empty();
}

bool UserRepository::AppendRoomMessage(const std::string& fromUser, long long ts, const std::string& textB64) {
    const std::string sealed = river::SealPayload(textB64);
    if (sealed.empty()) return false;

    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr) return false;
    if (!ExecSQLLocked("BEGIN IMMEDIATE;")) return false;
    bool ok = false;
    {
        Stmt st(db_, "INSERT INTO room_history (ts, from_user, body) VALUES (?, ?, ?);");
        if (st.ok()) {
            st.Int64(1, ts);
            st.Text(2, fromUser);
            st.Text(3, sealed);
            ok = st.Step() == SQLITE_DONE;
        }
    }
    if (ok) {
        Stmt st(db_,
                "DELETE FROM room_history WHERE id NOT IN "
                "(SELECT id FROM room_history ORDER BY id DESC LIMIT ?);");
        ok = st.ok();
        if (ok) {
            st.Int64(1, kRoomHistoryKeep);
            ok = st.Step() == SQLITE_DONE;
        }
    }
    if (!ok) {
        ExecSQLLocked("ROLLBACK;");
        return false;
    }
    return ExecSQLLocked("COMMIT;");
}

std::vector<RoomMessage> UserRepository::RecentRoomMessages(int limit) {
    std::vector<RoomMessage> out;
    if (limit <= 0) return out;
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr) return out;
    Stmt st(db_,
            "SELECT id, ts, from_user, body FROM "
            "(SELECT id, ts, from_user, body FROM room_history ORDER BY id DESC LIMIT ?) "
            "ORDER BY id ASC;");
    if (!st.ok()) return out;
    st.Int64(1, limit);
    while (st.Step() == SQLITE_ROW) {
        RoomMessage msg;
        msg.id = st.ColInt64(0);
        msg.ts = st.ColInt64(1);
        msg.fromUser = st.ColText(2);
        if (!river::OpenPayload(st.ColText(3), msg.textB64) || msg.textB64.empty()) continue;
        out.push_back(std::move(msg));
    }
    return out;
}

bool UserRepository::PruneExpiredOfflinePmsLocked() {
    Stmt st(db_, "DELETE FROM offline_pm WHERE ts < ?;");
    if (!st.ok()) return false;
    st.Int64(1, static_cast<long long>(time(nullptr)) - kOfflinePmTtlSeconds);
    return st.Step() == SQLITE_DONE;
}

OfflineQueueResult UserRepository::QueueOfflinePm(const std::string& toUser,
                                                  const std::string& fromUser,
                                                  long long ts,
                                                  const std::string& envelopeB64) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr || toUser.empty() || fromUser.empty() || envelopeB64.empty())
        return OfflineQueueResult::Error;
    if (!ExecSQLLocked("BEGIN IMMEDIATE;")) return OfflineQueueResult::Error;
    auto fail = [&](OfflineQueueResult r) {
        ExecSQLLocked("ROLLBACK;");
        return r;
    };
    if (!PruneExpiredOfflinePmsLocked()) return fail(OfflineQueueResult::Error);
    {
        Stmt st(db_, "SELECT COUNT(*) FROM offline_pm WHERE to_user=?;");
        if (!st.ok()) return fail(OfflineQueueResult::Error);
        st.Text(1, toUser);
        if (st.Step() != SQLITE_ROW) return fail(OfflineQueueResult::Error);
        if (st.ColInt64(0) >= kOfflinePmPerRecipient) return fail(OfflineQueueResult::Full);
    }
    {
        Stmt st(db_, "INSERT INTO offline_pm (to_user, from_user, ts, envelope) VALUES (?, ?, ?, ?);");
        if (!st.ok()) return fail(OfflineQueueResult::Error);
        st.Text(1, toUser);
        st.Text(2, fromUser);
        st.Int64(3, ts);
        st.Text(4, envelopeB64);
        if (st.Step() != SQLITE_DONE) return fail(OfflineQueueResult::Error);
    }
    return ExecSQLLocked("COMMIT;") ? OfflineQueueResult::Queued : OfflineQueueResult::Error;
}

std::vector<OfflinePm> UserRepository::TakeOfflinePms(const std::string& toUser) {
    std::vector<OfflinePm> out;
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr || toUser.empty()) return out;
    if (!ExecSQLLocked("BEGIN IMMEDIATE;")) return out;
    bool ok = PruneExpiredOfflinePmsLocked();
    if (ok) {
        Stmt st(db_, "SELECT id, from_user, ts, envelope FROM offline_pm WHERE to_user=? ORDER BY id ASC;");
        ok = st.ok();
        if (ok) {
            st.Text(1, toUser);
            int rc;
            while ((rc = st.Step()) == SQLITE_ROW) {
                OfflinePm pm;
                pm.id = st.ColInt64(0);
                pm.fromUser = st.ColText(1);
                pm.ts = st.ColInt64(2);
                pm.envelopeB64 = st.ColText(3);
                out.push_back(std::move(pm));
            }
            ok = rc == SQLITE_DONE;
        }
    }
    if (ok) {
        Stmt st(db_, "DELETE FROM offline_pm WHERE to_user=?;");
        ok = st.ok();
        if (ok) {
            st.Text(1, toUser);
            ok = st.Step() == SQLITE_DONE;
        }
    }
    if (!ok || !ExecSQLLocked("COMMIT;")) {
        ExecSQLLocked("ROLLBACK;");
        out.clear();
    }
    return out;
}

int UserRepository::CountOfflinePms(const std::string& toUser) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (db_ == nullptr) return 0;
    Stmt st(db_, "SELECT COUNT(*) FROM offline_pm WHERE to_user=?;");
    if (!st.ok()) return 0;
    st.Text(1, toUser);
    return st.Step() == SQLITE_ROW ? static_cast<int>(st.ColInt64(0)) : 0;
}
