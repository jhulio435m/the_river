// Tests rely on assert() side effects; keep them active in every build type.
#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <string>
#include <vector>

#include <sqlite3.h>

#include "common/base64.h"
#include "common/scram.h"
#include "common/security_utils.h"
#include "server/user_repository.h"

namespace {

std::string TempDbPath() {
    const char* tmp = std::getenv("TMPDIR");
    std::string base = tmp != nullptr && tmp[0] != '\0' ? tmp : "/tmp";
    return base + "/the_river_integration_" + RandomHex(8) + ".db";
}

void SetTestEnv() {
    setenv("THE_RIVER_ADMIN_USER", "admin", 1);
    setenv("THE_RIVER_ADMIN_BOOTSTRAP_PASSWORD", "admin-bootstrap-key", 1);
    setenv("THE_RIVER_NEW_USER_PASSWORD", "initial-user-key", 1);
    setenv("THE_RIVER_AES_KEY", "integration-test-key-with-plenty-of-entropy-42", 1);
}

// Runs a full SCRAM exchange (client side computed locally) against the
// credential stored in the repository.
bool ScramLoginSucceeds(UserRepository& repo, const std::string& user, const std::string& password) {
    river::scram::Credential credential;
    if (!repo.GetCredential(user, credential)) return false;
    const std::string clientNonce = river::scram::RandomNonceHex(16);
    const std::string combined = clientNonce + river::scram::RandomNonceHex(16);
    const std::string authMessage = river::scram::BuildAuthMessage(
        user, "hwid-test", clientNonce, combined, credential.saltHex, credential.iterations);
    if (authMessage.empty()) return false;
    std::string proof;
    std::string expectedServerSig;
    if (!river::scram::ComputeClientProof(password, credential.saltHex, credential.iterations, authMessage, proof,
                                          expectedServerSig))
        return false;
    if (!river::scram::VerifyClientProof(credential, authMessage, proof)) return false;
    return river::scram::VerifyServerSignature(expectedServerSig,
                                               river::scram::ServerSignature(credential, authMessage));
}

// Legacy mode (THE_RIVER_NEW_USER_PASSWORD set): no per-account password.
bool CreateUser(UserRepository& repo, std::string& username) {
    std::string initial;
    const bool ok = repo.CreateNextUser(username, initial);
    return ok && initial.empty();
}

bool MakeParts(const std::string& password, river::scram::Credential& out) {
    return river::scram::MakeCredential(password, out);
}

bool Rename(UserRepository& repo, const std::string& from, const std::string& to, const std::string& password) {
    river::scram::Credential c;
    if (!MakeParts(password, c)) return false;
    return repo.CompleteFirstLoginWithCredential(from, to, c.iterations, c.saltHex, c.storedKeyHex, c.serverKeyHex);
}

std::string StoredCredentialString(const std::string& dbPath, const std::string& user) {
    sqlite3* db = nullptr;
    assert(sqlite3_open(dbPath.c_str(), &db) == SQLITE_OK);
    sqlite3_stmt* st = nullptr;
    assert(sqlite3_prepare_v2(db, "SELECT password_hash FROM users WHERE username=?;", -1, &st, nullptr) == SQLITE_OK);
    sqlite3_bind_text(st, 1, user.c_str(), -1, SQLITE_TRANSIENT);
    std::string value;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char* t = sqlite3_column_text(st, 0);
        value = t ? reinterpret_cast<const char*>(t) : "";
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    return value;
}

void TestUserRepositoryLifecycle() {
    const std::string dbPath = TempDbPath();

    UserRepository repo;
    assert(repo.Open(dbPath));
    assert(repo.InitSchema());
    // Re-running InitSchema is idempotent.
    assert(repo.InitSchema());

    assert(river::scram::IsScramCredentialString(StoredCredentialString(dbPath, "admin")));
    assert(ScramLoginSucceeds(repo, "admin", "admin-bootstrap-key"));
    assert(!ScramLoginSucceeds(repo, "admin", "wrong-bootstrap-key"));

    std::string username;
    assert(CreateUser(repo, username));
    assert(!username.empty());
    assert(repo.UserExists(username));
    assert(ScramLoginSucceeds(repo, username, "initial-user-key"));
    assert(repo.FindUserByUsername(username).firstLogin == 1);

    // [CHANGE2]: credential computed client side and sent as parts.
    river::scram::Credential fresh;
    assert(river::scram::MakeCredential("operator-strong-key", fresh));
    // Invalid parts are refused.
    assert(!repo.CompleteFirstLoginWithCredential(username, "operator1", 1000, fresh.saltHex, fresh.storedKeyHex,
                                                  fresh.serverKeyHex));
    assert(!repo.CompleteFirstLoginWithCredential(username, "operator1", fresh.iterations, "zz", fresh.storedKeyHex,
                                                  fresh.serverKeyHex));
    assert(!repo.CompleteFirstLoginWithCredential(username, "operator1", fresh.iterations, fresh.saltHex, "abcd",
                                                  fresh.serverKeyHex));
    // Refused for admins and when the target name exists.
    assert(!repo.CompleteFirstLoginWithCredential("admin", "admin2", fresh.iterations, fresh.saltHex,
                                                  fresh.storedKeyHex, fresh.serverKeyHex));
    assert(!repo.CompleteFirstLoginWithCredential(username, "admin", fresh.iterations, fresh.saltHex,
                                                  fresh.storedKeyHex, fresh.serverKeyHex));
    assert(repo.UserExists(username));
    // Upper-case hex is normalized.
    std::string upperStored = fresh.storedKeyHex;
    for (char& c : upperStored)
        if (c >= 'a' && c <= 'f') c = static_cast<char>(c - 'a' + 'A');
    assert(repo.CompleteFirstLoginWithCredential(username, "operator1", fresh.iterations, fresh.saltHex, upperStored,
                                                 fresh.serverKeyHex));
    assert(repo.UserExists("operator1"));
    assert(!repo.UserExists(username));
    assert(ScramLoginSucceeds(repo, "operator1", "operator-strong-key"));
    assert(!ScramLoginSucceeds(repo, "operator1", "initial-user-key"));

    UserRecord record = repo.FindUserByUsername("operator1");
    assert(record.found);
    assert(record.firstLogin == 0);
    assert(!record.isAdmin);

    // Admin /passwd writes a SCRAM credential.
    assert(repo.ResetUserPassword("operator1", "reset-by-admin-key"));
    assert(river::scram::IsScramCredentialString(StoredCredentialString(dbPath, "operator1")));
    assert(ScramLoginSucceeds(repo, "operator1", "reset-by-admin-key"));
    assert(!repo.ResetUserPassword("ghost-user", "reset-by-admin-key"));

    // Admin maintenance helpers.
    assert(record.hwid.empty());
    assert(repo.UpdateUserHwid("operator1", "hwid-operator"));
    assert(repo.FindUserByUsername("operator1").hwid == "hwid-operator");
    assert(repo.ResetUserHwid("operator1"));
    assert(repo.FindUserByUsername("operator1").hwid.empty());
    assert(!repo.ResetUserHwid("ghost-user"));

    assert(repo.BanHwid("hwid-banned", "spam"));
    const std::vector<BannedHwidRecord> bans = repo.ListBannedHwids();
    assert(bans.size() == 1);
    assert(bans[0].hwid == "hwid-banned");
    assert(bans[0].reason == "spam");
    assert(bans[0].bannedAt > 0);
    assert(repo.UnbanHwid("hwid-banned"));
    assert(repo.ListBannedHwids().empty());

    std::string second;
    assert(CreateUser(repo, second));
    const std::vector<UserSummary> users = repo.ListUsers();
    assert(users.size() == 3);
    bool sawAdmin = false;
    bool sawPending = false;
    for (const auto& user : users) {
        if (user.username == "admin") sawAdmin = user.isAdmin;
        if (user.username == second) sawPending = user.firstLoginPending && !user.hwidBound;
    }
    assert(sawAdmin);
    assert(sawPending);

    assert(!repo.DeleteUser("admin"));
    assert(repo.DeleteUser(second));
    assert(!repo.UserExists(second));
    assert(repo.ListUsers().size() == 2);

    repo.Close();
    std::remove(dbPath.c_str());
}

void TestV1Migration() {
    const std::string dbPath = TempDbPath();
    const std::string legacyPassword = "legacy-password-123";
    {
        // A v1 database (schema version 1, pbkdf2-sha256 hashes).
        sqlite3* db = nullptr;
        assert(sqlite3_open(dbPath.c_str(), &db) == SQLITE_OK);
        assert(sqlite3_exec(db,
                            "CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,"
                            "first_login INTEGER DEFAULT 1, hwid TEXT, is_admin INTEGER DEFAULT 0);"
                            "CREATE TABLE banned_hwids (hwid TEXT PRIMARY KEY, reason TEXT, banned_at INTEGER);"
                            "PRAGMA user_version = 1;",
                            nullptr, nullptr, nullptr) == SQLITE_OK);
        const std::string v1Hash = MakePasswordHash(legacyPassword);
        assert(v1Hash.rfind("pbkdf2-sha256$", 0) == 0);
        const std::string adminHash = MakePasswordHash("legacy-admin-key-1");
        sqlite3_stmt* st = nullptr;
        assert(sqlite3_prepare_v2(db,
                                  "INSERT INTO users (username, password_hash, first_login, hwid, is_admin) "
                                  "VALUES (?, ?, ?, ?, ?);",
                                  -1, &st, nullptr) == SQLITE_OK);
        auto insert = [&](const char* name, const std::string& hash, int firstLogin, const char* hwid, int admin) {
            sqlite3_reset(st);
            sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int(st, 3, firstLogin);
            if (hwid) sqlite3_bind_text(st, 4, hwid, -1, SQLITE_TRANSIENT);
            else sqlite3_bind_null(st, 4);
            sqlite3_bind_int(st, 5, admin);
            assert(sqlite3_step(st) == SQLITE_DONE);
        };
        insert("legacy1", v1Hash, 0, "hwid-legacy", 0);
        insert("admin", adminHash, 0, nullptr, 1);
        insert("broken1", "pbkdf2-sha256$notanumber$zz$zz", 0, nullptr, 0);
        sqlite3_finalize(st);
        sqlite3_close(db);
    }

    UserRepository repo;
    assert(repo.Open(dbPath));
    assert(repo.InitSchema());

    const std::string migrated = StoredCredentialString(dbPath, "legacy1");
    assert(river::scram::IsScramCredentialString(migrated));
    assert(ScramLoginSucceeds(repo, "legacy1", legacyPassword));
    assert(!ScramLoginSucceeds(repo, "legacy1", "legacy-password-124"));
    // Existing admin is migrated, not replaced by the bootstrap password.
    assert(ScramLoginSucceeds(repo, "admin", "legacy-admin-key-1"));
    assert(!ScramLoginSucceeds(repo, "admin", "admin-bootstrap-key"));
    // Other columns are kept.
    UserRecord legacy = repo.FindUserByUsername("legacy1");
    assert(legacy.found && legacy.hwid == "hwid-legacy" && legacy.firstLogin == 0);
    // An unparseable row is left as is (cannot log in) without breaking startup.
    river::scram::Credential unused;
    assert(!repo.GetCredential("broken1", unused));
    assert(repo.UserExists("broken1"));

    // Second start: nothing to migrate, still fine.
    repo.Close();
    assert(repo.Open(dbPath));
    assert(repo.InitSchema());
    assert(StoredCredentialString(dbPath, "legacy1") == migrated);

    {
        sqlite3* db = nullptr;
        assert(sqlite3_open(dbPath.c_str(), &db) == SQLITE_OK);
        sqlite3_stmt* st = nullptr;
        assert(sqlite3_prepare_v2(db, "PRAGMA user_version;", -1, &st, nullptr) == SQLITE_OK);
        assert(sqlite3_step(st) == SQLITE_ROW);
        assert(sqlite3_column_int(st, 0) == UserRepository::kSchemaVersion);
        sqlite3_finalize(st);
        sqlite3_close(db);
    }

    repo.Close();
    std::remove(dbPath.c_str());
}

void TestKeysHistoryAndOfflinePms() {
    const std::string dbPath = TempDbPath();
    UserRepository repo;
    assert(repo.Open(dbPath));
    assert(repo.InitSchema());

    std::string alice;
    std::string bob;
    assert(CreateUser(repo, alice));
    assert(CreateUser(repo, bob));

    // Keys.
    std::string got;
    assert(!repo.GetUserKey(alice, got));
    const std::string key1 = river::base64::EncodeString(std::string(32, '\x01'));
    const std::string key2 = river::base64::EncodeString(std::string(32, '\x02'));
    assert(repo.SetUserKey(alice, key1) == KeySetResult::Changed);
    assert(repo.GetUserKey(alice, got) && got == key1);
    assert(repo.SetUserKey(alice, key1) == KeySetResult::Unchanged);
    assert(repo.SetUserKey(alice, key2) == KeySetResult::Changed);
    assert(repo.GetUserKey(alice, got) && got == key2);
    assert(repo.SetUserKey(bob, key1) == KeySetResult::Changed);

    // Room history: sealed at rest, pruned to 500, replay newest 100 oldest first.
    assert(repo.RecentRoomMessages().empty());
    for (int i = 0; i < 520; ++i) {
        assert(repo.AppendRoomMessage(i % 2 ? alice : bob, 1000 + i,
                                      river::base64::EncodeString("message " + std::to_string(i))));
    }
    {
        sqlite3* db = nullptr;
        assert(sqlite3_open(dbPath.c_str(), &db) == SQLITE_OK);
        sqlite3_stmt* st = nullptr;
        assert(sqlite3_prepare_v2(db, "SELECT COUNT(*), MIN(ts) FROM room_history;", -1, &st, nullptr) == SQLITE_OK);
        assert(sqlite3_step(st) == SQLITE_ROW);
        assert(sqlite3_column_int(st, 0) == 500);
        assert(sqlite3_column_int(st, 1) == 1020);
        sqlite3_finalize(st);
        // Body is not stored in clear.
        assert(sqlite3_prepare_v2(db, "SELECT body FROM room_history LIMIT 1;", -1, &st, nullptr) == SQLITE_OK);
        assert(sqlite3_step(st) == SQLITE_ROW);
        const std::string body = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
        assert(body.find(river::base64::EncodeString("message 20")) == std::string::npos);
        sqlite3_finalize(st);
        sqlite3_close(db);
    }
    const std::vector<RoomMessage> recent = repo.RecentRoomMessages();
    assert(recent.size() == 100);
    assert(recent.front().ts == 1420);
    assert(recent.back().ts == 1519);
    std::string text;
    assert(river::base64::DecodeToString(recent.back().textB64, text) && text == "message 519");
    assert(recent.back().fromUser == alice);
    assert(repo.RecentRoomMessages(5).size() == 5);
    assert(repo.RecentRoomMessages(5).front().ts == 1515);

    // Offline PMs: cap 200 per recipient, TTL 7 days, take deletes.
    const long long now = static_cast<long long>(time(nullptr));
    const std::string env = river::base64::EncodeString(std::string(80, 'e'));
    assert(repo.QueueOfflinePm(bob, alice, now - UserRepository::kOfflinePmTtlSeconds - 60, env) ==
           OfflineQueueResult::Queued);  // already expired
    // (Several senders: one sender may only hold 50 of the 200 slots.)
    for (int i = 0; i < UserRepository::kOfflinePmPerRecipient; ++i) {
        const std::string from = i < UserRepository::kOfflinePmPerSenderPerRecipient
                                     ? alice
                                     : "sender" + std::to_string(i / UserRepository::kOfflinePmPerSenderPerRecipient);
        assert(repo.QueueOfflinePm(bob, from, now + i, env) == OfflineQueueResult::Queued);
    }
    // Expired row was pruned on insert, so exactly 200 are live.
    assert(repo.CountOfflinePms(bob) == 200);
    assert(repo.QueueOfflinePm(bob, alice, now, env) == OfflineQueueResult::Full);
    // Other recipients are independent.
    assert(repo.QueueOfflinePm(alice, bob, now, env) == OfflineQueueResult::Queued);

    std::vector<OfflinePm> taken = repo.TakeOfflinePms(bob);
    assert(taken.size() == 200);
    assert(taken.front().ts == now && taken.back().ts == now + 199);
    assert(taken.front().fromUser == alice && taken.front().envelopeB64 == env);
    assert(repo.TakeOfflinePms(bob).empty());
    assert(repo.CountOfflinePms(bob) == 0);

    // Expired rows are never delivered.
    assert(repo.QueueOfflinePm(bob, alice, now - UserRepository::kOfflinePmTtlSeconds - 1, env) ==
           OfflineQueueResult::Queued);
    assert(repo.TakeOfflinePms(bob).empty());

    // DeleteUser cascades to the key and to PMs queued for that user (not to history).
    assert(repo.QueueOfflinePm(bob, alice, now, env) == OfflineQueueResult::Queued);
    assert(repo.CountOfflinePms(alice) == 1);
    assert(repo.DeleteUser(alice));
    assert(!repo.GetUserKey(alice, got));
    assert(repo.CountOfflinePms(alice) == 0);
    assert(repo.CountOfflinePms(bob) == 1);  // sent *by* alice: kept
    assert(repo.GetUserKey(bob, got) && got == key1);
    assert(repo.RecentRoomMessages().size() == 100);

    // A first-login rename starts with no key and no queued PMs.
    std::string carol;
    assert(CreateUser(repo, carol));
    assert(repo.SetUserKey(carol, key2) == KeySetResult::Changed);
    assert(repo.QueueOfflinePm(carol, bob, now, env) == OfflineQueueResult::Queued);
    river::scram::Credential cred;
    assert(river::scram::MakeCredential("carol-strong-key", cred));
    assert(repo.CompleteFirstLoginWithCredential(carol, "carol", cred.iterations, cred.saltHex, cred.storedKeyHex,
                                                 cred.serverKeyHex));
    assert(!repo.GetUserKey(carol, got));
    assert(!repo.GetUserKey("carol", got));
    assert(repo.CountOfflinePms(carol) == 0 && repo.CountOfflinePms("carol") == 0);

    repo.Close();
    std::remove(dbPath.c_str());
}

// Usernames are unique ignoring ASCII case; reserved names cannot be taken.
void TestCaseInsensitiveAndReservedNames() {
    const std::string dbPath = TempDbPath();
    UserRepository repo;
    assert(repo.Open(dbPath));
    assert(repo.InitSchema());

    std::string u1, u2, u3;
    assert(CreateUser(repo, u1));
    assert(CreateUser(repo, u2));
    assert(CreateUser(repo, u3));
    assert(repo.UsernameTaken("ADMIN") && repo.UsernameTaken("Admin") && repo.UsernameTaken(u1));
    assert(!repo.UsernameTaken("nobody-here"));

    for (const char* name : {"ADMIN", "Admin", "aDmIn", "SYSTEM", "system", "Server", "SERVER"}) {
        assert(UserRepository::IsReservedUsername(name));
        assert(!Rename(repo, u1, name, "reserved-name-key-1"));
    }
    assert(!UserRepository::IsReservedUsername("alice"));
    assert(repo.UserExists(u1));

    assert(Rename(repo, u1, "alice", "alice-strong-key-1"));
    // Case variants of an existing name are refused.
    assert(!Rename(repo, u2, "ALICE", "other-strong-key-2"));
    assert(!Rename(repo, u2, "Alice", "other-strong-key-2"));
    assert(repo.UserExists(u2) && !repo.UserExists("Alice"));
    assert(Rename(repo, u2, "bob", "bob-strong-key-22"));

    // Non-default iteration counts are refused (fake challenges always say
    // kDefaultIterations, so a custom count would reveal the account).
    {
        river::scram::Credential c;
        assert(MakeParts("carol-strong-key-3", c));
        river::scram::Credential custom;
        assert(river::scram::CredentialFromParts(300000, c.saltHex, c.storedKeyHex, c.serverKeyHex, custom));
        assert(!repo.CompleteFirstLoginWithCredential(u3, "carol", 300000, c.saltHex, c.storedKeyHex,
                                                      c.serverKeyHex));
        assert(!repo.CompleteFirstLoginWithCredential(u3, "carol", river::scram::kMinIterations, c.saltHex,
                                                      c.storedKeyHex, c.serverKeyHex));
        assert(repo.UserExists(u3));
    }

    // The unique index enforces it at the SQL level too.
    {
        sqlite3* db = nullptr;
        assert(sqlite3_open(dbPath.c_str(), &db) == SQLITE_OK);
        assert(sqlite3_exec(db, "INSERT INTO users (username, password_hash) VALUES ('BOB', 'x');", nullptr, nullptr,
                            nullptr) != SQLITE_OK);
        sqlite3_close(db);
    }

    // /newuser skips a sequential name taken in another case.
    {
        sqlite3* db = nullptr;
        assert(sqlite3_open(dbPath.c_str(), &db) == SQLITE_OK);
        assert(sqlite3_exec(db, "UPDATE users SET username='USER4' WHERE username='bob';", nullptr, nullptr,
                            nullptr) == SQLITE_OK);
        sqlite3_close(db);
    }
    std::string next;
    assert(CreateUser(repo, next));
    assert(next != "user4" && next.rfind("user", 0) == 0);
    repo.Close();
    std::remove(dbPath.c_str());
}

// A database that already has case-duplicate names still starts (logged).
void TestCaseDuplicateMigration() {
    const std::string dbPath = TempDbPath();
    {
        sqlite3* db = nullptr;
        assert(sqlite3_open(dbPath.c_str(), &db) == SQLITE_OK);
        assert(sqlite3_exec(db,
                            "CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,"
                            "first_login INTEGER DEFAULT 1, hwid TEXT, is_admin INTEGER DEFAULT 0);"
                            "CREATE TABLE banned_hwids (hwid TEXT PRIMARY KEY, reason TEXT, banned_at INTEGER);"
                            "PRAGMA user_version = 2;",
                            nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(db);
    }
    river::scram::Credential c;
    assert(MakeParts("dup-user-strong-key", c));
    const std::string cred = river::scram::Serialize(c);
    {
        sqlite3* db = nullptr;
        assert(sqlite3_open(dbPath.c_str(), &db) == SQLITE_OK);
        for (const char* name : {"dave", "Dave", "SYSTEM"}) {
            sqlite3_stmt* st = nullptr;
            assert(sqlite3_prepare_v2(db, "INSERT INTO users (username, password_hash, first_login) VALUES (?, ?, 0);",
                                      -1, &st, nullptr) == SQLITE_OK);
            sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, cred.c_str(), -1, SQLITE_TRANSIENT);
            assert(sqlite3_step(st) == SQLITE_DONE);
            sqlite3_finalize(st);
        }
        sqlite3_close(db);
    }
    UserRepository repo;
    assert(repo.Open(dbPath));
    assert(repo.InitSchema());  // logs the duplicates, does not fail
    assert(repo.UserExists("dave") && repo.UserExists("Dave"));
    assert(ScramLoginSucceeds(repo, "dave", "dup-user-strong-key"));
    assert(ScramLoginSucceeds(repo, "Dave", "dup-user-strong-key"));
    // No further variant can be added even without the unique index.
    std::string u;
    assert(CreateUser(repo, u));
    assert(!Rename(repo, u, "DAVE", "another-strong-key"));
    assert(repo.InitSchema());  // idempotent
    repo.Close();
    std::remove(dbPath.c_str());
}

// The fake-salt secret is generated once and persisted in the database.
void TestFakeSaltSecretPersisted() {
    const std::string dbPath = TempDbPath();
    std::string first;
    {
        UserRepository repo;
        assert(repo.FakeSaltSecret().empty());
        assert(repo.Open(dbPath));
        assert(repo.InitSchema());
        first = repo.FakeSaltSecret();
        assert(first.size() == 64 && river::scram::IsHexString(first, 64));
        assert(repo.InitSchema());
        assert(repo.FakeSaltSecret() == first);
        repo.Close();
    }
    {
        UserRepository repo;  // "restart"
        assert(repo.Open(dbPath));
        assert(repo.InitSchema());
        assert(repo.FakeSaltSecret() == first);
        repo.Close();
    }
    const std::string other = TempDbPath();
    {
        UserRepository repo;
        assert(repo.Open(other));
        assert(repo.InitSchema());
        assert(repo.FakeSaltSecret() != first);  // per database, random
        repo.Close();
    }
    std::remove(dbPath.c_str());
    std::remove(other.c_str());
}

// One sender may hold at most 50 of a recipient's 200 offline slots.
void TestOfflinePmPerSenderQuota() {
    const std::string dbPath = TempDbPath();
    UserRepository repo;
    assert(repo.Open(dbPath));
    assert(repo.InitSchema());
    const long long now = static_cast<long long>(time(nullptr));
    const std::string env = river::base64::EncodeString(std::string(80, 'e'));
    for (int i = 0; i < UserRepository::kOfflinePmPerSenderPerRecipient; ++i)
        assert(repo.QueueOfflinePm("victim", "spammer", now, env) == OfflineQueueResult::Queued);
    assert(repo.QueueOfflinePm("victim", "spammer", now, env) == OfflineQueueResult::SenderQuota);
    // Others can still reach the victim, and the spammer can reach others.
    assert(repo.QueueOfflinePm("victim", "friend", now, env) == OfflineQueueResult::Queued);
    assert(repo.QueueOfflinePm("someone", "spammer", now, env) == OfflineQueueResult::Queued);
    // The total cap still applies.
    for (int s = 0; s < 3; ++s)
        for (int i = 0; i < 50; ++i)
            repo.QueueOfflinePm("victim", "sender" + std::to_string(s), now, env);
    assert(repo.CountOfflinePms("victim") == UserRepository::kOfflinePmPerRecipient);
    assert(repo.QueueOfflinePm("victim", "late", now, env) == OfflineQueueResult::Full);
    // Once delivered, the quota is free again.
    assert(repo.TakeOfflinePms("victim").size() == 200);
    assert(repo.QueueOfflinePm("victim", "spammer", now, env) == OfflineQueueResult::Queued);
    repo.Close();
    std::remove(dbPath.c_str());
}

// Without THE_RIVER_NEW_USER_PASSWORD every /newuser account gets its own
// random one-time password that works for that account only.
void TestRandomInitialPasswords() {
    unsetenv("THE_RIVER_NEW_USER_PASSWORD");
    const std::string dbPath = TempDbPath();
    UserRepository repo;
    assert(repo.Open(dbPath));
    assert(repo.InitSchema());
    std::string u1, p1, u2, p2;
    assert(repo.CreateNextUser(u1, p1));
    assert(repo.CreateNextUser(u2, p2));
    assert(u1 != u2);
    assert(static_cast<int>(p1.size()) == UserRepository::kInitialPasswordChars && IsStrongEnoughPassword(p1));
    assert(IsStrongEnoughPassword(p2) && p1 != p2);
    for (char c : p1) assert(std::string("0O1lIo").find(c) == std::string::npos);
    assert(ScramLoginSucceeds(repo, u1, p1));
    assert(ScramLoginSucceeds(repo, u2, p2));
    assert(!ScramLoginSucceeds(repo, u1, p2));
    assert(!ScramLoginSucceeds(repo, u2, p1));
    assert(!ScramLoginSucceeds(repo, u1, "initial-user-key"));
    // Not stored in clear.
    assert(StoredCredentialString(dbPath, u1).find(p1) == std::string::npos);
    repo.Close();
    std::remove(dbPath.c_str());
    setenv("THE_RIVER_NEW_USER_PASSWORD", "initial-user-key", 1);
}

}  // namespace

int main() {
    SetTestEnv();
    TestUserRepositoryLifecycle();
    TestV1Migration();
    TestKeysHistoryAndOfflinePms();
    TestCaseInsensitiveAndReservedNames();
    TestCaseDuplicateMigration();
    TestFakeSaltSecretPersisted();
    TestOfflinePmPerSenderQuota();
    TestRandomInitialPasswords();
    std::cout << "integration tests OK" << std::endl;
    return 0;
}
