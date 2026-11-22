#pragma once

#include <mutex>
#include <string>
#include <vector>

#include <sqlite3.h>

#include "common/scram.h"

struct UserRecord {
    bool found = false;
    bool isAdmin = false;
    int firstLogin = 0;
    std::string hwid;
};

struct BannedHwidRecord {
    std::string hwid;
    std::string reason;
    long long bannedAt = 0;
};

struct UserSummary {
    std::string username;
    bool isAdmin = false;
    bool firstLoginPending = false;
    bool hwidBound = false;
};

// One room message as stored in room_history (body already opened).
struct RoomMessage {
    long long id = 0;
    long long ts = 0;
    std::string fromUser;
    std::string textB64;
};

// One queued end-to-end envelope for an offline recipient.
struct OfflinePm {
    long long id = 0;
    long long ts = 0;
    std::string fromUser;
    std::string envelopeB64;
};

enum class OfflineQueueResult { Queued, Full, Error };
enum class KeySetResult { Unchanged, Changed, Error };

class UserRepository {
public:
    // PROTOCOL_V2.md: room history keeps 500 rows, login replays 100,
    // offline PMs: 200 per recipient, 7 day TTL.
    static constexpr int kSchemaVersion = 2;
    static constexpr int kRoomHistoryKeep = 500;
    static constexpr int kRoomHistoryReplay = 100;
    static constexpr int kOfflinePmPerRecipient = 200;
    static constexpr long long kOfflinePmTtlSeconds = 7LL * 24 * 3600;

    UserRepository() = default;
    ~UserRepository();

    bool Open(const std::string& dbPath);
    void Close();
    bool InitSchema();

    UserRecord FindUserByUsername(const std::string& username);
    bool UpdateUserHwid(const std::string& username, const std::string& hwid);
    bool IsHwidBanned(const std::string& hwid);
    bool BanHwid(const std::string& hwid, const std::string& reason);
    bool UnbanHwid(const std::string& hwid);
    bool CreateNextUser(std::string& createdUsername);
    // Stores a fresh SCRAM credential derived from newPassword (admin /passwd).
    bool ResetUserPassword(const std::string& username, const std::string& newPassword);
    // [CHANGE2]: validates the parts with scram::CredentialFromParts, stores
    // them, clears first_login and renames oldUsername -> newUsername.
    // Refused for admins and when newUsername is taken by another account.
    bool CompleteFirstLoginWithCredential(const std::string& oldUsername,
                                          const std::string& newUsername,
                                          int iterations,
                                          const std::string& saltHex,
                                          const std::string& storedKeyHex,
                                          const std::string& serverKeyHex);
    bool UserExists(const std::string& username);
    // Parsed SCRAM credential; false if the user is unknown or the stored
    // value is not a valid scram-sha256 credential.
    bool GetCredential(const std::string& username, river::scram::Credential& credential);
    bool ResetUserHwid(const std::string& username);
    // Also deletes the user's public key and the offline PMs queued for them.
    bool DeleteUser(const std::string& username);
    std::vector<BannedHwidRecord> ListBannedHwids();
    std::vector<UserSummary> ListUsers();

    // Key directory (pubKeyB64 = base64 of the 32-byte X25519 public key).
    KeySetResult SetUserKey(const std::string& username, const std::string& pubKeyB64);
    bool GetUserKey(const std::string& username, std::string& pubKeyB64);

    // Room history. textB64 is sealed at rest with river::SealPayload.
    bool AppendRoomMessage(const std::string& fromUser, long long ts, const std::string& textB64);
    // Newest `limit` rows, returned oldest first. Rows that fail to open are skipped.
    std::vector<RoomMessage> RecentRoomMessages(int limit = kRoomHistoryReplay);

    // Offline PMs. Expired rows (ts older than 7 days) are pruned on every call.
    OfflineQueueResult QueueOfflinePm(const std::string& toUser,
                                      const std::string& fromUser,
                                      long long ts,
                                      const std::string& envelopeB64);
    // Returns (oldest first) and deletes every non-expired PM queued for toUser.
    std::vector<OfflinePm> TakeOfflinePms(const std::string& toUser);
    int CountOfflinePms(const std::string& toUser);

private:
    int SchemaVersionLocked();
    bool SetSchemaVersionLocked(int version);
    bool ExecSQLLocked(const std::string& sql);
    bool EnsureDefaultAdminLocked();
    bool MigrateV1CredentialsLocked();
    bool UserExistsLocked(const std::string& username);
    bool PruneExpiredOfflinePmsLocked();
    std::string NextSequentialUsernameLocked();

    sqlite3* db_ = nullptr;
    std::mutex mutex_;
};
