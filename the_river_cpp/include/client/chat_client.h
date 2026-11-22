#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "client/attachment_types.h"
#include "client/chat_state.h"
#include "common/e2e_crypto.h"
#include "common/net_platform.h"

// File helpers for streaming a received attachment to disk. Exposed so they can be
// exercised in isolation; ChatClient is their only production user.
namespace attachment_part {

std::string PartPathFor(const std::string& targetPath);
// Creates partPath exclusively (fails if it already exists: an existing file,
// e.g. another transfer's .part, is never truncated) and returns it opened for
// binary read/write.
std::shared_ptr<std::fstream> CreatePartFile(const std::string& partPath);
// Creates a fresh .part file for targetPath: PartPathFor(targetPath) if free,
// otherwise "<targetPath>.<n>.part" with a unique n. partPath receives the name.
std::shared_ptr<std::fstream> CreateUniquePartFile(const std::string& targetPath, std::string& partPath);
// Expected plaintext size of chunk `index` for an attachment of `totalSize` bytes.
std::size_t ExpectedChunkSize(std::size_t totalSize, int totalChunks, int index);
int ExpectedChunkCount(std::size_t totalSize);
// Writes `data` at index * kAttachmentBinaryChunkBytes.
bool WriteChunkAt(std::fstream& file, int index, const std::string& data);
// Verifies size (and SHA-256 when expectedSha256 is non-empty) of the closed .part
// file and renames it over targetPath. On failure the .part file is removed and
// `error` describes the problem.
bool FinalizePartFile(const std::string& partPath,
                      const std::string& targetPath,
                      std::size_t expectedSize,
                      const std::string& expectedSha256,
                      std::string& error);
void RemovePartFile(const std::string& partPath);

}  // namespace attachment_part

// Client-side message integrity for PM2/PMX plaintexts (PROTOCOL_V2.md 4.4):
// "RM1|<msgIdHex32>|<senderUnixTs>|<payload>". Exposed for tests.
namespace rm1 {

constexpr long long kMaxAgeSeconds = 8LL * 24 * 3600;     // older -> rejected
constexpr long long kMaxFutureSeconds = 24LL * 3600;      // clock skew tolerance
constexpr std::size_t kMaxIdsPerPeer = 5000;
constexpr const char* kSeenIdsFile = "river_seen_ids.txt";

std::string Wrap(const std::string& msgIdHex, long long senderTs, const std::string& payload);
bool Parse(const std::string& plaintext, std::string& msgIdHex, long long& senderTs, std::string& payload);

}  // namespace rm1

class ChatClient {
public:
    explicit ChatClient(ChatState& state);
    ~ChatClient();

    void Start();
    void Stop();

    bool SendLogin(const std::string& user, const std::string& pass);
    bool SendFirstLoginChange(const std::string& newUser, const std::string& newPass);
    bool SendPing();
    // Drops the current session and forgets cached credentials so the client
    // returns to the login screen instead of silently re-authenticating.
    void Logout();
    bool SendChatMessage(const std::string& user, const std::string& input);
    bool SendPrivateMessage(const std::string& fromUser, const std::string& target, const std::string& message);
    bool SendAttachment(const std::string& fromUser, const AttachmentDraft& attachment);
    bool RequestAttachment(const AttachmentPayload& attachment, const std::string& savePath, const std::string& mode);
    // Prints the own identity fingerprint (empty user) or a peer's (fetching
    // the peer key first when it is not cached).
    void ShowFingerprint(const std::string& user);
    // /trust <user>: accepts a changed peer key (re-pins it) and flushes the
    // messages and uploads held for that peer.
    void TrustPeerKey(const std::string& user);

private:
    struct IncomingAttachmentTransfer {
        AttachmentPayload attachment;
        std::string ownerUser;
        // Owner identity key used to open the @attachmeta envelope; chunks must
        // open with the same key (a KEY_CHANGED mid-transfer does not swap it).
        std::string ownerPub;
        std::string mode;
        std::string targetPath;
        // Chunks are streamed into partPath (targetPath + ".part") as they arrive and
        // only renamed to targetPath once size and SHA-256 have been verified.
        std::string partPath;
        std::shared_ptr<std::fstream> partFile;
        int totalChunks = 0;
        int receivedChunks = 0;
        std::vector<bool> receivedIndices;
    };

    // Sealed private payload waiting for the recipient's public key.
    struct PendingOutgoingSealed {
        bool control = false;  // true: [PMX] (attachment control), false: [PM2]
        std::string plaintext;
    };
    // Received envelope waiting for the sender's public key.
    struct PendingIncomingSealed {
        bool control = false;
        long long unixTs = 0;
        std::string envelope;
    };
    // Attachment upload requested by a peer (@attachreq).
    struct UploadJob {
        std::string requester;
        std::string requesterPub;
        std::string attachmentId;
        std::string mode;
        std::uint64_t generation = 0;
    };
    // Replay window of one (local user, peer) pair.
    struct SeenPeerIds {
        std::map<std::string, long long> ids;          // msgId -> sender ts
        std::multimap<long long, std::string> byTs;    // eviction order
        long long watermark = 0;  // ids with ts <= watermark were evicted: reject
    };
    enum class SeenResult { Accepted, Duplicate, TooOld, BadTimestamp };
    enum class PinResult { Matches, FirstSight, Changed };

    void NetworkLoop();
    void ReceiveLoop(SocketHandle sock);
    int SendRawLine(const std::string& payload);
    bool HandleAttachmentBroadcast(const std::string& line);
    bool HandleAttachmentPrivateControl(const std::string& sender,
                                        const std::string& senderPub,
                                        const std::string& payload,
                                        bool unverifiedKey);
    bool HandleAttachmentChunkFrame(const std::string& payload);
    void HandleAttachmentRequest(const UploadJob& job);
    bool SendAttachmentChunkFrame(const std::string& target,
                                  const std::string& attachmentId,
                                  int index,
                                  int totalChunks,
                                  const std::string& encryptedChunk);
    void FinishIncomingAttachment(IncomingAttachmentTransfer transfer);
    void StartAttachmentUpload(const UploadJob& job);
    void RunUploadWorker(UploadJob job, std::shared_ptr<std::atomic<bool>> done);
    void ClearQueuedUploads();
    void ReapFinishedUploads(bool joinAll);
    void FailPendingIncomingAttachments(const std::string& reason);
    // Closes and deletes the .part file of a transfer already removed from
    // incomingAttachments_ (call without holding incomingAttachmentMutex_).
    static void DiscardIncomingTransfer(IncomingAttachmentTransfer& transfer);
    void HandleServerPong();
    void RememberSessionCredentials();
    void ForgetSessionCredentials();
    bool ConsumeRememberedCredentials(std::string& user, std::string& pass);
    void CloseCurrentSocket();
    std::string CurrentUser() const;
    void SetCurrentUser(const std::string& user);
    void QueueAutoLogin(const std::string& user, const std::string& pass);
    bool ConsumeQueuedAutoLogin(std::string& user, std::string& pass);
    void QueueChallengeLogin(const std::string& user, const std::string& pass);

    // v2 authentication (PROTOCOL_V2.md section 2).
    void ResetAuthExchange();
    bool SendAuthProof(const std::string& challengeLine);
    bool VerifyAuthOk(const std::string& line);
    void FailAuthFatal(const std::string& reason);
    // Fatal auth reasons stay on screen until the user submits a new login.
    void SetStickyAuthError(const std::string& reason);
    void ApplyStickyAuthError();

    // Identity keys and E2E (sections 1.2, 3, 4.2).
    bool LoadOrCreateIdentity(const std::string& user,
                              const std::string& pass,
                              const std::string& oldUser,
                              const std::string& oldPass);
    void PublishIdentityKey();
    void ClearE2EState(bool notifyPending);
    bool HasIdentity() const;
    std::string OwnPublicKey() const;
    bool SealWithIdentity(const std::string& context,
                          const std::string& fromUser,
                          const std::string& toUser,
                          const std::string& recipientPub,
                          const std::string& plaintext,
                          std::string& envelope) const;
    bool OpenWithIdentity(const std::string& context,
                          const std::string& fromUser,
                          const std::string& toUser,
                          const std::string& senderPub,
                          const std::string& envelope,
                          std::string& plaintext) const;
    bool CachedPeerKey(const std::string& user, std::string& pub) const;
    // Queues a KEY_GET; requests made on the receive thread are coalesced and
    // sent as batch lines ([KEY_GET]:a,b,c, max 50 names) at the end of the
    // receive burst, others are sent right away.
    void RequestPeerKey(const std::string& user);
    void FlushKeyRequests();
    bool SendSealedToUser(const std::string& target, const std::string& plaintext, bool control);
    bool SealAndSendLine(bool control,
                         const std::string& target,
                         const std::string& targetPub,
                         const std::string& plaintext);
    void HandleKeyReply(const std::string& line);
    void HandleKeyChanged(const std::string& user);
    void HandleIncomingSealed(const std::string& line, bool control);
    void DeliverIncomingSealed(const std::string& from,
                               const std::string& fromPub,
                               const PendingIncomingSealed& item);
    void HandleRoomLine(const std::string& line, bool fromHistory);
    // TOFU pin check for a freshly received key. A changed key is NOT re-pinned.
    PinResult CheckAndPinPeerKey(const std::string& user, const std::string& pub);
    void LoadKnownKeysLocked();
    bool SaveKnownKeysLocked() const;
    // Replay protection (RM1 message ids, persisted in rm1::kSeenIdsFile).
    SeenResult CheckAndRecordMessageId(const std::string& me,
                                       const std::string& peer,
                                       const std::string& msgId,
                                       long long senderTs);
    void LoadSeenIdsLocked();
    bool InsertSeenLocked(SeenPeerIds& peer, const std::string& msgId, long long ts, bool& evicted);
    void CompactSeenIdsLocked();
    bool IsPeerUnverified(const std::string& user) const;

    ChatState& state_;
    std::atomic<bool> stopRequested_{false};
    std::thread networkThread_;

    mutable std::mutex socketMutex_;
    SocketHandle socket_ = kInvalidSocket;

    mutable std::mutex identityMutex_;
    std::string currentUser_;

    mutable std::mutex reloginMutex_;
    std::string queuedLoginUser_;
    std::string queuedLoginPass_;
    std::string pendingLoginUser_;
    std::string pendingLoginPass_;
    std::string rememberedUser_;
    std::string rememberedPass_;
    std::string disconnectNotice_;
    std::string stickyAuthError_;
    // Auth exchange of the current connection (guarded by reloginMutex_).
    std::string authClientNonce_;
    std::string authExpectedServerSig_;
    std::string authHwid_;

    // 0 = banner not seen yet, 1 = PROTO=2 banner, 2 = incompatible server.
    std::atomic<int> bannerState_{0};
    // Set only after a verified AUTH_OK on the current connection.
    std::atomic<bool> authVerified_{false};
    // Seconds to wait before the next reconnect (fatal auth error: 30 s,
    // server auth timeout / traffic limit: 5 s); 0 = reconnect at once.
    std::atomic<int> reconnectDelaySeconds_{0};
    // The user submitted a login during the backoff: reconnect now.
    std::atomic<bool> backoffCancel_{false};
    // Incremented for every new connection (aborts uploads of an old link).
    std::atomic<std::uint64_t> connGeneration_{0};
    // Receive-thread only: inside HISTORY_BEGIN ... HISTORY_END.
    bool inHistory_ = false;

    mutable std::mutex identityKeyMutex_;
    river::e2e::KeyPair identityKey_;

    mutable std::mutex peerMutex_;
    std::map<std::string, std::string> peerKeys_;
    std::set<std::string> keyRequestsInFlight_;
    std::vector<std::string> keyRequestQueue_;  // queued, not sent yet
    std::chrono::steady_clock::time_point keyQueueSince_{};
    // Server key-lookup budget exhausted: re-ask in-flight names at keyRetryAt_.
    bool keyRetryPending_ = false;
    std::chrono::steady_clock::time_point keyRetryAt_{};
    bool batchKeyGetUnsupported_ = false;
    std::map<std::string, std::vector<PendingOutgoingSealed>> pendingOutgoing_;
    std::map<std::string, std::vector<PendingIncomingSealed>> pendingIncoming_;
    std::size_t pendingIncomingTotal_ = 0;
    std::set<std::string> pendingFingerprint_;
    // Peers whose current key differs from the pinned one -> fingerprint shown
    // in the warning. Outgoing PMs and uploads to them are held until /trust.
    std::map<std::string, std::string> unverifiedPeers_;
    std::map<std::string, std::vector<PendingOutgoingSealed>> heldOutgoing_;
    std::map<std::string, std::vector<UploadJob>> heldUploads_;

    mutable std::mutex seenMutex_;
    bool seenLoaded_ = false;
    std::size_t seenFileLines_ = 0;
    std::map<std::string, SeenPeerIds> seenIds_;  // key: "<me> <peer>"

    mutable std::mutex pinsMutex_;
    bool pinsLoaded_ = false;
    std::map<std::string, std::string> knownKeyPins_;

    std::mutex pingMutex_;
    bool pingOutstanding_ = false;
    std::chrono::steady_clock::time_point pingSentAt_{};

    struct UploadWorker {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };
    std::mutex uploadsMutex_;
    std::vector<UploadWorker> uploads_;
    int uploadWorkersRunning_ = 0;
    std::set<std::string> activeUploadKeys_;  // "<requester>|<id>" being sent
    std::deque<UploadJob> uploadQueue_;

    mutable std::mutex offeredAttachmentMutex_;
    std::map<std::string, AttachmentDraft> offeredAttachments_;

    mutable std::mutex incomingAttachmentMutex_;
    std::map<std::string, IncomingAttachmentTransfer> incomingAttachments_;
};
