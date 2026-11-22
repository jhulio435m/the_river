#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
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
// Creates (truncating) the .part file and returns it opened for binary read/write.
std::shared_ptr<std::fstream> CreatePartFile(const std::string& partPath);
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

    void NetworkLoop();
    void ReceiveLoop(SocketHandle sock);
    int SendRawLine(const std::string& payload);
    bool HandleAttachmentBroadcast(const std::string& line);
    bool HandleAttachmentPrivateControl(const std::string& sender,
                                        const std::string& senderPub,
                                        const std::string& payload);
    bool HandleAttachmentChunkFrame(const std::string& payload);
    void HandleAttachmentRequest(const std::string& requester,
                                 const std::string& requesterPub,
                                 const std::string& attachmentId,
                                 const std::string& mode);
    bool SendAttachmentChunkFrame(const std::string& target,
                                  const std::string& attachmentId,
                                  int index,
                                  int totalChunks,
                                  const std::string& encryptedChunk);
    void FinishIncomingAttachment(IncomingAttachmentTransfer transfer);
    void StartAttachmentUpload(const std::string& requester,
                               const std::string& requesterPub,
                               const std::string& attachmentId,
                               const std::string& mode);
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
    void RequestPeerKey(const std::string& user);
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
    // TOFU pin check for a freshly received key; logs the spec warning on change.
    void CheckAndPinPeerKey(const std::string& user, const std::string& pub);
    void LoadKnownKeysLocked();
    bool SaveKnownKeysLocked() const;

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
    // Auth exchange of the current connection (guarded by reloginMutex_).
    std::string authClientNonce_;
    std::string authExpectedServerSig_;
    std::string authHwid_;

    // 0 = banner not seen yet, 1 = PROTO=2 banner, 2 = incompatible server.
    std::atomic<int> bannerState_{0};
    // Set only after a verified AUTH_OK on the current connection.
    std::atomic<bool> authVerified_{false};
    // Receive-thread only: inside HISTORY_BEGIN ... HISTORY_END.
    bool inHistory_ = false;

    mutable std::mutex identityKeyMutex_;
    river::e2e::KeyPair identityKey_;

    mutable std::mutex peerMutex_;
    std::map<std::string, std::string> peerKeys_;
    std::set<std::string> keyRequestsInFlight_;
    std::map<std::string, std::vector<PendingOutgoingSealed>> pendingOutgoing_;
    std::map<std::string, std::vector<PendingIncomingSealed>> pendingIncoming_;
    std::set<std::string> pendingFingerprint_;

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

    mutable std::mutex offeredAttachmentMutex_;
    std::map<std::string, AttachmentDraft> offeredAttachments_;

    mutable std::mutex incomingAttachmentMutex_;
    std::map<std::string, IncomingAttachmentTransfer> incomingAttachments_;
};
