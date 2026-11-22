#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "client/attachment_types.h"
#include "client/chat_state.h"
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

private:
    struct IncomingAttachmentTransfer {
        AttachmentPayload attachment;
        std::string ownerUser;
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

    void NetworkLoop();
    void ReceiveLoop(SocketHandle sock);
    int SendRawLine(const std::string& payload);
    bool SendEncryptedPayload(const std::string& user, const std::string& payload);
    bool HandleAttachmentBroadcast(const std::string& line);
    bool HandleAttachmentPrivateControl(const std::string& sender, const std::string& payload);
    bool HandleAttachmentChunkFrame(const std::string& payload);
    void HandleAttachmentRequest(const std::string& requester, const std::string& attachmentId, const std::string& mode);
    bool SendAttachmentChunkFrame(const std::string& target,
                                  const std::string& attachmentId,
                                  int index,
                                  int totalChunks,
                                  const std::string& encryptedChunk);
    void FinishIncomingAttachment(IncomingAttachmentTransfer transfer);
    void StartAttachmentUpload(const std::string& requester, const std::string& attachmentId, const std::string& mode);
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
    bool SendChallengeLogin(const std::string& nonce);

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
