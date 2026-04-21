#pragma once

#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "client/attachment_types.h"
#include "client/chat_state.h"
#include "common/net_platform.h"

class ChatClient {
public:
    explicit ChatClient(ChatState& state);
    ~ChatClient();

    void Start();
    void Stop();

    bool SendLogin(const std::string& user, const std::string& pass);
    bool SendFirstLoginChange(const std::string& newUser, const std::string& newPass);
    bool SendPing();
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
        int totalChunks = 0;
        int receivedChunks = 0;
        std::vector<std::string> chunks;
    };

    void NetworkLoop();
    void ReceiveLoop(SocketHandle sock);
    int SendRawLine(const std::string& payload);
    bool SendEncryptedPayload(const std::string& user, const std::string& payload);
    bool HandleAttachmentBroadcast(const std::string& line);
    bool HandleAttachmentPrivateControl(const std::string& sender, const std::string& payload);
    void HandleAttachmentRequest(const std::string& requester, const std::string& attachmentId, const std::string& mode);
    void FinishIncomingAttachment(IncomingAttachmentTransfer transfer);
    void CloseCurrentSocket();
    std::string CurrentUser() const;
    void SetCurrentUser(const std::string& user);
    void QueueAutoLogin(const std::string& user, const std::string& pass);
    bool ConsumeQueuedAutoLogin(std::string& user, std::string& pass);

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

    mutable std::mutex offeredAttachmentMutex_;
    std::map<std::string, AttachmentDraft> offeredAttachments_;

    mutable std::mutex incomingAttachmentMutex_;
    std::map<std::string, IncomingAttachmentTransfer> incomingAttachments_;
};
