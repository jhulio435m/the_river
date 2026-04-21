#pragma once

#include <atomic>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "client/attachment_types.h"
#include "client/chat_types.h"

class ChatState {
public:
    ChatState();

    ConnState GetConnectionState() const;
    void SetConnectionState(ConnState state);

    bool IsAuthenticated() const;
    void SetAuthenticated(bool value);

    bool MustChangeCredentials() const;
    void SetMustChangeCredentials(bool value);

    bool IsAuthActionPending() const;
    void SetAuthActionPending(bool value);

    bool IsCredentialChangePending() const;
    void SetCredentialChangePending(bool value);

    std::string StatusDetail() const;
    void SetStatusDetail(const std::string& value);

    std::string LastError() const;
    void SetLastError(const std::string& value);
    void ClearLastError();
    std::string CurrentIdentity() const;
    void SetCurrentIdentity(const std::string& user);

    bool ConsumeNewMessageFlag();
    void MarkNewMessage();

    void AddIncomingWireMessage(const std::string& rawMsg, const std::string& currentUser, bool isPm = false);
    void AddSystemLog(const std::string& message);
    void AddOutgoingChat(const std::string& user, const std::string& message);
    void AddOutgoingPrivateMessage(const std::string& user, const std::string& target, const std::string& message);
    void AddAttachmentOffer(const std::string& user, const AttachmentPayload& attachment);
    bool FindAttachment(const std::string& user, const std::string& attachmentId, AttachmentPayload& attachment) const;
    bool UpdateAttachmentState(const std::string& user,
                               const std::string& attachmentId,
                               AttachmentTransferState state,
                               const std::string& localPath = "");
    void ClearLogs();

    std::vector<LogEntry> SnapshotLogs() const;
    std::vector<std::string> SnapshotActiveUsers() const;
    int ActiveUserCount() const;

private:
    std::string GetTimestamp() const;
    void PushLogLocked(const LogEntry& entry);

    std::atomic<int> connStateRaw_{0};
    std::atomic<bool> authenticated_{false};
    std::atomic<bool> mustChangeCredentials_{false};
    std::atomic<bool> authActionPending_{false};
    std::atomic<bool> credentialChangePending_{false};
    std::atomic<bool> newMessage_{false};

    mutable std::mutex uiStateMutex_;
    std::string statusDetail_;
    std::string lastError_;
    std::string currentIdentity_;

    mutable std::mutex chatMutex_;
    std::deque<LogEntry> chatLogs_;

    mutable std::mutex usersMutex_;
    std::vector<std::string> activeUsers_;
};
