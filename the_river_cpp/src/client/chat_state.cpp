#include "client/chat_state.h"

#include <algorithm>
#include <ctime>
#include <sstream>

#include "client/attachment_utils.h"
#include "common/shared_config.h"
#include "include/aes.h"

ChatState::ChatState() = default;

ConnState ChatState::GetConnectionState() const {
    return static_cast<ConnState>(connStateRaw_.load());
}

void ChatState::SetConnectionState(ConnState state) {
    connStateRaw_.store(static_cast<int>(state));
}

bool ChatState::IsAuthenticated() const {
    return authenticated_.load();
}

void ChatState::SetAuthenticated(bool value) {
    authenticated_.store(value);
}

bool ChatState::MustChangeCredentials() const {
    return mustChangeCredentials_.load();
}

void ChatState::SetMustChangeCredentials(bool value) {
    mustChangeCredentials_.store(value);
}

bool ChatState::IsAuthActionPending() const {
    return authActionPending_.load();
}

void ChatState::SetAuthActionPending(bool value) {
    authActionPending_.store(value);
}

bool ChatState::IsCredentialChangePending() const {
    return credentialChangePending_.load();
}

void ChatState::SetCredentialChangePending(bool value) {
    credentialChangePending_.store(value);
}

std::string ChatState::StatusDetail() const {
    std::lock_guard<std::mutex> lock(uiStateMutex_);
    return statusDetail_;
}

void ChatState::SetStatusDetail(const std::string& value) {
    std::lock_guard<std::mutex> lock(uiStateMutex_);
    statusDetail_ = value;
}

std::string ChatState::LastError() const {
    std::lock_guard<std::mutex> lock(uiStateMutex_);
    return lastError_;
}

void ChatState::SetLastError(const std::string& value) {
    std::lock_guard<std::mutex> lock(uiStateMutex_);
    lastError_ = value;
}

void ChatState::ClearLastError() {
    std::lock_guard<std::mutex> lock(uiStateMutex_);
    lastError_.clear();
}

std::string ChatState::CurrentIdentity() const {
    std::lock_guard<std::mutex> lock(uiStateMutex_);
    return currentIdentity_;
}

void ChatState::SetCurrentIdentity(const std::string& user) {
    std::lock_guard<std::mutex> lock(uiStateMutex_);
    currentIdentity_ = user;
}

bool ChatState::ConsumeNewMessageFlag() {
    return newMessage_.exchange(false);
}

void ChatState::MarkNewMessage() {
    newMessage_.store(true);
}

std::string ChatState::GetTimestamp() const {
    time_t now = time(nullptr);
    struct tm t = *localtime(&now);
    char buf[20];
    strftime(buf, sizeof(buf), "%H:%M", &t);
    return buf;
}

void ChatState::PushLogLocked(const LogEntry& entry) {
    chatLogs_.push_back(entry);
    if (chatLogs_.size() > 200) chatLogs_.pop_front();
}

void ChatState::AddIncomingWireMessage(const std::string& rawMsg, const std::string& currentUser, bool isPm) {
    std::string msg = rawMsg;
    msg.erase(std::remove(msg.begin(), msg.end(), '\r'), msg.end());
    msg.erase(std::remove(msg.begin(), msg.end(), '\n'), msg.end());

    if (msg.rfind("[USERS]:", 0) == 0 || msg.rfind("[[USERS]]:", 0) == 0) {
        size_t startPos = (msg[0] == '[') ? (msg[1] == '[' ? 9 : 8) : 8;
        std::lock_guard<std::mutex> usersLock(usersMutex_);
        activeUsers_.clear();
        std::stringstream ss(msg.substr(startPos));
        std::string name;
        while (std::getline(ss, name, ',')) {
            name.erase(0, name.find_first_not_of(" "));
            name.erase(name.find_last_not_of(" ") + 1);
            if (!name.empty()) activeUsers_.push_back(name);
        }
        return;
    }

    std::lock_guard<std::mutex> chatLock(chatMutex_);
    const std::string timestamp = GetTimestamp();

    if (msg.find(':') != std::string::npos && msg.find("SYSTEM") == std::string::npos) {
        size_t sep = msg.find(':');
        std::string user = msg.substr(0, sep);
        std::string payload = msg.substr(sep + 1);

        std::string dec = AESHelper::Decrypt(payload, river::kAesKey, "");
        if (dec.find("[DECRYPT_ERR]") != std::string::npos) dec = payload;

        PushLogLocked({timestamp, user, dec, false, isPm});
        if (user != currentUser) MarkNewMessage();
    } else {
        PushLogLocked({timestamp, "SYSTEM", msg, true, false});
    }
}

void ChatState::AddSystemLog(const std::string& message) {
    std::lock_guard<std::mutex> chatLock(chatMutex_);
    PushLogLocked({GetTimestamp(), "SYSTEM", message, true, false});
}

void ChatState::AddOutgoingChat(const std::string& user, const std::string& message) {
    std::lock_guard<std::mutex> chatLock(chatMutex_);
    PushLogLocked({GetTimestamp(), user, message, false, false});
}

void ChatState::AddOutgoingPrivateMessage(const std::string& user, const std::string& target, const std::string& message) {
    std::lock_guard<std::mutex> chatLock(chatMutex_);
    PushLogLocked({GetTimestamp(), user, "[PM->" + target + "] " + message, false, true});
}

void ChatState::AddAttachmentOffer(const std::string& user, const AttachmentPayload& attachment) {
    std::lock_guard<std::mutex> chatLock(chatMutex_);
    for (auto& entry : chatLogs_) {
        if (entry.isAttachment && entry.user == user && entry.attachment.id == attachment.id) {
            entry.attachment = attachment;
            entry.text = "[" + AttachmentKindToLabel(attachment.kind) + "] " + attachment.displayName;
            return;
        }
    }

    PushLogLocked({GetTimestamp(),
                   user,
                   "[" + AttachmentKindToLabel(attachment.kind) + "] " + attachment.displayName,
                   false,
                   false,
                   true,
                   attachment});
    if (user != CurrentIdentity()) MarkNewMessage();
}

bool ChatState::FindAttachment(const std::string& user, const std::string& attachmentId, AttachmentPayload& attachment) const {
    std::lock_guard<std::mutex> chatLock(chatMutex_);
    for (auto it = chatLogs_.rbegin(); it != chatLogs_.rend(); ++it) {
        if (it->isAttachment && it->user == user && it->attachment.id == attachmentId) {
            attachment = it->attachment;
            return true;
        }
    }
    return false;
}

bool ChatState::UpdateAttachmentState(const std::string& user,
                                      const std::string& attachmentId,
                                      AttachmentTransferState state,
                                      const std::string& localPath) {
    std::lock_guard<std::mutex> chatLock(chatMutex_);
    for (auto it = chatLogs_.rbegin(); it != chatLogs_.rend(); ++it) {
        if (it->isAttachment && it->user == user && it->attachment.id == attachmentId) {
            it->attachment.state = state;
            if (!localPath.empty()) it->attachment.localPath = localPath;
            return true;
        }
    }
    return false;
}

void ChatState::ClearLogs() {
    std::lock_guard<std::mutex> chatLock(chatMutex_);
    chatLogs_.clear();
}

std::vector<LogEntry> ChatState::SnapshotLogs() const {
    std::lock_guard<std::mutex> chatLock(chatMutex_);
    return std::vector<LogEntry>(chatLogs_.begin(), chatLogs_.end());
}

std::vector<std::string> ChatState::SnapshotActiveUsers() const {
    std::lock_guard<std::mutex> usersLock(usersMutex_);
    return activeUsers_;
}

int ChatState::ActiveUserCount() const {
    std::lock_guard<std::mutex> usersLock(usersMutex_);
    return static_cast<int>(activeUsers_.size());
}
