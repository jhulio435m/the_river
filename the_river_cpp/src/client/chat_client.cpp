#include "client/chat_client.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <sstream>
#include <vector>

#include <openssl/evp.h>

#include "client/attachment_utils.h"
#include "client/platform_runtime.h"
#include "common/base64.h"
#include "common/secure_envelope.h"
#include "common/security_utils.h"
#include "common/shared_config.h"
#include "common/tor_connection.h"

namespace {

std::mutex gClientLogMutex;
std::atomic<unsigned long long> gAttachmentCounter{0};

// Diagnostics only: off unless THE_RIVER_CLIENT_LOG=1. Callers must log structural
// events (connection state, frame sizes, line kinds) and never message contents,
// credentials, usernames, session ids or attachment names/paths.
bool ClientLogEnabled() {
    static const bool enabled = [] {
        const char* value = std::getenv("THE_RIVER_CLIENT_LOG");
        return value != nullptr && std::string(value) == "1";
    }();
    return enabled;
}

void AppendClientLog(const std::string& line) {
    if (!ClientLogEnabled()) return;
    std::lock_guard<std::mutex> lock(gClientLogMutex);
    std::ofstream out("client_runtime.log", std::ios::app);
    if (!out.is_open()) return;
    out << line << "\n";
}

std::string GenerateAttachmentId() {
    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return "att" + std::to_string(now) + "_" + std::to_string(gAttachmentCounter.fetch_add(1));
}

std::vector<std::string> SplitByDelimiter(const std::string& value, char delimiter) {
    std::vector<std::string> parts;
    std::stringstream ss(value);
    std::string part;
    while (std::getline(ss, part, delimiter)) parts.push_back(part);
    return parts;
}

std::string BytesToHex(const unsigned char* data, std::size_t size) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(hex[(data[i] >> 4) & 0x0f]);
        out.push_back(hex[data[i] & 0x0f]);
    }
    return out;
}

std::string HashFileSha256(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) return "";

    std::vector<char> buffer(kAttachmentBinaryChunkBytes);
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1;
    while (ok && input.good()) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = input.gcount();
        if (got > 0) {
            ok = EVP_DigestUpdate(ctx, buffer.data(), static_cast<std::size_t>(got)) == 1;
        }
    }

    unsigned char digest[EVP_MAX_MD_SIZE] = {};
    unsigned int digestLen = 0;
    ok = ok && EVP_DigestFinal_ex(ctx, digest, &digestLen) == 1;
    EVP_MD_CTX_free(ctx);
    return ok ? BytesToHex(digest, digestLen) : "";
}

void AppendU16(std::string& out, std::uint16_t value) {
    out.push_back(static_cast<char>((value >> 8) & 0xff));
    out.push_back(static_cast<char>(value & 0xff));
}

void AppendU32(std::string& out, std::uint32_t value) {
    out.push_back(static_cast<char>((value >> 24) & 0xff));
    out.push_back(static_cast<char>((value >> 16) & 0xff));
    out.push_back(static_cast<char>((value >> 8) & 0xff));
    out.push_back(static_cast<char>(value & 0xff));
}

bool ReadU16(const std::string& input, std::size_t& offset, std::uint16_t& value) {
    if (offset + 2 > input.size()) return false;
    value = static_cast<std::uint16_t>(
        (static_cast<unsigned char>(input[offset]) << 8) |
        static_cast<unsigned char>(input[offset + 1]));
    offset += 2;
    return true;
}

bool ReadU32(const std::string& input, std::size_t& offset, std::uint32_t& value) {
    if (offset + 4 > input.size()) return false;
    value = (static_cast<std::uint32_t>(static_cast<unsigned char>(input[offset])) << 24) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(input[offset + 1])) << 16) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(input[offset + 2])) << 8) |
            static_cast<std::uint32_t>(static_cast<unsigned char>(input[offset + 3]));
    offset += 4;
    return true;
}

bool ReadSizedString(const std::string& input, std::size_t& offset, std::string& value) {
    std::uint16_t size = 0;
    if (!ReadU16(input, offset, size) || offset + size > input.size()) return false;
    value.assign(input.data() + offset, size);
    offset += size;
    return true;
}

void AppendSizedString(std::string& out, const std::string& value) {
    AppendU16(out, static_cast<std::uint16_t>(value.size()));
    out.append(value);
}

// Server control lines always start with "SYSTEM:"; matching only those keeps
// chat text or nicknames (e.g. "ACTUALIZADO se unio") from triggering state changes.
bool IsSystemNotice(const std::string& line, const char* token) {
    return line.rfind("SYSTEM:", 0) == 0 && line.find(token) != std::string::npos;
}

}  // namespace

namespace attachment_part {

std::string PartPathFor(const std::string& targetPath) {
    return targetPath + ".part";
}

std::shared_ptr<std::fstream> CreatePartFile(const std::string& partPath) {
    {
        // Create/truncate first: an in|out fstream will not create a missing file.
        std::ofstream create(partPath, std::ios::binary | std::ios::trunc);
        if (!create.is_open()) return nullptr;
    }
    auto file = std::make_shared<std::fstream>(partPath, std::ios::binary | std::ios::in | std::ios::out);
    if (!file->is_open()) {
        RemovePartFile(partPath);
        return nullptr;
    }
    return file;
}

int ExpectedChunkCount(std::size_t totalSize) {
    if (totalSize == 0) return 1;
    return static_cast<int>((totalSize + kAttachmentBinaryChunkBytes - 1) / kAttachmentBinaryChunkBytes);
}

std::size_t ExpectedChunkSize(std::size_t totalSize, int totalChunks, int index) {
    if (index < 0 || index >= totalChunks) return 0;
    const std::size_t start = static_cast<std::size_t>(index) * kAttachmentBinaryChunkBytes;
    if (start >= totalSize) return 0;
    return std::min(kAttachmentBinaryChunkBytes, totalSize - start);
}

bool WriteChunkAt(std::fstream& file, int index, const std::string& data) {
    if (index < 0 || !file.is_open()) return false;
    file.clear();
    if (data.empty()) return true;
    const std::streamoff offset =
        static_cast<std::streamoff>(index) * static_cast<std::streamoff>(kAttachmentBinaryChunkBytes);
    file.seekp(offset, std::ios::beg);
    if (!file.good()) return false;
    file.write(data.data(), static_cast<std::streamsize>(data.size()));
    return file.good();
}

bool FinalizePartFile(const std::string& partPath,
                      const std::string& targetPath,
                      std::size_t expectedSize,
                      const std::string& expectedSha256,
                      std::string& error) {
    std::streamoff actualSize = -1;
    {
        std::ifstream input(partPath, std::ios::binary | std::ios::ate);
        if (input.is_open()) actualSize = input.tellg();
    }
    if (actualSize < 0 || static_cast<std::size_t>(actualSize) != expectedSize || expectedSize > kMaxAttachmentBytes) {
        RemovePartFile(partPath);
        error = "Attachment integrity check failed.";
        return false;
    }
    if (!expectedSha256.empty()) {
        const std::string actualSha256 = HashFileSha256(partPath);
        if (actualSha256.empty() || !ConstantTimeEquals(actualSha256, expectedSha256)) {
            RemovePartFile(partPath);
            error = "Attachment integrity check failed.";
            return false;
        }
    }
    if (std::rename(partPath.c_str(), targetPath.c_str()) != 0) {
        // Windows rename() fails when the destination already exists.
        std::remove(targetPath.c_str());
        if (std::rename(partPath.c_str(), targetPath.c_str()) != 0) {
            RemovePartFile(partPath);
            error = "Could not save the received attachment.";
            return false;
        }
    }
    return true;
}

void RemovePartFile(const std::string& partPath) {
    if (!partPath.empty()) std::remove(partPath.c_str());
}

}  // namespace attachment_part

ChatClient::ChatClient(ChatState& state) : state_(state) {}

ChatClient::~ChatClient() {
    Stop();
}

void ChatClient::Start() {
    if (networkThread_.joinable()) return;
    stopRequested_.store(false);
    state_.SetStatusDetail("Inicializando cliente seguro...");
    state_.ClearLastError();
    networkThread_ = std::thread(&ChatClient::NetworkLoop, this);
}

void ChatClient::Stop() {
    stopRequested_.store(true);
    CloseCurrentSocket();
    if (networkThread_.joinable()) networkThread_.join();
    ReapFinishedUploads(true);
}

void ChatClient::Logout() {
    ForgetSessionCredentials();
    QueueAutoLogin("", "");
    {
        std::lock_guard<std::mutex> lock(reloginMutex_);
        pendingLoginUser_.clear();
        pendingLoginPass_.clear();
    }
    SetCurrentUser("");
    state_.SetLastPrivatePeer("");
    state_.AddSystemLog("SYSTEM: Sesion cerrada localmente.");
    CloseCurrentSocket();
}

void ChatClient::RememberSessionCredentials() {
    std::lock_guard<std::mutex> lock(reloginMutex_);
    // After a first-login change the fresh credentials live in the auto-login queue.
    if (!queuedLoginUser_.empty() && !queuedLoginPass_.empty()) {
        rememberedUser_ = queuedLoginUser_;
        rememberedPass_ = queuedLoginPass_;
    } else if (!pendingLoginUser_.empty() && !pendingLoginPass_.empty()) {
        rememberedUser_ = pendingLoginUser_;
        rememberedPass_ = pendingLoginPass_;
    }
}

void ChatClient::ForgetSessionCredentials() {
    std::lock_guard<std::mutex> lock(reloginMutex_);
    rememberedUser_.clear();
    rememberedPass_.clear();
}

bool ChatClient::ConsumeRememberedCredentials(std::string& user, std::string& pass) {
    std::lock_guard<std::mutex> lock(reloginMutex_);
    if (rememberedUser_.empty() || rememberedPass_.empty()) return false;
    user = rememberedUser_;
    pass = rememberedPass_;
    return true;
}

void ChatClient::HandleServerPong() {
    std::lock_guard<std::mutex> lock(pingMutex_);
    if (!pingOutstanding_) return;
    pingOutstanding_ = false;
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - pingSentAt_).count();
    state_.AddSystemLog("SYSTEM: PONG recibido. Latencia ida y vuelta: " + std::to_string(elapsed) + " ms.");
}

void ChatClient::ReapFinishedUploads(bool joinAll) {
    std::vector<std::thread> toJoin;
    {
        std::lock_guard<std::mutex> lock(uploadsMutex_);
        for (auto it = uploads_.begin(); it != uploads_.end();) {
            if (joinAll || it->done->load()) {
                toJoin.push_back(std::move(it->thread));
                it = uploads_.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto& thread : toJoin) {
        if (thread.joinable()) thread.join();
    }
}

void ChatClient::StartAttachmentUpload(const std::string& requester,
                                       const std::string& attachmentId,
                                       const std::string& mode) {
    ReapFinishedUploads(false);
    // Uploads run off the receive thread so heartbeats and chat keep flowing
    // while a large file streams to the requester.
    auto done = std::make_shared<std::atomic<bool>>(false);
    std::thread worker([this, requester, attachmentId, mode, done]() {
        HandleAttachmentRequest(requester, attachmentId, mode);
        done->store(true);
    });
    std::lock_guard<std::mutex> lock(uploadsMutex_);
    uploads_.push_back({std::move(worker), done});
}

void ChatClient::DiscardIncomingTransfer(IncomingAttachmentTransfer& transfer) {
    if (transfer.partFile) {
        transfer.partFile->close();
        transfer.partFile.reset();
    }
    attachment_part::RemovePartFile(transfer.partPath);
    transfer.partPath.clear();
}

void ChatClient::FailPendingIncomingAttachments(const std::string& reason) {
    std::map<std::string, IncomingAttachmentTransfer> pending;
    {
        std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
        pending.swap(incomingAttachments_);
    }
    for (auto& entry : pending) DiscardIncomingTransfer(entry.second);
    state_.FailRequestedAttachments();
    if (!pending.empty()) state_.SetLastError(reason);
}

void ChatClient::SetCurrentUser(const std::string& user) {
    std::lock_guard<std::mutex> lock(identityMutex_);
    currentUser_ = user;
    state_.SetCurrentIdentity(user);
}

std::string ChatClient::CurrentUser() const {
    std::lock_guard<std::mutex> lock(identityMutex_);
    return currentUser_;
}

void ChatClient::QueueAutoLogin(const std::string& user, const std::string& pass) {
    std::lock_guard<std::mutex> lock(reloginMutex_);
    queuedLoginUser_ = user;
    queuedLoginPass_ = pass;
}

bool ChatClient::ConsumeQueuedAutoLogin(std::string& user, std::string& pass) {
    std::lock_guard<std::mutex> lock(reloginMutex_);
    if (queuedLoginUser_.empty() || queuedLoginPass_.empty()) return false;
    user = queuedLoginUser_;
    pass = queuedLoginPass_;
    queuedLoginUser_.clear();
    queuedLoginPass_.clear();
    return true;
}

void ChatClient::QueueChallengeLogin(const std::string& user, const std::string& pass) {
    std::lock_guard<std::mutex> lock(reloginMutex_);
    pendingLoginUser_ = user;
    pendingLoginPass_ = pass;
}

bool ChatClient::SendChallengeLogin(const std::string& challengeLine) {
    std::lock_guard<std::mutex> lock(reloginMutex_);
    if (pendingLoginUser_.empty() || pendingLoginPass_.empty()) return false;

    const std::vector<std::string> parts = SplitByDelimiter(challengeLine, ':');
    if (parts.size() < 3) return false;
    const std::string& nonce = parts[1];
    const std::string& hashSpec = parts[2];
    const std::string hwid = MakeStableMachineId();
    const std::string verifier = DerivePasswordVerifier(pendingLoginPass_, hashSpec);
    if (verifier.empty()) return false;
    const std::string proof = HmacSha256Hex(verifier, nonce + "|" + pendingLoginUser_ + "|" + hwid);
    const std::string user = pendingLoginUser_;
    return SendRawLine("[LOGIN_PROOF]:" + user + ":" + hwid + ":" + proof + "\n") >= 0;
}

int ChatClient::SendRawLine(const std::string& payload) {
    std::lock_guard<std::mutex> lock(socketMutex_);
    if (!IsSocketValid(socket_)) return -1;

    std::string framePayload = payload;
    while (!framePayload.empty() && (framePayload.back() == '\n' || framePayload.back() == '\r')) {
        framePayload.pop_back();
    }

    if (!SendTextFrame(socket_, framePayload)) {
#ifdef _WIN32
        AppendClientLog("SendRawLine failed err=" + std::to_string(WSAGetLastError()));
#else
        AppendClientLog("SendRawLine failed err=" + std::to_string(errno));
#endif
        return -1;
    }

    AppendClientLog("SendRawLine ok bytes=" + std::to_string(framePayload.size()));
    return static_cast<int>(framePayload.size());
}

bool ChatClient::SendEncryptedPayload(const std::string& user, const std::string& payload) {
    return SendRawLine(user + ":" + river::SealPayload(payload) + "\n") >= 0;
}

void ChatClient::CloseCurrentSocket() {
    std::lock_guard<std::mutex> lock(socketMutex_);
    if (!IsSocketValid(socket_)) return;
    CloseSocketHandle(socket_);
    socket_ = kInvalidSocket;
}

bool ChatClient::SendLogin(const std::string& user, const std::string& pass) {
    SetCurrentUser(user);
    state_.ClearLastError();
    state_.SetAuthActionPending(true);
    state_.SetCredentialChangePending(false);
    state_.SetConnectionState(ConnState::AUTHENTICATING);
    state_.SetStatusDetail("Autenticando credenciales...");
    AppendClientLog("SendLogin");
    QueueChallengeLogin(user, pass);
    if (SendRawLine("[LOGIN_INIT]:" + user + ":" + MakeStableMachineId() + "\n") < 0) {
        state_.SetAuthActionPending(false);
        state_.SetLastError("No hay canal disponible para enviar el login.");
        state_.SetStatusDetail("Sin enlace activo hacia el servidor.");
        return false;
    }
    return true;
}

bool ChatClient::SendFirstLoginChange(const std::string& newUser, const std::string& newPass) {
    state_.ClearLastError();
    state_.SetCredentialChangePending(true);
    state_.SetConnectionState(ConnState::UPDATING_CREDENTIALS);
    state_.SetStatusDetail("Actualizando identidad inicial...");
    QueueAutoLogin(newUser, newPass);
    const std::string encPass = river::SealPayload(newPass);
    if (SendRawLine("[CHANGE]:" + newUser + ":" + encPass + "\n") < 0) {
        state_.SetCredentialChangePending(false);
        QueueAutoLogin("", "");
        state_.SetLastError("Could not send the initial credential change.");
        state_.SetStatusDetail("Sin enlace activo hacia el servidor.");
        return false;
    }
    return true;
}

bool ChatClient::SendPing() {
    {
        std::lock_guard<std::mutex> lock(pingMutex_);
        pingOutstanding_ = true;
        pingSentAt_ = std::chrono::steady_clock::now();
    }
    if (SendRawLine("PING\n") < 0) {
        std::lock_guard<std::mutex> lock(pingMutex_);
        pingOutstanding_ = false;
        state_.SetLastError("Could not send PING to the server.");
        return false;
    }
    return true;
}

bool ChatClient::SendChatMessage(const std::string& user, const std::string& input) {
    if (!SendEncryptedPayload(user, input)) {
        state_.SetLastError("Could not send the message. Channel unavailable.");
        return false;
    }
    return true;
}

bool ChatClient::SendPrivateMessage(const std::string& fromUser, const std::string& target, const std::string& message) {
    std::string enc = river::SealPayload(message);
    if (SendRawLine("[PM]:" + target + ":" + fromUser + ":" + enc + "\n") < 0) {
        state_.SetLastError("Could not send the private message.");
        return false;
    }
    return true;
}

bool ChatClient::SendAttachment(const std::string& fromUser, const AttachmentDraft& attachment) {
    if (fromUser.empty()) {
        state_.SetLastError("No hay identidad autenticada para enviar adjuntos.");
        return false;
    }
    if (attachment.localPath.empty() || attachment.displayName.empty()) {
        state_.SetLastError("Invalid attachment.");
        return false;
    }
    if (attachment.sizeBytes > kMaxAttachmentBytes) {
        state_.SetLastError("Attachment too large. Current limit: " + FormatAttachmentSize(kMaxAttachmentBytes) + ".");
        return false;
    }

    const std::string id = GenerateAttachmentId();
    {
        std::lock_guard<std::mutex> lock(offeredAttachmentMutex_);
        offeredAttachments_[id] = attachment;
    }

    const std::string kind =
        attachment.kind == AttachmentKind::Image ? "image" :
        attachment.kind == AttachmentKind::Video ? "video" : "file";
    const std::string encOffer = river::SealPayload(
        "@offer|" + id + "|" + kind + "|" +
            river::base64::EncodeString(attachment.displayName) + "|" +
            river::base64::EncodeString(attachment.mimeType) + "|" +
            std::to_string(attachment.sizeBytes));

    if (SendRawLine("[ATTACH]:" + encOffer + "\n") < 0) {
        std::lock_guard<std::mutex> lock(offeredAttachmentMutex_);
        offeredAttachments_.erase(id);
        state_.SetLastError("Could not announce the attachment.");
        return false;
    }

    state_.SetStatusDetail("Attachment announced: " + attachment.displayName);
    state_.ClearLastError();
    return true;
}

bool ChatClient::RequestAttachment(const AttachmentPayload& attachment, const std::string& savePath, const std::string& mode) {
    if (attachment.ownerUser.empty() || attachment.id.empty() || savePath.empty()) {
        state_.SetLastError("Solicitud de adjunto invalida.");
        return false;
    }
    if (attachment.sizeBytes > kMaxAttachmentBytes) {
        state_.SetLastError("Attachment too large. Current limit: " + FormatAttachmentSize(kMaxAttachmentBytes) + ".");
        return false;
    }

    IncomingAttachmentTransfer transfer;
    transfer.attachment = attachment;
    transfer.ownerUser = attachment.ownerUser;
    transfer.mode = mode;
    transfer.targetPath = savePath;
    const std::string key = attachment.ownerUser + "|" + attachment.id;
    IncomingAttachmentTransfer replaced;
    {
        std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
        auto existing = incomingAttachments_.find(key);
        if (existing != incomingAttachments_.end()) {
            replaced = std::move(existing->second);
            existing->second = std::move(transfer);
        } else {
            incomingAttachments_.emplace(key, std::move(transfer));
        }
    }
    DiscardIncomingTransfer(replaced);
    state_.UpdateAttachmentState(attachment.ownerUser, attachment.id, AttachmentTransferState::Requested);

    if (!SendPrivateMessage(CurrentUser(), attachment.ownerUser, "@attachreq|" + attachment.id + "|" + mode)) {
        IncomingAttachmentTransfer dropped;
        {
            std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
            auto it = incomingAttachments_.find(key);
            if (it != incomingAttachments_.end()) {
                dropped = std::move(it->second);
                incomingAttachments_.erase(it);
            }
        }
        DiscardIncomingTransfer(dropped);
        state_.UpdateAttachmentState(attachment.ownerUser, attachment.id, AttachmentTransferState::Available);
        return false;
    }
    return true;
}

bool ChatClient::HandleAttachmentBroadcast(const std::string& line) {
    if (line.rfind("[ATTACH]:", 0) != 0) return false;

    const std::string rest = line.substr(9);
    const std::size_t sep = rest.find(':');
    if (sep == std::string::npos) return true;

    const std::string sender = rest.substr(0, sep);
    const std::string encPayload = rest.substr(sep + 1);
    std::string payload;
    if (!river::OpenPayload(encPayload, payload) || payload.rfind("@offer|", 0) != 0) return true;

    const std::vector<std::string> parts = SplitByDelimiter(payload, '|');
    if (parts.size() < 6) return true;

    AttachmentPayload attachment;
    attachment.id = parts[1];
    attachment.ownerUser = sender;
    attachment.kind =
        parts[2] == "image" ? AttachmentKind::Image :
        parts[2] == "video" ? AttachmentKind::Video : AttachmentKind::File;
    river::base64::DecodeToString(parts[3], attachment.displayName);
    river::base64::DecodeToString(parts[4], attachment.mimeType);
    attachment.sizeBytes = static_cast<std::size_t>(std::strtoull(parts[5].c_str(), nullptr, 10));
    if (attachment.sizeBytes > kMaxAttachmentBytes || attachment.id.size() > 80 || !IsValidUsername(sender)) return true;
    attachment.state = AttachmentTransferState::Available;

    if (sender == CurrentUser()) {
        std::lock_guard<std::mutex> lock(offeredAttachmentMutex_);
        auto it = offeredAttachments_.find(attachment.id);
        if (it != offeredAttachments_.end()) attachment.localPath = it->second.localPath;
    }

    state_.AddAttachmentOffer(sender, attachment);
    return true;
}

void ChatClient::HandleAttachmentRequest(const std::string& requester, const std::string& attachmentId, const std::string& mode) {
    AttachmentDraft draft;
    {
        std::lock_guard<std::mutex> lock(offeredAttachmentMutex_);
        auto it = offeredAttachments_.find(attachmentId);
        if (it == offeredAttachments_.end()) {
            SendPrivateMessage(CurrentUser(), requester, "@attacherr|" + attachmentId + "|" +
                river::base64::EncodeString("Attachment unavailable."));
            return;
        }
        draft = it->second;
    }

    std::ifstream input(draft.localPath, std::ios::binary);
    if (!input.is_open()) {
        SendPrivateMessage(CurrentUser(), requester, "@attacherr|" + attachmentId + "|" +
            river::base64::EncodeString("Could not open the source attachment."));
        return;
    }

    if (draft.sizeBytes > kMaxAttachmentBytes) {
        SendPrivateMessage(CurrentUser(), requester, "@attacherr|" + attachmentId + "|" +
            river::base64::EncodeString("Attachment exceeds the transfer limit."));
        return;
    }

    const std::string contentSha256 = HashFileSha256(draft.localPath);
    if (contentSha256.empty()) {
        SendPrivateMessage(CurrentUser(), requester, "@attacherr|" + attachmentId + "|" +
            river::base64::EncodeString("Could not hash the source attachment."));
        return;
    }
    const std::string kind =
        draft.kind == AttachmentKind::Image ? "image" :
        draft.kind == AttachmentKind::Video ? "video" : "file";
    const std::size_t totalChunks = draft.sizeBytes == 0 ? 1 : (draft.sizeBytes + kAttachmentBinaryChunkBytes - 1) / kAttachmentBinaryChunkBytes;

    if (!SendPrivateMessage(CurrentUser(),
                            requester,
                            "@attachmeta|" + attachmentId + "|" + kind + "|" +
                                river::base64::EncodeString(draft.displayName) + "|" +
                                river::base64::EncodeString(draft.mimeType) + "|" +
                                std::to_string(draft.sizeBytes) + "|" + mode + "|" +
                                std::to_string(totalChunks) + "|" + contentSha256)) {
        return;
    }

    for (std::size_t index = 0; index < totalChunks; ++index) {
        if (stopRequested_.load()) return;
        std::string plainChunk;
        if (draft.sizeBytes > 0) {
            std::vector<char> buffer(kAttachmentBinaryChunkBytes);
            input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            const std::streamsize got = input.gcount();
            if (got <= 0) {
                SendPrivateMessage(CurrentUser(), requester, "@attacherr|" + attachmentId + "|" +
                    river::base64::EncodeString("Transferencia interrumpida."));
                return;
            }
            plainChunk.assign(buffer.data(), static_cast<std::size_t>(got));
        }
        const std::string encryptedChunk = river::SealPayloadBinary(plainChunk);
        if (encryptedChunk.empty() ||
            !SendAttachmentChunkFrame(requester,
                                      attachmentId,
                                      static_cast<int>(index),
                                      static_cast<int>(totalChunks),
                                      encryptedChunk)) {
            SendPrivateMessage(CurrentUser(), requester, "@attacherr|" + attachmentId + "|" +
                river::base64::EncodeString("Transferencia interrumpida."));
            return;
        }
    }
}

void ChatClient::FinishIncomingAttachment(IncomingAttachmentTransfer transfer) {
    // Close the stream before hashing/renaming (Windows cannot rename an open file).
    bool ok = true;
    std::string error;
    if (transfer.partFile) {
        transfer.partFile->flush();
        ok = transfer.partFile->good();
        transfer.partFile->close();
        transfer.partFile.reset();
    }
    if (!ok) {
        attachment_part::RemovePartFile(transfer.partPath);
        error = "Could not save the received attachment.";
    } else {
        ok = attachment_part::FinalizePartFile(transfer.partPath,
                                               transfer.targetPath,
                                               transfer.attachment.sizeBytes,
                                               transfer.attachment.contentSha256,
                                               error);
    }
    if (!ok) {
        state_.UpdateAttachmentState(transfer.ownerUser, transfer.attachment.id, AttachmentTransferState::Failed);
        state_.SetLastError(error);
        return;
    }

    state_.UpdateAttachmentState(transfer.ownerUser,
                                 transfer.attachment.id,
                                 AttachmentTransferState::Received,
                                 transfer.targetPath);
    state_.SetStatusDetail("Attachment received: " + transfer.attachment.displayName);
    state_.AddSystemLog("SYSTEM: Attachment received and saved to " + transfer.targetPath);
    state_.ClearLastError();
}

bool ChatClient::HandleAttachmentPrivateControl(const std::string& sender, const std::string& payload) {
    if (payload.rfind("@attachreq|", 0) == 0) {
        const std::vector<std::string> parts = SplitByDelimiter(payload, '|');
        if (parts.size() >= 3) StartAttachmentUpload(sender, parts[1], parts[2]);
        return true;
    }

    if (payload.rfind("@attachmeta|", 0) == 0) {
        const std::vector<std::string> parts = SplitByDelimiter(payload, '|');
        if (parts.size() < 8) return true;

        const std::string key = sender + "|" + parts[1];
        IncomingAttachmentTransfer dropped;
        std::string failure;
        {
            std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
            auto pending = incomingAttachments_.find(key);
            if (pending == incomingAttachments_.end()) return true;
            IncomingAttachmentTransfer& transfer = pending->second;
            if (transfer.partFile) return true;  // duplicate metadata for a transfer already in flight
            transfer.ownerUser = sender;
            transfer.attachment.id = parts[1];
            transfer.attachment.ownerUser = sender;
            transfer.attachment.kind =
                parts[2] == "image" ? AttachmentKind::Image :
                parts[2] == "video" ? AttachmentKind::Video : AttachmentKind::File;
            river::base64::DecodeToString(parts[3], transfer.attachment.displayName);
            river::base64::DecodeToString(parts[4], transfer.attachment.mimeType);
            transfer.attachment.sizeBytes = static_cast<std::size_t>(std::strtoull(parts[5].c_str(), nullptr, 10));
            transfer.mode = parts[6];
            transfer.totalChunks = std::atoi(parts[7].c_str());
            if (parts.size() >= 9) transfer.attachment.contentSha256 = parts[8];
            transfer.receivedChunks = 0;
            transfer.attachment.state = AttachmentTransferState::Requested;
            if (transfer.targetPath.empty()) transfer.targetPath = BuildAttachmentCachePath(parts[1], transfer.attachment.displayName);

            if (transfer.attachment.sizeBytes > kMaxAttachmentBytes) {
                failure = "Attachment exceeds the transfer limit.";
            } else if (transfer.totalChunks != attachment_part::ExpectedChunkCount(transfer.attachment.sizeBytes)) {
                failure = "Attachment metadata is invalid.";
            } else {
                transfer.receivedIndices.assign(static_cast<std::size_t>(transfer.totalChunks), false);
                transfer.partPath = attachment_part::PartPathFor(transfer.targetPath);
                transfer.partFile = attachment_part::CreatePartFile(transfer.partPath);
                if (!transfer.partFile) {
                    transfer.partPath.clear();
                    failure = "Could not save the received attachment.";
                }
            }
            if (!failure.empty()) {
                dropped = std::move(transfer);
                incomingAttachments_.erase(pending);
            }
        }
        if (!failure.empty()) {
            DiscardIncomingTransfer(dropped);
            state_.UpdateAttachmentState(sender, parts[1], AttachmentTransferState::Failed);
            state_.SetLastError(failure);
        }
        return true;
    }

    if (payload.rfind("@attacherr|", 0) == 0) {
        const std::vector<std::string> parts = SplitByDelimiter(payload, '|');
        if (parts.size() < 3) return true;

        std::string errorText;
        river::base64::DecodeToString(parts[2], errorText);
        IncomingAttachmentTransfer dropped;
        {
            std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
            auto it = incomingAttachments_.find(sender + "|" + parts[1]);
            if (it != incomingAttachments_.end()) {
                dropped = std::move(it->second);
                incomingAttachments_.erase(it);
            }
        }
        DiscardIncomingTransfer(dropped);
        state_.UpdateAttachmentState(sender, parts[1], AttachmentTransferState::Failed);
        state_.SetLastError(errorText.empty() ? "Could not transfer the attachment." : errorText);
        return true;
    }

    return false;
}

bool ChatClient::SendAttachmentChunkFrame(const std::string& target,
                                          const std::string& attachmentId,
                                          int index,
                                          int totalChunks,
                                          const std::string& encryptedChunk) {
    if (target.empty() || target.size() > 255 ||
        attachmentId.empty() || attachmentId.size() > 255 ||
        index < 0 || totalChunks <= 0 ||
        encryptedChunk.empty()) {
        return false;
    }

    std::string payload;
    AppendSizedString(payload, target);
    AppendSizedString(payload, attachmentId);
    AppendU32(payload, static_cast<std::uint32_t>(index));
    AppendU32(payload, static_cast<std::uint32_t>(totalChunks));
    payload.append(encryptedChunk);

    std::lock_guard<std::mutex> lock(socketMutex_);
    return IsSocketValid(socket_) && SendFrame(socket_, kFrameTypeAttachmentChunk, payload);
}

bool ChatClient::HandleAttachmentChunkFrame(const std::string& payload) {
    std::size_t offset = 0;
    std::string sender;
    std::string attachmentId;
    std::uint32_t index = 0;
    std::uint32_t totalChunks = 0;
    if (!ReadSizedString(payload, offset, sender) ||
        !ReadSizedString(payload, offset, attachmentId) ||
        !ReadU32(payload, offset, index) ||
        !ReadU32(payload, offset, totalChunks) ||
        totalChunks == 0 ||
        totalChunks > (kMaxAttachmentBytes + kAttachmentBinaryChunkBytes - 1) / kAttachmentBinaryChunkBytes ||
        index >= totalChunks ||
        offset >= payload.size()) {
        return true;
    }

    const std::string key = sender + "|" + attachmentId;
    std::string plainChunk;
    const std::string encryptedChunk = payload.substr(offset);
    const bool opened = river::OpenPayloadBinary(encryptedChunk, plainChunk) &&
                        plainChunk.size() <= kAttachmentBinaryChunkBytes;

    IncomingAttachmentTransfer finished;
    bool done = false;
    std::string failure;
    {
        // A chunk write is at most kAttachmentBinaryChunkBytes, so it stays under the lock;
        // that keeps FailPendingIncomingAttachments from deleting the file mid-write.
        std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
        auto it = incomingAttachments_.find(key);
        if (it == incomingAttachments_.end()) return true;

        IncomingAttachmentTransfer& transfer = it->second;
        if (!transfer.partFile || transfer.totalChunks != static_cast<int>(totalChunks)) return true;
        const int chunkIndex = static_cast<int>(index);
        if (transfer.receivedIndices[index]) return true;  // duplicate

        if (!opened) {
            failure = "Attachment chunk integrity check failed.";
        } else if (plainChunk.size() != attachment_part::ExpectedChunkSize(transfer.attachment.sizeBytes,
                                                                           transfer.totalChunks,
                                                                           chunkIndex)) {
            failure = "Attachment integrity check failed.";
        } else if (!attachment_part::WriteChunkAt(*transfer.partFile, chunkIndex, plainChunk)) {
            failure = "Could not save the received attachment.";
        } else {
            transfer.receivedIndices[index] = true;
            transfer.receivedChunks++;
        }

        if (!failure.empty() || transfer.receivedChunks == transfer.totalChunks) {
            finished = std::move(transfer);
            incomingAttachments_.erase(it);
            done = failure.empty();
        }
    }
    if (!failure.empty()) {
        DiscardIncomingTransfer(finished);
        state_.UpdateAttachmentState(sender, attachmentId, AttachmentTransferState::Failed);
        state_.SetLastError(failure);
        return true;
    }
    // Hashing and renaming happen outside incomingAttachmentMutex_.
    if (done) FinishIncomingAttachment(std::move(finished));
    return true;
}

void ChatClient::ReceiveLoop(SocketHandle sock) {
    AppendClientLog("ReceiveLoop start");
    while (!stopRequested_.load()) {
        std::uint16_t frameType = 0;
        std::string line;
        if (!RecvFrame(sock, frameType, line, 1024 * 1024)) {
            AppendClientLog("ReceiveLoop frame read failed");
            break;
        }

        if (frameType == kFrameTypeAttachmentChunk) {
            HandleAttachmentChunkFrame(line);
            continue;
        }
        if (frameType != kFrameTypeText) {
            AppendClientLog("ReceiveLoop unsupported frame type=" + std::to_string(frameType));
            continue;
        }

        AppendClientLog("ReceiveLoop frame bytes=" + std::to_string(line.size()));
        if (line == "PING") {
            AppendClientLog("ReceiveLoop line=PING");
            SendRawLine("PONG\n");
        } else if (line == "PONG") {
            HandleServerPong();
        } else if (line.rfind("AUTH_CHALLENGE:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=AUTH_CHALLENGE");
            if (!SendChallengeLogin(line)) {
                state_.SetAuthActionPending(false);
                state_.SetLastError("Could not complete authentication challenge.");
            }
        } else if (IsSystemNotice(line, "FIRST LOGIN")) {
            AppendClientLog("ReceiveLoop line=FIRST LOGIN");
            state_.SetAuthActionPending(false);
            state_.SetCredentialChangePending(false);
            state_.SetMustChangeCredentials(true);
            state_.SetConnectionState(ConnState::FIRST_LOGIN_REQUIRED);
            state_.SetStatusDetail("First access detected. You must change ID and key.");
            state_.ClearLastError();
        } else if (IsSystemNotice(line, "ACCESO CONCEDIDO")) {
            AppendClientLog("ReceiveLoop line=ACCESO CONCEDIDO");
            RememberSessionCredentials();
            {
                // After a first-login change the server knows us by the new identity.
                std::string queuedUser;
                {
                    std::lock_guard<std::mutex> lock(reloginMutex_);
                    queuedUser = queuedLoginUser_;
                }
                if (!queuedUser.empty()) SetCurrentUser(queuedUser);
            }
            QueueAutoLogin("", "");
            state_.SetAuthenticated(true);
            state_.SetMustChangeCredentials(false);
            state_.SetAuthActionPending(false);
            state_.SetCredentialChangePending(false);
            state_.SetConnectionState(ConnState::AUTHENTICATED);
            state_.SetStatusDetail("Canal seguro autenticado.");
            state_.ClearLastError();
        } else if (line.rfind("SESSION:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=SESSION");
            state_.SetStatusDetail("Sesion segura activa.");
        } else if (IsSystemNotice(line, "UPLINK ESTABLISHED")) {
            AppendClientLog("ReceiveLoop line=UPLINK ESTABLISHED");
            state_.SetConnectionState(ConnState::TOR_READY);
            state_.SetStatusDetail("Canal Tor establecido. Esperando login.");
            state_.ClearLastError();
            {
                // Keep the reason for a forced disconnect visible on the login screen.
                std::lock_guard<std::mutex> lock(reloginMutex_);
                if (!disconnectNotice_.empty()) {
                    state_.SetLastError(disconnectNotice_);
                    disconnectNotice_.clear();
                }
            }
            std::string queuedUser;
            std::string queuedPass;
            if (ConsumeQueuedAutoLogin(queuedUser, queuedPass)) {
                AppendClientLog("ReceiveLoop auto-login");
                SendLogin(queuedUser, queuedPass);
            } else if (ConsumeRememberedCredentials(queuedUser, queuedPass)) {
                AppendClientLog("ReceiveLoop session-resume");
                state_.AddSystemLog("SYSTEM: Enlace restablecido. Reautenticando como " + queuedUser + "...");
                SendLogin(queuedUser, queuedPass);
            }
        } else if (IsSystemNotice(line, "ACTUALIZADO. RECONECTA")) {
            AppendClientLog("ReceiveLoop line=ACTUALIZADO");
            state_.SetMustChangeCredentials(false);
            state_.SetAuthActionPending(false);
            state_.SetCredentialChangePending(false);
            state_.SetConnectionState(ConnState::RECONNECTING);
            state_.SetStatusDetail("Credenciales actualizadas. Reautenticando en cuanto el canal vuelva a estar listo...");
            state_.ClearLastError();
        } else if (IsSystemNotice(line, "ACTUALIZADO")) {
            AppendClientLog("ReceiveLoop line=ACTUALIZADO SIMPLE");
            state_.SetMustChangeCredentials(false);
            state_.SetAuthActionPending(false);
            state_.SetCredentialChangePending(false);
            state_.SetStatusDetail("Credenciales actualizadas. Finalizando acceso...");
            state_.ClearLastError();
        } else if (IsSystemNotice(line, "CREDENCIALES INCORRECTAS")) {
            AppendClientLog("ReceiveLoop line=CREDENCIALES INCORRECTAS");
            ForgetSessionCredentials();
            state_.SetAuthActionPending(false);
            state_.SetConnectionState(ConnState::TOR_READY);
            state_.SetStatusDetail("Canal Tor listo. Esperando nuevas credenciales.");
            state_.SetLastError("Credenciales incorrectas.");
            state_.AddSystemLog("SYSTEM: CREDENCIALES INCORRECTAS.");
        } else if (IsSystemNotice(line, "HWID NO RECONOCIDO")) {
            AppendClientLog("ReceiveLoop line=HWID NO RECONOCIDO");
            ForgetSessionCredentials();
            state_.SetAuthActionPending(false);
            state_.SetConnectionState(ConnState::TOR_READY);
            state_.SetStatusDetail("Canal Tor listo. Acceso denegado por HWID.");
            state_.SetLastError("Esta maquina no coincide con el HWID autorizado.");
            state_.AddSystemLog("SYSTEM: HWID NO RECONOCIDO.");
        } else if (IsSystemNotice(line, "ACCESO BLOQUEADO")) {
            AppendClientLog("ReceiveLoop line=ACCESO BLOQUEADO");
            ForgetSessionCredentials();
            if (state_.IsAuthenticated()) {
                std::lock_guard<std::mutex> lock(reloginMutex_);
                disconnectNotice_ = line.substr(8);
            }
            state_.SetAuthActionPending(false);
            state_.SetCredentialChangePending(false);
            state_.SetConnectionState(ConnState::TOR_READY);
            state_.SetStatusDetail("Canal Tor listo. Acceso bloqueado.");
            state_.SetLastError("Acceso bloqueado para esta maquina.");
            state_.AddSystemLog("SYSTEM: ACCESO BLOQUEADO.");
        } else if (IsSystemNotice(line, "KICKED BY ADMIN") || IsSystemNotice(line, "SESION REEMPLAZADA")) {
            AppendClientLog("ReceiveLoop line=SESSION TERMINATED");
            // Do not silently fight the admin or a newer session of the same identity.
            ForgetSessionCredentials();
            {
                std::lock_guard<std::mutex> lock(reloginMutex_);
                disconnectNotice_ = line.substr(8);
            }
            state_.SetLastError(line.substr(8));
            state_.AddSystemLog(line);
        } else if (IsSystemNotice(line, "ERROR ACTUALIZANDO USUARIO")) {
            AppendClientLog("ReceiveLoop line=ERROR ACTUALIZANDO USUARIO");
            QueueAutoLogin("", "");
            state_.SetCredentialChangePending(false);
            state_.SetConnectionState(ConnState::FIRST_LOGIN_REQUIRED);
            state_.SetStatusDetail("Could not complete the initial update.");
            state_.SetLastError("Could not update the user or key.");
            state_.AddSystemLog("SYSTEM: ERROR ACTUALIZANDO USUARIO.");
        } else if (line.rfind("[ATTACH]:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=ATTACH_OFFER");
            HandleAttachmentBroadcast(line);
        } else if (line.rfind("[PM]:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=PM");
            const std::string rest = line.substr(5);
            const std::size_t sep = rest.find(':');
            if (sep != std::string::npos) {
                const std::string sender = rest.substr(0, sep);
                const std::string encPayload = rest.substr(sep + 1);
                std::string dec;
                if (river::OpenPayload(encPayload, dec) && HandleAttachmentPrivateControl(sender, dec))
                    continue;
            }
            state_.AddIncomingWireMessage(rest, CurrentUser(), true);
        } else {
            AppendClientLog("ReceiveLoop line=UNHANDLED");
            state_.AddIncomingWireMessage(line, CurrentUser(), false);
        }
    }
    AppendClientLog("ReceiveLoop end");
}

void ChatClient::NetworkLoop() {
    AppendClientLog("NetworkLoop start");
    while (!stopRequested_.load()) {
        CloseCurrentSocket();
        bool hadIdentity = !CurrentUser().empty();
        if (!river::HasRequiredClientConfig()) {
            state_.SetConnectionState(ConnState::DISCONNECTED);
            state_.SetAuthenticated(false);
            state_.SetStatusDetail("Configura THE_RIVER_ONION y THE_RIVER_AES_KEY antes de conectar.");
            state_.SetLastError("Local private configuration is missing. Embedded build keys will not be used.");
            AppendClientLog("NetworkLoop missing private config");
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }
        state_.SetConnectionState(hadIdentity ? ConnState::RECONNECTING : ConnState::CONNECTING);
        state_.SetAuthenticated(false);
        state_.SetMustChangeCredentials(false);
        state_.SetAuthActionPending(false);
        state_.SetCredentialChangePending(false);
        state_.SetStatusDetail(hadIdentity ? "Restableciendo enlace Tor..." : "Conectando a la red Tor...");
        AppendClientLog("NetworkLoop CONNECTING");

        TorEndpoint endpoint{
            river::kTorProxyIp,
            river::kTorProxyPort,
            river::OnionAddress(),
            static_cast<unsigned short>(river::kTorOnionPort)
        };
        if (!IsTorProxyReachable(river::kTorProxyIp, river::kTorProxyPort)) {
            AppendClientLog("NetworkLoop Tor proxy missing, attempting auto-start");
            EnsureLocalTorIsRunning();
        }
        SocketHandle sock = ConnectViaTor(endpoint);
        if (!IsSocketValid(sock)) {
            AppendClientLog("NetworkLoop ConnectViaTor failed");
            state_.SetConnectionState(ConnState::DISCONNECTED);
            if (IsTermuxEnvironment() && !IsTorProxyReachable(river::kTorProxyIp, river::kTorProxyPort)) {
                state_.SetStatusDetail("No local Tor proxy detected at 127.0.0.1:9050.");
                state_.SetLastError(
                    "En Termux debes iniciar tor antes del cliente. Ejecuta el script run_termux_client.sh con --start-tor o arranca tor manualmente.");
            } else {
                state_.SetStatusDetail("Could not open an onion circuit to the server.");
                state_.SetLastError("Tor no disponible o hidden service sin respuesta.");
            }
            for (int i = 0; i < 50 && !stopRequested_.load(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(socketMutex_);
            socket_ = sock;
        }
        AppendClientLog("NetworkLoop TOR_OK");
        state_.SetConnectionState(ConnState::TOR_READY);
        state_.SetStatusDetail("Canal Tor listo. Esperando banner del servidor...");
        state_.ClearLastError();
        ReceiveLoop(sock);
        CloseCurrentSocket();
        FailPendingIncomingAttachments("Enlace perdido durante la transferencia del adjunto.");
        state_.SetAuthenticated(false);
        state_.SetConnectionState(ConnState::DISCONNECTED);
        state_.SetAuthActionPending(false);
        state_.SetCredentialChangePending(false);
        state_.SetStatusDetail("Canal cerrado. Reintentando enlace...");
        AppendClientLog("NetworkLoop DISCONNECTED");
    }
    AppendClientLog("NetworkLoop end");
}
