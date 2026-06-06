#include "client/chat_client.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iterator>
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

void AppendClientLog(const std::string& line) {
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

std::string BytesToString(const std::vector<unsigned char>& bytes) {
    if (bytes.empty()) return "";
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
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

}  // namespace

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
    AppendClientLog("SendLogin user=" + user);
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
    if (SendRawLine("PING\n") < 0) {
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
    {
        std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
        incomingAttachments_[attachment.ownerUser + "|" + attachment.id] = transfer;
    }
    state_.UpdateAttachmentState(attachment.ownerUser, attachment.id, AttachmentTransferState::Requested);

    if (!SendPrivateMessage(CurrentUser(), attachment.ownerUser, "@attachreq|" + attachment.id + "|" + mode)) {
        std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
        incomingAttachments_.erase(attachment.ownerUser + "|" + attachment.id);
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
    std::string joined;
    for (const auto& chunk : transfer.chunks) joined += chunk;

    std::vector<unsigned char> decoded;
    if (transfer.binaryChunks) {
        decoded.assign(joined.begin(), joined.end());
    } else {
        if (!river::base64::Decode(joined, decoded)) {
            state_.UpdateAttachmentState(transfer.ownerUser, transfer.attachment.id, AttachmentTransferState::Failed);
            state_.SetLastError("Could not reconstruct the received attachment.");
            return;
        }
    }
    if (decoded.size() > kMaxAttachmentBytes ||
        decoded.size() != transfer.attachment.sizeBytes ||
        (!transfer.attachment.contentSha256.empty() &&
         !ConstantTimeEquals(HashPassword(BytesToString(decoded)), transfer.attachment.contentSha256))) {
        state_.UpdateAttachmentState(transfer.ownerUser, transfer.attachment.id, AttachmentTransferState::Failed);
        state_.SetLastError("Attachment integrity check failed.");
        return;
    }

    std::ofstream output(transfer.targetPath, std::ios::binary);
    if (!output.is_open()) {
        state_.UpdateAttachmentState(transfer.ownerUser, transfer.attachment.id, AttachmentTransferState::Failed);
        state_.SetLastError("Could not save the received attachment.");
        return;
    }

    output.write(reinterpret_cast<const char*>(decoded.data()), static_cast<std::streamsize>(decoded.size()));
    output.close();

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
        if (parts.size() >= 3) HandleAttachmentRequest(sender, parts[1], parts[2]);
        return true;
    }

    if (payload.rfind("@attachmeta|", 0) == 0) {
        const std::vector<std::string> parts = SplitByDelimiter(payload, '|');
        if (parts.size() < 8) return true;

        const std::string key = sender + "|" + parts[1];
        std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
        auto pending = incomingAttachments_.find(key);
        if (pending == incomingAttachments_.end()) return true;
        IncomingAttachmentTransfer& transfer = pending->second;
        transfer.ownerUser = sender;
        transfer.attachment.id = parts[1];
        transfer.attachment.ownerUser = sender;
        transfer.attachment.kind =
            parts[2] == "image" ? AttachmentKind::Image :
            parts[2] == "video" ? AttachmentKind::Video : AttachmentKind::File;
        river::base64::DecodeToString(parts[3], transfer.attachment.displayName);
        river::base64::DecodeToString(parts[4], transfer.attachment.mimeType);
        transfer.attachment.sizeBytes = static_cast<std::size_t>(std::strtoull(parts[5].c_str(), nullptr, 10));
        if (transfer.attachment.sizeBytes > kMaxAttachmentBytes) {
            incomingAttachments_.erase(key);
            state_.UpdateAttachmentState(sender, parts[1], AttachmentTransferState::Failed);
            state_.SetLastError("Attachment exceeds the transfer limit.");
            return true;
        }
        transfer.mode = parts[6];
        transfer.totalChunks = std::max(1, std::atoi(parts[7].c_str()));
        transfer.binaryChunks = true;
        if (transfer.totalChunks < 1 ||
            transfer.totalChunks > static_cast<int>((kMaxAttachmentBytes + kAttachmentBinaryChunkBytes - 1) / kAttachmentBinaryChunkBytes)) {
            incomingAttachments_.erase(key);
            state_.UpdateAttachmentState(sender, parts[1], AttachmentTransferState::Failed);
            state_.SetLastError("Attachment metadata is invalid.");
            return true;
        }
        if (parts.size() >= 9) transfer.attachment.contentSha256 = parts[8];
        transfer.receivedChunks = 0;
        transfer.chunks.assign(transfer.totalChunks, "");
        transfer.attachment.state = AttachmentTransferState::Requested;
        if (transfer.targetPath.empty()) transfer.targetPath = BuildAttachmentCachePath(parts[1], transfer.attachment.displayName);
        return true;
    }

    if (payload.rfind("@attachchunk|", 0) == 0) {
        const std::vector<std::string> parts = SplitByDelimiter(payload, '|');
        if (parts.size() < 4) return true;

        const std::string key = sender + "|" + parts[1];
        IncomingAttachmentTransfer completed;
        bool done = false;
        {
            std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
            auto it = incomingAttachments_.find(key);
            if (it == incomingAttachments_.end()) return true;

            IncomingAttachmentTransfer& transfer = it->second;
            transfer.binaryChunks = false;
            const int index = std::atoi(parts[2].c_str());
            if (index < 0 || index >= transfer.totalChunks) return true;
            if (parts[3].size() > kAttachmentChunkChars) return true;
            if (transfer.chunks[index].empty()) {
                transfer.chunks[index] = parts[3];
                transfer.receivedChunks++;
            }
            if (transfer.receivedChunks == transfer.totalChunks) {
                completed = transfer;
                incomingAttachments_.erase(it);
                done = true;
            }
        }
        if (done) FinishIncomingAttachment(completed);
        return true;
    }

    if (payload.rfind("@attacherr|", 0) == 0) {
        const std::vector<std::string> parts = SplitByDelimiter(payload, '|');
        if (parts.size() < 3) return true;

        std::string errorText;
        river::base64::DecodeToString(parts[2], errorText);
        {
            std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
            incomingAttachments_.erase(sender + "|" + parts[1]);
        }
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

    std::string plainChunk;
    const std::string encryptedChunk = payload.substr(offset);
    if (!river::OpenPayloadBinary(encryptedChunk, plainChunk) ||
        plainChunk.size() > kAttachmentBinaryChunkBytes) {
        state_.UpdateAttachmentState(sender, attachmentId, AttachmentTransferState::Failed);
        state_.SetLastError("Attachment chunk integrity check failed.");
        return true;
    }

    const std::string key = sender + "|" + attachmentId;
    IncomingAttachmentTransfer completed;
    bool done = false;
    {
        std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
        auto it = incomingAttachments_.find(key);
        if (it == incomingAttachments_.end()) return true;

        IncomingAttachmentTransfer& transfer = it->second;
        if (transfer.totalChunks != static_cast<int>(totalChunks)) return true;
        if (transfer.chunks[index].empty()) {
            transfer.chunks[index] = plainChunk;
            transfer.receivedChunks++;
        }
        if (transfer.receivedChunks == transfer.totalChunks) {
            completed = transfer;
            incomingAttachments_.erase(it);
            done = true;
        }
    }
    if (done) FinishIncomingAttachment(completed);
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
        } else if (line.rfind("AUTH_CHALLENGE:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=AUTH_CHALLENGE");
            if (!SendChallengeLogin(line)) {
                state_.SetAuthActionPending(false);
                state_.SetLastError("Could not complete authentication challenge.");
            }
        } else if (line.find("FIRST LOGIN") != std::string::npos) {
            AppendClientLog("ReceiveLoop line=FIRST LOGIN");
            state_.SetAuthActionPending(false);
            state_.SetCredentialChangePending(false);
            state_.SetMustChangeCredentials(true);
            state_.SetConnectionState(ConnState::FIRST_LOGIN_REQUIRED);
            state_.SetStatusDetail("First access detected. You must change ID and key.");
            state_.ClearLastError();
        } else if (line.find("ACCESO CONCEDIDO") != std::string::npos) {
            AppendClientLog("ReceiveLoop line=ACCESO CONCEDIDO");
            QueueAutoLogin("", "");
            state_.SetAuthenticated(true);
            state_.SetMustChangeCredentials(false);
            state_.SetAuthActionPending(false);
            state_.SetCredentialChangePending(false);
            state_.SetConnectionState(ConnState::AUTHENTICATED);
            state_.SetStatusDetail("Canal seguro autenticado.");
            state_.ClearLastError();
        } else if (line.rfind("SESSION:", 0) == 0) {
            AppendClientLog("ReceiveLoop session=" + line.substr(8));
            state_.SetStatusDetail("Sesion segura activa.");
        } else if (line.find("UPLINK ESTABLISHED") != std::string::npos) {
            AppendClientLog("ReceiveLoop line=UPLINK ESTABLISHED");
            state_.SetConnectionState(ConnState::TOR_READY);
            state_.SetStatusDetail("Canal Tor establecido. Esperando login.");
            state_.ClearLastError();
            std::string queuedUser;
            std::string queuedPass;
            if (ConsumeQueuedAutoLogin(queuedUser, queuedPass)) {
                AppendClientLog("ReceiveLoop auto-login user=" + queuedUser);
                SendLogin(queuedUser, queuedPass);
            }
        } else if (line.find("ACTUALIZADO. RECONECTA") != std::string::npos) {
            AppendClientLog("ReceiveLoop line=ACTUALIZADO");
            state_.SetMustChangeCredentials(false);
            state_.SetAuthActionPending(false);
            state_.SetCredentialChangePending(false);
            state_.SetConnectionState(ConnState::RECONNECTING);
            state_.SetStatusDetail("Credenciales actualizadas. Reautenticando en cuanto el canal vuelva a estar listo...");
            state_.ClearLastError();
        } else if (line.find("ACTUALIZADO") != std::string::npos) {
            AppendClientLog("ReceiveLoop line=ACTUALIZADO SIMPLE");
            QueueAutoLogin("", "");
            state_.SetMustChangeCredentials(false);
            state_.SetAuthActionPending(false);
            state_.SetCredentialChangePending(false);
            state_.SetStatusDetail("Credenciales actualizadas. Finalizando acceso...");
            state_.ClearLastError();
        } else if (line.find("CREDENCIALES INCORRECTAS") != std::string::npos) {
            AppendClientLog("ReceiveLoop line=CREDENCIALES INCORRECTAS");
            state_.SetAuthActionPending(false);
            state_.SetConnectionState(ConnState::TOR_READY);
            state_.SetStatusDetail("Canal Tor listo. Esperando nuevas credenciales.");
            state_.SetLastError("Credenciales incorrectas.");
            state_.AddSystemLog("SYSTEM: CREDENCIALES INCORRECTAS.");
        } else if (line.find("HWID NO RECONOCIDO") != std::string::npos) {
            AppendClientLog("ReceiveLoop line=HWID NO RECONOCIDO");
            state_.SetAuthActionPending(false);
            state_.SetConnectionState(ConnState::TOR_READY);
            state_.SetStatusDetail("Canal Tor listo. Acceso denegado por HWID.");
            state_.SetLastError("Esta maquina no coincide con el HWID autorizado.");
            state_.AddSystemLog("SYSTEM: HWID NO RECONOCIDO.");
        } else if (line.find("ACCESO BLOQUEADO") != std::string::npos) {
            AppendClientLog("ReceiveLoop line=ACCESO BLOQUEADO");
            state_.SetAuthActionPending(false);
            state_.SetCredentialChangePending(false);
            state_.SetConnectionState(ConnState::TOR_READY);
            state_.SetStatusDetail("Canal Tor listo. Acceso bloqueado.");
            state_.SetLastError("Acceso bloqueado para esta maquina.");
            state_.AddSystemLog("SYSTEM: ACCESO BLOQUEADO.");
        } else if (line.find("ERROR ACTUALIZANDO USUARIO") != std::string::npos) {
            AppendClientLog("ReceiveLoop line=ERROR ACTUALIZANDO USUARIO");
            state_.SetCredentialChangePending(false);
            state_.SetConnectionState(ConnState::FIRST_LOGIN_REQUIRED);
            state_.SetStatusDetail("Could not complete the initial update.");
            state_.SetLastError("Could not update the user or key.");
            state_.AddSystemLog("SYSTEM: ERROR ACTUALIZANDO USUARIO.");
        } else if (line.rfind("[ATTACH]:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=ATTACH_OFFER");
            HandleAttachmentBroadcast(line);
        } else if (line.find("[PM]:") == 0) {
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
            AppendClientLog("ReceiveLoop line=" + line);
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
        state_.SetAuthenticated(false);
        state_.SetConnectionState(ConnState::DISCONNECTED);
        state_.SetAuthActionPending(false);
        state_.SetCredentialChangePending(false);
        state_.SetStatusDetail("Canal cerrado. Reintentando enlace...");
        AppendClientLog("NetworkLoop DISCONNECTED");
    }
    AppendClientLog("NetworkLoop end");
}
