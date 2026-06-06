#include "client/chat_client.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <mutex>
#include <sstream>
#include <vector>

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

    int totalSent = 0;
    while (totalSent < static_cast<int>(payload.size())) {
        int sent = send(socket_, payload.c_str() + totalSent, static_cast<int>(payload.size()) - totalSent, 0);
        if (sent <= 0) {
#ifdef _WIN32
            AppendClientLog("SendRawLine failed totalSent=" + std::to_string(totalSent) +
                            " err=" + std::to_string(WSAGetLastError()));
#else
            AppendClientLog("SendRawLine failed totalSent=" + std::to_string(totalSent) +
                            " err=" + std::to_string(errno));
#endif
            return -1;
        }
        totalSent += sent;
    }

    AppendClientLog("SendRawLine ok bytes=" + std::to_string(totalSent));
    return totalSent;
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

    std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(input)),
                                     std::istreambuf_iterator<char>());
    if (bytes.size() > kMaxAttachmentBytes) {
        SendPrivateMessage(CurrentUser(), requester, "@attacherr|" + attachmentId + "|" +
            river::base64::EncodeString("Attachment exceeds the transfer limit."));
        return;
    }

    const std::string contentSha256 = HashPassword(BytesToString(bytes));
    const std::string encoded = river::base64::Encode(bytes);
    const std::string kind =
        draft.kind == AttachmentKind::Image ? "image" :
        draft.kind == AttachmentKind::Video ? "video" : "file";
    const std::size_t totalChunks = encoded.empty() ? 1 : (encoded.size() + kAttachmentChunkChars - 1) / kAttachmentChunkChars;

    if (!SendPrivateMessage(CurrentUser(),
                            requester,
                            "@attachmeta|" + attachmentId + "|" + kind + "|" +
                                river::base64::EncodeString(draft.displayName) + "|" +
                                river::base64::EncodeString(draft.mimeType) + "|" +
                                std::to_string(draft.sizeBytes) + "|" + mode + "|" +
                                std::to_string(totalChunks) + "|" + contentSha256)) {
        return;
    }

    if (encoded.empty()) {
        SendPrivateMessage(CurrentUser(), requester, "@attachchunk|" + attachmentId + "|0|");
        return;
    }

    for (std::size_t index = 0; index < totalChunks; ++index) {
        const std::string chunk = encoded.substr(index * kAttachmentChunkChars, kAttachmentChunkChars);
        if (!SendPrivateMessage(CurrentUser(), requester,
                                "@attachchunk|" + attachmentId + "|" + std::to_string(index) + "|" + chunk)) {
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
    if (!river::base64::Decode(joined, decoded)) {
        state_.UpdateAttachmentState(transfer.ownerUser, transfer.attachment.id, AttachmentTransferState::Failed);
        state_.SetLastError("Could not reconstruct the received attachment.");
        return;
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
        if (transfer.totalChunks < 1 ||
            transfer.totalChunks > static_cast<int>((kMaxAttachmentBytes * 2 + kAttachmentChunkChars - 1) / kAttachmentChunkChars)) {
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

void ChatClient::ReceiveLoop(SocketHandle sock) {
    char buf[16384];
    std::string accum;
    AppendClientLog("ReceiveLoop start");
    while (!stopRequested_.load()) {
        int bytes = recv(sock, buf, 16383, 0);
        if (bytes == 0) {
            AppendClientLog("ReceiveLoop recv=0 peer closed");
            break;
        }
        if (bytes < 0) {
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) {
                AppendClientLog("ReceiveLoop timeout");
                continue;
            }
            AppendClientLog("ReceiveLoop error=" + std::to_string(err));
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            AppendClientLog("ReceiveLoop error=" + std::to_string(errno));
#endif
            break;
        }

        buf[bytes] = '\0';
        AppendClientLog("ReceiveLoop bytes=" + std::to_string(bytes));
        accum += buf;
        if (accum.size() > 1024 * 1024) accum.clear();

        size_t pos = 0;
        while ((pos = accum.find('\n')) != std::string::npos) {
            std::string line = accum.substr(0, pos);
            accum.erase(0, pos + 1);

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
