#include "server/chat_server.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <ctime>
#include <cstdio>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <signal.h>
#include <sys/select.h>
#endif

#include "common/base64.h"
#include "common/e2e_crypto.h"
#include "common/scram.h"
#include "common/secure_envelope.h"
#include "common/security_utils.h"
#include "common/shared_config.h"

namespace {

constexpr std::size_t kMaxLineBytes = 65536;
constexpr std::size_t kMaxChatPayloadBytes = 8192;
constexpr std::size_t kMaxAttachmentControlBytes = 16384;
// PROTOCOL_V2.md 4.2/4.3: PM2/PMX envelopes (decoded) and chunk envelopes.
constexpr std::size_t kMaxPrivateEnvelopeBytes = 16u * 1024u;
constexpr std::size_t kMaxChunkEnvelopeBytes = 64u * 1024u + river::e2e::kEnvelopeOverhead;
constexpr std::size_t kMaxAttachmentBytes = 12u * 1024u * 1024u;
constexpr std::size_t kMaxAttachmentIdChars = 80;
constexpr std::size_t kMaxAttachmentNameBytes = 1024;
constexpr std::size_t kMaxAttachmentMimeBytes = 255;
constexpr std::size_t kMaxHwidChars = 128;
constexpr std::size_t kClientNonceHexChars = 32;
constexpr std::size_t kServerNonceBytes = 16;  // 32 hex chars appended to the client nonce
constexpr const char* kObsoleteClientNotice = "SYSTEM: CLIENTE OBSOLETO. Actualiza al protocolo 2.";
constexpr int kLoginChallengeTtlSeconds = 60;
constexpr int kMaxLinesPerMinute = 120;
constexpr int kMaxMessagesPerMinute = 60;
constexpr int kMaxAttachmentsPerMinute = 12;
// Each binary chunk carries up to 32 KiB, so a 12 MiB file needs ~384 frames.
// Chunks have their own budget so large files are not rejected by the offer limit.
constexpr int kMaxAttachmentChunksPerMinute = 1200;
constexpr int kMaxConcurrentConnections = 256;
constexpr int kSocketRecvTimeoutSeconds = 120;
constexpr int kSocketSendTimeoutSeconds = 30;
// Outbound queue bounds per client (attachment relays carry ~32 KiB chunks).
constexpr std::size_t kMaxQueuedBytes = 16u * 1024u * 1024u;
constexpr std::size_t kMaxQueuedFrames = 2000;
// How long UnregisterSocket lets the writer flush before cutting the stream.
constexpr int kUnregisterDrainMillis = 2000;
// Graceful shutdown: wait for handlers after the notice, then force.
constexpr int kShutdownGraceMillis = 3000;
constexpr int kShutdownForceMillis = 2000;

std::atomic<bool> g_stopRequested{false};

void ShutdownRaw(SocketHandle sock) {
#ifdef _WIN32
    shutdown(sock, SD_BOTH);
#else
    shutdown(sock, SHUT_RDWR);
#endif
}

#ifdef _WIN32
BOOL WINAPI ConsoleCtrlHandler(DWORD type) {
    switch (type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            ChatServer::RequestStop();
            return TRUE;
        default:
            return FALSE;
    }
}
#else
extern "C" void HandleStopSignal(int) {
    ChatServer::RequestStop();
}
#endif

void InstallStopHandlers() {
#ifdef _WIN32
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
#else
    struct sigaction sa {};
    sa.sa_handler = HandleStopSignal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  // no SA_RESTART: let select() return EINTR promptly
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);
#endif
}

void ApplySocketTimeouts(SocketHandle sock) {
#ifdef _WIN32
    DWORD recvTimeout = kSocketRecvTimeoutSeconds * 1000;
    DWORD sendTimeout = kSocketSendTimeoutSeconds * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&recvTimeout), sizeof(recvTimeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&sendTimeout), sizeof(sendTimeout));
#else
    timeval recvTimeout{};
    recvTimeout.tv_sec = kSocketRecvTimeoutSeconds;
    timeval sendTimeout{};
    sendTimeout.tv_sec = kSocketSendTimeoutSeconds;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recvTimeout, sizeof(recvTimeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &sendTimeout, sizeof(sendTimeout));
#endif
}

std::string FormatTimestamp(time_t value) {
    if (value <= 0) return "-";
    char ts[32];
    std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", std::localtime(&value));
    return ts;
}

std::string FormatDuration(time_t seconds) {
    if (seconds < 0) seconds = 0;
    const long long h = static_cast<long long>(seconds) / 3600;
    const long long m = (static_cast<long long>(seconds) % 3600) / 60;
    const long long sec = static_cast<long long>(seconds) % 60;
    char buf[48];
    std::snprintf(buf, sizeof(buf), "%lldh %02lldm %02llds", h, m, sec);
    return buf;
}

std::string RestAfterToken(const std::string& command, std::size_t tokenIndex) {
    std::size_t pos = 0;
    for (std::size_t i = 0; i < tokenIndex; ++i) {
        pos = command.find_first_not_of(" \t", pos);
        if (pos == std::string::npos) return "";
        pos = command.find_first_of(" \t", pos);
        if (pos == std::string::npos) return "";
    }
    pos = command.find_first_not_of(" \t", pos);
    return pos == std::string::npos ? "" : command.substr(pos);
}

bool StartsWith(const std::string& value, const std::string& prefix) {
    return value.rfind(prefix, 0) == 0;
}

std::vector<std::string> SplitWhitespace(const std::string& input) {
    std::stringstream ss(input);
    std::vector<std::string> parts;
    std::string part;
    while (ss >> part) parts.push_back(part);
    return parts;
}

// Splits on ':' keeping empty fields ("a::b" -> {"a", "", "b"}).
std::vector<std::string> SplitFields(const std::string& input) {
    std::vector<std::string> fields;
    std::size_t start = 0;
    while (true) {
        const std::size_t sep = input.find(':', start);
        if (sep == std::string::npos) {
            fields.push_back(input.substr(start));
            return fields;
        }
        fields.push_back(input.substr(start, sep - start));
        start = sep + 1;
    }
}

// Decimal digits only, no sign / whitespace, value <= maxValue.
bool ParseStrictUnsigned(const std::string& text, unsigned long long maxValue, unsigned long long& out) {
    if (text.empty() || text.size() > 19) return false;
    unsigned long long value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') return false;
        value = value * 10 + static_cast<unsigned long long>(c - '0');
    }
    if (value > maxValue) return false;
    out = value;
    return true;
}

// Strict base64 decode; `canonical` receives the re-encoded form so the
// server only ever relays canonical base64.
bool DecodeB64Field(const std::string& b64, std::string& decoded, std::string& canonical) {
    if (!river::base64::DecodeToString(b64, decoded)) return false;
    canonical = river::base64::EncodeString(decoded);
    return true;
}

bool HasControlOrSeparator(const std::string& value) {
    for (unsigned char c : value) {
        if (c < 0x20 || c == 0x7f || c == ':' || c == '|') return true;
    }
    return false;
}

std::string ToLowerAscii(std::string value) {
    for (char& c : value)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return value;
}

std::string JsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (unsigned char c : value) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[7] = {};
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
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

}

ChatServer::ChatServer(const std::string& dbPath, const std::string& logPath)
    : dbPath_(dbPath), logPath_(logPath) {
    fakeSaltSecret_ = river::scram::RandomNonceHex(32);
    if (fakeSaltSecret_.empty()) fakeSaltSecret_ = RandomHex(32);
}

std::string ChatServer::FakeSaltHex(const std::string& username) const {
    // 16 bytes, like a real salt; stable for the process lifetime so repeated
    // AUTH_START for the same unknown name does not reveal it is fake.
    return ToLowerAscii(HmacSha256Hex(fakeSaltSecret_, "river-fake-salt|" + username)).substr(0, 32);
}

void ChatServer::RequestStop() {
    g_stopRequested.store(true);
}

void ChatServer::RegisterSocket(SocketHandle sock) {
    auto channel = std::make_shared<SocketChannel>();
    channel->sock = sock;
    channel->writer = std::thread(&ChatServer::WriterLoop, this, channel);
    std::lock_guard<std::mutex> lk(channelsMutex_);
    channels_[sock] = channel;
}

void ChatServer::WriterLoop(std::shared_ptr<SocketChannel> channel) {
    bool sendFailed = false;
    std::unique_lock<std::mutex> lk(channel->mutex);
    while (true) {
        channel->cv.wait(lk, [&] {
            return channel->closed || channel->draining || !channel->queue.empty();
        });
        if (channel->closed) break;
        if (channel->queue.empty()) break;  // draining and nothing left to flush

        OutboundFrame frame = std::move(channel->queue.front());
        channel->queue.pop_front();
        channel->queuedBytes -= frame.payload.size();
        if (frame.closeAfter) {
            // Everything queued before the sentinel has been written.
            ShutdownChannelLocked(*channel);
            break;
        }

        lk.unlock();
        // The descriptor stays open while this thread runs: UnregisterSocket
        // joins us before closing it.
        const bool ok = ::SendFrame(channel->sock, frame.type, frame.payload);
        lk.lock();
        if (!ok) {
            sendFailed = !channel->closed;
            ShutdownChannelLocked(*channel);
            break;
        }
    }
    channel->accepting = false;
    channel->queue.clear();
    channel->queuedBytes = 0;
    channel->writerDone = true;
    const SocketHandle sock = channel->sock;
    lk.unlock();
    channel->cv.notify_all();
    if (sendFailed) LogRuntime("NET", "send failed on socket " + std::to_string(sock));
}

void ChatServer::UnregisterSocket(SocketHandle sock) {
    std::shared_ptr<SocketChannel> channel;
    {
        std::lock_guard<std::mutex> lk(channelsMutex_);
        auto it = channels_.find(sock);
        if (it != channels_.end()) {
            channel = it->second;
            channels_.erase(it);
        }
    }
    if (!channel) {
        CloseSocketHandle(sock);
        return;
    }
    {
        std::unique_lock<std::mutex> lk(channel->mutex);
        // Let the writer flush what is already queued (e.g. a final rate-limit
        // notice), but never wait unboundedly on a slow peer.
        channel->accepting = false;
        channel->draining = true;
        channel->cv.notify_all();
        if (!channel->cv.wait_for(lk, std::chrono::milliseconds(kUnregisterDrainMillis),
                                  [&] { return channel->writerDone; })) {
            ShutdownRaw(sock);  // unblocks a writer stuck in send()
        }
        // From here on nobody but this thread touches the descriptor:
        // ShutdownSocket/Enqueue check `closed` under this mutex.
        channel->closed = true;
    }
    channel->cv.notify_all();
    if (channel->writer.joinable()) channel->writer.join();
    CloseSocketHandle(sock);
}

std::shared_ptr<ChatServer::SocketChannel> ChatServer::ChannelFor(SocketHandle sock) {
    std::lock_guard<std::mutex> lk(channelsMutex_);
    auto it = channels_.find(sock);
    return it == channels_.end() ? nullptr : it->second;
}

void ChatServer::ShutdownChannelLocked(SocketChannel& channel) {
    channel.accepting = false;
    channel.queue.clear();
    channel.queuedBytes = 0;
    // Only shut the stream down; the owning handler thread performs the close.
    if (!channel.closed) ShutdownRaw(channel.sock);
    channel.cv.notify_all();
}

void ChatServer::ShutdownSocket(SocketHandle sock) {
    std::shared_ptr<SocketChannel> channel = ChannelFor(sock);
    if (!channel) return;
    std::lock_guard<std::mutex> guard(channel->mutex);
    if (channel->closed) return;
    ShutdownChannelLocked(*channel);
}

bool ChatServer::Enqueue(const std::shared_ptr<SocketChannel>& channel, OutboundFrame frame) {
    if (!channel) return false;
    std::size_t bytes = 0;
    std::size_t frames = 0;
    {
        std::lock_guard<std::mutex> guard(channel->mutex);
        if (channel->closed || !channel->accepting) return false;
        const std::size_t size = frame.payload.size();
        if (channel->queue.size() >= kMaxQueuedFrames ||
            channel->queuedBytes + size > kMaxQueuedBytes) {
            // Never block the producer: drop the slow client instead.
            channel->overloaded = true;
            bytes = channel->queuedBytes;
            frames = channel->queue.size();
            ShutdownChannelLocked(*channel);
        } else {
            channel->queuedBytes += size;
            channel->queue.push_back(std::move(frame));
            channel->cv.notify_all();
            return true;
        }
    }
    LogRuntime("NET", "Cliente en socket " + std::to_string(channel->sock) +
                          " saturado (" + std::to_string(frames) + " frames, " +
                          std::to_string(bytes) + " bytes en cola); desconectando.");
    return false;
}

void ChatServer::EnqueueFinal(const std::shared_ptr<SocketChannel>& channel, const std::string& msg) {
    if (!channel) return;
    std::lock_guard<std::mutex> guard(channel->mutex);
    // Already closing (overloaded, earlier final notice, or handler exiting).
    if (channel->closed || !channel->accepting) return;
    // The notice bypasses the queue limits: it is small and the last frame.
    OutboundFrame notice;
    notice.type = kFrameTypeText;
    notice.payload = msg;
    channel->queuedBytes += notice.payload.size();
    channel->queue.push_back(std::move(notice));
    OutboundFrame sentinel;
    sentinel.closeAfter = true;
    channel->queue.push_back(std::move(sentinel));
    channel->accepting = false;
    channel->cv.notify_all();
}

void ChatServer::SendLineThenClose(SocketHandle sock, const std::string& msg) {
    EnqueueFinal(ChannelFor(sock), msg);
}

bool ChatServer::SendFrameLocked(SocketHandle sock, std::uint16_t type, const std::string& payload) {
    OutboundFrame frame;
    frame.type = type;
    frame.payload = payload;
    return Enqueue(ChannelFor(sock), std::move(frame));
}

bool ChatServer::SendLine(SocketHandle sock, const std::string& msg) {
    return SendFrameLocked(sock, kFrameTypeText, msg);
}

void ChatServer::ShutdownAllClients(const std::string& notice) {
    std::vector<std::shared_ptr<SocketChannel>> snapshot;
    {
        std::lock_guard<std::mutex> lk(channelsMutex_);
        for (auto& [sock, channel] : channels_) snapshot.push_back(channel);
    }
    for (auto& channel : snapshot) EnqueueFinal(channel, notice);
}

void ChatServer::HandlerFinished() {
    std::lock_guard<std::mutex> lk(handlersMutex_);
    --activeHandlers_;
    handlersCv_.notify_all();
}

void ChatServer::RegisterAuthenticatedSession(const ClientSession& session) {
    std::vector<SocketHandle> replaced;
    {
        std::lock_guard<std::mutex> lk(clientsMutex_);
        for (auto& [sock, cl] : clients_) {
            if (sock != session.socket && cl.auth && cl.nick == session.nick) {
                cl.auth = false;
                replaced.push_back(sock);
            }
        }
        clients_[session.socket] = session;
    }
    for (SocketHandle sock : replaced) {
        LogRuntime("SEC", "Sesion previa de '" + session.nick + "' reemplazada por un nuevo inicio de sesion.");
        SendLineThenClose(sock, "SYSTEM: SESION REEMPLAZADA. Tu identidad inicio sesion desde otra conexion.");
    }
}

void ChatServer::LogEncryptedMessage(const std::string& user, const std::string& encryptedPayload) {
    std::lock_guard<std::mutex> lk(logMutex_);
    std::ofstream f(logPath_, std::ios::app);
    if (!f.is_open()) return;

    char ts[32];
    std::time_t now = std::time(nullptr);
    std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    std::string entry = std::string(ts) + "|" + user + ":payload_sha256=" + HashPassword(encryptedPayload);
    f << river::SealPayload(entry) << "\n";
}

void ChatServer::LogRuntime(const std::string& category, const std::string& message) {
    std::lock_guard<std::mutex> lk(logMutex_);
    char ts[32];
    std::time_t now = std::time(nullptr);
    std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    
    std::string entry = "[" + category + "] " + message;
    std::cout << entry << std::endl;

    std::ofstream f("server_runtime.log", std::ios::app);
    if (f.is_open()) {
        f << ts << " " << entry << "\n";
    }
    std::ofstream jf("server_runtime.jsonl", std::ios::app);
    if (jf.is_open()) {
        jf << "{\"ts\":\"" << ts
           << "\",\"category\":\"" << JsonEscape(category)
           << "\",\"message\":\"" << JsonEscape(message) << "\"}\n";
    }
}

void ChatServer::Broadcast(const std::string& msg) {
    std::lock_guard<std::mutex> lk(clientsMutex_);
    for (auto& [sock, cl] : clients_)
        if (cl.auth) SendLine(sock, msg);
}

void ChatServer::BroadcastUsers() {
    std::lock_guard<std::mutex> lk(clientsMutex_);
    std::string list = "[USERS]:";
    for (auto& [sock, cl] : clients_)
        if (cl.auth) list += cl.nick + ",";
    for (auto& [sock, cl] : clients_)
        if (cl.auth) SendLine(sock, list);
}

bool ChatServer::SendDirectLineToUser(const std::string& toNick, const std::string& line) {
    std::lock_guard<std::mutex> lk(clientsMutex_);
    for (auto& [sock, cl] : clients_) {
        if (cl.auth && cl.nick == toNick) {
            SendLine(sock, line);
            return true;
        }
    }
    return false;
}

bool ChatServer::RelayAttachmentChunk(const std::string& fromNick, const std::string& payload) {
    std::size_t offset = 0;
    std::string target;
    std::string attachmentId;
    std::uint32_t index = 0;
    std::uint32_t totalChunks = 0;
    if (!ReadSizedString(payload, offset, target) ||
        !ReadSizedString(payload, offset, attachmentId) ||
        !ReadU32(payload, offset, index) ||
        !ReadU32(payload, offset, totalChunks) ||
        !IsValidUsername(target) ||
        attachmentId.empty() ||
        attachmentId.size() > 80 ||
        totalChunks == 0 ||
        index >= totalChunks ||
        offset >= payload.size()) {
        return false;
    }

    const std::string encryptedChunk = payload.substr(offset);
    if (encryptedChunk.size() < river::e2e::kEnvelopeOverhead ||
        encryptedChunk.size() > kMaxChunkEnvelopeBytes) return false;

    std::string outbound;
    AppendSizedString(outbound, fromNick);
    AppendSizedString(outbound, attachmentId);
    AppendU32(outbound, index);
    AppendU32(outbound, totalChunks);
    outbound.append(encryptedChunk);

    std::lock_guard<std::mutex> lk(clientsMutex_);
    for (auto& [sock, cl] : clients_) {
        if (cl.auth && cl.nick == target) {
            return SendFrameLocked(sock, kFrameTypeAttachmentChunk, outbound);
        }
    }
    return false;
}

void ChatServer::AuditAdminAction(const std::string& admin, const std::string& action, const std::string& detail) {
    std::lock_guard<std::mutex> lk(logMutex_);
    std::ofstream f("admin_audit.log", std::ios::app);
    if (!f.is_open()) return;
    char ts[32];
    std::time_t now = std::time(nullptr);
    std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    f << ts << "|" << admin << "|" << action << "|" << detail << "\n";
    std::ofstream jf("admin_audit.jsonl", std::ios::app);
    if (jf.is_open()) {
        jf << "{\"ts\":\"" << ts
           << "\",\"admin\":\"" << JsonEscape(admin)
           << "\",\"action\":\"" << JsonEscape(action)
           << "\",\"detail\":\"" << JsonEscape(detail) << "\"}\n";
    }
}

bool ChatServer::KickUser(const std::string& nick, const std::string& reason) {
    SocketHandle targetSock = kInvalidSocket;
    {
        std::lock_guard<std::mutex> lk(clientsMutex_);
        for (auto& [sock, cl] : clients_) {
            if (cl.auth && cl.nick == nick && !cl.isAdmin) {
                targetSock = sock;
                break;
            }
        }
    }
    if (!IsSocketValid(targetSock)) return false;
    SendLineThenClose(targetSock, "SYSTEM: KICKED BY ADMIN. " + reason);
    return true;
}

bool ChatServer::DescribeUser(const std::string& nick, ClientSession& session) {
    std::lock_guard<std::mutex> lk(clientsMutex_);
    for (const auto& [sock, cl] : clients_) {
        if (cl.auth && cl.nick == nick) {
            session = cl;
            return true;
        }
    }
    return false;
}

void ChatServer::DisconnectByHwid(const std::string& hwid, const std::string& reason) {
    std::vector<SocketHandle> targets;
    {
        std::lock_guard<std::mutex> lk(clientsMutex_);
        for (auto& [sock, cl] : clients_) {
            if (cl.auth && !cl.isAdmin && cl.hwid == hwid)
                targets.push_back(sock);
        }
    }
    for (SocketHandle sock : targets) {
        SendLineThenClose(sock, "SYSTEM: ACCESO BLOQUEADO. " + reason);
    }
}

std::string ChatServer::BuildUsersSnapshot() {
    std::stringstream ss;
    bool first = true;
    std::lock_guard<std::mutex> lk(clientsMutex_);
    for (const auto& [sock, cl] : clients_) {
        if (!cl.auth) continue;
        if (!first) ss << ", ";
        ss << cl.nick;
        if (cl.isAdmin) ss << " [admin]";
        first = false;
    }
    return first ? "sin usuarios conectados" : ss.str();
}

ChatServer::LoginResult ChatServer::AuthorizeLoginProof(const std::string& username,
                                                        const std::string& hwid,
                                                        const std::string& authMessage,
                                                        const std::string& clientProofRaw,
                                                        std::string& serverSignatureRaw) {
    serverSignatureRaw.clear();
    {
        std::lock_guard<std::mutex> lk(attemptsMutex_);
        const time_t now = time(nullptr);
        auto userLock = loginLocks_.find(username);
        if (userLock != loginLocks_.end() && userLock->second > now)
            return {LoginCode::Blocked, false};
        auto originLock = loginLocksByOrigin_.find(hwid);
        if (originLock != loginLocksByOrigin_.end() && originLock->second > now)
            return {LoginCode::Blocked, false};
    }

    LoginResult result;
    river::scram::Credential credential;
    bool proofOk = false;
    if (repo_.GetCredential(username, credential)) {
        proofOk = !authMessage.empty() &&
                  river::scram::VerifyClientProof(credential, authMessage, clientProofRaw);
    } else {
        // Unknown user (or unusable stored value): do the same verification
        // work against a credential nobody can satisfy, then fail.
        river::scram::Credential dummy;
        if (river::scram::CredentialFromParts(river::scram::kDefaultIterations, FakeSaltHex(username),
                                              std::string(64, '0'), std::string(64, '0'), dummy)) {
            river::scram::VerifyClientProof(dummy, authMessage, clientProofRaw);
        }
    }
    if (proofOk) serverSignatureRaw = river::scram::ServerSignature(credential, authMessage);

    if (!proofOk || serverSignatureRaw.size() != river::scram::kKeyBytes) {
        serverSignatureRaw.clear();
        result.code = LoginCode::InvalidCredentials;
    } else {
        UserRecord record = repo_.FindUserByUsername(username);
        result.isAdmin = record.isAdmin;
        if (!record.found) {
            result.code = LoginCode::InvalidCredentials;
        } else if (!record.isAdmin && repo_.IsHwidBanned(hwid)) {
            result.code = LoginCode::Blocked;
        } else if (!record.isAdmin && !record.hwid.empty() && record.hwid != hwid) {
            result.code = LoginCode::HwidMismatch;
        } else {
            if (!record.isAdmin && record.hwid.empty()) repo_.UpdateUserHwid(username, hwid);
            result.code = record.firstLogin ? LoginCode::FirstLogin : LoginCode::Ok;
        }
        if (result.code != LoginCode::Ok && result.code != LoginCode::FirstLogin) serverSignatureRaw.clear();
    }

    {
        std::lock_guard<std::mutex> lk(attemptsMutex_);
        if (result.code == LoginCode::Ok || result.code == LoginCode::FirstLogin) {
            loginFailures_.erase(username);
            loginLocks_.erase(username);
            loginFailuresByOrigin_.erase(hwid);
            loginLocksByOrigin_.erase(hwid);
        } else if (result.code == LoginCode::InvalidCredentials) {
            int& userFailures = loginFailures_[username];
            int& originFailures = loginFailuresByOrigin_[hwid];
            userFailures++;
            originFailures++;
            if (userFailures >= 5) {
                loginLocks_[username] = time(nullptr) + 300;
                userFailures = 0;
                LogRuntime("SEC", "Usuario '" + username + "' bloqueado por 5 min.");
            }
            if (originFailures >= 10) {
                loginLocksByOrigin_[hwid] = time(nullptr) + 300;
                originFailures = 0;
                LogRuntime("SEC", "Origen '" + hwid + "' bloqueado por 5 min.");
            }
        }
    }

    return result;
}

void ChatServer::CompleteLogin(SocketHandle clientSocket, const ClientSession& session, bool afterChange) {
    {
        // Held across registration, history replay and the offline drain so
        // no MSG/PM2 is missed or delivered twice (see chat_server.h).
        std::lock_guard<std::mutex> delivery(deliveryMutex_);
        if (afterChange) SendLine(clientSocket, "SYSTEM: ACTUALIZADO.");
        SendLine(clientSocket, "SYSTEM: ACCESO CONCEDIDO.");
        SendLine(clientSocket, "SESSION:" + session.sessionId);
        RegisterAuthenticatedSession(session);

        const std::vector<RoomMessage> history = repo_.RecentRoomMessages(UserRepository::kRoomHistoryReplay);
        SendLine(clientSocket, "HISTORY_BEGIN:" + std::to_string(history.size()));
        for (const auto& msg : history) {
            SendLine(clientSocket, "HIST:" + msg.fromUser + ":" + std::to_string(msg.ts) + ":" + msg.textB64);
        }
        SendLine(clientSocket, "HISTORY_END");

        const std::vector<OfflinePm> pending = repo_.TakeOfflinePms(session.nick);
        for (const auto& pm : pending) {
            SendLine(clientSocket, "PM2:" + pm.fromUser + ":" + std::to_string(pm.ts) + ":" + pm.envelopeB64);
        }
        if (!pending.empty())
            LogRuntime("PM", std::to_string(pending.size()) + " mensajes privados en cola entregados a '" +
                                 session.nick + "'.");
    }
    Broadcast(session.nick + " se unió");
    BroadcastUsers();
}

void ChatServer::RoutePrivateEnvelope(SocketHandle senderSocket,
                                      const std::string& fromNick,
                                      const std::string& toNick,
                                      const std::string& envelopeB64,
                                      bool queueIfOffline) {
    const long long ts = static_cast<long long>(time(nullptr));
    const std::string line = std::string(queueIfOffline ? "PM2:" : "PMX:") + fromNick + ":" +
                             std::to_string(ts) + ":" + envelopeB64;
    std::lock_guard<std::mutex> delivery(deliveryMutex_);
    if (SendDirectLineToUser(toNick, line)) return;
    if (!repo_.UserExists(toNick)) {
        SendLine(senderSocket, "SYSTEM: Usuario '" + toNick + "' no encontrado.");
        return;
    }
    if (!queueIfOffline) {
        SendLine(senderSocket, "SYSTEM: Usuario '" + toNick + "' no conectado.");
        return;
    }
    switch (repo_.QueueOfflinePm(toNick, fromNick, ts, envelopeB64)) {
        case OfflineQueueResult::Queued:
            SendLine(senderSocket, "SYSTEM: Mensaje privado en cola para " + toNick + ".");
            break;
        case OfflineQueueResult::Full:
            SendLine(senderSocket, "SYSTEM: Cola de mensajes privados llena para " + toNick + ".");
            break;
        case OfflineQueueResult::Error:
            SendLine(senderSocket, "SYSTEM: MENSAJE PRIVADO RECHAZADO.");
            break;
    }
}

void ChatServer::HandleAdminCommand(SocketHandle clientSocket,
                                    const ClientSession& currentClient,
                                    const std::string& command) {
    std::vector<std::string> parts = SplitWhitespace(command);
    if (parts.empty()) return;

    if (parts[0] == "/help") {
        SendLine(
            clientSocket,
            "SYSTEM: /newuser | /passwd <user> <new-key> | /banhwid <hwid> [reason] | "
            "/unbanhwid <hwid> | /banuser <user> [reason] | /bans | /users | /accounts | "
            "/whois <user> | /kick <user> [reason] | /resethwid <user> | /deluser <user> | "
            "/announce <text>");
        return;
    }

    if (parts[0] == "/whois") {
        if (parts.size() < 2) {
            SendLine(clientSocket, "SYSTEM: Uso: /whois <user>");
            return;
        }
        std::string fingerprint = "-";
        {
            std::string keyB64;
            std::string keyRaw;
            if (repo_.GetUserKey(parts[1], keyB64) && river::base64::DecodeToString(keyB64, keyRaw)) {
                const std::string fp = river::e2e::Fingerprint(keyRaw);
                if (!fp.empty()) fingerprint = fp;
            }
        }
        ClientSession target;
        if (DescribeUser(parts[1], target)) {
            const time_t now = time(nullptr);
            SendLine(clientSocket,
                     "SYSTEM: WHOIS " + target.nick +
                         " | conectado | admin=" + (target.isAdmin ? "si" : "no") +
                         " | hwid=" + (target.hwid.empty() ? "-" : target.hwid) +
                         " | sesion=" + FormatDuration(now - target.connectedAt) +
                         " | ultima actividad hace " + FormatDuration(now - target.lastSeen) +
                         " | huella=" + fingerprint);
            return;
        }
        UserRecord record = repo_.FindUserByUsername(parts[1]);
        if (!record.found) {
            SendLine(clientSocket, "SYSTEM: Usuario '" + parts[1] + "' no existe.");
            return;
        }
        SendLine(clientSocket,
                 "SYSTEM: WHOIS " + parts[1] +
                     " | desconectado | admin=" + (record.isAdmin ? "si" : "no") +
                     " | primer_acceso=" + (record.firstLogin ? "pendiente" : "completado") +
                     " | hwid=" + (record.hwid.empty() ? "-" : record.hwid) +
                     " | huella=" + fingerprint);
        return;
    }

    if (parts[0] == "/accounts") {
        const std::vector<UserSummary> users = repo_.ListUsers();
        std::string line = "SYSTEM: Cuentas registradas (" + std::to_string(users.size()) + "): ";
        bool first = true;
        for (const auto& user : users) {
            if (!first) line += ", ";
            line += user.username;
            if (user.isAdmin) line += " [admin]";
            if (user.firstLoginPending) line += " [pendiente]";
            if (!user.hwidBound && !user.isAdmin) line += " [sin hwid]";
            first = false;
        }
        SendLine(clientSocket, line);
        return;
    }

    if (parts[0] == "/bans") {
        const std::vector<BannedHwidRecord> bans = repo_.ListBannedHwids();
        if (bans.empty()) {
            SendLine(clientSocket, "SYSTEM: No hay HWIDs baneados.");
            return;
        }
        SendLine(clientSocket, "SYSTEM: HWIDs baneados (" + std::to_string(bans.size()) + "):");
        for (const auto& ban : bans) {
            SendLine(clientSocket,
                     "SYSTEM:   " + ban.hwid + " | " + FormatTimestamp(static_cast<time_t>(ban.bannedAt)) +
                         " | " + (ban.reason.empty() ? "-" : ban.reason));
        }
        return;
    }

    if (parts[0] == "/banuser") {
        if (parts.size() < 2) {
            SendLine(clientSocket, "SYSTEM: Uso: /banuser <user> [razon]");
            return;
        }
        if (parts[1] == river::AdminUsername()) {
            SendLine(clientSocket, "SYSTEM: No se puede banear al admin.");
            return;
        }
        std::string hwid;
        ClientSession target;
        if (DescribeUser(parts[1], target)) {
            if (target.isAdmin) {
                SendLine(clientSocket, "SYSTEM: No se puede banear a un admin.");
                return;
            }
            hwid = target.hwid;
        } else {
            UserRecord record = repo_.FindUserByUsername(parts[1]);
            if (!record.found) {
                SendLine(clientSocket, "SYSTEM: Usuario '" + parts[1] + "' no existe.");
                return;
            }
            if (record.isAdmin) {
                SendLine(clientSocket, "SYSTEM: No se puede banear a un admin.");
                return;
            }
            hwid = record.hwid;
        }
        if (hwid.empty()) {
            SendLine(clientSocket, "SYSTEM: El usuario '" + parts[1] + "' no tiene HWID asociado todavia.");
            return;
        }
        std::string reason = RestAfterToken(command, 2);
        if (reason.empty()) reason = "ban administrativo de " + parts[1];
        if (repo_.BanHwid(hwid, reason)) {
            AuditAdminAction(currentClient.nick, "banuser", parts[1] + " " + hwid + " " + reason);
            DisconnectByHwid(hwid, "HWID baneado.");
            SendLine(clientSocket, "SYSTEM: Usuario " + parts[1] + " baneado (HWID " + hwid + ").");
        } else {
            SendLine(clientSocket, "SYSTEM: No se pudo banear al usuario.");
        }
        return;
    }

    if (parts[0] == "/resethwid") {
        if (parts.size() < 2) {
            SendLine(clientSocket, "SYSTEM: Uso: /resethwid <user>");
            return;
        }
        if (repo_.ResetUserHwid(parts[1])) {
            AuditAdminAction(currentClient.nick, "resethwid", parts[1]);
            SendLine(clientSocket, "SYSTEM: HWID liberado para " + parts[1] + ". Se asociara en su proximo acceso.");
        } else {
            SendLine(clientSocket, "SYSTEM: No se pudo liberar el HWID de " + parts[1] + ".");
        }
        return;
    }

    if (parts[0] == "/deluser") {
        if (parts.size() < 2) {
            SendLine(clientSocket, "SYSTEM: Uso: /deluser <user>");
            return;
        }
        if (parts[1] == river::AdminUsername() || parts[1] == currentClient.nick) {
            SendLine(clientSocket, "SYSTEM: No se puede eliminar esa cuenta.");
            return;
        }
        if (repo_.DeleteUser(parts[1])) {
            AuditAdminAction(currentClient.nick, "deluser", parts[1]);
            if (KickUser(parts[1], "Cuenta eliminada por admin.")) BroadcastUsers();
            SendLine(clientSocket, "SYSTEM: Cuenta eliminada: " + parts[1]);
        } else {
            SendLine(clientSocket, "SYSTEM: No se pudo eliminar la cuenta " + parts[1] + ".");
        }
        return;
    }

    if (parts[0] == "/announce") {
        const std::string text = RestAfterToken(command, 1);
        if (text.empty()) {
            SendLine(clientSocket, "SYSTEM: Uso: /announce <texto>");
            return;
        }
        AuditAdminAction(currentClient.nick, "announce", text);
        Broadcast("SYSTEM: [ANUNCIO] " + text);
        return;
    }

    if (parts[0] == "/newuser") {
        std::string username;
        if (repo_.CreateNextUser(username)) {
            AuditAdminAction(currentClient.nick, "newuser", username);
            SendLine(clientSocket, "SYSTEM: NUEVO USUARIO: " + username + " / clave inicial definida por THE_RIVER_NEW_USER_PASSWORD");
        } else {
            SendLine(clientSocket, "SYSTEM: ERROR creando usuario.");
        }
        return;
    }

    if (parts[0] == "/passwd") {
        if (parts.size() < 3) {
            SendLine(clientSocket, "SYSTEM: Uso: /passwd <user> <new-key>");
            return;
        }
        if (!IsValidUsername(parts[1]) || !IsStrongEnoughPassword(parts[2])) {
            SendLine(clientSocket, "SYSTEM: Usuario o clave no cumple la politica de seguridad.");
            return;
        }
        if (repo_.ResetUserPassword(parts[1], parts[2])) {
            AuditAdminAction(currentClient.nick, "passwd", parts[1]);
            SendLine(clientSocket, "SYSTEM: Clave actualizada para " + parts[1]);
        } else {
            SendLine(clientSocket, "SYSTEM: No se pudo actualizar la clave de " + parts[1]);
        }
        return;
    }

    if (parts[0] == "/banhwid") {
        if (parts.size() < 2) {
            SendLine(clientSocket, "SYSTEM: Uso: /banhwid <hwid> [razon]");
            return;
        }
        std::string reason = RestAfterToken(command, 2);
        if (reason.empty()) reason = "ban administrativo";
        if (repo_.BanHwid(parts[1], reason)) {
            AuditAdminAction(currentClient.nick, "banhwid", parts[1] + " " + reason);
            DisconnectByHwid(parts[1], "HWID baneado.");
            SendLine(clientSocket, "SYSTEM: HWID baneado: " + parts[1]);
        } else {
            SendLine(clientSocket, "SYSTEM: No se pudo banear HWID.");
        }
        return;
    }

    if (parts[0] == "/unbanhwid") {
        if (parts.size() < 2) {
            SendLine(clientSocket, "SYSTEM: Uso: /unbanhwid <hwid>");
            return;
        }
        if (repo_.UnbanHwid(parts[1])) {
            AuditAdminAction(currentClient.nick, "unbanhwid", parts[1]);
            SendLine(clientSocket, "SYSTEM: HWID desbloqueado: " + parts[1]);
        } else {
            SendLine(clientSocket, "SYSTEM: No se pudo desbloquear HWID.");
        }
        return;
    }

    if (parts[0] == "/users") {
        SendLine(clientSocket, "SYSTEM: Usuarios activos: " + BuildUsersSnapshot());
        return;
    }

    if (parts[0] == "/kick") {
        if (parts.size() < 2) {
            SendLine(clientSocket, "SYSTEM: Uso: /kick <user> [razon]");
            return;
        }
        if (parts[1] == river::AdminUsername()) {
            SendLine(clientSocket, "SYSTEM: No se puede expulsar al admin.");
            return;
        }
        std::string kickReason = RestAfterToken(command, 2);
        if (kickReason.empty()) kickReason = "Expulsado por admin.";
        if (KickUser(parts[1], kickReason)) {
            AuditAdminAction(currentClient.nick, "kick", parts[1]);
            Broadcast("SYSTEM: [ADMIN] NODE " + parts[1] + " KICKED.");
            BroadcastUsers();
        } else {
            SendLine(clientSocket, "SYSTEM: Usuario no encontrado.");
        }
        return;
    }

    SendLine(clientSocket, "SYSTEM: Comando admin no reconocido. Usa /help.");
}

void ChatServer::HeartbeatLoop() {
    while (!stopping_.load()) {
        // Sleep 30 s in small steps so shutdown is not delayed.
        for (int i = 0; i < 300 && !stopping_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (stopping_.load()) break;
        std::vector<SocketHandle> stale;
        {
            std::lock_guard<std::mutex> lk(clientsMutex_);
            time_t now = time(nullptr);
            for (auto& [sock, cl] : clients_) {
                if (!cl.auth) continue;
                if (now - cl.lastSeen > 90) stale.push_back(sock);
                else SendLine(sock, "PING");
            }
        }
        for (SocketHandle sock : stale) {
            LogRuntime("HB", "Cliente " + std::to_string(sock) + " sin respuesta; cerrando.");
            ShutdownSocket(sock);
        }
    }
}

void ChatServer::HandleClient(SocketHandle clientSocket) {
    std::string currentNick;
    std::string currentHwid;
    bool authed = false;
    bool isAdmin = false;
    bool firstLoginPending = false;
    std::string sessionId;
    // Outstanding AUTH_CHALLENGE2 (one per connection; a new AUTH_START replaces it).
    std::string pendingLoginUser;
    std::string pendingLoginHwid;
    std::string pendingClientNonce;
    std::string pendingCombinedNonce;
    std::string pendingSaltHex;
    int pendingIterations = 0;
    time_t pendingLoginIssuedAt = 0;
    time_t rateWindowStart = time(nullptr);
    int linesInWindow = 0;
    int messagesInWindow = 0;
    int attachmentsInWindow = 0;
    int attachmentChunksInWindow = 0;
    bool closeForRateLimit = false;

    auto resetRateWindowIfNeeded = [&]() {
        const time_t now = time(nullptr);
        if (now - rateWindowStart >= 60) {
            rateWindowStart = now;
            linesInWindow = 0;
            messagesInWindow = 0;
            attachmentsInWindow = 0;
            attachmentChunksInWindow = 0;
        }
    };

    // RegisterSocket was already called by Run() so a shutdown racing with
    // accept() still reaches this connection.
    SendLine(clientSocket, "SYSTEM: UPLINK ESTABLISHED. PROTO=2");

    while (true) {
        std::uint16_t frameType = 0;
        std::string raw;
        if (!RecvFrame(clientSocket, frameType, raw, 1024 * 1024)) break;
        resetRateWindowIfNeeded();
        if (authed) {
            std::lock_guard<std::mutex> lk(clientsMutex_);
            auto it = clients_.find(clientSocket);
            if (it != clients_.end()) it->second.lastSeen = time(nullptr);
        }
        if (frameType == kFrameTypeAttachmentChunk) {
            if (!authed || ++attachmentChunksInWindow > kMaxAttachmentChunksPerMinute ||
                !RelayAttachmentChunk(currentNick, raw)) {
                SendLine(clientSocket, "SYSTEM: ADJUNTO RECHAZADO.");
            }
            continue;
        }
        if (frameType != kFrameTypeText) continue;
        raw.erase(std::remove(raw.begin(), raw.end(), '\r'), raw.end());
        if (raw.empty()) continue;
        if (++linesInWindow > kMaxLinesPerMinute) {
            SendLine(clientSocket, "SYSTEM: LIMITE DE TRAFICO EXCEDIDO.");
            closeForRateLimit = true;
            break;
        }
        if (raw.size() > kMaxLineBytes) {
            SendLine(clientSocket, "SYSTEM: LINEA DEMASIADO GRANDE.");
            continue;
        }

            if (raw == "PONG") continue;
            if (raw == "PING") {
                SendLine(clientSocket, "PONG");
                continue;
            }

            if (StartsWith(raw, "[LOGIN_INIT]:") || StartsWith(raw, "[LOGIN_PROOF]:") ||
                StartsWith(raw, "[CHANGE]:")) {
                // v1 handshake (pass-the-hash): no compatibility mode.
                SendLineThenClose(clientSocket, kObsoleteClientNotice);
                continue;
            }

            if (StartsWith(raw, "[AUTH_START]:")) {
                if (authed || firstLoginPending) continue;
                const std::vector<std::string> f = SplitFields(raw.substr(13));
                pendingCombinedNonce.clear();
                if (f.size() != 4 || f[0] != "2") {
                    SendLineThenClose(clientSocket, kObsoleteClientNotice);
                    continue;
                }
                const std::string& user = f[1];
                const std::string& hwid = f[2];
                const std::string& clientNonce = f[3];
                if (!IsValidUsername(user) || hwid.empty() || hwid.size() > kMaxHwidChars ||
                    HasControlOrSeparator(hwid) ||
                    !river::scram::IsHexString(clientNonce, kClientNonceHexChars)) {
                    SendLine(clientSocket, "SYSTEM: CREDENCIALES INCORRECTAS.");
                    continue;
                }
                river::scram::Credential credential;
                if (repo_.GetCredential(user, credential)) {
                    pendingSaltHex = credential.saltHex;
                    pendingIterations = credential.iterations;
                } else {
                    // Unknown user: deterministic fake salt, fixed iterations.
                    pendingSaltHex = FakeSaltHex(user);
                    pendingIterations = river::scram::kDefaultIterations;
                }
                const std::string serverNonce = river::scram::RandomNonceHex(kServerNonceBytes);
                if (serverNonce.empty()) {
                    SendLine(clientSocket, "SYSTEM: CREDENCIALES INCORRECTAS.");
                    continue;
                }
                pendingLoginUser = user;
                pendingLoginHwid = hwid;
                pendingClientNonce = clientNonce;
                pendingCombinedNonce = clientNonce + serverNonce;
                pendingLoginIssuedAt = time(nullptr);
                SendLine(clientSocket, "AUTH_CHALLENGE2:" + pendingCombinedNonce + ":" + pendingSaltHex + ":" +
                                           std::to_string(pendingIterations));
            } else if (StartsWith(raw, "[AUTH_PROOF]:")) {
                if (authed || firstLoginPending) continue;
                const std::vector<std::string> f = SplitFields(raw.substr(13));
                std::string proofRaw;
                const bool shapeOk = f.size() == 4 && !pendingCombinedNonce.empty() &&
                                     f[0] == pendingLoginUser && f[1] == pendingLoginHwid &&
                                     f[2] == pendingCombinedNonce &&
                                     time(nullptr) - pendingLoginIssuedAt <= kLoginChallengeTtlSeconds &&
                                     river::base64::DecodeToString(f[3], proofRaw) &&
                                     proofRaw.size() == river::scram::kKeyBytes;
                const std::string user = pendingLoginUser;
                const std::string hwid = pendingLoginHwid;
                const std::string authMessage =
                    shapeOk ? river::scram::BuildAuthMessage(user, hwid, pendingClientNonce, pendingCombinedNonce,
                                                             pendingSaltHex, pendingIterations)
                            : std::string();
                pendingCombinedNonce.clear();  // single use
                if (!shapeOk || authMessage.empty()) {
                    SendLine(clientSocket, "SYSTEM: CREDENCIALES INCORRECTAS.");
                    continue;
                }

                std::string serverSignature;
                LoginResult login = AuthorizeLoginProof(user, hwid, authMessage, proofRaw, serverSignature);
                if (login.code == LoginCode::Ok || login.code == LoginCode::FirstLogin) {
                    SendLine(clientSocket, "AUTH_OK:" + river::base64::EncodeString(serverSignature));
                    currentHwid = hwid;
                    currentNick = user;
                    isAdmin = login.isAdmin;
                    sessionId = RandomHex(16);
                }

                if (login.code == LoginCode::FirstLogin) {
                    SendLine(clientSocket, "SYSTEM: FIRST LOGIN. CHANGE REQUIRED.");
                    firstLoginPending = true;
                } else if (login.code == LoginCode::Ok) {
                    authed = true;
                    firstLoginPending = false;
                    const time_t now = time(nullptr);
                    ClientSession session;
                    session.socket = clientSocket;
                    session.nick = user;
                    session.hwid = hwid;
                    session.sessionId = sessionId;
                    session.auth = true;
                    session.isAdmin = isAdmin;
                    session.lastSeen = now;
                    session.connectedAt = now;
                    CompleteLogin(clientSocket, session, false);
                } else if (login.code == LoginCode::Blocked) {
                    SendLine(clientSocket, "SYSTEM: ACCESO BLOQUEADO.");
                } else if (login.code == LoginCode::HwidMismatch) {
                    SendLine(clientSocket, "SYSTEM: HWID NO RECONOCIDO.");
                } else {
                    SendLine(clientSocket, "SYSTEM: CREDENCIALES INCORRECTAS.");
                }
            } else if (StartsWith(raw, "[CHANGE2]:") && firstLoginPending && !currentNick.empty()) {
                const std::vector<std::string> f = SplitFields(raw.substr(10));
                unsigned long long iterations = 0;
                const bool valid = f.size() == 5 && IsValidUsername(f[0]) &&
                                   ParseStrictUnsigned(f[2], static_cast<unsigned long long>(river::scram::kMaxIterations),
                                                       iterations) &&
                                   iterations >= static_cast<unsigned long long>(river::scram::kMinIterations) &&
                                   river::scram::IsValidSaltHex(f[1]) &&
                                   river::scram::IsHexString(f[3], 2 * river::scram::kKeyBytes) &&
                                   river::scram::IsHexString(f[4], 2 * river::scram::kKeyBytes);
                if (!valid || !repo_.CompleteFirstLoginWithCredential(currentNick, f[0], static_cast<int>(iterations),
                                                                      f[1], f[3], f[4])) {
                    SendLine(clientSocket, "SYSTEM: ERROR ACTUALIZANDO USUARIO.");
                    continue;
                }
                const std::string newUser = f[0];
                LogRuntime("SEC", "Primer acceso completado: '" + currentNick + "' -> '" + newUser + "'.");
                currentNick = newUser;
                sessionId = RandomHex(16);
                authed = true;
                firstLoginPending = false;
                const time_t now = time(nullptr);
                ClientSession session;
                session.socket = clientSocket;
                session.nick = newUser;
                session.hwid = currentHwid;
                session.sessionId = sessionId;
                session.auth = true;
                session.isAdmin = false;
                session.lastSeen = now;
                session.connectedAt = now;
                CompleteLogin(clientSocket, session, true);
            } else if (!authed) {
                continue;  // everything below requires an authenticated session
            } else if (StartsWith(raw, "[KEY_SET]:")) {
                std::string keyRaw;
                std::string keyB64;
                if (!DecodeB64Field(raw.substr(10), keyRaw, keyB64) || keyRaw.size() != river::e2e::kKeyBytes) {
                    SendLine(clientSocket, "SYSTEM: CLAVE PUBLICA RECHAZADA.");
                    continue;
                }
                const KeySetResult result = repo_.SetUserKey(currentNick, keyB64);
                if (result == KeySetResult::Error) {
                    SendLine(clientSocket, "SYSTEM: CLAVE PUBLICA RECHAZADA.");
                    continue;
                }
                SendLine(clientSocket, "SYSTEM: CLAVE PUBLICA REGISTRADA.");
                if (result == KeySetResult::Changed) {
                    LogRuntime("KEY", "Clave publica de '" + currentNick + "' actualizada (" +
                                          river::e2e::Fingerprint(keyRaw) + ").");
                    Broadcast("KEY_CHANGED:" + currentNick);
                }
            } else if (StartsWith(raw, "[KEY_GET]:")) {
                const std::string user = raw.substr(10);
                if (user.empty() || user.size() > 64 || HasControlOrSeparator(user)) continue;
                std::string keyB64;
                if (IsValidUsername(user) && repo_.GetUserKey(user, keyB64))
                    SendLine(clientSocket, "KEY:" + user + ":" + keyB64);
                else
                    SendLine(clientSocket, "KEY:" + user + ":-");
            } else if (StartsWith(raw, "[MSG]:")) {
                if (++messagesInWindow > kMaxMessagesPerMinute) {
                    SendLine(clientSocket, "SYSTEM: LIMITE DE MENSAJES EXCEDIDO.");
                    continue;
                }
                std::string text;
                std::string textB64;
                if (!DecodeB64Field(raw.substr(6), text, textB64) || text.empty()) {
                    SendLine(clientSocket, "SYSTEM: MENSAJE RECHAZADO.");
                    continue;
                }
                if (text.size() > kMaxChatPayloadBytes) {
                    SendLine(clientSocket, "SYSTEM: MENSAJE DEMASIADO GRANDE.");
                    continue;
                }
                if (StartsWith(text, "/")) {
                    if (isAdmin) {
                        ClientSession currentClient;
                        {
                            std::lock_guard<std::mutex> lk(clientsMutex_);
                            currentClient = clients_[clientSocket];
                        }
                        HandleAdminCommand(clientSocket, currentClient, text);
                    } else {
                        // Never broadcast mistyped commands from regular users to the room.
                        SendLine(clientSocket, "SYSTEM: Comando no disponible. Usa /help para ver los comandos.");
                    }
                    continue;
                }
                LogEncryptedMessage(currentNick, textB64);
                {
                    std::lock_guard<std::mutex> delivery(deliveryMutex_);
                    const long long ts = static_cast<long long>(time(nullptr));
                    if (!repo_.AppendRoomMessage(currentNick, ts, textB64))
                        LogRuntime("DB", "No se pudo guardar un mensaje en room_history.");
                    Broadcast("MSG:" + currentNick + ":" + std::to_string(ts) + ":" + textB64);
                }
            } else if (StartsWith(raw, "[PM2]:") || StartsWith(raw, "[PMX]:")) {
                if (++messagesInWindow > kMaxMessagesPerMinute) {
                    SendLine(clientSocket, "SYSTEM: LIMITE DE MENSAJES EXCEDIDO.");
                    continue;
                }
                const bool queueIfOffline = StartsWith(raw, "[PM2]:");
                const std::string rest = raw.substr(6);
                const std::size_t sep = rest.find(':');
                std::string target;
                std::string envelope;
                std::string envelopeB64;
                if (sep != std::string::npos) target = rest.substr(0, sep);
                if (sep == std::string::npos || !IsValidUsername(target) ||
                    !DecodeB64Field(rest.substr(sep + 1), envelope, envelopeB64) ||
                    envelope.size() < river::e2e::kEnvelopeOverhead ||
                    envelope.size() > kMaxPrivateEnvelopeBytes) {
                    SendLine(clientSocket, "SYSTEM: MENSAJE PRIVADO RECHAZADO.");
                    continue;
                }
                RoutePrivateEnvelope(clientSocket, currentNick, target, envelopeB64, queueIfOffline);
            } else if (StartsWith(raw, "[ATTACH2]:")) {
                if (++attachmentsInWindow > kMaxAttachmentsPerMinute) {
                    SendLine(clientSocket, "SYSTEM: LIMITE DE ADJUNTOS EXCEDIDO.");
                    continue;
                }
                if (raw.size() > kMaxAttachmentControlBytes) {
                    SendLine(clientSocket, "SYSTEM: ADJUNTO RECHAZADO POR TAMANO.");
                    continue;
                }
                // <id>:<kind>:<nameB64>:<mimeB64>:<size>
                const std::vector<std::string> f = SplitFields(raw.substr(10));
                std::string name, nameB64, mime, mimeB64;
                unsigned long long size = 0;
                const bool valid =
                    f.size() == 5 &&
                    !f[0].empty() && f[0].size() <= kMaxAttachmentIdChars && !HasControlOrSeparator(f[0]) &&
                    (f[1] == "image" || f[1] == "video" || f[1] == "file") &&
                    DecodeB64Field(f[2], name, nameB64) && !name.empty() && name.size() <= kMaxAttachmentNameBytes &&
                    DecodeB64Field(f[3], mime, mimeB64) && mime.size() <= kMaxAttachmentMimeBytes &&
                    ParseStrictUnsigned(f[4], kMaxAttachmentBytes, size) && size > 0;
                if (!valid) {
                    SendLine(clientSocket, "SYSTEM: ADJUNTO RECHAZADO.");
                    continue;
                }
                Broadcast("ATTACH2:" + currentNick + ":" + f[0] + ":" + f[1] + ":" + nameB64 + ":" + mimeB64 + ":" +
                          std::to_string(size));
            }
        if (closeForRateLimit) break;
    }

    bool replacedByNewerSession = false;
    {
        std::lock_guard<std::mutex> lk(clientsMutex_);
        clients_.erase(clientSocket);
        for (const auto& [sock, cl] : clients_) {
            if (cl.auth && cl.nick == currentNick) {
                replacedByNewerSession = true;
                break;
            }
        }
    }
    UnregisterSocket(clientSocket);
    openConnections_.fetch_sub(1);
    if (!currentNick.empty() && authed && !replacedByNewerSession) {
        Broadcast(currentNick + " salió");
        BroadcastUsers();
    }
    HandlerFinished();  // must stay last: Run() may tear down after this
}

int ChatServer::Run() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    if (!river::HasRequiredServerConfig()) {
        std::cerr << "[CFG] Faltan variables obligatorias: THE_RIVER_AES_KEY, "
                  << "THE_RIVER_ADMIN_BOOTSTRAP_PASSWORD y THE_RIVER_NEW_USER_PASSWORD." << std::endl;
        return 1;
    }

    if (!repo_.Open(dbPath_)) {
        std::cerr << "[DB] No se pudo abrir " << dbPath_ << std::endl;
        return 1;
    }
    if (!repo_.InitSchema()) {
        std::cerr << "[DB] No se pudo inicializar el esquema." << std::endl;
        return 1;
    }

    SocketHandle serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (!IsSocketValid(serverSocket)) {
        std::cerr << "[NET] No se pudo crear socket del servidor." << std::endl;
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    const std::string bindAddress = river::BindAddress();
    if (inet_pton(AF_INET, bindAddress.c_str(), &addr.sin_addr) != 1) {
        std::cerr << "[NET] THE_RIVER_BIND_ADDR invalido: " << bindAddress << std::endl;
        return 1;
    }
    addr.sin_port = htons(river::kServerPort);

    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    if (bind(serverSocket, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        std::cerr << "[NET] No se pudo hacer bind en " << bindAddress << ":" << river::kServerPort << std::endl;
        return 1;
    }
    if (listen(serverSocket, 20) != 0) {
        std::cerr << "[NET] No se pudo escuchar conexiones." << std::endl;
        return 1;
    }

    LogRuntime("SYS", "THE RIVER SECURE SERVER ONLINE — " + bindAddress + ":" + std::to_string(river::kServerPort));
    LogRuntime("CFG", "Admin predefinido: " + river::AdminUsername());
    LogRuntime("CFG", "Nuevo usuario por /newuser con clave inicial desde THE_RIVER_NEW_USER_PASSWORD.");
    LogRuntime("HB",  "Heartbeat cada 30s, timeout 90s.");
    LogRuntime("NET", "Maximo de conexiones simultaneas: " + std::to_string(kMaxConcurrentConnections) + ".");

    InstallStopHandlers();
    heartbeatThread_ = std::thread(&ChatServer::HeartbeatLoop, this);

    while (!g_stopRequested.load()) {
        // Poll the listening socket so a stop request is noticed within ~1 s.
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(serverSocket, &readSet);
        timeval tv{};
        tv.tv_sec = 1;
        const int ready = select(static_cast<int>(serverSocket) + 1, &readSet, nullptr, nullptr, &tv);
        if (ready <= 0) {
            if (ready < 0 && !g_stopRequested.load())
                std::this_thread::sleep_for(std::chrono::milliseconds(50));  // EINTR or transient error
            continue;
        }

        sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        SocketHandle client = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);
        if (!IsSocketValid(client)) continue;

        if (openConnections_.load() >= kMaxConcurrentConnections) {
            LogRuntime("NET", "Limite de conexiones alcanzado; rechazando cliente.");
            // Never registered, so a direct synchronous send is correct here.
            ::SendLine(client, "SYSTEM: SERVIDOR SATURADO. Intenta mas tarde.");
            CloseSocketHandle(client);
            continue;
        }
        ApplySocketTimeouts(client);
        openConnections_.fetch_add(1);

        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &clientAddr.sin_addr, ip, sizeof(ip));
        LogRuntime("CON", "Nueva conexion: " + std::string(ip));
        RegisterSocket(client);
        {
            std::lock_guard<std::mutex> lk(handlersMutex_);
            ++activeHandlers_;
        }
        try {
            std::thread(&ChatServer::HandleClient, this, client).detach();
        } catch (const std::exception&) {
            LogRuntime("NET", "No se pudo crear hilo para el cliente; cerrando.");
            UnregisterSocket(client);
            openConnections_.fetch_sub(1);
            HandlerFinished();
        }
    }

    // ---- Graceful shutdown ----
    LogRuntime("SYS", "Senal de parada recibida; apagando servidor...");
    stopping_.store(true);
    CloseSocketHandle(serverSocket);

    // Deliver the notice after whatever is already queued, then close.
    ShutdownAllClients("SYSTEM: SERVIDOR APAGANDOSE.");
    auto waitHandlers = [&](int millis) {
        std::unique_lock<std::mutex> lk(handlersMutex_);
        handlersCv_.wait_for(lk, std::chrono::milliseconds(millis), [&] { return activeHandlers_ == 0; });
        return activeHandlers_;
    };
    int remaining = waitHandlers(kShutdownGraceMillis);
    if (remaining > 0) {
        // Slow peers still draining: cut their streams so handlers exit.
        std::vector<SocketHandle> socks;
        {
            std::lock_guard<std::mutex> lk(channelsMutex_);
            for (auto& [sock, channel] : channels_) socks.push_back(sock);
        }
        for (SocketHandle sock : socks) ShutdownSocket(sock);
        remaining = waitHandlers(kShutdownForceMillis);
    }
    if (remaining > 0)
        LogRuntime("SYS", std::to_string(remaining) + " hilos de cliente siguen activos al apagar.");

    if (heartbeatThread_.joinable()) heartbeatThread_.join();
    repo_.Close();
    LogRuntime("SYS", "Servidor detenido.");
    return 0;
}
