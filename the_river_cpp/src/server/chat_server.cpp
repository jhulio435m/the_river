#include "server/chat_server.h"

#include <algorithm>
#include <ctime>
#include <cstdio>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#include "common/base64.h"
#include "common/secure_envelope.h"
#include "common/security_utils.h"
#include "common/shared_config.h"

namespace {

constexpr std::size_t kMaxLineBytes = 65536;
constexpr std::size_t kMaxChatPayloadBytes = 8192;
constexpr std::size_t kMaxAttachmentControlBytes = 16384;
constexpr int kLoginChallengeTtlSeconds = 60;
constexpr int kMaxLinesPerMinute = 120;
constexpr int kMaxMessagesPerMinute = 60;
constexpr int kMaxAttachmentsPerMinute = 12;

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

std::string ChallengeSpecFromPasswordHash(const std::string& storedHash) {
    if (storedHash.rfind("pbkdf2-sha256$", 0) != 0) return "";
    std::vector<std::string> parts;
    std::stringstream ss(storedHash);
    std::string part;
    while (std::getline(ss, part, '$')) parts.push_back(part);
    if (parts.size() != 4) return "";
    return parts[0] + "$" + parts[1] + "$" + parts[2];
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
    : dbPath_(dbPath), logPath_(logPath) {}

bool ChatServer::SendLine(SocketHandle sock, const std::string& msg) {
    const bool ok = ::SendLine(sock, msg);
    if (!ok) LogRuntime("NET", "send failed on socket " + std::to_string(sock));
    return ok;
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

bool ChatServer::SendPrivateMessage(const std::string& toNick, const std::string& fromNick, const std::string& encPayload) {
    std::lock_guard<std::mutex> lk(clientsMutex_);
    for (auto& [sock, cl] : clients_) {
        if (cl.auth && cl.nick == toNick) {
            SendLine(sock, "[PM]:" + fromNick + ":" + encPayload);
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
    if (encryptedChunk.size() > 64 * 1024) return false;

    std::string outbound;
    AppendSizedString(outbound, fromNick);
    AppendSizedString(outbound, attachmentId);
    AppendU32(outbound, index);
    AppendU32(outbound, totalChunks);
    outbound.append(encryptedChunk);

    std::lock_guard<std::mutex> lk(clientsMutex_);
    for (auto& [sock, cl] : clients_) {
        if (cl.auth && cl.nick == target) {
            return SendFrame(sock, kFrameTypeAttachmentChunk, outbound);
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
    SendLine(targetSock, "SYSTEM: KICKED BY ADMIN. " + reason);
    CloseSocketHandle(targetSock);
    return true;
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
        SendLine(sock, "SYSTEM: ACCESO BLOQUEADO. " + reason);
        CloseSocketHandle(sock);
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

ChatServer::LoginResult ChatServer::AuthorizeLogin(const std::string& username,
                                                   const std::string& password,
                                                   const std::string& hwid) {
    {
        std::lock_guard<std::mutex> lk(attemptsMutex_);
        auto it = loginLocks_.find(username);
        if (it != loginLocks_.end() && it->second > time(nullptr))
            return {LoginCode::Blocked, false};
    }

    UserRecord record = repo_.FindUserByCredentials(username, password);
    LoginResult result;
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

    {
        std::lock_guard<std::mutex> lk(attemptsMutex_);
        if (result.code == LoginCode::Ok || result.code == LoginCode::FirstLogin) {
            loginFailures_.erase(username);
            loginLocks_.erase(username);
        } else if (result.code == LoginCode::InvalidCredentials) {
            int& failures = loginFailures_[username];
            failures++;
            if (failures >= 5) {
                loginLocks_[username] = time(nullptr) + 300;
                failures = 0;
            LogRuntime("SEC", "Usuario '" + username + "' bloqueado por 5 min.");
            }
        }
    }

    return result;
}

ChatServer::LoginResult ChatServer::AuthorizeLoginProof(const std::string& username,
                                                        const std::string& proof,
                                                        const std::string& nonce,
                                                        const std::string& hwid) {
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

    std::string storedHash;
    LoginResult result;
    if (!repo_.GetPasswordHash(username, storedHash)) {
        result.code = LoginCode::InvalidCredentials;
    } else if (storedHash.rfind("pbkdf2-sha256$", 0) != 0) {
        result.code = LoginCode::InvalidCredentials;
    } else {
        const std::string expected = HmacSha256Hex(storedHash, nonce + "|" + username + "|" + hwid);
        if (!ConstantTimeEquals(expected, proof)) {
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
        }
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

void ChatServer::HandleAdminCommand(SocketHandle clientSocket,
                                    const ClientSession& currentClient,
                                    const std::string& command) {
    std::vector<std::string> parts = SplitWhitespace(command);
    if (parts.empty()) return;

    if (parts[0] == "/help") {
        SendLine(
            clientSocket,
            "SYSTEM: /newuser | /passwd <user> <new-key> | /banhwid <hwid> [reason] | "
            "/unbanhwid <hwid> | /users | /kick <user>");
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
        std::string reason = "ban administrativo";
        if (parts.size() > 2) {
            size_t reasonPos = command.find(parts[2]);
            reason = reasonPos == std::string::npos ? reason : command.substr(reasonPos);
        }
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
            SendLine(clientSocket, "SYSTEM: Uso: /kick <user>");
            return;
        }
        if (parts[1] == river::AdminUsername()) {
            SendLine(clientSocket, "SYSTEM: No se puede expulsar al admin.");
            return;
        }
        if (KickUser(parts[1], "Expulsado por admin.")) {
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
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
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
            CloseSocketHandle(sock);
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
    std::string pendingLoginUser;
    std::string pendingLoginHwid;
    std::string pendingLoginNonce;
    time_t pendingLoginIssuedAt = 0;
    time_t rateWindowStart = time(nullptr);
    int linesInWindow = 0;
    int messagesInWindow = 0;
    int attachmentsInWindow = 0;
    bool closeForRateLimit = false;

    auto resetRateWindowIfNeeded = [&]() {
        const time_t now = time(nullptr);
        if (now - rateWindowStart >= 60) {
            rateWindowStart = now;
            linesInWindow = 0;
            messagesInWindow = 0;
            attachmentsInWindow = 0;
        }
    };

    SendLine(clientSocket, "SYSTEM: UPLINK ESTABLISHED.");

    while (true) {
        std::uint16_t frameType = 0;
        std::string raw;
        if (!RecvFrame(clientSocket, frameType, raw, 1024 * 1024)) break;
        resetRateWindowIfNeeded();
        if (frameType == kFrameTypeAttachmentChunk) {
            if (!authed || ++attachmentsInWindow > kMaxAttachmentsPerMinute || !RelayAttachmentChunk(currentNick, raw)) {
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

            if (authed) {
                std::lock_guard<std::mutex> lk(clientsMutex_);
                auto it = clients_.find(clientSocket);
                if (it != clients_.end()) it->second.lastSeen = time(nullptr);
            }

            if (raw == "PONG") continue;

            if (StartsWith(raw, "[LOGIN_INIT]:")) {
                std::stringstream ss(raw.substr(13));
                std::string user;
                std::string hwid;
                std::getline(ss, user, ':');
                std::getline(ss, hwid, ':');
                if (!IsValidUsername(user) || hwid.empty() || hwid.size() > 128) {
                    SendLine(clientSocket, "SYSTEM: CREDENCIALES INCORRECTAS.");
                    continue;
                }
                std::string storedHash;
                if (!repo_.GetPasswordHash(user, storedHash)) {
                    SendLine(clientSocket, "SYSTEM: CREDENCIALES INCORRECTAS.");
                    continue;
                }
                const std::string challengeSpec = ChallengeSpecFromPasswordHash(storedHash);
                if (challengeSpec.empty()) {
                    SendLine(clientSocket, "SYSTEM: CREDENCIALES INCORRECTAS.");
                    continue;
                }
                pendingLoginUser = user;
                pendingLoginHwid = hwid;
                pendingLoginNonce = RandomHex(16);
                pendingLoginIssuedAt = time(nullptr);
                SendLine(clientSocket, "AUTH_CHALLENGE:" + pendingLoginNonce + ":" + challengeSpec);
            } else if (StartsWith(raw, "[LOGIN_PROOF]:")) {
                std::stringstream ss(raw.substr(14));
                std::string user;
                std::string hwid;
                std::string proof;
                std::getline(ss, user, ':');
                std::getline(ss, hwid, ':');
                std::getline(ss, proof, ':');
                if (user != pendingLoginUser ||
                    hwid != pendingLoginHwid ||
                    pendingLoginNonce.empty() ||
                    proof.size() != 64 ||
                    time(nullptr) - pendingLoginIssuedAt > kLoginChallengeTtlSeconds) {
                    pendingLoginNonce.clear();
                    SendLine(clientSocket, "SYSTEM: CREDENCIALES INCORRECTAS.");
                    continue;
                }

                currentHwid = hwid;
                LoginResult login = AuthorizeLoginProof(user, proof, pendingLoginNonce, hwid);
                pendingLoginNonce.clear();
                isAdmin = login.isAdmin;

                if (login.code == LoginCode::FirstLogin) {
                    SendLine(clientSocket, "SYSTEM: FIRST LOGIN. CHANGE REQUIRED.");
                    currentNick = user;
                    sessionId = RandomHex(16);
                    firstLoginPending = true;
                } else if (login.code == LoginCode::Ok) {
                    SendLine(clientSocket, "SYSTEM: ACCESO CONCEDIDO.");
                    currentNick = user;
                    sessionId = RandomHex(16);
                    SendLine(clientSocket, "SESSION:" + sessionId);
                    authed = true;
                    firstLoginPending = false;
                    {
                        std::lock_guard<std::mutex> lk(clientsMutex_);
                        clients_[clientSocket] = {clientSocket, user, hwid, sessionId, true, isAdmin, time(nullptr)};
                    }
                    Broadcast(user + " se unió");
                    BroadcastUsers();
                } else if (login.code == LoginCode::Blocked) {
                    SendLine(clientSocket, "SYSTEM: ACCESO BLOQUEADO.");
                } else if (login.code == LoginCode::HwidMismatch) {
                    SendLine(clientSocket, "SYSTEM: HWID NO RECONOCIDO.");
                } else {
                    SendLine(clientSocket, "SYSTEM: CREDENCIALES INCORRECTAS.");
                }
            } else if (StartsWith(raw, "[CHANGE]:") && firstLoginPending && !currentNick.empty()) {
                std::stringstream ss(raw.substr(9));
                std::string newUser;
                std::string newPass;
                std::getline(ss, newUser, ':');
                std::getline(ss, newPass, ':');
                std::string decryptedPass;
                if (river::OpenPayload(newPass, decryptedPass)) newPass = decryptedPass;
                if (!IsValidUsername(newUser) || !IsStrongEnoughPassword(newPass)) {
                    SendLine(clientSocket, "SYSTEM: ERROR ACTUALIZANDO USUARIO.");
                } else if (repo_.CompleteFirstLogin(currentNick, newUser, newPass)) {
                    currentNick = newUser;
                    sessionId = RandomHex(16);
                    authed = true;
                    firstLoginPending = false;
                    {
                        std::lock_guard<std::mutex> lk(clientsMutex_);
                        clients_[clientSocket] = {clientSocket, newUser, currentHwid, sessionId, true, false, time(nullptr)};
                    }
                    SendLine(clientSocket, "SYSTEM: ACTUALIZADO.");
                    SendLine(clientSocket, "SYSTEM: ACCESO CONCEDIDO.");
                    SendLine(clientSocket, "SESSION:" + sessionId);
                    Broadcast(newUser + " se unió");
                    BroadcastUsers();
                } else {
                    SendLine(clientSocket, "SYSTEM: ERROR ACTUALIZANDO USUARIO.");
                }
            } else if (StartsWith(raw, "[ATTACH]:") && authed) {
                if (++attachmentsInWindow > kMaxAttachmentsPerMinute) {
                    SendLine(clientSocket, "SYSTEM: LIMITE DE ADJUNTOS EXCEDIDO.");
                    continue;
                }
                if (raw.size() > kMaxAttachmentControlBytes) {
                    SendLine(clientSocket, "SYSTEM: ADJUNTO RECHAZADO POR TAMANO.");
                    continue;
                }
                Broadcast("[ATTACH]:" + currentNick + ":" + raw.substr(9));
            } else if (StartsWith(raw, "[PM]:") && authed) {
                if (++messagesInWindow > kMaxMessagesPerMinute) {
                    SendLine(clientSocket, "SYSTEM: LIMITE DE MENSAJES EXCEDIDO.");
                    continue;
                }
                std::string rest = raw.substr(5);
                size_t firstSep = rest.find(':');
                if (firstSep == std::string::npos) continue;
                std::string target = rest.substr(0, firstSep);
                std::string remaining = rest.substr(firstSep + 1);
                size_t secondSep = remaining.find(':');
                if (secondSep == std::string::npos) continue;
                std::string encPayload = remaining.substr(secondSep + 1);
                if (!IsValidUsername(target) || encPayload.size() > kMaxChatPayloadBytes) {
                    SendLine(clientSocket, "SYSTEM: MENSAJE PRIVADO RECHAZADO.");
                    continue;
                }
                if (!SendPrivateMessage(target, currentNick, encPayload))
                    SendLine(clientSocket, "SYSTEM: Usuario '" + target + "' no encontrado.");
            } else if (authed && isAdmin) {
                if (++messagesInWindow > kMaxMessagesPerMinute) {
                    SendLine(clientSocket, "SYSTEM: LIMITE DE MENSAJES EXCEDIDO.");
                    continue;
                }
                std::string payload = raw;
                size_t sep = raw.find(':');
                if (sep != std::string::npos) payload = raw.substr(sep + 1);
                if (payload.size() > kMaxChatPayloadBytes) {
                    SendLine(clientSocket, "SYSTEM: MENSAJE DEMASIADO GRANDE.");
                    continue;
                }

                std::string dec;
                const bool opened = river::OpenPayload(payload, dec);
                if (StartsWith(dec, "/")) {
                    ClientSession currentClient;
                    {
                        std::lock_guard<std::mutex> lk(clientsMutex_);
                        currentClient = clients_[clientSocket];
                    }
                    HandleAdminCommand(clientSocket, currentClient, dec);
                } else if (opened) {
                    LogEncryptedMessage(currentNick, payload);
                    Broadcast(currentNick + ":" + payload);
                } else {
                    SendLine(clientSocket, "SYSTEM: MENSAJE RECHAZADO POR AUTENTICACION.");
                }
            } else if (authed) {
                if (++messagesInWindow > kMaxMessagesPerMinute) {
                    SendLine(clientSocket, "SYSTEM: LIMITE DE MENSAJES EXCEDIDO.");
                    continue;
                }
                std::string payload = raw;
                size_t sep = raw.find(':');
                if (sep != std::string::npos) payload = raw.substr(sep + 1);
                if (payload.size() > kMaxChatPayloadBytes) {
                    SendLine(clientSocket, "SYSTEM: MENSAJE DEMASIADO GRANDE.");
                    continue;
                }
                std::string plainCheck;
                if (!river::OpenPayload(payload, plainCheck)) {
                    SendLine(clientSocket, "SYSTEM: MENSAJE RECHAZADO POR AUTENTICACION.");
                    continue;
                }
                LogEncryptedMessage(currentNick, payload);
                Broadcast(currentNick + ":" + payload);
            }
        if (closeForRateLimit) break;
    }

    {
        std::lock_guard<std::mutex> lk(clientsMutex_);
        clients_.erase(clientSocket);
    }
    if (!currentNick.empty() && authed) {
        Broadcast(currentNick + " salió");
        BroadcastUsers();
    }
    CloseSocketHandle(clientSocket);
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

    std::thread(&ChatServer::HeartbeatLoop, this).detach();

    while (true) {
        sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        SocketHandle client = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);
        if (!IsSocketValid(client)) continue;

        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &clientAddr.sin_addr, ip, sizeof(ip));
        LogRuntime("CON", "Nueva conexion: " + std::string(ip));
        std::thread(&ChatServer::HandleClient, this, client).detach();
    }

    return 0;
}
