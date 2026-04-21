#include "server/chat_server.h"

#include <algorithm>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>

#include "common/security_utils.h"
#include "common/shared_config.h"
#include "include/aes.h"

namespace {

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

}

ChatServer::ChatServer(const std::string& dbPath, const std::string& logPath)
    : dbPath_(dbPath), logPath_(logPath) {}

void ChatServer::SendLine(SocketHandle sock, const std::string& msg) {
    std::string full = msg + "\n";
    send(sock, full.c_str(), (int)full.size(), 0);
}

void ChatServer::LogEncryptedMessage(const std::string& user, const std::string& encryptedPayload) {
    std::lock_guard<std::mutex> lk(logMutex_);
    std::ofstream f(logPath_, std::ios::app);
    if (!f.is_open()) return;

    char ts[32];
    std::time_t now = std::time(nullptr);
    std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    std::string entry = std::string(ts) + "|" + user + ":" + encryptedPayload;
    f << AESHelper::Encrypt(entry, river::kAesKey, "") << "\n";
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
                std::cout << "[SEC] Usuario '" << username << "' bloqueado por 5 min." << std::endl;
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
            "SYSTEM: /newuser | /passwd <user> <clave> | /banhwid <hwid> [razon] | "
            "/unbanhwid <hwid> | /users | /kick <user>");
        return;
    }

    if (parts[0] == "/newuser") {
        std::string username;
        if (repo_.CreateNextUser(username))
            SendLine(clientSocket, "SYSTEM: NUEVO USUARIO: " + username + " / clave inicial: " + river::kDefaultUserPassword);
        else
            SendLine(clientSocket, "SYSTEM: ERROR creando usuario.");
        return;
    }

    if (parts[0] == "/passwd") {
        if (parts.size() < 3) {
            SendLine(clientSocket, "SYSTEM: Uso: /passwd <user> <clave>");
            return;
        }
        if (repo_.ResetUserPassword(parts[1], parts[2]))
            SendLine(clientSocket, "SYSTEM: Clave actualizada para " + parts[1]);
        else
            SendLine(clientSocket, "SYSTEM: No se pudo actualizar la clave de " + parts[1]);
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
        if (repo_.UnbanHwid(parts[1]))
            SendLine(clientSocket, "SYSTEM: HWID desbloqueado: " + parts[1]);
        else
            SendLine(clientSocket, "SYSTEM: No se pudo desbloquear HWID.");
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
        if (parts[1] == river::kAdminUsername) {
            SendLine(clientSocket, "SYSTEM: No se puede expulsar al admin.");
            return;
        }
        if (KickUser(parts[1], "Expulsado por admin.")) {
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
            std::cout << "[HB] Cliente " << sock << " sin respuesta; cerrando." << std::endl;
            CloseSocketHandle(sock);
        }
    }
}

void ChatServer::HandleClient(SocketHandle clientSocket) {
    char buffer[65536];
    std::string accum;
    std::string currentNick;
    std::string currentHwid;
    bool authed = false;
    bool isAdmin = false;
    bool firstLoginPending = false;

    SendLine(clientSocket, "SYSTEM: UPLINK ESTABLISHED.");

    while (true) {
        int bytes = recv(clientSocket, buffer, 65535, 0);
        if (bytes <= 0) break;

        buffer[bytes] = '\0';
        accum += buffer;
        if (accum.size() > 1024 * 1024) {
            accum.clear();
            continue;
        }

        size_t pos = 0;
        while ((pos = accum.find('\n')) != std::string::npos) {
            std::string raw = accum.substr(0, pos);
            accum.erase(0, pos + 1);
            raw.erase(std::remove(raw.begin(), raw.end(), '\r'), raw.end());
            if (raw.empty()) continue;

            if (authed) {
                std::lock_guard<std::mutex> lk(clientsMutex_);
                auto it = clients_.find(clientSocket);
                if (it != clients_.end()) it->second.lastSeen = time(nullptr);
            }

            if (raw == "PONG") continue;

            if (StartsWith(raw, "[LOGIN]:")) {
                std::stringstream ss(raw.substr(8));
                std::string user;
                std::string pass;
                std::string hwid;
                std::getline(ss, user, ':');
                std::getline(ss, pass, ':');
                std::getline(ss, hwid, ':');

                currentHwid = hwid;
                LoginResult login = AuthorizeLogin(user, pass, hwid);
                isAdmin = login.isAdmin;

                if (login.code == LoginCode::FirstLogin) {
                    SendLine(clientSocket, "SYSTEM: FIRST LOGIN. CHANGE REQUIRED.");
                    currentNick = user;
                    firstLoginPending = true;
                } else if (login.code == LoginCode::Ok) {
                    SendLine(clientSocket, "SYSTEM: ACCESO CONCEDIDO.");
                    currentNick = user;
                    authed = true;
                    firstLoginPending = false;
                    {
                        std::lock_guard<std::mutex> lk(clientsMutex_);
                        clients_[clientSocket] = {clientSocket, user, hwid, true, isAdmin, time(nullptr)};
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
                if (repo_.CompleteFirstLogin(currentNick, newUser, newPass)) {
                    currentNick = newUser;
                    authed = true;
                    firstLoginPending = false;
                    {
                        std::lock_guard<std::mutex> lk(clientsMutex_);
                        clients_[clientSocket] = {clientSocket, newUser, currentHwid, true, false, time(nullptr)};
                    }
                    SendLine(clientSocket, "SYSTEM: ACTUALIZADO.");
                    SendLine(clientSocket, "SYSTEM: ACCESO CONCEDIDO.");
                    Broadcast(newUser + " se unió");
                    BroadcastUsers();
                } else {
                    SendLine(clientSocket, "SYSTEM: ERROR ACTUALIZANDO USUARIO.");
                }
            } else if (StartsWith(raw, "[ATTACH]:") && authed) {
                Broadcast("[ATTACH]:" + currentNick + ":" + raw.substr(9));
            } else if (StartsWith(raw, "[PM]:") && authed) {
                std::string rest = raw.substr(5);
                size_t firstSep = rest.find(':');
                if (firstSep == std::string::npos) continue;
                std::string target = rest.substr(0, firstSep);
                std::string remaining = rest.substr(firstSep + 1);
                size_t secondSep = remaining.find(':');
                if (secondSep == std::string::npos) continue;
                std::string encPayload = remaining.substr(secondSep + 1);
                if (!SendPrivateMessage(target, currentNick, encPayload))
                    SendLine(clientSocket, "SYSTEM: Usuario '" + target + "' no encontrado.");
            } else if (authed && isAdmin) {
                std::string payload = raw;
                size_t sep = raw.find(':');
                if (sep != std::string::npos) payload = raw.substr(sep + 1);

                std::string dec = AESHelper::Decrypt(payload, river::kAesKey, "");
                if (StartsWith(dec, "/")) {
                    ClientSession currentClient;
                    {
                        std::lock_guard<std::mutex> lk(clientsMutex_);
                        currentClient = clients_[clientSocket];
                    }
                    HandleAdminCommand(clientSocket, currentClient, dec);
                } else {
                    LogEncryptedMessage(currentNick, payload);
                    Broadcast(currentNick + ":" + payload);
                }
            } else if (authed) {
                std::string payload = raw;
                size_t sep = raw.find(':');
                if (sep != std::string::npos) payload = raw.substr(sep + 1);
                LogEncryptedMessage(currentNick, payload);
                Broadcast(currentNick + ":" + payload);
            }
        }
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
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(river::kServerPort);

    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    if (bind(serverSocket, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        std::cerr << "[NET] No se pudo hacer bind en el puerto " << river::kServerPort << std::endl;
        return 1;
    }
    if (listen(serverSocket, 20) != 0) {
        std::cerr << "[NET] No se pudo escuchar conexiones." << std::endl;
        return 1;
    }

    std::cout << ">>> THE RIVER SECURE SERVER ONLINE — PORT " << river::kServerPort << " <<<" << std::endl;
    std::cout << "[CFG] Admin predefinido: " << river::kAdminUsername << std::endl;
    std::cout << "[CFG] Nuevo usuario por /newuser con clave inicial: " << river::kDefaultUserPassword << std::endl;
    std::cout << "[HB]  Heartbeat cada 30s, timeout 90s." << std::endl;

    std::thread(&ChatServer::HeartbeatLoop, this).detach();

    while (true) {
        sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        SocketHandle client = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);
        if (!IsSocketValid(client)) continue;

        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &clientAddr.sin_addr, ip, sizeof(ip));
        std::cout << "[CON] Nueva conexion: " << ip << std::endl;
        std::thread(&ChatServer::HandleClient, this, client).detach();
    }

    return 0;
}
