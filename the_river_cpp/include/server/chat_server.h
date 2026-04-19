#pragma once

#include <atomic>
#include <map>
#include <mutex>
#include <string>

#include "common/net_platform.h"
#include "server/user_repository.h"

class ChatServer {
public:
    ChatServer(const std::string& dbPath, const std::string& logPath);
    int Run();

private:
    struct ClientSession {
        SocketHandle socket = kInvalidSocket;
        std::string nick;
        std::string hwid;
        bool auth = false;
        bool isAdmin = false;
        time_t lastSeen = 0;
    };

    enum class LoginCode {
        Ok = 0,
        FirstLogin = 1,
        InvalidCredentials = -1,
        HwidMismatch = -2,
        Blocked = -3
    };

    struct LoginResult {
        LoginCode code = LoginCode::InvalidCredentials;
        bool isAdmin = false;
    };

    void HandleClient(SocketHandle clientSocket);
    void HeartbeatLoop();
    void SendLine(SocketHandle sock, const std::string& msg);
    void Broadcast(const std::string& msg);
    void BroadcastUsers();
    bool SendPrivateMessage(const std::string& toNick, const std::string& fromNick, const std::string& encPayload);
    bool KickUser(const std::string& nick, const std::string& reason);
    void DisconnectByHwid(const std::string& hwid, const std::string& reason);
    void HandleAdminCommand(SocketHandle clientSocket, const ClientSession& currentClient, const std::string& command);
    void LogEncryptedMessage(const std::string& user, const std::string& encryptedPayload);
    std::string BuildUsersSnapshot();
    LoginResult AuthorizeLogin(const std::string& username, const std::string& password, const std::string& hwid);

    std::string dbPath_;
    std::string logPath_;
    UserRepository repo_;

    std::map<SocketHandle, ClientSession> clients_;
    std::map<std::string, time_t> loginLocks_;
    std::map<std::string, int> loginFailures_;
    std::mutex clientsMutex_;
    std::mutex attemptsMutex_;
    std::mutex logMutex_;
};
