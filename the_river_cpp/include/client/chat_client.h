#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <thread>

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

private:
    void NetworkLoop();
    void ReceiveLoop(SocketHandle sock);
    int SendRawLine(const std::string& payload);
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
};
