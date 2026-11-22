#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "common/net_platform.h"
#include "server/user_repository.h"

// Threading model
// ---------------
// * Run() (main thread): accept loop (select with 1 s timeout), then the
//   graceful shutdown sequence once a stop is requested.
// * One detached handler thread per connection (HandleClient): reads frames,
//   enqueues replies. It alone closes its descriptor (UnregisterSocket).
// * One writer thread per connection (WriterLoop): drains that connection's
//   outbound queue onto the socket. Started in RegisterSocket and joined in
//   UnregisterSocket before the descriptor is closed, so no thread ever
//   touches a closed (possibly reused) descriptor.
// * One heartbeat thread (joined on shutdown).
//
// Producers (SendLine/SendFrameLocked/Broadcast...) only enqueue; they never
// block on the network.
//
// Lock ordering (acquire left to right, never the reverse):
//   clientsMutex_ -> channelsMutex_ -> SocketChannel::mutex
//   attemptsMutex_ -> logMutex_
//   handlersMutex_ is a leaf. logMutex_ is never taken while holding a
//   SocketChannel::mutex (log after releasing it).
class ChatServer {
public:
    ChatServer(const std::string& dbPath, const std::string& logPath);
    int Run();

    // Async-signal-safe: only sets an atomic flag polled by Run().
    static void RequestStop();

private:
    struct OutboundFrame {
        std::uint16_t type = 0;
        std::string payload;
        // Sentinel: after every frame queued before it is sent, the writer
        // shuts the socket down so the handler thread cleans up.
        bool closeAfter = false;
    };

    // Per-socket outbound queue plus its writer thread. Also guards against
    // using a descriptor after its owning handler thread closed it.
    struct SocketChannel {
        SocketHandle sock = kInvalidSocket;
        std::mutex mutex;
        std::condition_variable cv;
        std::deque<OutboundFrame> queue;
        std::size_t queuedBytes = 0;
        bool accepting = true;    // false: new frames are dropped
        bool draining = false;    // UnregisterSocket: flush what is queued, then exit
        bool closed = false;      // descriptor is about to be / has been closed
        bool writerDone = false;  // writer thread has left its loop
        bool overloaded = false;
        std::thread writer;
    };

    struct ClientSession {
        SocketHandle socket = kInvalidSocket;
        std::string nick;
        std::string hwid;
        std::string sessionId;
        bool auth = false;
        bool isAdmin = false;
        time_t lastSeen = 0;
        time_t connectedAt = 0;
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
    void WriterLoop(std::shared_ptr<SocketChannel> channel);
    // Enqueue operations (non-blocking). Return false if the frame was dropped.
    bool SendLine(SocketHandle sock, const std::string& msg);
    bool SendFrameLocked(SocketHandle sock, std::uint16_t type, const std::string& payload);
    bool Enqueue(const std::shared_ptr<SocketChannel>& channel, OutboundFrame frame);
    // Enqueue a final notice; the socket is shut down once it has been sent.
    void SendLineThenClose(SocketHandle sock, const std::string& msg);
    void EnqueueFinal(const std::shared_ptr<SocketChannel>& channel, const std::string& msg);
    void ShutdownChannelLocked(SocketChannel& channel);
    void ShutdownAllClients(const std::string& notice);
    void HandlerFinished();
    void RegisterSocket(SocketHandle sock);
    void UnregisterSocket(SocketHandle sock);
    std::shared_ptr<SocketChannel> ChannelFor(SocketHandle sock);
    void ShutdownSocket(SocketHandle sock);
    void RegisterAuthenticatedSession(const ClientSession& session);
    void Broadcast(const std::string& msg);
    void BroadcastUsers();
    bool SendDirectLineToUser(const std::string& toNick, const std::string& line);
    bool SendPrivateMessage(const std::string& toNick, const std::string& fromNick, const std::string& encPayload);
    bool RelayAttachmentChunk(const std::string& fromNick, const std::string& payload);
    bool KickUser(const std::string& nick, const std::string& reason);
    bool DescribeUser(const std::string& nick, ClientSession& session);
    void DisconnectByHwid(const std::string& hwid, const std::string& reason);
    void HandleAdminCommand(SocketHandle clientSocket, const ClientSession& currentClient, const std::string& command);
    void LogEncryptedMessage(const std::string& user, const std::string& encryptedPayload);
    void LogRuntime(const std::string& category, const std::string& message);
    std::string BuildUsersSnapshot();
    LoginResult AuthorizeLogin(const std::string& username, const std::string& password, const std::string& hwid);
    LoginResult AuthorizeLoginProof(const std::string& username,
                                    const std::string& proof,
                                    const std::string& nonce,
                                    const std::string& hwid);
    void AuditAdminAction(const std::string& admin, const std::string& action, const std::string& detail);

    std::string dbPath_;
    std::string logPath_;
    UserRepository repo_;

    std::map<SocketHandle, ClientSession> clients_;
    std::map<std::string, time_t> loginLocks_;
    std::map<std::string, int> loginFailures_;
    std::map<std::string, int> loginFailuresByOrigin_;
    std::map<std::string, time_t> loginLocksByOrigin_;
    std::map<SocketHandle, std::shared_ptr<SocketChannel>> channels_;
    std::atomic<int> openConnections_{0};
    std::atomic<bool> stopping_{false};
    std::thread heartbeatThread_;
    int activeHandlers_ = 0;
    std::mutex handlersMutex_;
    std::condition_variable handlersCv_;
    std::mutex clientsMutex_;
    std::mutex channelsMutex_;
    std::mutex attemptsMutex_;
    std::mutex logMutex_;
};
