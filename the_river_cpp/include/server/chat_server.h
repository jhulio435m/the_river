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
// * One heartbeat thread (joined on shutdown): every second it enforces the
//   pre-authentication deadlines; every 30 s it PINGs, reaps silent sessions
//   and prunes the login-failure tables.
//
// Producers (SendLine/SendFrameLocked/Broadcast...) only enqueue; they never
// block on the network.
//
// Lock ordering (acquire left to right, never the reverse):
//   deliveryMutex_ -> clientsMutex_ -> channelsMutex_ -> SocketChannel::mutex
//   deliveryMutex_ serializes "store room message + broadcast MSG",
//   "route PM2 (deliver or queue)" and "register session + replay history +
//   drain offline PMs", so a login never misses or duplicates a MSG/PM2.
//   The repository's own mutex is a leaf.
//   attemptsMutex_ -> logMutex_ (attemptsMutex_ is otherwise a leaf)
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
        // Connection lifecycle, read by the accept loop and the heartbeat.
        // phase: kPhasePreAuth until AUTH_OK, kPhaseFirstLogin while waiting
        // for [CHANGE2], kPhaseAuthenticated once the session is registered.
        std::atomic<int> phase{0};
        std::atomic<long long> phaseSinceMs{0};  // steady clock, ms
        std::atomic<bool> evicted{false};          // chosen for eviction / reaping
    };
    static constexpr int kPhasePreAuth = 0;
    static constexpr int kPhaseFirstLogin = 1;
    static constexpr int kPhaseAuthenticated = 2;

    // Failed-proof bookkeeping (bounded, pruned from the heartbeat).
    struct FailureEntry {
        int count = 0;           // failures inside the current window
        time_t windowStart = 0;
        time_t lastFailure = 0;
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
    void ShutdownChannel(const std::shared_ptr<SocketChannel>& channel);
    void SetPhase(const std::shared_ptr<SocketChannel>& channel, int phase);
    // Accept-time admission: false = reject (all slots held by authenticated
    // or first-login connections). May evict the oldest pre-auth connection.
    bool AdmitNewConnection();
    void EnforceConnectionDeadlines();
    // Login-failure throttle (see PROTOCOL_V2.md implementation notes).
    void RecordLoginFailure(const std::string& userKey);
    void ClearLoginFailures(const std::string& userKey);
    int FailureDelayMillis(const std::string& userKey);
    void PruneLoginFailures();
    // Sleeps in small steps; returns early when the server is stopping.
    void ThrottleSleep(int millis);
    void RegisterAuthenticatedSession(const ClientSession& session);
    void Broadcast(const std::string& msg);
    void BroadcastUsers();
    bool SendDirectLineToUser(const std::string& toNick, const std::string& line);
    bool RelayAttachmentChunk(const std::string& fromNick, const std::string& payload);
    bool KickUser(const std::string& nick, const std::string& reason);
    bool DescribeUser(const std::string& nick, ClientSession& session);
    void DisconnectByHwid(const std::string& hwid, const std::string& reason);
    void HandleAdminCommand(SocketHandle clientSocket, const ClientSession& currentClient, const std::string& command);
    void LogEncryptedMessage(const std::string& user, const std::string& encryptedPayload);
    void LogRuntime(const std::string& category, const std::string& message);
    std::string BuildUsersSnapshot();
    // SCRAM proof check plus failure accounting / HWID policy (a valid proof
    // is never refused because of earlier failures). On Ok/FirstLogin,
    // serverSignatureRaw holds the 32-byte ServerSignature for AUTH_OK.
    LoginResult AuthorizeLoginProof(const std::string& username,
                                    const std::string& hwid,
                                    const std::string& authMessage,
                                    const std::string& clientProofRaw,
                                    std::string& serverSignatureRaw);
    // Deterministic fake challenge parameters for unknown users (spec 2).
    std::string FakeSaltHex(const std::string& username) const;
    // Registers the session and sends ACCESO CONCEDIDO, SESSION, history and
    // queued offline PMs (in that order), then the join broadcast + user list.
    void CompleteLogin(SocketHandle clientSocket, const ClientSession& session, bool afterChange);
    // PM2/PMX routing. queueIfOffline=false for PMX.
    void RoutePrivateEnvelope(SocketHandle senderSocket,
                              const std::string& fromNick,
                              const std::string& toNick,
                              const std::string& envelopeB64,
                              bool queueIfOffline);
    void AuditAdminAction(const std::string& admin, const std::string& action, const std::string& detail);

    std::string dbPath_;
    std::string logPath_;
    UserRepository repo_;

    std::map<SocketHandle, ClientSession> clients_;
    // Keyed by lower-cased username; at most kMaxFailureEntries entries.
    std::map<std::string, FailureEntry> loginFailures_;
    // Server-wide failed proofs in the current minute (global throttle).
    int globalFailures_ = 0;
    time_t globalFailureWindowStart_ = 0;
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
    std::mutex deliveryMutex_;
    // Secret for fake salts: loaded from the database (server_settings) at
    // startup so fake salts are stable across restarts, like real ones.
    std::string fakeSaltSecret_;
};
