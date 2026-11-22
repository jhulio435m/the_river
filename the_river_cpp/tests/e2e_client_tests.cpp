// End-to-end test of the real ChatClient (protocol v2, PROTOCOL_V2.md).
//
// Usage: river_e2e_client_tests <path to the_river_server>
//
// The orchestrator runs:
//  - a SOCKS5 shim on an ephemeral port, handed to every client through
//    THE_RIVER_TOR_PROXY_PORT; it forwards each CONNECT to the current target
//    (a fake server in this process or the real server) and records every byte
//    the clients send, so the test can assert what is (not) on the wire;
//  - fake v2 servers (scripted here) for the failure paths a real server never
//    produces: missing PROTO=2 banner, bad AUTH_OK signature, ACCESO CONCEDIDO
//    without AUTH_OK, CLIENTE OBSOLETO, history replay/dedupe;
//  - the real the_river_server binary (fresh temp dir, THE_RIVER_PORT);
//  - client "drivers": this same binary re-executed with --driver in its own
//    temp dir (identity file, known keys, cfg) and THE_RIVER_MACHINE_ID. A
//    driver runs one ChatClient (no GUI) and executes commands read on stdin.
#include <poll.h>

#include <algorithm>
#include <atomic>
#include <climits>
#include <condition_variable>
#include <ctime>
#include <functional>
#include <memory>
#include <mutex>
#include <random>

#include "client/attachment_utils.h"
#include "client/chat_client.h"
#include "client/chat_state.h"
#include "client/command_processor.h"
#include "common/base64.h"
#include "common/net_platform.h"
#include "common/scram.h"
#include "e2e_support.h"

namespace b64 = river::base64;
#define CHECK(cond, what) E2E_CHECK(cond, what)

namespace {

// ---------------------------------------------------------------- driver mode
void DumpLogs(ChatState& st, std::size_t& shown) {
    auto logs = st.SnapshotLogs();
    for (std::size_t i = shown; i < logs.size(); ++i) {
        const auto& e = logs[i];
        std::cout << "LOG|" << e.time << "|" << e.user << "|" << (e.isSystem ? "S" : "") << (e.isPM ? "P" : "")
                  << (e.isHistory ? "H" : "") << (e.isAttachment ? "A" : "") << "|" << e.text;
        if (e.isAttachment) std::cout << "|id=" << e.attachment.id << "|state=" << static_cast<int>(e.attachment.state);
        std::cout << "\n";
    }
    std::cout.flush();
    shown = logs.size();
}

int RunDriver() {
    ChatState st;
    ChatClient client(st);
    client.Start();
    std::size_t shown = 0;
    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream in(line);
        std::string op;
        in >> op;
        std::string rest;
        std::getline(in, rest);
        if (!rest.empty() && rest[0] == ' ') rest.erase(0, 1);
        if (op == "login") {
            std::string u, p;
            std::istringstream r(rest);
            r >> u >> p;
            std::cout << "RET|" << client.SendLogin(u, p) << "\n";
        } else if (op == "change") {
            std::string u, p;
            std::istringstream r(rest);
            r >> u >> p;
            std::cout << "RET|" << client.SendFirstLoginChange(u, p) << "|err=" << st.LastError() << "\n";
        } else if (op == "cmd") {
            ProcessLocalCommand(client, st, st.CurrentIdentity(), rest);
        } else if (op == "offer") {
            AttachmentDraft d;
            std::string err;
            if (!BuildAttachmentDraftFromPath(rest, d, err)) std::cout << "RET|0|" << err << "\n";
            else std::cout << "RET|" << client.SendAttachment(st.CurrentIdentity(), d) << "\n";
        } else if (op == "fetch") {  // fetch <owner> <savepath>: newest offer from owner
            std::string owner, path;
            std::istringstream r(rest);
            r >> owner >> path;
            auto logs = st.SnapshotLogs();
            bool ok = false;
            for (auto it = logs.rbegin(); it != logs.rend(); ++it) {
                if (it->isAttachment && it->user == owner) {
                    ok = client.RequestAttachment(it->attachment, path, "save");
                    break;
                }
            }
            std::cout << "RET|" << ok << "\n";
        } else if (op == "state") {
            std::cout << "STATE|conn=" << static_cast<int>(st.GetConnectionState()) << "|auth=" << st.IsAuthenticated()
                      << "|err=" << st.LastError() << "|newmsg=" << st.ConsumeNewMessageFlag()
                      << "|id=" << st.CurrentIdentity() << "|\n";
        } else if (op == "dump") {
            DumpLogs(st, shown);
        } else if (op == "quit") {
            break;
        }
        std::cout << "OK" << std::endl;
    }
    DumpLogs(st, shown);
    client.Stop();
    return 0;
}

// ---------------------------------------------------------------- orchestrator
std::string g_self;
const std::string kOnion = std::string(56, 'a') + ".onion";

std::atomic<int> g_targetPort{0};
std::mutex g_capMutex;
std::string g_captured;            // client -> server bytes through the shim
std::string g_lastSocksTarget;     // "host:port" of the last CONNECT request
int g_shimPort = 0;

std::string Captured() {
    std::lock_guard<std::mutex> lock(g_capMutex);
    return g_captured;
}
void ClearCaptured() {
    std::lock_guard<std::mutex> lock(g_capMutex);
    g_captured.clear();
}
bool OnWire(const std::string& needle) { return Captured().find(needle) != std::string::npos; }

bool RecvAll(int s, char* p, std::size_t n) {
    while (n > 0) {
        ssize_t r = recv(s, p, n, 0);
        if (r <= 0) return false;
        p += r;
        n -= static_cast<std::size_t>(r);
    }
    return true;
}

void Pipe(int src, int dst, bool capture) {
    char buf[65536];
    while (true) {
        ssize_t r = recv(src, buf, sizeof(buf), 0);
        if (r <= 0) break;
        if (capture) {
            std::lock_guard<std::mutex> lock(g_capMutex);
            g_captured.append(buf, static_cast<std::size_t>(r));
        }
        if (!SendAll(dst, buf, static_cast<std::size_t>(r))) break;
    }
    shutdown(src, SHUT_RDWR);
    shutdown(dst, SHUT_RDWR);
}

void SocksConn(int c) {
    char hello[3];
    char head[4];
    unsigned char len = 0;
    if (!RecvAll(c, hello, 3) || send(c, "\x05\x00", 2, MSG_NOSIGNAL) != 2 || !RecvAll(c, head, 4) ||
        !RecvAll(c, reinterpret_cast<char*>(&len), 1)) {
        close(c);
        return;
    }
    std::string host(len + 2u, '\0');
    if (!RecvAll(c, &host[0], host.size())) {
        close(c);
        return;
    }
    const int port = (static_cast<unsigned char>(host[len]) << 8) | static_cast<unsigned char>(host[len + 1]);
    {
        std::lock_guard<std::mutex> lock(g_capMutex);
        g_lastSocksTarget = host.substr(0, len) + ":" + std::to_string(port);
    }
    int up = e2e::ConnectLocal(g_targetPort.load());
    if (up < 0) {
        send(c, "\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00", 10, MSG_NOSIGNAL);  // connection refused
        close(c);
        return;
    }
    send(c, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10, MSG_NOSIGNAL);
    std::thread t1(Pipe, c, up, true);
    std::thread t2(Pipe, up, c, false);
    t1.join();
    t2.join();
    close(c);
    close(up);
}

void StartShim() {
    int ls = e2e::ListenLocal(0, g_shimPort);
    if (ls < 0) {
        std::cerr << "cannot start SOCKS shim" << std::endl;
        std::exit(2);
    }
    std::thread([ls] {
        while (true) {
            int c = accept4(ls, nullptr, nullptr, SOCK_CLOEXEC);
            if (c < 0) continue;
            std::thread(SocksConn, c).detach();
        }
    }).detach();
}

// ---- frames on the fake-server side
void SendText(int s, const std::string& line) { SendFrame(s, kFrameTypeText, line); }

// Next text line, "" on timeout, "<EOF>" when the peer closed.
std::string RecvText(int s, int timeoutMs) {
    pollfd p{s, POLLIN, 0};
    if (poll(&p, 1, timeoutMs) <= 0) return "";
    std::uint16_t type = 0;
    std::string payload;
    if (!RecvFrame(s, type, payload, 1 << 20)) return "<EOF>";
    if (!payload.empty() && payload.back() == '\n') payload.pop_back();
    return payload;
}

class FakeListener {
public:
    FakeListener() {
        fd_ = e2e::ListenLocal(0, port_);
        g_targetPort.store(port_);
    }
    ~FakeListener() {
        if (fd_ >= 0) close(fd_);
    }
    // Accepted socket or -1 after timeoutMs.
    int Accept(int timeoutMs = 15000) {
        pollfd p{fd_, POLLIN, 0};
        if (poll(&p, 1, timeoutMs) <= 0) return -1;
        int c = accept4(fd_, nullptr, nullptr, SOCK_CLOEXEC);
        if (c >= 0) {
            timeval tv{5, 0};  // a frame that started arriving completes quickly
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        }
        return c;
    }

private:
    int fd_ = -1;
    int port_ = 0;
};

void CloseFd(int& fd) {
    if (fd >= 0) {
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
    fd = -1;
}

std::vector<std::string> Split(const std::string& s, char sep = ':') {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (true) {
        std::size_t p = s.find(sep, start);
        if (p == std::string::npos) {
            out.push_back(s.substr(start));
            return out;
        }
        out.push_back(s.substr(start, p - start));
        start = p + 1;
    }
}

bool StartsWith(const std::string& s, const std::string& p) { return s.rfind(p, 0) == 0; }
bool EndsWith(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}
bool Contains(const std::string& s, const std::string& p) { return s.find(p) != std::string::npos; }

std::string Hwid(int n) {
    char b[3];
    std::snprintf(b, sizeof(b), "%02x", n);
    std::string out;
    for (int i = 0; i < 32; ++i) out += b;
    return out;
}

void SleepMs(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

// ---- client driver process
class Driver {
public:
    Driver(const std::string& name, const std::string& hwid, const std::string& dir = "")
        : name_(name), dir_(dir.empty() ? e2e::MakeTempDir("river_e2e_drv_" + name + "_") : dir) {
        e2e::ChildOptions opt;
        opt.argv = {g_self, "--driver"};
        opt.cwd = dir_;
        opt.pipeStdin = true;
        opt.pipeStdout = true;
        opt.unsetEnv = {"THE_RIVER_AES_KEY", "THE_RIVER_CLIENT_LOG", "THE_RIVER_MACHINE_ID_FILE"};
        opt.setEnv = {{"THE_RIVER_ONION", kOnion},
                      {"THE_RIVER_MACHINE_ID", hwid},
                      {"THE_RIVER_TOR_PROXY_PORT", std::to_string(g_shimPort)}};
        child_ = e2e::Spawn(opt);
        reader_ = std::thread([this] { ReadLoop(); });
    }
    ~Driver() { Quit(); }

    const std::string& Dir() const { return dir_; }

    void Cmd(const std::string& c) {
        if (child_.stdinFd < 0) return;
        const std::string line = c + "\n";
        if (write(child_.stdinFd, line.data(), line.size()) < 0) {
            // driver gone; checks will fail on their own
        }
    }

    std::vector<std::string> Logs() {
        std::lock_guard<std::mutex> lock(m_);
        std::vector<std::string> out;
        for (const auto& l : lines_)
            if (StartsWith(l, "LOG|")) out.push_back(l);
        return out;
    }
    int CountLogs(const std::function<bool(const std::string&)>& pred) {
        int n = 0;
        for (const auto& l : Logs())
            if (pred(l)) ++n;
        return n;
    }
    bool AnyLog(const std::function<bool(const std::string&)>& pred) { return CountLogs(pred) > 0; }

    // Polls (dump + state) until a LOG line matches; LOG lines are printed once
    // each, so every log line seen so far is considered.
    bool WaitLog(const std::function<bool(const std::string&)>& pred, int timeoutMs = 10000) {
        return WaitLine("LOG|", pred, timeoutMs, 0);
    }
    bool WaitText(const std::string& text, int timeoutMs = 10000) {
        return WaitLog([&](const std::string& l) { return Contains(l, text); }, timeoutMs);
    }
    // Waits for a STATE line (only those produced after this call) matching.
    bool WaitState(const std::function<bool(const std::string&)>& pred, int timeoutMs = 15000) {
        std::size_t from;
        {
            std::lock_guard<std::mutex> lock(m_);
            from = lines_.size();
        }
        return WaitLine("STATE|", pred, timeoutMs, from);
    }
    bool WaitAuth(int timeoutMs = 15000) {
        return WaitState([](const std::string& l) { return Contains(l, "|auth=1|"); }, timeoutMs);
    }
    // Sends a command and returns the first "RET|" line it produced.
    std::string CmdRet(const std::string& c, int timeoutMs = 5000) {
        std::size_t from;
        {
            std::lock_guard<std::mutex> lock(m_);
            from = lines_.size();
        }
        Cmd(c);
        std::unique_lock<std::mutex> lock(m_);
        cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), [&] { return FindFrom("RET|", from) >= 0; });
        const int idx = FindFrom("RET|", from);
        return idx < 0 ? std::string() : lines_[static_cast<std::size_t>(idx)];
    }
    // Single state query (does not poll dump).
    std::string State() {
        std::size_t from;
        {
            std::lock_guard<std::mutex> lock(m_);
            from = lines_.size();
        }
        Cmd("state");
        std::unique_lock<std::mutex> lock(m_);
        cv_.wait_for(lock, std::chrono::seconds(3), [&] { return FindFrom("STATE|", from) >= 0; });
        int idx = FindFrom("STATE|", from);
        return idx < 0 ? std::string() : lines_[static_cast<std::size_t>(idx)];
    }
    std::string LastLogs(std::size_t n) {
        auto logs = Logs();
        std::string out;
        for (std::size_t i = logs.size() > n ? logs.size() - n : 0; i < logs.size(); ++i) out += logs[i] + "\n";
        return out;
    }

    void Quit() {
        if (child_.pid <= 0) return;
        Cmd("quit");
        close(child_.stdinFd);
        child_.stdinFd = -1;
        int status = 0;
        if (!e2e::WaitChild(child_.pid, 10000, status)) {
            std::cerr << "driver " << name_ << " did not exit; killing" << std::endl;
            kill(child_.pid, SIGKILL);
            waitpid(child_.pid, &status, 0);
        }
        child_.pid = -1;
        if (reader_.joinable()) reader_.join();
        close(child_.stdoutFd);
        child_.stdoutFd = -1;
    }

private:
    void ReadLoop() {
        std::string pending;
        char buf[4096];
        while (true) {
            ssize_t r = read(child_.stdoutFd, buf, sizeof(buf));
            if (r <= 0) break;
            pending.append(buf, static_cast<std::size_t>(r));
            std::size_t nl;
            std::lock_guard<std::mutex> lock(m_);
            while ((nl = pending.find('\n')) != std::string::npos) {
                lines_.push_back(pending.substr(0, nl));
                pending.erase(0, nl + 1);
            }
            cv_.notify_all();
        }
    }
    int FindFrom(const std::string& prefix, std::size_t from) const {
        for (std::size_t i = from; i < lines_.size(); ++i)
            if (StartsWith(lines_[i], prefix)) return static_cast<int>(i);
        return -1;
    }
    bool WaitLine(const std::string& prefix, const std::function<bool(const std::string&)>& pred, int timeoutMs,
                  std::size_t from) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
        while (true) {
            {
                std::lock_guard<std::mutex> lock(m_);
                for (std::size_t i = from; i < lines_.size(); ++i)
                    if (StartsWith(lines_[i], prefix) && pred(lines_[i])) return true;
            }
            if (std::chrono::steady_clock::now() >= deadline) return false;
            Cmd("dump");
            Cmd("state");
            SleepMs(100);
        }
    }

    std::string name_;
    std::string dir_;
    e2e::Child child_;
    std::thread reader_;
    std::mutex m_;
    std::condition_variable cv_;
    std::vector<std::string> lines_;
};

// ---- SCRAM on the fake-server side
// Banner, AUTH_START, challenge, AUTH_PROOF verification. Returns the auth message.
std::string FakeHandshake(int c, const river::scram::Credential& cred, const std::string& user, const std::string& tag) {
    SendText(c, "SYSTEM: UPLINK ESTABLISHED. PROTO=2");
    const std::string start = RecvText(c, 10000);
    auto parts = Split(start);
    CHECK(parts.size() == 5 && parts[0] == "[AUTH_START]" && parts[1] == "2" && parts[2] == user &&
              parts[4].size() == 32,
          tag + " AUTH_START format [AUTH_START]:2:user:hwid:nonce32 (" + start + ")");
    if (parts.size() != 5) return "";
    const std::string cn = parts[4];
    const std::string combined = cn + river::scram::RandomNonceHex(16);
    SendText(c, "AUTH_CHALLENGE2:" + combined + ":" + cred.saltHex + ":" + std::to_string(cred.iterations));
    const std::string proofLine = RecvText(c, 10000);
    auto p = Split(proofLine);
    const std::string am =
        river::scram::BuildAuthMessage(user, parts[3], cn, combined, cred.saltHex, cred.iterations);
    std::string proof;
    const bool ok = p.size() == 5 && p[0] == "[AUTH_PROOF]" && p[1] == user && p[3] == combined &&
                    b64::DecodeToString(p[4], proof) && river::scram::VerifyClientProof(cred, am, proof);
    CHECK(ok, tag + " AUTH_PROOF verifies against the server-side SCRAM check");
    return am;
}

std::string ServerSigB64(const river::scram::Credential& cred, const std::string& am) {
    return b64::EncodeString(river::scram::ServerSignature(cred, am));
}

// ---------------------------------------------------------------- fake server scenarios
void RunFakeTests() {
    river::scram::Credential cred;
    river::scram::MakeCredential("CorrectHorse123", cred);

    {  // F1: banner without PROTO=2
        FakeListener fake;
        Driver d("f1", Hwid(1));
        int c = fake.Accept();
        CHECK(c >= 0, "F1 client connects through the SOCKS5 proxy");
        {
            std::lock_guard<std::mutex> lock(g_capMutex);
            CHECK(g_lastSocksTarget == kOnion + ":80", "F1 SOCKS5 CONNECT targets <onion>:80 (" + g_lastSocksTarget + ")");
        }
        SendText(c, "SYSTEM: UPLINK ESTABLISHED.");
        SleepMs(400);
        d.Cmd("login alice CorrectHorse123");
        const std::string l = RecvText(c, 1500);
        CHECK(l.empty(), "F1 no AUTH_START to a server without PROTO=2 (" + l + ")");
        const std::string st = d.State();
        CHECK(Contains(st, "Servidor incompatible (se requiere protocolo 2)."), "F1 incompatible-server error: " + st);
        d.Quit();
        CloseFd(c);
    }
    {  // F2: bad server signature
        FakeListener fake;
        Driver d("f2", Hwid(2));
        int c = fake.Accept();
        d.Cmd("login alice CorrectHorse123");
        FakeHandshake(c, cred, "alice", "F2");
        SendText(c, "AUTH_OK:" + b64::EncodeString(river::scram::RandomNonceHex(16)));  // 32 wrong bytes
        SendText(c, "SYSTEM: ACCESO CONCEDIDO.");
        SendText(c, "SESSION:1");
        std::string l = RecvText(c, 5000);
        CHECK(l == "<EOF>", "F2 bad AUTH_OK signature -> client closes socket, no KEY_SET (" + l + ")");
        // The error is also logged; the status line itself is cleared as soon as
        // the client re-opens its Tor link, so check the (persistent) log.
        const std::string st = d.State();
        CHECK(Contains(st, "|auth=0|") && d.WaitText("SYSTEM: Firma del servidor invalida", 3000),
              "F2 not authenticated + 'Firma del servidor invalida' logged: " + st);
        int c2 = fake.Accept();
        if (c2 >= 0) SendText(c2, "SYSTEM: UPLINK ESTABLISHED. PROTO=2");
        l = c2 >= 0 ? RecvText(c2, 2000) : "";
        CHECK(l.empty(), "F2 no automatic re-login after fatal auth error (" + l + ")");
        d.Quit();
        CloseFd(c);
        CloseFd(c2);
    }
    {  // F3: ACCESO CONCEDIDO without AUTH_OK
        FakeListener fake;
        Driver d("f3", Hwid(3));
        int c = fake.Accept();
        d.Cmd("login alice CorrectHorse123");
        FakeHandshake(c, cred, "alice", "F3");
        SendText(c, "SYSTEM: ACCESO CONCEDIDO.");
        const std::string l = RecvText(c, 5000);
        CHECK(l == "<EOF>", "F3 ACCESO CONCEDIDO without verified AUTH_OK rejected (" + l + ")");
        CHECK(Contains(d.State(), "|auth=0|"), "F3 not authenticated");
        d.Quit();
        CloseFd(c);
    }
    {  // F4: good signature, interleaved broadcasts, KEY_SET, /fingerprint
        FakeListener fake;
        Driver d("f4", Hwid(4));
        int c = fake.Accept();
        d.Cmd("login alice CorrectHorse123");
        const std::string am = FakeHandshake(c, cred, "alice", "F4");
        SendText(c, "AUTH_OK:" + ServerSigB64(cred, am));
        SendText(c, "KEY_CHANGED:zed");
        SendText(c, "SYSTEM: ACCESO CONCEDIDO.");
        SendText(c, "SESSION:abc");
        std::string l;
        for (int i = 0; i < 5; ++i) {  // tolerate a [KEY_GET] or similar before KEY_SET
            l = RecvText(c, 10000);
            if (l.empty() || l == "<EOF>" || StartsWith(l, "[KEY_SET]:")) break;
        }
        std::string key;
        const bool keyOk = StartsWith(l, "[KEY_SET]:") && b64::DecodeToString(l.substr(10), key) && key.size() == 32;
        CHECK(keyOk && d.WaitAuth(5000), "F4 verified AUTH_OK -> authenticated and [KEY_SET]:<b64 32 bytes> (" + l + ")");
        SendText(c, "HISTORY_BEGIN:0");
        SendText(c, "HISTORY_END");
        SendText(c, "KEY_CHANGED:alice");
        d.Cmd("cmd /fingerprint");
        CHECK(d.WaitText("Tu huella: ", 5000), "F4 /fingerprint (own)");
        CHECK(!d.AnyLog([](const std::string& x) { return Contains(x, "La clave de alice"); }),
              "F4 own KEY_CHANGED produces no warning");
        CHECK(e2e::FileExists(d.Dir() + "/river_identity_alice.key"), "F4 identity file river_identity_alice.key created");
        d.Quit();
        CloseFd(c);
    }
    {  // F5: CLIENTE OBSOLETO -> stop auto-login
        FakeListener fake;
        Driver d("f5", Hwid(5));
        int c = fake.Accept();
        d.Cmd("login alice CorrectHorse123");
        SendText(c, "SYSTEM: UPLINK ESTABLISHED. PROTO=2");
        RecvText(c, 5000);
        SendText(c, "SYSTEM: CLIENTE OBSOLETO. Actualiza al protocolo 2.");
        std::string l = RecvText(c, 5000);
        CHECK(l == "<EOF>", "F5 CLIENTE OBSOLETO -> client closes (" + l + ")");
        int c2 = fake.Accept();
        if (c2 >= 0) SendText(c2, "SYSTEM: UPLINK ESTABLISHED. PROTO=2");
        l = c2 >= 0 ? RecvText(c2, 2000) : "";
        CHECK(l.empty(), "F5 no auto re-login after CLIENTE OBSOLETO (" + l + ")");
        d.Quit();
        CloseFd(c);
        CloseFd(c2);
    }
}

// History replay: no new-message flag for history, dedupe after a transparent re-login.
void RunFakeHistoryTest() {
    river::scram::Credential cred;
    river::scram::MakeCredential("CorrectHorse123", cred);
    FakeListener fake;
    Driver d("hist", Hwid(6));
    const long long now = static_cast<long long>(std::time(nullptr));
    std::vector<std::string> hist = {
        "HIST:bob:" + std::to_string(now - 120) + ":" + b64::EncodeString("old one"),
        "HIST:carol:" + std::to_string(now - 60) + ":" + b64::EncodeString("old two"),
    };
    for (int round = 0; round < 2; ++round) {
        int c = fake.Accept();
        CHECK(c >= 0, "H round " + std::to_string(round) + " connection");
        if (c < 0) return;
        if (round == 0) d.Cmd("login alice CorrectHorse123");
        const std::string am = FakeHandshake(c, cred, "alice", "H" + std::to_string(round));
        SendText(c, "AUTH_OK:" + ServerSigB64(cred, am));
        SendText(c, "SYSTEM: ACCESO CONCEDIDO.");
        SendText(c, "SESSION:x");
        RecvText(c, 10000);  // [KEY_SET]
        SendText(c, "HISTORY_BEGIN:" + std::to_string(hist.size()));
        for (const auto& h : hist) SendText(c, h);
        SendText(c, "HISTORY_END");
        SleepMs(600);
        if (round == 0) {
            const std::string st = d.State();
            CHECK(Contains(st, "|newmsg=0|"), "H history does not raise new-message flag: " + st);
            SendText(c, "MSG:bob:" + std::to_string(now) + ":" + b64::EncodeString("live msg"));
            SleepMs(400);
            const std::string st2 = d.State();
            CHECK(Contains(st2, "|newmsg=1|"), "H live MSG raises new-message flag: " + st2);
            hist.push_back("HIST:bob:" + std::to_string(now) + ":" + b64::EncodeString("live msg"));
            CloseFd(c);  // drop the link -> transparent re-login
        } else {
            d.WaitText("live msg", 2000);
            SleepMs(200);
            d.Cmd("dump");
            SleepMs(200);
            const int oldOne = d.CountLogs([](const std::string& l) { return EndsWith(l, "old one"); });
            const int live = d.CountLogs([](const std::string& l) { return EndsWith(l, "live msg"); });
            CHECK(oldOne == 1 && live == 1, "H no duplicates after reconnect re-login:\n" + d.LastLogs(10));
            char t[16];
            const std::time_t then = static_cast<std::time_t>(now - 120);
            std::strftime(t, sizeof(t), "%H:%M", std::localtime(&then));
            const std::string want = std::string("LOG|") + t + "|bob|H|old one";
            CHECK(d.AnyLog([&](const std::string& l) { return StartsWith(l, want); }),
                  "H history timestamp from unix ts and H flag");
            CloseFd(c);
        }
    }
    d.Quit();
}

// ---------------------------------------------------------------- real server scenarios
void RunRealScenario() {
    Driver adm("admin", Hwid(10));
    adm.Cmd("login admin AdminPassword123");
    CHECK(adm.WaitAuth(20000), "R admin login via SCRAM against real server");
    adm.Cmd("cmd /newuser");
    adm.Cmd("cmd /newuser");
    std::vector<std::string> names;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (names.size() < 2 && std::chrono::steady_clock::now() < deadline) {
        adm.Cmd("dump");
        SleepMs(150);
        names.clear();
        for (const auto& l : adm.Logs()) {
            const std::size_t p = l.find("NUEVO USUARIO: ");
            if (p == std::string::npos) continue;
            std::string n = l.substr(p + 15);
            n = n.substr(0, n.find(' '));
            names.push_back(n);
        }
    }
    CHECK(names.size() == 2, "R admin /newuser via [MSG] (two users)\n" + adm.LastLogs(5));
    if (names.size() < 2) return;
    const std::string u1 = names[0];
    const std::string u2 = names[1];

    ClearCaptured();
    auto a = std::make_unique<Driver>("alice", Hwid(11));
    a->Cmd("login " + u1 + " InitialPass12345");
    CHECK(a->WaitState([](const std::string& l) { return Contains(l, "|conn=4|"); }, 20000),
          "R first login -> FIRST_LOGIN_REQUIRED");
    const std::string weak = a->CmdRet("change alice weak");
    CHECK(StartsWith(weak, "RET|0|err=Clave demasiado debil"), "R weak password rejected locally (" + weak + ")");
    a->Cmd("change alice AlicePassword123");
    CHECK(a->WaitState([](const std::string& l) { return Contains(l, "|auth=1|") && Contains(l, "|id=alice|"); },
                       30000),
          "R CHANGE2 accepted -> authenticated as alice");
    SleepMs(300);
    CHECK(!OnWire("AlicePassword123"), "R new password never on the wire");
    CHECK(!OnWire("InitialPass12345"), "R initial password never on the wire");
    CHECK(OnWire("[CHANGE2]:alice:"), "R [CHANGE2]: line on the wire");
    CHECK(OnWire("[KEY_SET]:"), "R [KEY_SET]: on the wire");
    CHECK(e2e::FileExists(a->Dir() + "/river_identity_alice.key"), "R identity file river_identity_alice.key created");

    auto b = std::make_unique<Driver>("bob", Hwid(12));
    b->Cmd("login " + u2 + " InitialPass12345");
    b->WaitState([](const std::string& l) { return Contains(l, "|conn=4|"); }, 20000);
    b->Cmd("change bob BobPassword12345");
    CHECK(b->WaitState([](const std::string& l) { return Contains(l, "|auth=1|") && Contains(l, "|id=bob|"); }, 30000),
          "R bob authenticated");
    SleepMs(500);

    // Room message: delivered, echoed to the sender exactly once.
    a->Cmd("cmd hello room from alice");
    CHECK(b->WaitText("|alice||hello room from alice"), "R bob receives MSG from alice");
    CHECK(a->WaitText("|alice||hello room from alice", 5000) &&
              a->CountLogs([](const std::string& l) { return EndsWith(l, "|alice||hello room from alice"); }) == 1,
          "R alice sees own echo exactly once");

    // E2E PMs both ways (peer keys fetched on demand).
    b->Cmd("cmd /msg alice secret one");
    CHECK(a->WaitText("|bob|P|[PM] secret one"), "R alice gets E2E PM2 from bob");
    a->Cmd("cmd /r reply two");
    CHECK(b->WaitText("|alice|P|[PM] reply two"), "R bob gets /r reply");
    CHECK(!OnWire("secret one") && !OnWire("reply two"), "R PM plaintext not on the wire");
    CHECK(OnWire("[PM2]:alice:") && OnWire("[PM2]:bob:"), "R PMs travel as [PM2] envelopes");
    CHECK(Contains(e2e::ReadFile(b->Dir() + "/river_known_keys.txt"), "alice "), "R known_keys pinned on bob side");
    b->Cmd("cmd /fingerprint alice");
    CHECK(b->WaitText("Huella de alice: ", 5000), "R /fingerprint alice");
    b->Cmd("cmd /msg nobody123 hi");
    CHECK(b->WaitText("nobody123 aun no tiene clave publica.", 8000), "R PM to unknown user -> no public key");

    // Attachment: alice offers, bob fetches over PMX + E2E chunks.
    const std::string src = a->Dir() + "/blob.bin";
    {
        std::mt19937 rng(12345);
        std::string blob(100000, '\0');
        for (auto& ch : blob) ch = static_cast<char>(rng() & 0xff);
        e2e::WriteFile(src, blob);
    }
    a->Cmd("offer " + src);
    CHECK(b->WaitText("|alice|A|"), "R bob sees ATTACH2 offer");
    const std::string save = b->Dir() + "/got.bin";
    b->Cmd("fetch alice " + save);
    const bool received = b->WaitText("Attachment received and saved", 20000);
    CHECK(received && e2e::FileExists(save) && e2e::ReadFile(save) == e2e::ReadFile(src),
          "R attachment received byte-identical (PMX + E2E chunks)");
    CHECK(!OnWire(e2e::ReadFile(src).substr(5000, 64)), "R attachment bytes not on the wire in clear");
    CHECK(a->WaitText("|alice|A|", 5000) &&
              a->CountLogs([](const std::string& l) { return Contains(l, "|alice|A|"); }) == 1,
          "R alice sees own ATTACH2 echo once");

    // Offline PM + history on re-login (alice restarts in her own dir).
    const std::string aliceDir = a->Dir();
    a->Quit();
    a.reset();
    b->WaitText("alice salió", 5000);  // server noticed the disconnect
    b->Cmd("cmd /msg alice offline three");
    CHECK(b->WaitText("Mensaje privado en cola para alice", 8000), "R offline PM queued by server");
    b->Cmd("cmd room while away");
    CHECK(b->WaitText("|bob||room while away", 5000), "R room message while alice is away");
    a = std::make_unique<Driver>("alice", Hwid(11), aliceDir);
    a->Cmd("login alice AlicePassword123");
    CHECK(a->WaitAuth(20000), "R alice relogin");
    CHECK(a->WaitText("|bob|P|[PM] offline three"), "R offline PM delivered after login");
    CHECK(a->WaitText("|alice|H|hello room from alice", 5000) && a->WaitText("|bob|H|room while away", 5000),
          "R history replayed with H flag");
    CHECK(!a->AnyLog([](const std::string& l) { return Contains(l, "La clave de bob"); }),
          "R no key-change warning for bob (same key)");

    // Key change: bob loses his identity file -> new key -> alice warned (TOFU).
    const std::string bobDir = b->Dir();
    b->Quit();
    b.reset();
    std::remove((bobDir + "/river_identity_bob.key").c_str());
    b = std::make_unique<Driver>("bob", Hwid(12), bobDir);
    b->Cmd("login bob BobPassword12345");
    CHECK(b->WaitAuth(20000) && b->WaitText("Clave de identidad generada", 5000),
          "R bob relogin with new identity key");
    SleepMs(500);
    a->Cmd("cmd /msg bob after change");
    CHECK(a->WaitLog([](const std::string& l) {
              return Contains(l, "[!] La clave de bob cambio (huella ") && Contains(l, "Verificala por otro canal.");
          }),
          "R alice warned: '[!] La clave de bob cambio (huella ...). Verificala por otro canal.'");
    CHECK(b->WaitText("|alice|P|[PM] after change"), "R bob reads PM sealed to new key");

    const std::string keepA = a->Dir();
    a->Quit();
    b->Quit();
    adm.Quit();
    if (e2e::g_failures == 0) {
        e2e::RemoveTree(keepA);
        e2e::RemoveTree(bobDir);
        e2e::RemoveTree(adm.Dir());
    }
}

void RunRealTests(const std::string& serverBin) {
    const std::string dir = e2e::MakeTempDir("river_e2e_client_srv_");
    const int port = e2e::FreePort();
    e2e::ChildOptions opt;
    opt.argv = {e2e::AbsolutePath(serverBin)};
    opt.cwd = dir;
    opt.stdoutFile = dir + "/server.out";
    opt.unsetEnv = {"THE_RIVER_ADMIN_USER", "THE_RIVER_ONION", "THE_RIVER_MACHINE_ID"};
    opt.setEnv = {
        {"THE_RIVER_AES_KEY", std::string(48, 'k')},
        {"THE_RIVER_ADMIN_BOOTSTRAP_PASSWORD", "AdminPassword123"},
        {"THE_RIVER_NEW_USER_PASSWORD", "InitialPass12345"},
        {"THE_RIVER_DB", dir + "/db.sqlite"},
        {"THE_RIVER_LOG", dir + "/log.txt"},
        {"THE_RIVER_BIND_ADDR", "127.0.0.1"},
        {"THE_RIVER_PORT", std::to_string(port)},
    };
    e2e::Child server = e2e::Spawn(opt);
    const bool up = e2e::WaitForPort(port, 15000, server.pid);
    CHECK(up, "R real server listens");
    g_targetPort.store(port);
    if (up) RunRealScenario();
    const int rc = e2e::TerminateChild(server.pid, 10000);
    CHECK(rc == 0, "R server exits 0 on SIGTERM (got " + std::to_string(rc) + ")");
    if (e2e::g_failures != 0) {
        std::cerr << "--- server output tail (" << dir << "/server.out):\n"
                  << e2e::TailLines(e2e::ReadFile(dir + "/server.out"), 30) << std::endl;
    } else {
        e2e::RemoveTree(dir);
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc >= 2 && std::string(argv[1]) == "--driver") return RunDriver();
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <the_river_server binary> [fake|hist|real ...]" << std::endl;
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    char self[PATH_MAX] = {0};
    const ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n <= 0) return 2;
    g_self.assign(self, static_cast<std::size_t>(n));

    std::vector<std::string> which(argv + 2, argv + argc);
    auto wants = [&](const std::string& w) {
        return which.empty() || std::find(which.begin(), which.end(), w) != which.end();
    };
    StartShim();
    const auto t0 = std::chrono::steady_clock::now();
    if (wants("fake")) RunFakeTests();
    if (wants("hist")) RunFakeHistoryTest();
    if (wants("real")) RunRealTests(argv[1]);
    const auto secs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
    std::cout << "elapsed " << secs.count() << " ms" << std::endl;
    std::cout.flush();
    // Detached shim threads may still be blocked in recv(): skip static destructors.
    std::_Exit(e2e::Summary());
}
