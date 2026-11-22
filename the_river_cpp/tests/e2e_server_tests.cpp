// Tests rely on assert() side effects; keep them active in every build type.
#undef NDEBUG
// End-to-end test of the real server binary (protocol v2, PROTOCOL_V2.md).
//
// Usage: river_e2e_server_tests <path to the_river_server>
// Starts the server in a fresh temp dir on a free port (THE_RIVER_PORT), drives
// it over plain TCP as several clients (admin, alice, bob, ...), then stops it
// with SIGTERM and checks it exits 0.
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>

#include "common/base64.h"
#include "common/e2e_crypto.h"
#include "common/net_platform.h"
#include "common/scram.h"
#include "e2e_support.h"

namespace b64 = river::base64;
#define CHECK(cond, what) E2E_CHECK(cond, what)

static int g_port = 0;

struct Frame { std::uint16_t type; std::string payload; };

class Conn {
public:
    std::string name;
    explicit Conn(std::string n) : name(std::move(n)) {}
    ~Conn() { Close(); }
    bool Connect() {
        for (int attempt = 0; attempt < 50; ++attempt) {
            sock_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_port = htons(static_cast<uint16_t>(g_port));
            inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
            if (connect(sock_, (sockaddr*)&a, sizeof(a)) == 0) {
                connectedAt_ = std::chrono::steady_clock::now();
                reader_ = std::thread([this] { ReadLoop(); });
                return true;
            }
            close(sock_);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        return false;
    }
    void Close() {
        if (sock_ >= 0) { shutdown(sock_, SHUT_RDWR); }
        if (reader_.joinable()) reader_.join();
        if (sock_ >= 0) { close(sock_); sock_ = -1; }
    }
    bool Send(const std::string& line) { return SendFrame(sock_, kFrameTypeText, line); }
    bool SendBin(const std::string& p) { return SendFrame(sock_, kFrameTypeAttachmentChunk, p); }
    // Waits for the first text line starting with prefix; removes it and returns it.
    bool Wait(const std::string& prefix, std::string& out, int ms = 4000, std::uint16_t type = kFrameTypeText) {
        std::unique_lock<std::mutex> lk(m_);
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (true) {
            for (auto it = q_.begin(); it != q_.end(); ++it) {
                if (it->type == type && it->payload.rfind(prefix, 0) == 0) {
                    out = it->payload;
                    q_.erase(it);
                    return true;
                }
            }
            if (cv_.wait_until(lk, deadline) == std::cv_status::timeout) return false;
        }
    }
    bool Wait(const std::string& prefix, int ms = 4000) { std::string s; return Wait(prefix, s, ms); }
    // Returns all text lines received so far (consumes them).
    std::vector<std::string> Drain(int settleMs = 300) {
        std::this_thread::sleep_for(std::chrono::milliseconds(settleMs));
        std::lock_guard<std::mutex> lk(m_);
        std::vector<std::string> out;
        for (auto& f : q_)
            if (f.type == kFrameTypeText && f.payload.rfind("SYSTEM: UPLINK", 0) != 0) out.push_back(f.payload);
        q_.clear();
        return out;
    }
    bool Closed(int ms = 3000) {
        std::unique_lock<std::mutex> lk(m_);
        return cv_.wait_for(lk, std::chrono::milliseconds(ms), [&] { return eof_; });
    }
    bool IsClosed() {
        std::lock_guard<std::mutex> lk(m_);
        return eof_;
    }
    // Milliseconds between Connect() and the server closing the stream.
    long long ClosedAfterMs() {
        std::lock_guard<std::mutex> lk(m_);
        return std::chrono::duration_cast<std::chrono::milliseconds>(eofAt_ - connectedAt_).count();
    }
    // Answer server PINGs automatically (default) or record them.
    void SetAutoPong(bool on) { autoPong_ = on; }

private:
    void ReadLoop() {
        while (true) {
            std::uint16_t t; std::string p;
            if (!RecvFrame(sock_, t, p, 2 * 1024 * 1024)) break;
            std::lock_guard<std::mutex> lk(m_);
            if (autoPong_ && t == kFrameTypeText && p == "PING") { SendFrame(sock_, kFrameTypeText, "PONG"); continue; }
            q_.push_back({t, p});
            cv_.notify_all();
        }
        std::lock_guard<std::mutex> lk(m_);
        eof_ = true;
        eofAt_ = std::chrono::steady_clock::now();
        cv_.notify_all();
    }
    int sock_ = -1;
    std::thread reader_;
    std::mutex m_;
    std::condition_variable cv_;
    std::deque<Frame> q_;
    bool eof_ = false;
    bool autoPong_ = true;
    std::chrono::steady_clock::time_point connectedAt_{}, eofAt_{};
};

std::vector<std::string> Split(const std::string& s) {
    std::vector<std::string> f; size_t st = 0;
    while (true) { size_t p = s.find(':', st); if (p == std::string::npos) { f.push_back(s.substr(st)); return f; } f.push_back(s.substr(st, p - st)); st = p + 1; }
}

// Returns "OK", "FIRST", or the failure line.
std::string Login(Conn& c, const std::string& user, const std::string& pass, const std::string& hwid,
                  bool* sigOk = nullptr, std::string* challengeOut = nullptr) {
    const std::string cn = river::scram::RandomNonceHex(16);
    c.Send("[AUTH_START]:2:" + user + ":" + hwid + ":" + cn);
    std::string line;
    if (!c.Wait("AUTH_CHALLENGE2:", line)) return "NO_CHALLENGE";
    if (challengeOut) *challengeOut = line;
    auto f = Split(line);
    if (f.size() != 4) return "BAD_CHALLENGE";
    const std::string combined = f[1], salt = f[2];
    const int iter = std::stoi(f[3]);
    if (combined.rfind(cn, 0) != 0 || combined.size() != 64) return "BAD_NONCE";
    const std::string am = river::scram::BuildAuthMessage(user, hwid, cn, combined, salt, iter);
    std::string proof, expSig;
    if (!river::scram::ComputeClientProof(pass, salt, iter, am, proof, expSig)) return "PROOF_FAIL";
    c.Send("[AUTH_PROOF]:" + user + ":" + hwid + ":" + combined + ":" + b64::EncodeString(proof));
    // Either AUTH_OK or a SYSTEM failure.
    for (int i = 0; i < 40; ++i) {
        std::string l;
        if (c.Wait("AUTH_OK:", l, 100)) {
            std::string sig;
            bool ok = b64::DecodeToString(l.substr(8), sig) && river::scram::VerifyServerSignature(expSig, sig);
            if (sigOk) *sigOk = ok;
            std::string next;
            for (int j = 0; j < 40; ++j) {
                if (c.Wait("SYSTEM: ACCESO CONCEDIDO.", 100)) return "OK";
                if (c.Wait("SYSTEM: FIRST LOGIN. CHANGE REQUIRED.", 100)) return "FIRST";
            }
            return "AUTH_OK_ONLY";
        }
        for (const char* fail : {"SYSTEM: CREDENCIALES INCORRECTAS.", "SYSTEM: ACCESO BLOQUEADO.", "SYSTEM: HWID NO RECONOCIDO."})
            if (c.Wait(fail, 1)) return fail;
    }
    return "TIMEOUT";
}

std::string Change2(Conn& c, const std::string& newUser, const std::string& pass) {
    river::scram::Credential cr;
    river::scram::MakeCredential(pass, cr);
    c.Send("[CHANGE2]:" + newUser + ":" + cr.saltHex + ":" + std::to_string(cr.iterations) + ":" + cr.storedKeyHex + ":" + cr.serverKeyHex);
    if (c.Wait("SYSTEM: ACTUALIZADO.", 5000)) return "OK";
    return "FAIL";
}

// [CHANGE2] whose iteration field is replaced by `iterText`.
std::string Change2Iter(Conn& c, const std::string& newUser, const std::string& pass, const std::string& iterText) {
    river::scram::Credential cr;
    river::scram::MakeCredential(pass, cr);
    c.Send("[CHANGE2]:" + newUser + ":" + cr.saltHex + ":" + iterText + ":" + cr.storedKeyHex + ":" + cr.serverKeyHex);
    std::string line;
    for (int i = 0; i < 50; ++i) {
        if (c.Wait("SYSTEM: ACTUALIZADO.", 100)) return "OK";
        if (c.Wait("SYSTEM: ERROR ACTUALIZANDO USUARIO.", 1)) return "ERROR";
    }
    return "TIMEOUT";
}

// "SYSTEM: NUEVO USUARIO: userN / clave inicial: <pw> (...)" -> name, password.
bool NewUser(Conn& admin, std::string& name, std::string& password) {
    admin.Send("[MSG]:" + b64::EncodeString("/newuser"));
    std::string line;
    if (!admin.Wait("SYSTEM: NUEVO USUARIO: ", line)) return false;
    const std::string rest = line.substr(23);
    name = rest.substr(0, rest.find(' '));
    const std::string tag = " / clave inicial: ";
    const std::size_t p = rest.find(tag);
    if (p == std::string::npos) return false;
    password = rest.substr(p + tag.size());
    password = password.substr(0, password.find(' '));
    return !name.empty() && password.size() >= 12;
}

std::string MsgText(const std::string& line, std::string* from = nullptr) {
    auto f = Split(line);
    if (f.size() != 4) return "<bad>";
    if (from) *from = f[1];
    std::string t; b64::DecodeToString(f[3], t); return t;
}

void AppendU16(std::string& o, uint16_t v) { o.push_back(char(v >> 8)); o.push_back(char(v & 0xff)); }
void AppendU32(std::string& o, uint32_t v) { for (int s = 24; s >= 0; s -= 8) o.push_back(char((v >> s) & 0xff)); }
void AppendSized(std::string& o, const std::string& v) { AppendU16(o, (uint16_t)v.size()); o += v; }

static void RunChecks() {
    // ---- pre-auth slot flood: 70 idle unauthenticated connections ----
    std::vector<std::unique_ptr<Conn>> idlers;
    for (int i = 0; i < 70; ++i) {
        idlers.push_back(std::make_unique<Conn>("idle" + std::to_string(i)));
        idlers.back()->Connect();
        idlers.back()->Wait("SYSTEM: UPLINK", 2000);
    }
    // ---- admin ----
    Conn admin("admin");
    CHECK(admin.Connect(), "admin connects");
    CHECK(admin.Wait("SYSTEM: UPLINK ESTABLISHED. PROTO=2"), "banner has PROTO=2");
    bool sig = false;
    CHECK(Login(admin, "admin", "admin-bootstrap-key", "hw-admin", &sig) == "OK",
          "admin login while 70 pre-auth connections are open (unauth cap evicts, never blocks)");
    CHECK(sig, "admin server signature verifies");
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        int closed = 0;
        for (auto& c : idlers) closed += c->IsClosed() ? 1 : 0;
        CHECK(closed >= 6 && idlers.front()->IsClosed(),
              "oldest pre-auth connections evicted at the unauth cap (closed=" + std::to_string(closed) + ")");
        idlers.clear();
    }
    // ---- pre-auth deadline (checked at the end): idle, never authenticates ----
    Conn lazy("lazy");
    lazy.SetAutoPong(false);
    CHECK(lazy.Connect(), "lazy pre-auth connection");
    lazy.Wait("SYSTEM: UPLINK");
    {
        Conn p("preauth-ping");
        p.Connect();
        p.Wait("SYSTEM: UPLINK");
        p.Send("PING");
        CHECK(!p.Wait("PONG", 600), "PING not answered before authentication");
        p.SendBin(std::string(16, 'x'));
        CHECK(p.Closed(), "binary frame before authentication closes the connection");
    }
    {
        std::string s;
        CHECK(admin.Wait("SESSION:", s), "admin SESSION");
        CHECK(admin.Wait("HISTORY_BEGIN:0"), "admin empty history begin");
        CHECK(admin.Wait("HISTORY_END"), "admin history end");
    }
    admin.Drain();
    std::string u1, p1, u2, p2, u3, p3;
    CHECK(NewUser(admin, u1, p1) && u1 == "user1", "/newuser user1 with random initial password");
    CHECK(NewUser(admin, u2, p2) && u2 == "user2", "/newuser user2 with random initial password");
    CHECK(p1 != p2 && p1 != "initial-user-key", "initial passwords differ per account");

    // ---- alice first login ----
    Conn a("alice");
    a.Connect();
    a.Wait("SYSTEM: UPLINK");
    sig = false;
    CHECK(Login(a, "user1", p1, "hw-alice", &sig) == "FIRST", "user1 first login");
    CHECK(sig, "first-login AUTH_OK signature verifies");
    CHECK(Change2(a, "alice", "alice-strong-key-1") == "OK", "CHANGE2 -> alice");
    {
        auto lines = a.Drain();
        std::string joined; for (auto& l : lines) joined += l + "\n";
        CHECK(lines.size() >= 4 && lines[0] == "SYSTEM: ACCESO CONCEDIDO." && lines[1].rfind("SESSION:", 0) == 0 &&
              lines[2] == "HISTORY_BEGIN:0" && lines[3] == "HISTORY_END", "post-CHANGE2 order:\n" + joined);
    }
    river::e2e::KeyPair ka, kb;
    river::e2e::GenerateKeyPair(ka);
    river::e2e::GenerateKeyPair(kb);
    a.Send("[KEY_SET]:" + b64::EncodeString(ka.pub32));
    CHECK(a.Wait("SYSTEM: CLAVE PUBLICA REGISTRADA."), "alice KEY_SET");
    CHECK(admin.Wait("KEY_CHANGED:alice"), "admin sees KEY_CHANGED:alice");
    a.Send("[KEY_SET]:" + b64::EncodeString(ka.pub32));
    CHECK(a.Wait("SYSTEM: CLAVE PUBLICA REGISTRADA."), "alice KEY_SET same key");
    CHECK(!admin.Wait("KEY_CHANGED:alice", 500), "no KEY_CHANGED for unchanged key");
    a.Send("[KEY_SET]:" + b64::EncodeString(std::string(31, 'x')));
    CHECK(a.Wait("SYSTEM: CLAVE PUBLICA RECHAZADA."), "bad key length rejected");
    a.Send("[KEY_SET]:!!notb64");
    CHECK(a.Wait("SYSTEM: CLAVE PUBLICA RECHAZADA."), "bad key b64 rejected");

    // ---- bob first login ----
    Conn b("bob");
    b.Connect();
    CHECK(Login(b, "user2", p1, "hw-bob") == "SYSTEM: CREDENCIALES INCORRECTAS.",
          "user1's initial password does not open user2");
    CHECK(Login(b, "user2", p2, "hw-bob") == "FIRST", "user2 first login with its own password");
    CHECK(Change2(b, "bob", "bob-strong-key-22") == "OK", "CHANGE2 -> bob");
    b.Send("[KEY_SET]:" + b64::EncodeString(kb.pub32));
    CHECK(b.Wait("SYSTEM: CLAVE PUBLICA REGISTRADA."), "bob KEY_SET");
    CHECK(a.Wait("KEY_CHANGED:bob"), "alice sees KEY_CHANGED:bob");
    b.Drain();

    std::string line;
    a.Send("[KEY_GET]:bob");
    CHECK(a.Wait("KEY:bob:", line) && line == "KEY:bob:" + b64::EncodeString(kb.pub32), "KEY_GET bob");
    a.Send("[KEY_GET]:nobody");
    CHECK(a.Wait("KEY:nobody:", line) && line == "KEY:nobody:-", "KEY_GET unknown -> -");
    a.Send("[KEY_GET]:admin");
    CHECK(a.Wait("KEY:admin:", line) && line == "KEY:admin:-", "KEY_GET user without key -> -");
    {
        // Batch form: one KEY: line per name, in order.
        a.Drain();
        a.Send("[KEY_GET]:bob,nobody,admin,alice");
        std::vector<std::string> keys;
        for (int i = 0; i < 4; ++i) if (a.Wait("KEY:", line)) keys.push_back(line);
        CHECK(keys.size() == 4 && keys[0] == "KEY:bob:" + b64::EncodeString(kb.pub32) && keys[1] == "KEY:nobody:-" &&
                  keys[2] == "KEY:admin:-" && keys[3] == "KEY:alice:" + b64::EncodeString(ka.pub32),
              "batch KEY_GET answers each name in order");
        std::string many;
        for (int i = 0; i < 60; ++i) many += (i ? "," : "") + std::string("peer") + std::to_string(i);
        a.Send("[KEY_GET]:" + many);
        int got = 0;
        while (a.Wait("KEY:peer", line, 500)) ++got;
        CHECK(got == 50, "batch KEY_GET capped at 50 names (got " + std::to_string(got) + ")");
        // 130 single KEY_GET lines: own budget, not the 120 lines/min limit.
        for (int i = 0; i < 130; ++i) a.Send("[KEY_GET]:offline" + std::to_string(i));
        got = 0;
        while (got < 130 && a.Wait("KEY:offline", line, 2000)) ++got;
        CHECK(got == 130 && !a.IsClosed(), "130 KEY_GET lines answered without hitting the line limit");
    }

    // ---- room ----
    a.Drain();
    a.Send("[MSG]:" + b64::EncodeString("hello room \xc3\xb1"));
    std::string from;
    CHECK(b.Wait("MSG:alice:", line) && MsgText(line, &from) == "hello room \xc3\xb1", "bob gets MSG");
    CHECK(admin.Wait("MSG:alice:", line), "admin gets MSG");
    CHECK(a.Wait("MSG:alice:", line), "sender gets own MSG");
    a.Send("[MSG]:" + b64::EncodeString("/help"));
    CHECK(a.Wait("SYSTEM: Comando no disponible."), "regular user /cmd refused");
    CHECK(!b.Wait("MSG:alice:", 400), "command not broadcast");
    a.Send("[MSG]:" + b64::EncodeString(std::string(8193, 'z')));
    CHECK(a.Wait("SYSTEM: MENSAJE DEMASIADO GRANDE."), "8 KiB+1 rejected");
    a.Send("[MSG]:@@@");
    CHECK(a.Wait("SYSTEM: MENSAJE RECHAZADO."), "bad b64 MSG rejected");
    a.Send("[MSG]:");
    CHECK(a.Wait("SYSTEM: MENSAJE RECHAZADO."), "empty MSG rejected");
    a.Send("alice:plainv1payload");
    CHECK(!b.Wait("alice:", 400), "v1 user:sealed path gone");

    // ---- PM2 online ----
    std::string env;
    CHECK(river::e2e::Seal(ka, kb.pub32, "pm", "alice", "bob", "secret one", env), "seal pm");
    a.Send("[PM2]:bob:" + b64::EncodeString(env));
    CHECK(b.Wait("PM2:alice:", line), "bob gets PM2");
    {
        auto f = Split(line); std::string e, pt;
        CHECK(f.size() == 4 && b64::DecodeToString(f[3], e) &&
              river::e2e::Open(kb, ka.pub32, "pm", "alice", "bob", e, pt) && pt == "secret one", "bob opens PM2");
    }
    a.Send("[PM]:bob:x:y");
    CHECK(!b.Wait("[PM]:", 400), "v1 [PM] path gone");
    a.Send("[PM2]:bob:" + b64::EncodeString(std::string(16 * 1024 + 1, 'q')));
    CHECK(a.Wait("SYSTEM: MENSAJE PRIVADO RECHAZADO."), "PM2 > 16 KiB rejected");
    a.Send("[PM2]:bob:" + b64::EncodeString("short"));
    CHECK(a.Wait("SYSTEM: MENSAJE PRIVADO RECHAZADO."), "PM2 < envelope overhead rejected");

    // ---- PMX online ----
    river::e2e::Seal(ka, kb.pub32, "pm", "alice", "bob", "@attachreq|x", env);
    a.Send("[PMX]:bob:" + b64::EncodeString(env));
    CHECK(b.Wait("PMX:alice:", line), "bob gets PMX");

    // ---- ATTACH2 ----
    const std::string nameB64 = b64::EncodeString("photo.png"), mimeB64 = b64::EncodeString("image/png");
    a.Send("[ATTACH2]:att-001:image:" + nameB64 + ":" + mimeB64 + ":12345");
    CHECK(b.Wait("ATTACH2:alice:", line) && line == "ATTACH2:alice:att-001:image:" + nameB64 + ":" + mimeB64 + ":12345",
          "bob gets ATTACH2");
    CHECK(admin.Wait("ATTACH2:alice:att-001"), "admin gets ATTACH2");
    a.Send("[ATTACH2]:att-002:exe:" + nameB64 + ":" + mimeB64 + ":12");
    CHECK(a.Wait("SYSTEM: ADJUNTO RECHAZADO."), "bad kind rejected");
    a.Send("[ATTACH2]:att-003:file:" + nameB64 + ":" + mimeB64 + ":" + std::to_string(12 * 1024 * 1024 + 1));
    CHECK(a.Wait("SYSTEM: ADJUNTO RECHAZADO."), "size > 12 MiB rejected");
    a.Send("[ATTACH2]:att|4:file:" + nameB64 + ":" + mimeB64 + ":5");
    CHECK(a.Wait("SYSTEM: ADJUNTO RECHAZADO."), "id with | rejected");
    a.Send("[ATTACH]:whatever");
    CHECK(!b.Wait("[ATTACH]:", 400), "v1 [ATTACH] path gone");

    // ---- chunk relay ----
    {
        std::string chunkEnv;
        river::e2e::Seal(ka, kb.pub32, "att:att-001", "alice", "bob", std::string(1000, 'c'), chunkEnv);
        std::string p; AppendSized(p, "bob"); AppendSized(p, "att-001"); AppendU32(p, 0); AppendU32(p, 1); p += chunkEnv;
        a.SendBin(p);
        std::string got;
        CHECK(b.Wait("", got, 3000, kFrameTypeAttachmentChunk), "bob gets chunk frame");
        std::string expect; AppendSized(expect, "alice"); AppendSized(expect, "att-001"); AppendU32(expect, 0); AppendU32(expect, 1); expect += chunkEnv;
        CHECK(got == expect, "chunk relayed with sender rewritten");
        std::string big; AppendSized(big, "bob"); AppendSized(big, "att-001"); AppendU32(big, 0); AppendU32(big, 1); big += std::string(64 * 1024 + 65, 'x');
        a.SendBin(big);
        CHECK(a.Wait("SYSTEM: ADJUNTO RECHAZADO."), "chunk > 64 KiB + 64 rejected");
    }

    // ---- PM2 offline ----
    b.Close();
    CHECK(a.Wait("bob salió"), "alice sees bob leave");
    river::e2e::Seal(ka, kb.pub32, "pm", "alice", "bob", "while you were out", env);
    a.Send("[PM2]:bob:" + b64::EncodeString(env));
    CHECK(a.Wait("SYSTEM: Mensaje privado en cola para bob."), "PM2 to offline bob queued");
    a.Send("[PMX]:bob:" + b64::EncodeString(env));
    CHECK(a.Wait("SYSTEM: Usuario 'bob' no conectado."), "PMX to offline bob refused");
    a.Send("[PMX]:ghost:" + b64::EncodeString(env));
    CHECK(a.Wait("SYSTEM: Usuario 'ghost' no encontrado."), "PMX to unknown refused");
    a.Send("[PM2]:ghost:" + b64::EncodeString(env));
    CHECK(a.Wait("SYSTEM: Usuario 'ghost' no encontrado."), "PM2 to unknown refused");

    // ---- bob second login: history + offline PM ----
    Conn b2("bob2");
    b2.Connect();
    sig = false;
    CHECK(Login(b2, "bob", "bob-strong-key-22", "hw-bob", &sig) == "OK", "bob normal login");
    CHECK(sig, "bob server signature verifies");
    {
        auto lines = b2.Drain(500);
        std::string joined; for (auto& l : lines) joined += l + "\n";
        bool ok = lines.size() >= 5 && lines[0].rfind("SESSION:", 0) == 0 && lines[1] == "HISTORY_BEGIN:1" &&
                  lines[2].rfind("HIST:alice:", 0) == 0 && MsgText(lines[2]) == "hello room \xc3\xb1" &&
                  lines[3] == "HISTORY_END" && lines[4].rfind("PM2:alice:", 0) == 0;
        CHECK(ok, "login order SESSION/HISTORY/PM2:\n" + joined);
        if (lines.size() >= 5) {
            auto f = Split(lines[4]); std::string e, pt;
            CHECK(f.size() == 4 && b64::DecodeToString(f[3], e) &&
                  river::e2e::Open(kb, ka.pub32, "pm", "alice", "bob", e, pt) && pt == "while you were out",
                  "queued PM2 opens");
        }
    }
    b2.Close();
    Conn b3("bob3");
    b3.Connect();
    CHECK(Login(b3, "bob", "bob-strong-key-22", "hw-bob") == "OK", "bob third login");
    {
        auto lines = b3.Drain(500);
        bool anyPm = false; for (auto& l : lines) if (l.rfind("PM2:", 0) == 0) anyPm = true;
        CHECK(!anyPm, "offline PM delivered only once");
    }

    // ---- admin /whois shows fingerprint ----
    admin.Drain();
    admin.Send("[MSG]:" + b64::EncodeString("/whois alice"));
    CHECK(admin.Wait("SYSTEM: WHOIS alice", line) && line.find("huella=" + river::e2e::Fingerprint(ka.pub32)) != std::string::npos,
          "whois shows fingerprint: " + line);
    admin.Send("[MSG]:" + b64::EncodeString("/passwd bob bob-new-strong-key"));
    CHECK(admin.Wait("SYSTEM: Clave actualizada para bob"), "/passwd bob");

    // ---- CHANGE2 hardening: reserved / case-variant names, iterations ----
    CHECK(NewUser(admin, u3, p3), "/newuser user3");
    {
        Conn c("carol");
        c.Connect();
        CHECK(Login(c, u3, p3, "hw-carol") == "FIRST", "user3 first login");
        for (const char* bad : {"ADMIN", "Admin", "SYSTEM", "server", "ALICE"})
            CHECK(Change2Iter(c, bad, "carol-strong-key-1", "210000") == "ERROR",
                  std::string("CHANGE2 to '") + bad + "' refused");
        CHECK(Change2Iter(c, "carol", "carol-strong-key-1", "300000") == "ERROR", "CHANGE2 iter 300000 refused");
        CHECK(Change2Iter(c, "carol", "carol-strong-key-1", "100000") == "ERROR", "CHANGE2 iter 100000 refused");
        CHECK(Change2Iter(c, "carol", "carol-strong-key-1", "210000") == "OK", "CHANGE2 carol with default iter");
    }
    {
        // Failed proofs never lock the account: 6 bad proofs for admin from two
        // other connections (each closed after 3), then a correct login works.
        int closedAfter3 = 0;
        for (int round = 0; round < 2; ++round) {
            Conn x("guesser" + std::to_string(round));
            x.Connect();
            x.Wait("SYSTEM: UPLINK");
            for (int i = 0; i < 3; ++i) Login(x, "admin", "wrong-guess-" + std::to_string(i), "hw-g");
            if (x.Closed(4000)) ++closedAfter3;
        }
        CHECK(closedAfter3 == 2, "connection closed after 3 failed proofs");
        Conn ok("admin-again");
        ok.Connect();
        CHECK(Login(ok, "admin", "admin-bootstrap-key", "hw-admin") == "OK",
              "correct admin proof accepted after 6 bad proofs from other connections");
    }

    // ---- failures ----
    {
        Conn v1("v1");
        v1.Connect();
        v1.Wait("SYSTEM: UPLINK");
        v1.Send("[LOGIN_INIT]:alice:hw-alice");
        CHECK(v1.Wait("SYSTEM: CLIENTE OBSOLETO. Actualiza al protocolo 2."), "v1 LOGIN_INIT refused");
        CHECK(v1.Closed(), "v1 connection closed by server");
    }
    {
        Conn w("wrong");
        w.Connect();
        CHECK(Login(w, "alice", "not-the-password", "hw-alice") == "SYSTEM: CREDENCIALES INCORRECTAS.", "wrong password refused");
        CHECK(!w.Wait("AUTH_OK:", 300), "no AUTH_OK on wrong password");
    }
    {
        Conn u("unknown");
        u.Connect();
        std::string ch1, ch2;
        CHECK(Login(u, "ghostuser", "whatever-pass-1", "hw-x", nullptr, &ch1) == "SYSTEM: CREDENCIALES INCORRECTAS.",
              "unknown user gets challenge and fails");
        auto f1 = Split(ch1);
        CHECK(f1.size() == 4 && f1[2].size() == 32 && f1[3] == "210000", "fake challenge shape: " + ch1);
        Login(u, "ghostuser", "whatever-pass-1", "hw-x", nullptr, &ch2);
        auto f2 = Split(ch2);
        CHECK(f2.size() == 4 && f1.size() == 4 && f1[2] == f2[2] && f1[1] != f2[1], "fake salt deterministic, nonce fresh");
    }
    {
        Conn h("hwid");
        h.Connect();
        CHECK(Login(h, "bob", "bob-new-strong-key", "hw-other") == "SYSTEM: HWID NO RECONOCIDO.", "HWID mismatch refused");
    }
    {
        Conn n("newpass");
        n.Connect();
        CHECK(Login(n, "bob", "bob-new-strong-key", "hw-bob") == "OK", "login with /passwd key");
    }

    // ---- pre-auth deadline ----
    {
        std::string notice;
        const bool got = lazy.Wait("SYSTEM: TIEMPO DE AUTENTICACION AGOTADO.", notice, 40000);
        const bool closed = lazy.Closed(5000);
        const long long after = lazy.ClosedAfterMs();
        CHECK(got && closed && after >= 29000 && after <= 36000,
              "unauthenticated connection closed at the 30 s deadline (after " + std::to_string(after) + " ms)");
    }

}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <the_river_server binary>" << std::endl;
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    const std::string dir = e2e::MakeTempDir("river_e2e_server_");
    g_port = e2e::FreePort();
    e2e::ChildOptions opt;
    opt.argv = {e2e::AbsolutePath(argv[1])};
    opt.cwd = dir;
    opt.stdoutFile = dir + "/server.out";
    // No THE_RIVER_NEW_USER_PASSWORD: /newuser generates per-account passwords.
    opt.unsetEnv = {"THE_RIVER_ADMIN_USER", "THE_RIVER_ONION", "THE_RIVER_MACHINE_ID", "THE_RIVER_NEW_USER_PASSWORD"};
    opt.setEnv = {
        {"THE_RIVER_AES_KEY", "e2e-test-key-with-plenty-of-entropy-123"},
        {"THE_RIVER_ADMIN_BOOTSTRAP_PASSWORD", "admin-bootstrap-key"},
        {"THE_RIVER_DB", dir + "/t.db"},
        {"THE_RIVER_LOG", dir + "/chat.log"},
        {"THE_RIVER_BIND_ADDR", "127.0.0.1"},
        {"THE_RIVER_PORT", std::to_string(g_port)},
    };
    std::cout << "server dir " << dir << ", port " << g_port << std::endl;
    e2e::Child server = e2e::Spawn(opt);
    const bool up = e2e::WaitForPort(g_port, 15000, server.pid);
    CHECK(up, "server listens on THE_RIVER_PORT");
    if (up) RunChecks();
    const int rc = e2e::TerminateChild(server.pid, 10000);
    CHECK(rc == 0, "server exits 0 on SIGTERM (got " + std::to_string(rc) + ")");
    const int result = e2e::Summary();
    if (result != 0) {
        std::cerr << "--- server output tail (" << dir << "/server.out):\n"
                  << e2e::TailLines(e2e::ReadFile(dir + "/server.out"), 30) << std::endl;
    } else {
        e2e::RemoveTree(dir);
    }
    return result;
}
