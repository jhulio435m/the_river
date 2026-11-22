#include "client/chat_client.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <vector>

#include <openssl/evp.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "client/attachment_utils.h"
#include "client/platform_runtime.h"
#include "common/base64.h"
#include "common/e2e_crypto.h"
#include "common/scram.h"
#include "common/security_utils.h"
#include "common/shared_config.h"
#include "common/tor_connection.h"

namespace {

std::mutex gClientLogMutex;
std::atomic<unsigned long long> gAttachmentCounter{0};

// Diagnostics only: off unless THE_RIVER_CLIENT_LOG=1. Callers must log structural
// events (connection state, frame sizes, line kinds) and never message contents,
// credentials, usernames, session ids or attachment names/paths.
bool ClientLogEnabled() {
    static const bool enabled = [] {
        const char* value = std::getenv("THE_RIVER_CLIENT_LOG");
        return value != nullptr && std::string(value) == "1";
    }();
    return enabled;
}

void AppendClientLog(const std::string& line) {
    if (!ClientLogEnabled()) return;
    std::lock_guard<std::mutex> lock(gClientLogMutex);
    std::ofstream out("client_runtime.log", std::ios::app);
    if (!out.is_open()) return;
    out << line << "\n";
}

// Liveness of the server link. The socket's receive timeout is only a polling
// interval: an expiry with nothing received means "idle", not "dead". Once
// authenticated the client sends its own PING after keepaliveSec without any
// frame (the server PINGs every 30 s and answers PING with PONG), and the link
// is declared dead only after deadSec without a single frame.
struct LinkTimings {
    int pollSec = 10;
    int keepaliveSec = 45;
    int deadSec = 90;
};

// THE_RIVER_CLIENT_LINK_TIMEOUTS="<poll>,<keepalive>,<dead>" (seconds) overrides
// the defaults. Test-only knob (tests/e2e_client_tests.cpp uses it to exercise
// the keepalive and dead-link paths in a few seconds); not meant for users.
LinkTimings ClientLinkTimings() {
    static const LinkTimings timings = [] {
        LinkTimings t;
        const char* value = std::getenv("THE_RIVER_CLIENT_LINK_TIMEOUTS");
        if (value == nullptr) return t;
        int poll = 0, keepalive = 0, dead = 0;
        if (std::sscanf(value, "%d,%d,%d", &poll, &keepalive, &dead) == 3 && poll > 0 && keepalive > 0 &&
            dead > keepalive) {
            t.pollSec = poll;
            t.keepaliveSec = keepalive;
            t.deadSec = dead;
        }
        return t;
    }();
    return timings;
}

void SetSocketRecvTimeout(SocketHandle sock, int seconds) {
#ifdef _WIN32
    DWORD timeoutMs = static_cast<DWORD>(seconds) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
#else
    timeval tv{};
    tv.tv_sec = seconds;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

// Server notices shown on the login screen (the text after "SYSTEM: "): the
// server speaks Spanish; known notices get their English text, an admin's free
// text reason after them is kept as is.
UiText ServerNoticeText(const std::string& notice) {
    static const std::pair<const char*, const char*> kKnown[] = {
        {"SESION REEMPLAZADA. Tu identidad inicio sesion desde otra conexion.",
         "SESSION REPLACED. Your identity signed in from another connection."},
        {"TIEMPO DE AUTENTICACION AGOTADO.", "AUTHENTICATION TIME LIMIT EXCEEDED."},
        {"LIMITE DE TRAFICO EXCEDIDO.", "TRAFFIC LIMIT EXCEEDED."},
        {"ACCESO BLOQUEADO.", "ACCESS BLOCKED."},
        {"SESION REEMPLAZADA.", "SESSION REPLACED."},
    };
    for (const auto& [es, en] : kKnown) {
        const std::string prefix = es;
        if (notice.compare(0, prefix.size(), prefix) == 0) return UiText(en + notice.substr(prefix.size()), notice);
    }
    return UiText(notice);
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

std::string BytesToHex(const unsigned char* data, std::size_t size) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(hex[(data[i] >> 4) & 0x0f]);
        out.push_back(hex[data[i] & 0x0f]);
    }
    return out;
}

std::string HashFileSha256(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) return "";

    std::vector<char> buffer(kAttachmentBinaryChunkBytes);
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1;
    while (ok && input.good()) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize got = input.gcount();
        if (got > 0) {
            ok = EVP_DigestUpdate(ctx, buffer.data(), static_cast<std::size_t>(got)) == 1;
        }
    }

    unsigned char digest[EVP_MAX_MD_SIZE] = {};
    unsigned int digestLen = 0;
    ok = ok && EVP_DigestFinal_ex(ctx, digest, &digestLen) == 1;
    EVP_MD_CTX_free(ctx);
    return ok ? BytesToHex(digest, digestLen) : "";
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

constexpr std::size_t kMaxRoomTextBytes = 8 * 1024;  // spec 4.1 payload limit
constexpr std::size_t kMaxPendingPerPeer = 64;            // outgoing, waiting for a key
constexpr std::size_t kMaxPendingIncomingPerPeer = 256;   // server queues <= 200 offline PMs
constexpr std::size_t kMaxPendingIncomingTotal = 2000;
constexpr std::size_t kMaxKeyGetNamesPerLine = 50;
constexpr long long kKeyBatchWindowMs = 60;
constexpr std::size_t kMaxHeldPerPeer = 64;
constexpr std::size_t kMaxHeldUploadsPerPeer = 8;
constexpr int kMaxConcurrentUploads = 2;
constexpr std::size_t kMaxQueuedUploads = 8;
constexpr int kFatalAuthBackoffSeconds = 30;
constexpr int kTransientBackoffSeconds = 5;   // auth timeout / traffic limit
constexpr int kKeyLookupRetrySeconds = 61;    // server key-lookup budget is per minute
constexpr std::size_t kMaxSeenFileLines = 200000;
constexpr const char* kUnverifiedPrefix = "[clave no verificada] ";
constexpr const char* kKnownKeysFile = "river_known_keys.txt";
constexpr int kMaxKnownKeyLines = 10000;
constexpr const char* kIncompatibleServerError = "Servidor incompatible (se requiere protocolo 2).";
constexpr const char* kIncompatibleServerErrorEn = "Incompatible server (protocol 2 required).";

bool FileExists(const std::string& path) {
    if (path.empty()) return false;
    std::ifstream input(path, std::ios::binary);
    return input.is_open();
}

// Attachment ids travel in ':'-separated lines and '|'-separated control
// strings and end up in cache file names, so only a conservative alphabet is
// accepted (our own ids are "att<ms>_<n>").
bool IsValidAttachmentId(const std::string& id) {
    if (id.empty() || id.size() > 80 || id[0] == '.') return false;
    for (unsigned char c : id) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok) return false;
    }
    return true;
}

bool ParseUnixTs(const std::string& value, long long& out) {
    if (value.empty() || value.size() > 18) return false;
    long long result = 0;
    for (char c : value) {
        if (c < '0' || c > '9') return false;
        result = result * 10 + (c - '0');
    }
    out = result;
    return true;
}

bool ParseIterations(const std::string& value, int& out) {
    if (value.empty() || value.size() > 9) return false;
    int result = 0;
    for (char c : value) {
        if (c < '0' || c > '9') return false;
        result = result * 10 + (c - '0');
    }
    out = result;
    return true;
}

// "<from>:<unixTs>:<payload>" (the part after "MSG:", "HIST:", "PM2:", "PMX:").
bool SplitSenderTsPayload(const std::string& rest, std::string& from, long long& ts, std::string& payload) {
    const std::size_t first = rest.find(':');
    if (first == std::string::npos || first == 0) return false;
    const std::size_t second = rest.find(':', first + 1);
    if (second == std::string::npos) return false;
    from = rest.substr(0, first);
    if (!ParseUnixTs(rest.substr(first + 1, second - first - 1), ts)) return false;
    payload = rest.substr(second + 1);
    return true;
}

// True if the banner advertises exactly protocol 2 ("PROTO=2", not "PROTO=20").
bool BannerHasProto2(const std::string& line) {
    std::size_t pos = line.find("PROTO=2");
    while (pos != std::string::npos) {
        const std::size_t end = pos + 7;
        if (end >= line.size() || line[end] < '0' || line[end] > '9') return true;
        pos = line.find("PROTO=2", end);
    }
    return false;
}

void WipeString(std::string& value) {
    for (char& c : value) c = '\0';
    value.clear();
}

// True on the thread running ReceiveLoop (key requests made there are batched).
thread_local bool tlsOnReceiveThread = false;

// True when the socket becomes readable (or fails) within timeoutMs.
bool SocketReadable(SocketHandle sock, int timeoutMs) {
    if (timeoutMs < 0) timeoutMs = 0;
#ifdef _WIN32
    WSAPOLLFD p{};
    p.fd = sock;
    p.events = POLLRDNORM;
    return WSAPoll(&p, 1, timeoutMs) != 0;
#else
    pollfd p{sock, POLLIN, 0};
    return ::poll(&p, 1, timeoutMs) != 0;
#endif
}

bool IsLowerHex(const std::string& value, std::size_t size) {
    if (value.size() != size) return false;
    for (char c : value) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

long long NowUnix() {
    return static_cast<long long>(std::time(nullptr));
}

// Creates `path` only if it does not exist yet (O_EXCL); never truncates.
bool CreateFileExclusive(const std::string& path) {
#ifdef _WIN32
    const int fd = _open(path.c_str(), _O_CREAT | _O_EXCL | _O_WRONLY | _O_BINARY, _S_IREAD | _S_IWRITE);
    if (fd < 0) return false;
    _close(fd);
#else
    const int fd = ::open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    ::close(fd);
#endif
    return true;
}

// Server control lines always start with "SYSTEM:"; matching only those keeps
// chat text or nicknames (e.g. "ACTUALIZADO se unio") from triggering state changes.
bool IsSystemNotice(const std::string& line, const char* token) {
    return line.rfind("SYSTEM:", 0) == 0 && line.find(token) != std::string::npos;
}

}  // namespace

namespace attachment_part {

std::string PartPathFor(const std::string& targetPath) {
    return targetPath + ".part";
}

std::shared_ptr<std::fstream> CreatePartFile(const std::string& partPath) {
    // Exclusive create: another transfer's .part (or any existing file) is never
    // truncated or shared. An in|out fstream will not create a missing file.
    if (partPath.empty() || !CreateFileExclusive(partPath)) return nullptr;
    auto file = std::make_shared<std::fstream>(partPath, std::ios::binary | std::ios::in | std::ios::out);
    if (!file->is_open()) {
        RemovePartFile(partPath);
        return nullptr;
    }
    return file;
}

std::shared_ptr<std::fstream> CreateUniquePartFile(const std::string& targetPath, std::string& partPath) {
    partPath.clear();
    if (targetPath.empty()) return nullptr;
    static std::atomic<unsigned long long> counter{0};
    for (int attempt = 0; attempt < 64; ++attempt) {
        std::string candidate = PartPathFor(targetPath);
        if (attempt > 0) {
            candidate = targetPath + "." + river::scram::RandomNonceHex(4) + "-" +
                        std::to_string(counter.fetch_add(1)) + ".part";
        }
        auto file = CreatePartFile(candidate);
        if (file) {
            partPath = candidate;
            return file;
        }
    }
    return nullptr;
}

int ExpectedChunkCount(std::size_t totalSize) {
    if (totalSize == 0) return 1;
    return static_cast<int>((totalSize + kAttachmentBinaryChunkBytes - 1) / kAttachmentBinaryChunkBytes);
}

std::size_t ExpectedChunkSize(std::size_t totalSize, int totalChunks, int index) {
    if (index < 0 || index >= totalChunks) return 0;
    const std::size_t start = static_cast<std::size_t>(index) * kAttachmentBinaryChunkBytes;
    if (start >= totalSize) return 0;
    return std::min(kAttachmentBinaryChunkBytes, totalSize - start);
}

bool WriteChunkAt(std::fstream& file, int index, const std::string& data) {
    if (index < 0 || !file.is_open()) return false;
    file.clear();
    if (data.empty()) return true;
    const std::streamoff offset =
        static_cast<std::streamoff>(index) * static_cast<std::streamoff>(kAttachmentBinaryChunkBytes);
    file.seekp(offset, std::ios::beg);
    if (!file.good()) return false;
    file.write(data.data(), static_cast<std::streamsize>(data.size()));
    return file.good();
}

bool FinalizePartFile(const std::string& partPath,
                      const std::string& targetPath,
                      std::size_t expectedSize,
                      const std::string& expectedSha256,
                      std::string& error) {
    std::streamoff actualSize = -1;
    {
        std::ifstream input(partPath, std::ios::binary | std::ios::ate);
        if (input.is_open()) actualSize = input.tellg();
    }
    if (actualSize < 0 || static_cast<std::size_t>(actualSize) != expectedSize || expectedSize > kMaxAttachmentBytes) {
        RemovePartFile(partPath);
        error = "Attachment integrity check failed.";
        return false;
    }
    if (!expectedSha256.empty()) {
        const std::string actualSha256 = HashFileSha256(partPath);
        if (actualSha256.empty() || !ConstantTimeEquals(actualSha256, expectedSha256)) {
            RemovePartFile(partPath);
            error = "Attachment integrity check failed.";
            return false;
        }
    }
    if (std::rename(partPath.c_str(), targetPath.c_str()) != 0) {
        // Windows rename() fails when the destination already exists.
        std::remove(targetPath.c_str());
        if (std::rename(partPath.c_str(), targetPath.c_str()) != 0) {
            RemovePartFile(partPath);
            error = "Could not save the received attachment.";
            return false;
        }
    }
    return true;
}

void RemovePartFile(const std::string& partPath) {
    if (!partPath.empty()) std::remove(partPath.c_str());
}

}  // namespace attachment_part

namespace rm1 {

std::string Wrap(const std::string& msgIdHex, long long senderTs, const std::string& payload) {
    return "RM1|" + msgIdHex + "|" + std::to_string(senderTs) + "|" + payload;
}

bool Parse(const std::string& plaintext, std::string& msgIdHex, long long& senderTs, std::string& payload) {
    // "RM1|" + 32 lowercase hex + "|" + decimal ts + "|" + payload (may contain '|').
    if (plaintext.rfind("RM1|", 0) != 0) return false;
    const std::size_t idEnd = plaintext.find('|', 4);
    if (idEnd == std::string::npos) return false;
    const std::string id = plaintext.substr(4, idEnd - 4);
    if (!IsLowerHex(id, 32)) return false;
    const std::size_t tsEnd = plaintext.find('|', idEnd + 1);
    if (tsEnd == std::string::npos) return false;
    long long ts = 0;
    if (!ParseUnixTs(plaintext.substr(idEnd + 1, tsEnd - idEnd - 1), ts) || ts <= 0) return false;
    msgIdHex = id;
    senderTs = ts;
    payload = plaintext.substr(tsEnd + 1);
    return true;
}

}  // namespace rm1

ChatClient::ChatClient(ChatState& state) : state_(state) {}

ChatClient::~ChatClient() {
    Stop();
}

void ChatClient::Start() {
    if (networkThread_.joinable()) return;
    stopRequested_.store(false);
    state_.SetStatusDetail(UiText("Initializing secure client...", "Inicializando cliente seguro..."));
    state_.ClearLastError();
    networkThread_ = std::thread(&ChatClient::NetworkLoop, this);
}

void ChatClient::Stop() {
    stopRequested_.store(true);
    CloseCurrentSocket();
    if (networkThread_.joinable()) networkThread_.join();
    ReapFinishedUploads(true);
    ClearE2EState(false);
}

void ChatClient::Logout() {
    ForgetSessionCredentials();
    QueueAutoLogin("", "");
    {
        std::lock_guard<std::mutex> lock(reloginMutex_);
        WipeString(pendingLoginUser_);
        WipeString(pendingLoginPass_);
    }
    ResetAuthExchange();
    ClearE2EState(false);
    SetCurrentUser("");
    state_.SetLastPrivatePeer("");
    state_.AddSystemLog("SYSTEM: Sesion cerrada localmente.");
    CloseCurrentSocket();
}

void ChatClient::RememberSessionCredentials() {
    std::lock_guard<std::mutex> lock(reloginMutex_);
    // After a first-login change the fresh credentials live in the auto-login queue.
    if (!queuedLoginUser_.empty() && !queuedLoginPass_.empty()) {
        rememberedUser_ = queuedLoginUser_;
        rememberedPass_ = queuedLoginPass_;
    } else if (!pendingLoginUser_.empty() && !pendingLoginPass_.empty()) {
        rememberedUser_ = pendingLoginUser_;
        rememberedPass_ = pendingLoginPass_;
    }
}

void ChatClient::ForgetSessionCredentials() {
    std::lock_guard<std::mutex> lock(reloginMutex_);
    WipeString(rememberedUser_);
    WipeString(rememberedPass_);
}

bool ChatClient::ConsumeRememberedCredentials(std::string& user, std::string& pass) {
    std::lock_guard<std::mutex> lock(reloginMutex_);
    if (rememberedUser_.empty() || rememberedPass_.empty()) return false;
    user = rememberedUser_;
    pass = rememberedPass_;
    return true;
}

void ChatClient::HandleServerPong() {
    std::lock_guard<std::mutex> lock(pingMutex_);
    if (!pingOutstanding_) return;
    pingOutstanding_ = false;
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - pingSentAt_).count();
    state_.AddSystemLog("SYSTEM: PONG recibido. Latencia ida y vuelta: " + std::to_string(elapsed) + " ms.");
}

void ChatClient::ReapFinishedUploads(bool joinAll) {
    std::vector<std::thread> toJoin;
    {
        std::lock_guard<std::mutex> lock(uploadsMutex_);
        for (auto it = uploads_.begin(); it != uploads_.end();) {
            if (joinAll || it->done->load()) {
                toJoin.push_back(std::move(it->thread));
                it = uploads_.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (auto& thread : toJoin) {
        if (thread.joinable()) thread.join();
    }
}

void ChatClient::StartAttachmentUpload(const UploadJob& job) {
    ReapFinishedUploads(false);
    if (stopRequested_.load()) return;
    // Uploads run off the receive thread so heartbeats and chat keep flowing
    // while a large file streams to the requester. At most kMaxConcurrentUploads
    // run at once (one per requester+id); the rest wait in a bounded queue.
    const std::string key = job.requester + "|" + job.attachmentId;
    bool busy = false;
    {
        std::lock_guard<std::mutex> lock(uploadsMutex_);
        if (activeUploadKeys_.count(key) > 0) return;  // duplicate of an upload in flight
        for (const auto& queued : uploadQueue_) {
            if (queued.requester == job.requester && queued.attachmentId == job.attachmentId) return;
        }
        if (uploadWorkersRunning_ < kMaxConcurrentUploads) {
            activeUploadKeys_.insert(key);
            ++uploadWorkersRunning_;
            auto done = std::make_shared<std::atomic<bool>>(false);
            std::thread worker(&ChatClient::RunUploadWorker, this, job, done);
            uploads_.push_back({std::move(worker), done});
        } else if (uploadQueue_.size() < kMaxQueuedUploads) {
            uploadQueue_.push_back(job);
        } else {
            busy = true;
        }
    }
    if (busy) {
        SealAndSendLine(true, job.requester, job.requesterPub,
                        "@attacherr|" + job.attachmentId + "|" + river::base64::EncodeString("Ocupado, reintenta"));
    }
}

void ChatClient::RunUploadWorker(UploadJob job, std::shared_ptr<std::atomic<bool>> done) {
    while (true) {
        if (!stopRequested_.load() && job.generation == connGeneration_.load()) HandleAttachmentRequest(job);
        std::lock_guard<std::mutex> lock(uploadsMutex_);
        activeUploadKeys_.erase(job.requester + "|" + job.attachmentId);
        if (stopRequested_.load() || uploadQueue_.empty()) {
            --uploadWorkersRunning_;
            break;
        }
        job = uploadQueue_.front();
        uploadQueue_.pop_front();
        activeUploadKeys_.insert(job.requester + "|" + job.attachmentId);
    }
    done->store(true);
}

void ChatClient::ClearQueuedUploads() {
    std::lock_guard<std::mutex> lock(uploadsMutex_);
    uploadQueue_.clear();
}

void ChatClient::DiscardIncomingTransfer(IncomingAttachmentTransfer& transfer) {
    if (transfer.partFile) {
        transfer.partFile->close();
        transfer.partFile.reset();
    }
    attachment_part::RemovePartFile(transfer.partPath);
    transfer.partPath.clear();
}

void ChatClient::FailPendingIncomingAttachments(const std::string& reason) {
    std::map<std::string, IncomingAttachmentTransfer> pending;
    {
        std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
        pending.swap(incomingAttachments_);
    }
    for (auto& entry : pending) DiscardIncomingTransfer(entry.second);
    state_.FailRequestedAttachments();
    if (!pending.empty()) state_.SetLastError(reason);
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

// ---------------------------------------------------------------------------
// v2 authentication
// ---------------------------------------------------------------------------

void ChatClient::ResetAuthExchange() {
    std::lock_guard<std::mutex> lock(reloginMutex_);
    authClientNonce_.clear();
    WipeString(authExpectedServerSig_);
    authHwid_.clear();
    authVerified_.store(false);
}

bool ChatClient::SendAuthProof(const std::string& challengeLine) {
    // AUTH_CHALLENGE2:<combinedNonceHex>:<saltHex>:<iter>
    const std::vector<std::string> parts = SplitByDelimiter(challengeLine, ':');
    if (parts.size() != 4) return false;
    const std::string& combined = parts[1];
    const std::string& saltHex = parts[2];
    int iterations = 0;
    if (!ParseIterations(parts[3], iterations)) return false;

    std::string user;
    std::string pass;
    std::string hwid;
    std::string clientNonce;
    {
        std::lock_guard<std::mutex> lock(reloginMutex_);
        if (pendingLoginUser_.empty() || pendingLoginPass_.empty() || authClientNonce_.empty()) return false;
        user = pendingLoginUser_;
        pass = pendingLoginPass_;
        hwid = authHwid_;
        clientNonce = authClientNonce_;
        // One challenge per AUTH_START: a replayed or second challenge fails.
        authClientNonce_.clear();
    }

    bool ok = combined.size() == clientNonce.size() + 32 &&
              combined.compare(0, clientNonce.size(), clientNonce) == 0 &&
              river::scram::IsHexString(combined, combined.size()) &&
              river::scram::IsValidSaltHex(saltHex) &&
              river::scram::IsValidIterations(iterations);
    std::string proof;
    std::string expectedSig;
    if (ok) {
        const std::string authMessage =
            river::scram::BuildAuthMessage(user, hwid, clientNonce, combined, saltHex, iterations);
        ok = !authMessage.empty() &&
             river::scram::ComputeClientProof(pass, saltHex, iterations, authMessage, proof, expectedSig);
    }
    WipeString(pass);
    if (!ok) return false;

    {
        std::lock_guard<std::mutex> lock(reloginMutex_);
        authExpectedServerSig_ = expectedSig;
    }
    WipeString(expectedSig);
    const bool sent = SendRawLine("[AUTH_PROOF]:" + user + ":" + hwid + ":" + combined + ":" +
                                  river::base64::EncodeString(proof)) >= 0;
    WipeString(proof);
    return sent;
}

bool ChatClient::VerifyAuthOk(const std::string& line) {
    std::string expected;
    {
        std::lock_guard<std::mutex> lock(reloginMutex_);
        expected = authExpectedServerSig_;
        WipeString(authExpectedServerSig_);
    }
    if (expected.empty()) return false;
    std::string received;
    const bool ok = river::base64::DecodeToString(line.substr(8), received) &&
                    river::scram::VerifyServerSignature(expected, received);
    WipeString(expected);
    if (ok) authVerified_.store(true);
    return ok;
}

void ChatClient::FailAuthFatal(const UiText& reason) {
    AppendClientLog("Auth fatal");
    // Never retry these credentials automatically against a server that could
    // not prove it knows them.
    ForgetSessionCredentials();
    QueueAutoLogin("", "");
    ResetAuthExchange();
    // Sticky until the user submits a new login; the next reconnect waits
    // kFatalAuthBackoffSeconds instead of hammering the server.
    SetStickyAuthError(reason);
    backoffCancel_.store(false);
    reconnectDelaySeconds_.store(kFatalAuthBackoffSeconds);
    state_.SetAuthenticated(false);
    state_.SetAuthActionPending(false);
    state_.SetCredentialChangePending(false);
    state_.SetMustChangeCredentials(false);
    state_.SetLastError(reason);
    state_.AddSystemLog("SYSTEM: " + reason.es);
    CloseCurrentSocket();
}

void ChatClient::SetStickyAuthError(const UiText& reason) {
    std::lock_guard<std::mutex> lock(reloginMutex_);
    stickyAuthError_ = reason;
}

void ChatClient::ApplyStickyAuthError() {
    UiText reason;
    {
        std::lock_guard<std::mutex> lock(reloginMutex_);
        reason = stickyAuthError_;
    }
    if (!reason.empty()) state_.SetLastError(reason);
}

int ChatClient::SendRawLine(const std::string& payload) {
    std::lock_guard<std::mutex> lock(socketMutex_);
    if (!IsSocketValid(socket_)) return -1;

    std::string framePayload = payload;
    while (!framePayload.empty() && (framePayload.back() == '\n' || framePayload.back() == '\r')) {
        framePayload.pop_back();
    }

    if (!SendTextFrame(socket_, framePayload)) {
#ifdef _WIN32
        AppendClientLog("SendRawLine failed err=" + std::to_string(WSAGetLastError()));
#else
        AppendClientLog("SendRawLine failed err=" + std::to_string(errno));
#endif
        return -1;
    }

    AppendClientLog("SendRawLine ok bytes=" + std::to_string(framePayload.size()));
    return static_cast<int>(framePayload.size());
}

void ChatClient::CloseCurrentSocket() {
    std::lock_guard<std::mutex> lock(socketMutex_);
    if (!IsSocketValid(socket_)) return;
#ifdef _WIN32
    shutdown(socket_, SD_BOTH);
#else
    shutdown(socket_, SHUT_RDWR);
#endif
    CloseSocketHandle(socket_);
    socket_ = kInvalidSocket;
}

bool ChatClient::SendLogin(const std::string& user, const std::string& pass) {
    SetCurrentUser(user);
    // A new login attempt replaces a sticky fatal-auth reason and ends the backoff.
    SetStickyAuthError("");
    backoffCancel_.store(true);
    state_.ClearLastError();
    state_.SetCredentialChangePending(false);
    AppendClientLog("SendLogin");
    if (bannerState_.load() == 2) {
        state_.SetAuthActionPending(false);
        state_.SetLastError(UiText(kIncompatibleServerErrorEn, kIncompatibleServerError));
        return false;
    }
    if (user.empty() || user.size() > 64 || user.find_first_of(":|\r\n") != std::string::npos || pass.empty()) {
        state_.SetAuthActionPending(false);
        state_.SetLastError(UiText("Invalid ID or key.", "Identificador o clave invalidos."));
        return false;
    }
    state_.SetAuthActionPending(true);
    state_.SetConnectionState(ConnState::AUTHENTICATING);
    state_.SetStatusDetail(UiText("Authenticating credentials...", "Autenticando credenciales..."));
    if (bannerState_.load() == 0) {
        // The server has not confirmed PROTO=2 yet: log in once its banner arrives.
        QueueAutoLogin(user, pass);
        state_.SetStatusDetail(UiText("Waiting for the server banner...", "Esperando banner del servidor..."));
        return true;
    }

    QueueChallengeLogin(user, pass);
    const std::string nonce = river::scram::RandomNonceHex(16);
    const std::string hwid = MakeStableMachineId();
    {
        std::lock_guard<std::mutex> lock(reloginMutex_);
        authClientNonce_ = nonce;
        WipeString(authExpectedServerSig_);
        authHwid_ = hwid;
    }
    authVerified_.store(false);
    if (nonce.empty() || hwid.find_first_of(":|") != std::string::npos ||
        SendRawLine("[AUTH_START]:2:" + user + ":" + hwid + ":" + nonce + "\n") < 0) {
        state_.SetAuthActionPending(false);
        state_.SetLastError(UiText("No channel available to send the login.",
                                   "No hay canal disponible para enviar el login."));
        state_.SetStatusDetail(UiText("No active link to the server.", "Sin enlace activo hacia el servidor."));
        return false;
    }
    return true;
}

bool ChatClient::SendFirstLoginChange(const std::string& newUser, const std::string& newPass) {
    state_.ClearLastError();
    if (!IsValidUsername(newUser)) {
        state_.SetLastError(UiText("Invalid ID: 3-24 characters (letters, digits, '_' or '-').",
                                   "Identificador invalido: 3-24 caracteres (letras, numeros, '_' o '-')."));
        return false;
    }
    if (!IsStrongEnoughPassword(newPass)) {
        state_.SetLastError(UiText("Key too weak: use 12 to 128 characters and do not include ':'.",
                                   "Clave demasiado debil: usa entre 12 y 128 caracteres y no incluyas ':'."));
        return false;
    }
    if (!authVerified_.load()) {
        state_.SetLastError(UiText("No verified authentication to update the credentials.",
                                   "No hay una autenticacion verificada para actualizar credenciales."));
        return false;
    }
    // The password never leaves the client: only the SCRAM credential is sent.
    river::scram::Credential credential;
    if (!river::scram::MakeCredential(newPass, credential)) {
        state_.SetLastError(UiText("Could not derive the new credential.", "No se pudo derivar la nueva credencial."));
        return false;
    }
    state_.SetCredentialChangePending(true);
    state_.SetConnectionState(ConnState::UPDATING_CREDENTIALS);
    state_.SetStatusDetail(UiText("Updating the initial identity...", "Actualizando identidad inicial..."));
    QueueAutoLogin(newUser, newPass);
    if (SendRawLine("[CHANGE2]:" + newUser + ":" + credential.saltHex + ":" +
                    std::to_string(credential.iterations) + ":" + credential.storedKeyHex + ":" +
                    credential.serverKeyHex + "\n") < 0) {
        state_.SetCredentialChangePending(false);
        QueueAutoLogin("", "");
        state_.SetLastError(UiText("Could not send the initial credential change.",
                                   "No se pudo enviar el cambio inicial de credenciales."));
        state_.SetStatusDetail(UiText("No active link to the server.", "Sin enlace activo hacia el servidor."));
        return false;
    }
    return true;
}

bool ChatClient::SendPing() {
    if (!authVerified_.load()) {
        // The server does not answer PING before AUTH_OK.
        state_.SetLastError(UiText("No authenticated session: PING unavailable.",
                                   "Sin sesion autenticada: PING no disponible."));
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(pingMutex_);
        pingOutstanding_ = true;
        pingSentAt_ = std::chrono::steady_clock::now();
    }
    if (SendRawLine("PING\n") < 0) {
        std::lock_guard<std::mutex> lock(pingMutex_);
        pingOutstanding_ = false;
        state_.SetLastError(UiText("Could not send PING to the server.", "No se pudo enviar PING al servidor."));
        return false;
    }
    return true;
}

bool ChatClient::SendChatMessage(const std::string& /*user*/, const std::string& input) {
    if (input.size() > kMaxRoomTextBytes) {
        state_.SetLastError(UiText("Message too long (8 KiB maximum).", "Mensaje demasiado largo (maximo 8 KiB)."));
        return false;
    }
    if (SendRawLine("[MSG]:" + river::base64::EncodeString(input) + "\n") < 0) {
        state_.SetLastError(UiText("Could not send the message. Channel unavailable.",
                                   "No se pudo enviar el mensaje. Canal no disponible."));
        return false;
    }
    return true;
}

bool ChatClient::SendPrivateMessage(const std::string& /*fromUser*/, const std::string& target, const std::string& message) {
    if (!HasIdentity()) {
        state_.SetLastError(UiText("No identity key loaded: private messages need an active session.",
                                   "No hay clave de identidad cargada: los mensajes privados requieren una sesion activa."));
        return false;
    }
    if (!SendSealedToUser(target, message, false)) {
        state_.SetLastError(UiText("Could not send the private message.", "No se pudo enviar el mensaje privado."));
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Identity keys, key directory, TOFU pins
// ---------------------------------------------------------------------------

bool ChatClient::HasIdentity() const {
    std::lock_guard<std::mutex> lock(identityKeyMutex_);
    return river::e2e::IsValidKeyPair(identityKey_);
}

std::string ChatClient::OwnPublicKey() const {
    std::lock_guard<std::mutex> lock(identityKeyMutex_);
    return river::e2e::IsValidKeyPair(identityKey_) ? identityKey_.pub32 : std::string();
}

bool ChatClient::SealWithIdentity(const std::string& context,
                                  const std::string& fromUser,
                                  const std::string& toUser,
                                  const std::string& recipientPub,
                                  const std::string& plaintext,
                                  std::string& envelope) const {
    std::lock_guard<std::mutex> lock(identityKeyMutex_);
    if (!river::e2e::IsValidKeyPair(identityKey_)) return false;
    return river::e2e::Seal(identityKey_, recipientPub, context, fromUser, toUser, plaintext, envelope);
}

bool ChatClient::OpenWithIdentity(const std::string& context,
                                  const std::string& fromUser,
                                  const std::string& toUser,
                                  const std::string& senderPub,
                                  const std::string& envelope,
                                  std::string& plaintext) const {
    std::lock_guard<std::mutex> lock(identityKeyMutex_);
    if (!river::e2e::IsValidKeyPair(identityKey_)) return false;
    return river::e2e::Open(identityKey_, senderPub, context, fromUser, toUser, envelope, plaintext);
}

bool ChatClient::LoadOrCreateIdentity(const std::string& user,
                                      const std::string& pass,
                                      const std::string& oldUser,
                                      const std::string& oldPass) {
    const std::string newPath = river::e2e::IdentityFileName(user);
    if (newPath.empty() || pass.empty()) return false;
    const bool changed = !oldUser.empty() && !oldPass.empty();
    const std::string oldPath = changed ? river::e2e::IdentityFileName(oldUser) : std::string();

    river::e2e::KeyPair keyPair;
    bool loaded = false;
    bool hadFile = false;
    if (changed && !oldPath.empty()) {
        // First-login change: keep the existing key, re-encrypted under the new password.
        hadFile = FileExists(oldPath);
        loaded = hadFile && river::e2e::LoadIdentity(oldPath, oldPass, keyPair);
    }
    if (!loaded) {
        const bool newExists = FileExists(newPath);
        hadFile = hadFile || newExists;
        loaded = newExists && river::e2e::LoadIdentity(newPath, pass, keyPair);
    }
    bool generated = false;
    if (!loaded) {
        if (!river::e2e::GenerateKeyPair(keyPair)) return false;
        generated = true;
    }

    bool saved = true;
    if (generated || changed) saved = river::e2e::SaveIdentity(newPath, keyPair, pass);
    if (saved && changed && !oldPath.empty() && oldPath != newPath) std::remove(oldPath.c_str());

    const std::string fingerprint = river::e2e::Fingerprint(keyPair.pub32);
    {
        std::lock_guard<std::mutex> lock(identityKeyMutex_);
        river::e2e::Clear(identityKey_);
        identityKey_.priv32 = keyPair.priv32;
        identityKey_.pub32 = keyPair.pub32;
    }
    if (generated) {
        state_.AddSystemLog(hadFile
            ? "SYSTEM: No se pudo abrir la clave de identidad local; se genero una nueva (huella " + fingerprint +
                  "). Tus contactos veran un aviso de cambio de clave."
            : "SYSTEM: Clave de identidad generada (huella " + fingerprint + ").");
    }
    if (!saved) state_.AddSystemLog("SYSTEM: No se pudo guardar la clave de identidad en disco; solo vale para esta sesion.");
    return true;
}

void ChatClient::PublishIdentityKey() {
    const std::string pub = OwnPublicKey();
    if (pub.empty()) return;
    if (SendRawLine("[KEY_SET]:" + river::base64::EncodeString(pub) + "\n") < 0) {
        state_.SetLastError(UiText("Could not publish the public key.", "No se pudo publicar la clave publica."));
    }
}

void ChatClient::ClearE2EState(bool notifyPending) {
    {
        std::lock_guard<std::mutex> lock(identityKeyMutex_);
        river::e2e::Clear(identityKey_);
    }
    std::map<std::string, std::vector<PendingOutgoingSealed>> outgoing;
    std::map<std::string, std::vector<PendingOutgoingSealed>> held;
    {
        std::lock_guard<std::mutex> lock(peerMutex_);
        peerKeys_.clear();
        keyRequestsInFlight_.clear();
        keyRequestQueue_.clear();
        batchKeyGetUnsupported_ = false;
        keyRetryPending_ = false;
        outgoing.swap(pendingOutgoing_);
        held.swap(heldOutgoing_);
        pendingIncoming_.clear();
        pendingIncomingTotal_ = 0;
        pendingFingerprint_.clear();
        // Re-detected on the next key fetch: the changed key was never pinned.
        unverifiedPeers_.clear();
        heldUploads_.clear();
    }
    for (auto* source : {&outgoing, &held}) {
        for (auto& entry : *source) {
            bool hadText = false;
            for (auto& item : entry.second) {
                if (!item.control) hadText = true;
                WipeString(item.plaintext);
            }
            if (notifyPending && hadText)
                state_.AddSystemLog("SYSTEM: Mensaje privado a " + entry.first + " no enviado (enlace perdido).");
        }
    }
}

bool ChatClient::CachedPeerKey(const std::string& user, std::string& pub) const {
    std::lock_guard<std::mutex> lock(peerMutex_);
    auto it = peerKeys_.find(user);
    if (it == peerKeys_.end()) return false;
    pub = it->second;
    return true;
}

bool ChatClient::IsPeerUnverified(const std::string& user) const {
    std::lock_guard<std::mutex> lock(peerMutex_);
    return unverifiedPeers_.count(user) > 0;
}

void ChatClient::RequestPeerKey(const std::string& user) {
    bool queued = false;
    {
        std::lock_guard<std::mutex> lock(peerMutex_);
        if (keyRequestsInFlight_.insert(user).second) {
            if (keyRequestQueue_.empty()) keyQueueSince_ = std::chrono::steady_clock::now();
            keyRequestQueue_.push_back(user);
            queued = true;
        }
    }
    // On the receive thread the queue is flushed once the current burst of
    // lines has been processed (ReceiveLoop), so e.g. offline PMs from many
    // senders cost a few batch lines instead of one KEY_GET each.
    if (queued && !tlsOnReceiveThread) FlushKeyRequests();
}

void ChatClient::FlushKeyRequests() {
    std::vector<std::string> names;
    bool singleOnly = false;
    {
        std::lock_guard<std::mutex> lock(peerMutex_);
        names.swap(keyRequestQueue_);
        singleOnly = batchKeyGetUnsupported_;
    }
    if (names.empty()) return;
    const std::size_t perLine = singleOnly ? 1 : kMaxKeyGetNamesPerLine;
    std::vector<std::string> failed;
    for (std::size_t i = 0; i < names.size(); i += perLine) {
        const std::size_t end = std::min(names.size(), i + perLine);
        std::string list;
        for (std::size_t j = i; j < end; ++j) {
            if (j > i) list += ",";
            list += names[j];
        }
        if (SendRawLine("[KEY_GET]:" + list + "\n") < 0) failed.insert(failed.end(), names.begin() + i, names.begin() + end);
    }
    if (!failed.empty()) {
        std::lock_guard<std::mutex> lock(peerMutex_);
        for (const auto& name : failed) keyRequestsInFlight_.erase(name);
    }
}

bool ChatClient::SealAndSendLine(bool control,
                                 const std::string& target,
                                 const std::string& targetPub,
                                 const std::string& plaintext) {
    const std::string me = CurrentUser();
    if (me.empty()) return false;
    // Spec 4.4: a fresh message id and the sender clock go inside the sealed
    // plaintext so the recipient can reject replays and show the real time.
    const std::string msgId = river::scram::RandomNonceHex(16);
    if (!IsLowerHex(msgId, 32)) return false;
    std::string wrapped = rm1::Wrap(msgId, NowUnix(), plaintext);
    std::string envelope;
    const bool sealed = SealWithIdentity("pm", me, target, targetPub, wrapped, envelope);
    WipeString(wrapped);
    if (!sealed) return false;
    return SendRawLine(std::string(control ? "[PMX]:" : "[PM2]:") + target + ":" +
                       river::base64::EncodeString(envelope) + "\n") >= 0;
}

bool ChatClient::SendSealedToUser(const std::string& target, const std::string& plaintext, bool control) {
    if (!HasIdentity() || CurrentUser().empty() || !IsValidUsername(target)) return false;
    std::string pub;
    bool queued = false;
    bool held = false;
    {
        std::lock_guard<std::mutex> lock(peerMutex_);
        auto it = peerKeys_.find(target);
        if (unverifiedPeers_.count(target) > 0) {
            // The peer's key changed and the user has not accepted it yet.
            auto& queue = heldOutgoing_[target];
            if (queue.size() >= kMaxHeldPerPeer) return false;
            queue.push_back({control, plaintext});
            held = true;
        } else if (it != peerKeys_.end()) {
            pub = it->second;
        } else {
            auto& queue = pendingOutgoing_[target];
            if (queue.size() >= kMaxPendingPerPeer) return false;
            queue.push_back({control, plaintext});
            queued = true;
        }
    }
    if (held) {
        state_.AddSystemLog(std::string("SYSTEM: ") + (control ? "Solicitud de adjunto" : "Mensaje privado") + " a " +
                            target + " retenido: su clave cambio. Usa /trust " + target +
                            " para aceptar la nueva clave.");
        return true;
    }
    if (queued) {
        // Sent once the KEY: reply arrives (HandleKeyReply).
        RequestPeerKey(target);
        return true;
    }
    return SealAndSendLine(control, target, pub, plaintext);
}

void ChatClient::LoadKnownKeysLocked() {
    if (pinsLoaded_) return;
    pinsLoaded_ = true;
    std::ifstream input(kKnownKeysFile);
    if (!input.is_open()) return;
    std::string line;
    int lines = 0;
    while (lines++ < kMaxKnownKeyLines && std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const std::size_t space = line.find(' ');
        if (space == std::string::npos) continue;
        const std::string user = line.substr(0, space);
        const std::string fingerprint = line.substr(space + 1);
        if (!IsValidUsername(user) || fingerprint.empty() || fingerprint.size() > 64) continue;
        knownKeyPins_[user] = fingerprint;
    }
}

bool ChatClient::SaveKnownKeysLocked() const {
    const std::string target = kKnownKeysFile;
    const std::string temp = target + ".tmp";
    {
        std::ofstream out(temp, std::ios::trunc);
        if (!out.is_open()) return false;
        for (const auto& entry : knownKeyPins_) out << entry.first << " " << entry.second << "\n";
        out.flush();
        if (!out.good()) {
            out.close();
            std::remove(temp.c_str());
            return false;
        }
    }
    if (std::rename(temp.c_str(), target.c_str()) != 0) {
        // Windows rename() refuses to overwrite an existing file.
        std::remove(target.c_str());
        if (std::rename(temp.c_str(), target.c_str()) != 0) {
            std::remove(temp.c_str());
            return false;
        }
    }
    return true;
}

ChatClient::PinResult ChatClient::CheckAndPinPeerKey(const std::string& user, const std::string& pub) {
    const std::string fingerprint = river::e2e::Fingerprint(pub);
    std::lock_guard<std::mutex> lock(pinsMutex_);
    LoadKnownKeysLocked();
    auto it = knownKeyPins_.find(user);
    if (it == knownKeyPins_.end()) {
        knownKeyPins_[user] = fingerprint;  // first sight: trust on first use
        SaveKnownKeysLocked();
        return PinResult::FirstSight;
    }
    // A changed key is never re-pinned automatically: /trust does that.
    return it->second == fingerprint ? PinResult::Matches : PinResult::Changed;
}

void ChatClient::HandleKeyReply(const std::string& rest) {
    // KEY:<user>:<pubkeyB64>  or  KEY:<user>:-
    const std::size_t sep = rest.find(':');
    if (sep == std::string::npos) return;
    const std::string user = rest.substr(0, sep);
    const std::string value = rest.substr(sep + 1);

    if (user.find(',') != std::string::npos) {
        // A server without the batch form answered "KEY:<a,b,...>:-" for the
        // whole list: ask again one name per line.
        const std::vector<std::string> names = SplitByDelimiter(user, ',');
        {
            std::lock_guard<std::mutex> lock(peerMutex_);
            batchKeyGetUnsupported_ = true;
            for (const auto& name : names) {
                if (IsValidUsername(name) && keyRequestsInFlight_.count(name) > 0) {
                    if (keyRequestQueue_.empty()) keyQueueSince_ = std::chrono::steady_clock::now();
                    keyRequestQueue_.push_back(name);
                }
            }
        }
        FlushKeyRequests();
        return;
    }
    if (!IsValidUsername(user)) return;

    std::string pub;
    const bool hasKey = value != "-" && river::base64::DecodeToString(value, pub) &&
                        pub.size() == river::e2e::kKeyBytes;
    std::vector<PendingOutgoingSealed> outgoing;
    std::vector<PendingIncomingSealed> incoming;
    std::vector<UploadJob> uploads;
    bool wantedFingerprint = false;
    const PinResult pin = hasKey ? CheckAndPinPeerKey(user, pub) : PinResult::Matches;
    const std::string fingerprint = hasKey ? river::e2e::Fingerprint(pub) : std::string();
    bool warn = false;
    std::size_t newlyHeldText = 0;
    {
        std::lock_guard<std::mutex> lock(peerMutex_);
        keyRequestsInFlight_.erase(user);
        if (hasKey) peerKeys_[user] = pub;
        else peerKeys_.erase(user);
        auto out = pendingOutgoing_.find(user);
        if (out != pendingOutgoing_.end()) {
            outgoing.swap(out->second);
            pendingOutgoing_.erase(out);
        }
        auto in = pendingIncoming_.find(user);
        if (in != pendingIncoming_.end()) {
            incoming.swap(in->second);
            pendingIncomingTotal_ -= std::min(pendingIncomingTotal_, incoming.size());
            pendingIncoming_.erase(in);
        }
        wantedFingerprint = pendingFingerprint_.erase(user) > 0;
        if (hasKey && pin == PinResult::Changed) {
            // Hold everything for this peer until the user runs /trust.
            std::string& shown = unverifiedPeers_[user];
            if (shown != fingerprint) {
                shown = fingerprint;
                warn = true;
            }
            auto& heldQueue = heldOutgoing_[user];
            for (auto& item : outgoing) {
                if (!item.control) ++newlyHeldText;
                if (heldQueue.size() < kMaxHeldPerPeer) heldQueue.push_back(std::move(item));
                else WipeString(item.plaintext);
            }
            outgoing.clear();
        } else if (hasKey) {
            // The key matches the pin again: release what was held for it.
            if (unverifiedPeers_.erase(user) > 0) {
                auto held = heldOutgoing_.find(user);
                if (held != heldOutgoing_.end()) {
                    held->second.insert(held->second.end(), std::make_move_iterator(outgoing.begin()),
                                        std::make_move_iterator(outgoing.end()));
                    outgoing.swap(held->second);
                    heldOutgoing_.erase(held);
                }
                auto heldUp = heldUploads_.find(user);
                if (heldUp != heldUploads_.end()) {
                    uploads.swap(heldUp->second);
                    heldUploads_.erase(heldUp);
                }
            }
        }
    }

    if (!hasKey) {
        const std::string noKey = user + " aun no tiene clave publica.";
        bool reported = false;
        for (auto& item : outgoing) {
            if (item.control && item.plaintext.rfind("@attachreq|", 0) == 0) {
                const std::vector<std::string> parts = SplitByDelimiter(item.plaintext, '|');
                if (parts.size() >= 2) {
                    IncomingAttachmentTransfer dropped;
                    {
                        std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
                        auto it = incomingAttachments_.find(user + "|" + parts[1]);
                        if (it != incomingAttachments_.end()) {
                            dropped = std::move(it->second);
                            incomingAttachments_.erase(it);
                        }
                    }
                    DiscardIncomingTransfer(dropped);
                    state_.UpdateAttachmentState(user, parts[1], AttachmentTransferState::Failed);
                }
            }
            WipeString(item.plaintext);
            reported = true;
        }
        if (reported || wantedFingerprint) {
            state_.SetLastError(noKey);
            state_.AddSystemLog("SYSTEM: " + noKey);
        }
        for (std::size_t i = 0; i < incoming.size(); ++i) state_.AddSystemLog("[PM ilegible de " + user + "]");
        return;
    }

    if (warn) {
        state_.AddSystemLog("[!] La clave de " + user + " cambio (huella " + fingerprint +
                            "). Verificala por otro canal. Usa /trust " + user + " para aceptar la nueva clave.");
    }
    if (newlyHeldText > 0) {
        state_.AddSystemLog("SYSTEM: Mensaje privado a " + user + " retenido hasta que aceptes su nueva clave (/trust " +
                            user + ").");
    }
    if (wantedFingerprint) {
        state_.AddSystemLog("SYSTEM: Huella de " + user + ": " + fingerprint +
                            (pin == PinResult::Changed ? " (NO verificada: usa /trust " + user + " para aceptarla)" : ""));
    }
    for (auto& item : outgoing) {
        if (!SealAndSendLine(item.control, user, pub, item.plaintext) && !item.control)
            state_.AddSystemLog("SYSTEM: Could not send the private message.");
        WipeString(item.plaintext);
    }
    for (const auto& job : uploads) {
        if (job.requesterPub == pub) StartAttachmentUpload(job);
    }
    for (const auto& item : incoming) DeliverIncomingSealed(user, pub, item);
}

void ChatClient::HandleKeyChanged(const std::string& user) {
    if (!IsValidUsername(user) || user == CurrentUser()) return;
    std::lock_guard<std::mutex> lock(peerMutex_);
    peerKeys_.erase(user);
}

void ChatClient::TrustPeerKey(const std::string& user) {
    if (!IsValidUsername(user) || user == CurrentUser()) {
        state_.AddSystemLog("SYSTEM: Usage: /trust <user>");
        return;
    }
    std::string fingerprint;
    {
        std::lock_guard<std::mutex> lock(peerMutex_);
        auto it = unverifiedPeers_.find(user);
        if (it == unverifiedPeers_.end()) {
            state_.AddSystemLog("SYSTEM: No hay ningun cambio de clave pendiente de aceptar para " + user + ".");
            return;
        }
        fingerprint = it->second;
    }
    {
        // Pin exactly the fingerprint the warning showed.
        std::lock_guard<std::mutex> lock(pinsMutex_);
        LoadKnownKeysLocked();
        knownKeyPins_[user] = fingerprint;
        SaveKnownKeysLocked();
    }
    std::vector<PendingOutgoingSealed> outgoing;
    std::vector<UploadJob> uploads;
    std::string pub;
    bool keyCurrent = false;
    {
        std::lock_guard<std::mutex> lock(peerMutex_);
        auto it = unverifiedPeers_.find(user);
        if (it != unverifiedPeers_.end() && it->second == fingerprint) unverifiedPeers_.erase(it);
        auto held = heldOutgoing_.find(user);
        if (held != heldOutgoing_.end()) {
            outgoing.swap(held->second);
            heldOutgoing_.erase(held);
        }
        auto heldUp = heldUploads_.find(user);
        if (heldUp != heldUploads_.end()) {
            uploads.swap(heldUp->second);
            heldUploads_.erase(heldUp);
        }
        auto key = peerKeys_.find(user);
        keyCurrent = key != peerKeys_.end() && river::e2e::Fingerprint(key->second) == fingerprint;
        if (keyCurrent) {
            pub = key->second;
        } else {
            // Not cached (or changed again): send once the key is fetched and
            // matches the new pin.
            auto& queue = pendingOutgoing_[user];
            for (auto& item : outgoing) queue.push_back(std::move(item));
            outgoing.clear();
        }
    }
    state_.AddSystemLog("SYSTEM: Nueva clave de " + user + " aceptada (huella " + fingerprint + ").");
    if (!keyCurrent) {
        RequestPeerKey(user);
        return;
    }
    for (auto& item : outgoing) {
        if (!SealAndSendLine(item.control, user, pub, item.plaintext) && !item.control)
            state_.AddSystemLog("SYSTEM: Could not send the private message.");
        WipeString(item.plaintext);
    }
    for (const auto& job : uploads) {
        if (job.requesterPub == pub) StartAttachmentUpload(job);
    }
}

void ChatClient::ShowFingerprint(const std::string& user) {
    const std::string me = CurrentUser();
    if (user.empty() || user == me) {
        const std::string pub = OwnPublicKey();
        if (pub.empty()) {
            state_.AddSystemLog("SYSTEM: No hay clave de identidad cargada (inicia sesion).");
        } else {
            state_.AddSystemLog("SYSTEM: Tu huella: " + river::e2e::Fingerprint(pub));
        }
        return;
    }
    if (!IsValidUsername(user)) {
        state_.AddSystemLog("SYSTEM: Invalid target user '" + user + "'.");
        return;
    }
    std::string pub;
    if (CachedPeerKey(user, pub)) {
        state_.AddSystemLog("SYSTEM: Huella de " + user + ": " + river::e2e::Fingerprint(pub) +
                            (IsPeerUnverified(user) ? " (NO verificada: usa /trust " + user + " para aceptarla)" : ""));
        return;
    }
    if (!state_.IsAuthenticated()) {
        state_.AddSystemLog("SYSTEM: Sin sesion activa para consultar claves.");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(peerMutex_);
        pendingFingerprint_.insert(user);
    }
    state_.AddSystemLog("SYSTEM: Solicitando la clave publica de " + user + "...");
    RequestPeerKey(user);
}

void ChatClient::HandleIncomingSealed(const std::string& rest, bool control) {
    std::string from;
    std::string payload;
    long long ts = 0;
    if (!SplitSenderTsPayload(rest, from, ts, payload) || !IsValidUsername(from)) return;

    PendingIncomingSealed item;
    item.control = control;
    item.unixTs = ts;
    if (!river::base64::DecodeToString(payload, item.envelope) || item.envelope.empty()) {
        if (!control) state_.AddSystemLog("[PM ilegible de " + from + "]");
        return;
    }

    std::string pub;
    bool queued = false;
    bool overflow = false;
    {
        std::lock_guard<std::mutex> lock(peerMutex_);
        auto it = peerKeys_.find(from);
        if (it != peerKeys_.end()) {
            pub = it->second;
        } else {
            auto& queue = pendingIncoming_[from];
            if (queue.size() >= kMaxPendingIncomingPerPeer || pendingIncomingTotal_ >= kMaxPendingIncomingTotal) {
                overflow = true;
            } else {
                queue.push_back(std::move(item));
                ++pendingIncomingTotal_;
            }
            queued = true;
        }
    }
    if (overflow) {
        state_.AddSystemLog("[PM ilegible de " + from + "]");
        return;
    }
    if (queued) {
        // Opened once the sender's KEY: reply arrives (e.g. offline PMs right after login).
        RequestPeerKey(from);
        return;
    }
    DeliverIncomingSealed(from, pub, item);
}

void ChatClient::DeliverIncomingSealed(const std::string& from,
                                       const std::string& fromPub,
                                       const PendingIncomingSealed& item) {
    const std::string me = CurrentUser();
    std::string plaintext;
    std::string msgId;
    std::string payload;
    long long senderTs = 0;
    if (me.empty() || !OpenWithIdentity("pm", from, me, fromPub, item.envelope, plaintext) ||
        !rm1::Parse(plaintext, msgId, senderTs, payload)) {
        // Undecryptable, or not in the RM1 format (spec 4.4): rejected.
        WipeString(plaintext);
        state_.AddSystemLog("[PM ilegible de " + from + "]");
        return;
    }
    WipeString(plaintext);
    const SeenResult seen = CheckAndRecordMessageId(me, from, msgId, senderTs);
    if (seen != SeenResult::Accepted) {
        WipeString(payload);
        if (!item.control) {
            state_.AddSystemLog(seen == SeenResult::Duplicate
                                    ? "SYSTEM: [!] Mensaje privado repetido de " + from + " descartado (reenvio)."
                                    : "SYSTEM: [!] Mensaje privado de " + from +
                                          " descartado (marca de tiempo fuera de rango).");
        }
        return;
    }
    const bool unverified = IsPeerUnverified(from);
    if (HandleAttachmentPrivateControl(from, fromPub, payload, unverified)) return;
    if (item.control) return;  // [PMX] only carries attachment control
    // The authenticated sender clock replaces the server timestamp.
    state_.AddIncomingPrivateMessage(from, unverified ? kUnverifiedPrefix + payload : payload, senderTs, me);
    WipeString(payload);
}

// ---------------------------------------------------------------------------
// Replay protection: seen RM1 message ids (spec 4.4)
// ---------------------------------------------------------------------------

bool ChatClient::InsertSeenLocked(SeenPeerIds& peer, const std::string& msgId, long long ts, bool& evicted) {
    if (!peer.ids.emplace(msgId, ts).second) return false;
    peer.byTs.emplace(ts, msgId);
    while (peer.ids.size() > rm1::kMaxIdsPerPeer && !peer.byTs.empty()) {
        // Anything at or before an evicted id's timestamp is rejected from now on,
        // so evicting never reopens a replay window.
        auto oldest = peer.byTs.begin();
        peer.watermark = std::max(peer.watermark, oldest->first);
        peer.ids.erase(oldest->second);
        peer.byTs.erase(oldest);
        evicted = true;
    }
    return true;
}

void ChatClient::LoadSeenIdsLocked() {
    if (seenLoaded_) return;
    seenLoaded_ = true;
    std::ifstream input(rm1::kSeenIdsFile);
    if (!input.is_open()) return;
    const long long minTs = NowUnix() - rm1::kMaxAgeSeconds;
    std::string line;
    std::size_t lines = 0;
    bool pruned = false;
    while (lines < kMaxSeenFileLines && std::getline(input, line)) {
        ++lines;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::istringstream in(line);
        std::string tag;
        std::string me;
        std::string peer;
        in >> tag >> me >> peer;
        if (!IsValidUsername(me) || !IsValidUsername(peer)) continue;
        SeenPeerIds& entry = seenIds_[me + " " + peer];
        if (tag == "S") {
            std::string id;
            std::string tsText;
            long long ts = 0;
            in >> id >> tsText;
            if (!IsLowerHex(id, 32) || !ParseUnixTs(tsText, ts)) continue;
            if (ts < minTs) {
                pruned = true;  // rejected by age anyway
                continue;
            }
            bool evicted = false;
            InsertSeenLocked(entry, id, ts, evicted);
        } else if (tag == "W") {
            std::string tsText;
            long long ts = 0;
            in >> tsText;
            if (ParseUnixTs(tsText, ts)) entry.watermark = std::max(entry.watermark, ts);
        }
    }
    seenFileLines_ = lines;
    std::size_t live = 0;
    for (const auto& entry : seenIds_) live += entry.second.ids.size() + 1;
    if (pruned || seenFileLines_ > live * 2 + 1000) CompactSeenIdsLocked();
}

void ChatClient::CompactSeenIdsLocked() {
    const std::string target = rm1::kSeenIdsFile;
    const std::string temp = target + ".tmp";
    const long long minTs = NowUnix() - rm1::kMaxAgeSeconds;
    std::size_t lines = 0;
    {
        std::ofstream out(temp, std::ios::trunc);
        if (!out.is_open()) return;
        for (const auto& entry : seenIds_) {
            // A watermark older than the age limit adds nothing.
            if (entry.second.watermark >= minTs) {
                out << "W " << entry.first << " " << entry.second.watermark << "\n";
                ++lines;
            }
            for (const auto& id : entry.second.ids) {
                out << "S " << entry.first << " " << id.first << " " << id.second << "\n";
                ++lines;
            }
        }
        out.flush();
        if (!out.good()) {
            out.close();
            std::remove(temp.c_str());
            return;
        }
    }
    if (std::rename(temp.c_str(), target.c_str()) != 0) {
        std::remove(target.c_str());
        if (std::rename(temp.c_str(), target.c_str()) != 0) {
            std::remove(temp.c_str());
            return;
        }
    }
    seenFileLines_ = lines;
}

ChatClient::SeenResult ChatClient::CheckAndRecordMessageId(const std::string& me,
                                                           const std::string& peer,
                                                           const std::string& msgId,
                                                           long long senderTs) {
    const long long now = NowUnix();
    if (senderTs > now + rm1::kMaxFutureSeconds) return SeenResult::BadTimestamp;
    if (senderTs < now - rm1::kMaxAgeSeconds) return SeenResult::TooOld;
    std::lock_guard<std::mutex> lock(seenMutex_);
    LoadSeenIdsLocked();
    const std::string key = me + " " + peer;
    SeenPeerIds& entry = seenIds_[key];
    if (senderTs <= entry.watermark) return SeenResult::TooOld;
    if (entry.ids.count(msgId) > 0) return SeenResult::Duplicate;
    bool evicted = false;
    InsertSeenLocked(entry, msgId, senderTs, evicted);
    {
        // Append-only between compactions; flushed before the message is shown.
        std::ofstream out(rm1::kSeenIdsFile, std::ios::app);
        if (out.is_open()) {
            out << "S " << key << " " << msgId << " " << senderTs << "\n";
            if (evicted) out << "W " << key << " " << entry.watermark << "\n";
            out.flush();
        }
    }
    seenFileLines_ += evicted ? 2 : 1;
    std::size_t live = 0;
    for (const auto& peerEntry : seenIds_) live += peerEntry.second.ids.size() + 1;
    if (seenFileLines_ > live * 2 + 1000) CompactSeenIdsLocked();
    return SeenResult::Accepted;
}

void ChatClient::HandleRoomLine(const std::string& rest, bool fromHistory) {
    std::string from;
    std::string payload;
    long long ts = 0;
    if (!SplitSenderTsPayload(rest, from, ts, payload)) return;
    std::string text;
    if (!river::base64::DecodeToString(payload, text)) text = "[mensaje ilegible]";
    state_.AddRoomMessage(from, text, ts, fromHistory, CurrentUser());
}

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

bool ChatClient::SendAttachment(const std::string& fromUser, const AttachmentDraft& attachment) {
    if (fromUser.empty()) {
        state_.SetLastError(UiText("No authenticated identity to send attachments.",
                                   "No hay identidad autenticada para enviar adjuntos."));
        return false;
    }
    if (attachment.localPath.empty() || attachment.displayName.empty()) {
        state_.SetLastError(UiText("Invalid attachment.", "Adjunto invalido."));
        return false;
    }
    if (attachment.sizeBytes > kMaxAttachmentBytes) {
        state_.SetLastError(UiText("Attachment too large. Current limit: " + FormatAttachmentSize(kMaxAttachmentBytes) + ".",
                                   "Adjunto demasiado grande. Limite actual: " + FormatAttachmentSize(kMaxAttachmentBytes) + "."));
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
    if (SendRawLine("[ATTACH2]:" + id + ":" + kind + ":" +
                    river::base64::EncodeString(attachment.displayName) + ":" +
                    river::base64::EncodeString(attachment.mimeType) + ":" +
                    std::to_string(attachment.sizeBytes) + "\n") < 0) {
        std::lock_guard<std::mutex> lock(offeredAttachmentMutex_);
        offeredAttachments_.erase(id);
        state_.SetLastError(UiText("Could not announce the attachment.", "No se pudo anunciar el adjunto."));
        return false;
    }

    state_.SetStatusDetail(UiText("Attachment announced: " + attachment.displayName,
                                  "Adjunto anunciado: " + attachment.displayName));
    state_.ClearLastError();
    return true;
}

bool ChatClient::RequestAttachment(const AttachmentPayload& attachment, const std::string& savePath, const std::string& mode) {
    if (attachment.ownerUser.empty() || !IsValidAttachmentId(attachment.id) || savePath.empty() ||
        mode.find_first_of("|:") != std::string::npos) {
        state_.SetLastError(UiText("Invalid attachment request.", "Solicitud de adjunto invalida."));
        return false;
    }
    if (attachment.sizeBytes > kMaxAttachmentBytes) {
        state_.SetLastError(UiText("Attachment too large. Current limit: " + FormatAttachmentSize(kMaxAttachmentBytes) + ".",
                                   "Adjunto demasiado grande. Limite actual: " + FormatAttachmentSize(kMaxAttachmentBytes) + "."));
        return false;
    }

    IncomingAttachmentTransfer transfer;
    transfer.attachment = attachment;
    transfer.ownerUser = attachment.ownerUser;
    transfer.mode = mode;
    transfer.targetPath = savePath;
    const std::string key = attachment.ownerUser + "|" + attachment.id;
    IncomingAttachmentTransfer replaced;
    {
        std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
        auto existing = incomingAttachments_.find(key);
        if (existing != incomingAttachments_.end()) {
            replaced = std::move(existing->second);
            existing->second = std::move(transfer);
        } else {
            incomingAttachments_.emplace(key, std::move(transfer));
        }
    }
    DiscardIncomingTransfer(replaced);
    state_.UpdateAttachmentState(attachment.ownerUser, attachment.id, AttachmentTransferState::Requested);

    // Attachment control goes as [PMX] (E2E, never queued offline by the server).
    if (!SendSealedToUser(attachment.ownerUser, "@attachreq|" + attachment.id + "|" + mode, true)) {
        IncomingAttachmentTransfer dropped;
        {
            std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
            auto it = incomingAttachments_.find(key);
            if (it != incomingAttachments_.end()) {
                dropped = std::move(it->second);
                incomingAttachments_.erase(it);
            }
        }
        DiscardIncomingTransfer(dropped);
        state_.UpdateAttachmentState(attachment.ownerUser, attachment.id, AttachmentTransferState::Available);
        state_.SetLastError(UiText("Could not request the attachment.", "No se pudo solicitar el adjunto."));
        return false;
    }
    return true;
}

bool ChatClient::HandleAttachmentBroadcast(const std::string& line) {
    // ATTACH2:<fromUser>:<id>:<kind>:<nameB64>:<mimeB64>:<size>
    if (line.rfind("ATTACH2:", 0) != 0) return false;
    const std::vector<std::string> parts = SplitByDelimiter(line.substr(8), ':');
    if (parts.size() != 6) return true;

    const std::string& sender = parts[0];
    AttachmentPayload attachment;
    attachment.id = parts[1];
    attachment.ownerUser = sender;
    attachment.kind =
        parts[2] == "image" ? AttachmentKind::Image :
        parts[2] == "video" ? AttachmentKind::Video : AttachmentKind::File;
    if (!river::base64::DecodeToString(parts[3], attachment.displayName) ||
        !river::base64::DecodeToString(parts[4], attachment.mimeType)) {
        return true;
    }
    long long size = 0;
    if (!ParseUnixTs(parts[5], size)) return true;
    attachment.sizeBytes = static_cast<std::size_t>(size);
    if (attachment.sizeBytes > kMaxAttachmentBytes || !IsValidAttachmentId(attachment.id) ||
        !IsValidUsername(sender) || attachment.displayName.empty()) {
        return true;
    }
    attachment.state = AttachmentTransferState::Available;

    if (sender == CurrentUser()) {
        std::lock_guard<std::mutex> lock(offeredAttachmentMutex_);
        auto it = offeredAttachments_.find(attachment.id);
        if (it != offeredAttachments_.end()) attachment.localPath = it->second.localPath;
    }

    state_.AddAttachmentOffer(sender, attachment);
    return true;
}

void ChatClient::HandleAttachmentRequest(const UploadJob& job) {
    const std::string& requester = job.requester;
    const std::string& requesterPub = job.requesterPub;
    const std::string& attachmentId = job.attachmentId;
    const std::string& mode = job.mode;
    auto sendError = [&](const std::string& text) {
        SealAndSendLine(true, requester, requesterPub,
                        "@attacherr|" + attachmentId + "|" + river::base64::EncodeString(text));
    };

    AttachmentDraft draft;
    {
        std::lock_guard<std::mutex> lock(offeredAttachmentMutex_);
        auto it = offeredAttachments_.find(attachmentId);
        if (it == offeredAttachments_.end()) {
            sendError("Attachment unavailable.");
            return;
        }
        draft = it->second;
    }

    std::ifstream input(draft.localPath, std::ios::binary);
    if (!input.is_open()) {
        sendError("Could not open the source attachment.");
        return;
    }

    if (draft.sizeBytes > kMaxAttachmentBytes) {
        sendError("Attachment exceeds the transfer limit.");
        return;
    }

    const std::string contentSha256 = HashFileSha256(draft.localPath);
    if (contentSha256.empty()) {
        sendError("Could not hash the source attachment.");
        return;
    }
    const std::string kind =
        draft.kind == AttachmentKind::Image ? "image" :
        draft.kind == AttachmentKind::Video ? "video" : "file";
    const std::size_t totalChunks = draft.sizeBytes == 0 ? 1 : (draft.sizeBytes + kAttachmentBinaryChunkBytes - 1) / kAttachmentBinaryChunkBytes;

    if (!SealAndSendLine(true,
                         requester,
                         requesterPub,
                         "@attachmeta|" + attachmentId + "|" + kind + "|" +
                             river::base64::EncodeString(draft.displayName) + "|" +
                             river::base64::EncodeString(draft.mimeType) + "|" +
                             std::to_string(draft.sizeBytes) + "|" + mode + "|" +
                             std::to_string(totalChunks) + "|" + contentSha256)) {
        return;
    }

    const std::string me = CurrentUser();
    const std::string context = "att:" + attachmentId;
    for (std::size_t index = 0; index < totalChunks; ++index) {
        if (stopRequested_.load() || job.generation != connGeneration_.load()) return;
        std::string plainChunk;
        if (draft.sizeBytes > 0) {
            std::vector<char> buffer(kAttachmentBinaryChunkBytes);
            input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            const std::streamsize got = input.gcount();
            if (got <= 0) {
                sendError("Transferencia interrumpida.");
                return;
            }
            plainChunk.assign(buffer.data(), static_cast<std::size_t>(got));
        }
        // Each chunk is its own E2E envelope, sealed owner -> requester.
        std::string encryptedChunk;
        if (me.empty() ||
            !SealWithIdentity(context, me, requester, requesterPub, plainChunk, encryptedChunk) ||
            !SendAttachmentChunkFrame(requester,
                                      attachmentId,
                                      static_cast<int>(index),
                                      static_cast<int>(totalChunks),
                                      encryptedChunk)) {
            sendError("Transferencia interrumpida.");
            return;
        }
    }
}

void ChatClient::FinishIncomingAttachment(IncomingAttachmentTransfer transfer) {
    // Close the stream before hashing/renaming (Windows cannot rename an open file).
    bool ok = true;
    std::string error;
    if (transfer.partFile) {
        transfer.partFile->flush();
        ok = transfer.partFile->good();
        transfer.partFile->close();
        transfer.partFile.reset();
    }
    if (!ok) {
        attachment_part::RemovePartFile(transfer.partPath);
        error = "Could not save the received attachment.";
    } else {
        ok = attachment_part::FinalizePartFile(transfer.partPath,
                                               transfer.targetPath,
                                               transfer.attachment.sizeBytes,
                                               transfer.attachment.contentSha256,
                                               error);
    }
    if (!ok) {
        state_.UpdateAttachmentState(transfer.ownerUser, transfer.attachment.id, AttachmentTransferState::Failed);
        state_.SetLastError(error);
        return;
    }

    state_.UpdateAttachmentState(transfer.ownerUser,
                                 transfer.attachment.id,
                                 AttachmentTransferState::Received,
                                 transfer.targetPath);
    state_.SetStatusDetail(UiText("Attachment received: " + transfer.attachment.displayName,
                                  "Adjunto recibido: " + transfer.attachment.displayName));
    state_.AddSystemLog("SYSTEM: Attachment received and saved to " + transfer.targetPath);
    if (transfer.attachment.kind != AttachmentKind::File &&
        !IsAttachmentSafeToOpen(transfer.attachment.kind, transfer.targetPath)) {
        state_.AddSystemLog("SYSTEM: [!] " + transfer.attachment.displayName +
                            " no tiene una extension de imagen/video permitida: no se abrira desde el chat. "
                            "Usa Guardar como... y revisalo antes de ejecutarlo.");
    }
    state_.ClearLastError();
}

bool ChatClient::HandleAttachmentPrivateControl(const std::string& sender,
                                                const std::string& senderPub,
                                                const std::string& payload,
                                                bool unverifiedKey) {
    if (payload.rfind("@attachreq|", 0) == 0) {
        const std::vector<std::string> parts = SplitByDelimiter(payload, '|');
        if (parts.size() < 3 || !IsValidAttachmentId(parts[1]) || parts[2].find(':') != std::string::npos ||
            parts[2].size() > 32) {
            return true;
        }
        UploadJob job;
        job.requester = sender;
        job.requesterPub = senderPub;
        job.attachmentId = parts[1];
        job.mode = parts[2];
        job.generation = connGeneration_.load();
        if (unverifiedKey) {
            // The requester's key changed and was not accepted: hold the upload.
            bool added = false;
            {
                std::lock_guard<std::mutex> lock(peerMutex_);
                auto& held = heldUploads_[sender];
                bool duplicate = false;
                for (const auto& existing : held) duplicate = duplicate || existing.attachmentId == job.attachmentId;
                if (!duplicate && held.size() < kMaxHeldUploadsPerPeer) {
                    held.push_back(job);
                    added = true;
                }
            }
            if (added) {
                state_.AddSystemLog("SYSTEM: Solicitud de adjunto de " + sender +
                                    " retenida: su clave cambio. Usa /trust " + sender +
                                    " para aceptar la nueva clave.");
            }
            return true;
        }
        StartAttachmentUpload(job);
        return true;
    }

    if (payload.rfind("@attachmeta|", 0) == 0) {
        const std::vector<std::string> parts = SplitByDelimiter(payload, '|');
        if (parts.size() < 8 || !IsValidAttachmentId(parts[1])) return true;

        const std::string key = sender + "|" + parts[1];
        IncomingAttachmentTransfer dropped;
        std::string failure;
        {
            std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
            auto pending = incomingAttachments_.find(key);
            if (pending == incomingAttachments_.end()) return true;
            IncomingAttachmentTransfer& transfer = pending->second;
            if (transfer.partFile) return true;  // duplicate metadata for a transfer already in flight
            if (unverifiedKey) failure = "La clave de " + sender + " cambio: usa /trust " + sender +
                                         " y vuelve a pedir el adjunto.";
            transfer.ownerUser = sender;
            transfer.ownerPub = senderPub;
            transfer.attachment.id = parts[1];
            transfer.attachment.ownerUser = sender;
            transfer.attachment.kind =
                parts[2] == "image" ? AttachmentKind::Image :
                parts[2] == "video" ? AttachmentKind::Video : AttachmentKind::File;
            river::base64::DecodeToString(parts[3], transfer.attachment.displayName);
            river::base64::DecodeToString(parts[4], transfer.attachment.mimeType);
            transfer.attachment.sizeBytes = static_cast<std::size_t>(std::strtoull(parts[5].c_str(), nullptr, 10));
            transfer.mode = parts[6];
            transfer.totalChunks = std::atoi(parts[7].c_str());
            if (parts.size() >= 9) transfer.attachment.contentSha256 = parts[8];
            transfer.receivedChunks = 0;
            transfer.attachment.state = AttachmentTransferState::Requested;
            if (transfer.targetPath.empty())
                transfer.targetPath = BuildAttachmentCachePath(sender, parts[1], transfer.attachment.displayName);

            if (!failure.empty()) {
                // unverified sender key (set above)
            } else if (transfer.attachment.sizeBytes > kMaxAttachmentBytes) {
                failure = "Attachment exceeds the transfer limit.";
            } else if (transfer.totalChunks != attachment_part::ExpectedChunkCount(transfer.attachment.sizeBytes)) {
                failure = "Attachment metadata is invalid.";
            } else {
                transfer.receivedIndices.assign(static_cast<std::size_t>(transfer.totalChunks), false);
                // Exclusive, unique .part name: never truncates another transfer's file.
                transfer.partFile = attachment_part::CreateUniquePartFile(transfer.targetPath, transfer.partPath);
                if (!transfer.partFile) {
                    transfer.partPath.clear();
                    failure = "Could not save the received attachment.";
                }
            }
            if (!failure.empty()) {
                dropped = std::move(transfer);
                incomingAttachments_.erase(pending);
            }
        }
        if (!failure.empty()) {
            DiscardIncomingTransfer(dropped);
            state_.UpdateAttachmentState(sender, parts[1], AttachmentTransferState::Failed);
            state_.SetLastError(failure);
        }
        return true;
    }

    if (payload.rfind("@attacherr|", 0) == 0) {
        const std::vector<std::string> parts = SplitByDelimiter(payload, '|');
        if (parts.size() < 3) return true;

        std::string errorText;
        river::base64::DecodeToString(parts[2], errorText);
        IncomingAttachmentTransfer dropped;
        {
            std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
            auto it = incomingAttachments_.find(sender + "|" + parts[1]);
            if (it != incomingAttachments_.end()) {
                dropped = std::move(it->second);
                incomingAttachments_.erase(it);
            }
        }
        DiscardIncomingTransfer(dropped);
        state_.UpdateAttachmentState(sender, parts[1], AttachmentTransferState::Failed);
        state_.SetLastError(errorText.empty() ? UiText("Could not transfer the attachment.", "No se pudo transferir el adjunto.")
                                           : UiText(errorText));
        return true;
    }

    return false;
}

bool ChatClient::SendAttachmentChunkFrame(const std::string& target,
                                          const std::string& attachmentId,
                                          int index,
                                          int totalChunks,
                                          const std::string& encryptedChunk) {
    if (target.empty() || target.size() > 255 ||
        attachmentId.empty() || attachmentId.size() > 255 ||
        index < 0 || totalChunks <= 0 ||
        encryptedChunk.empty()) {
        return false;
    }

    std::string payload;
    AppendSizedString(payload, target);
    AppendSizedString(payload, attachmentId);
    AppendU32(payload, static_cast<std::uint32_t>(index));
    AppendU32(payload, static_cast<std::uint32_t>(totalChunks));
    payload.append(encryptedChunk);

    std::lock_guard<std::mutex> lock(socketMutex_);
    return IsSocketValid(socket_) && SendFrame(socket_, kFrameTypeAttachmentChunk, payload);
}

bool ChatClient::HandleAttachmentChunkFrame(const std::string& payload) {
    std::size_t offset = 0;
    std::string sender;
    std::string attachmentId;
    std::uint32_t index = 0;
    std::uint32_t totalChunks = 0;
    if (!ReadSizedString(payload, offset, sender) ||
        !ReadSizedString(payload, offset, attachmentId) ||
        !ReadU32(payload, offset, index) ||
        !ReadU32(payload, offset, totalChunks) ||
        totalChunks == 0 ||
        totalChunks > (kMaxAttachmentBytes + kAttachmentBinaryChunkBytes - 1) / kAttachmentBinaryChunkBytes ||
        index >= totalChunks ||
        offset >= payload.size() ||
        !IsValidAttachmentId(attachmentId)) {
        return true;
    }

    const std::string key = sender + "|" + attachmentId;
    std::string ownerPub;
    {
        std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
        auto it = incomingAttachments_.find(key);
        if (it == incomingAttachments_.end() || !it->second.partFile) return true;
        ownerPub = it->second.ownerPub;
    }

    // Chunk envelopes are sealed owner -> requester with context "att:<id>".
    std::string plainChunk;
    const std::string me = CurrentUser();
    const bool opened = !ownerPub.empty() && !me.empty() &&
                        OpenWithIdentity("att:" + attachmentId, sender, me, ownerPub,
                                         payload.substr(offset), plainChunk) &&
                        plainChunk.size() <= kAttachmentBinaryChunkBytes;

    IncomingAttachmentTransfer finished;
    bool done = false;
    std::string failure;
    {
        // A chunk write is at most kAttachmentBinaryChunkBytes, so it stays under the lock;
        // that keeps FailPendingIncomingAttachments from deleting the file mid-write.
        std::lock_guard<std::mutex> lock(incomingAttachmentMutex_);
        auto it = incomingAttachments_.find(key);
        if (it == incomingAttachments_.end()) return true;

        IncomingAttachmentTransfer& transfer = it->second;
        if (!transfer.partFile || transfer.totalChunks != static_cast<int>(totalChunks)) return true;
        const int chunkIndex = static_cast<int>(index);
        if (transfer.receivedIndices[index]) return true;  // duplicate

        if (!opened) {
            failure = "Attachment chunk integrity check failed.";
        } else if (plainChunk.size() != attachment_part::ExpectedChunkSize(transfer.attachment.sizeBytes,
                                                                           transfer.totalChunks,
                                                                           chunkIndex)) {
            failure = "Attachment integrity check failed.";
        } else if (!attachment_part::WriteChunkAt(*transfer.partFile, chunkIndex, plainChunk)) {
            failure = "Could not save the received attachment.";
        } else {
            transfer.receivedIndices[index] = true;
            transfer.receivedChunks++;
        }

        if (!failure.empty() || transfer.receivedChunks == transfer.totalChunks) {
            finished = std::move(transfer);
            incomingAttachments_.erase(it);
            done = failure.empty();
        }
    }
    if (!failure.empty()) {
        DiscardIncomingTransfer(finished);
        state_.UpdateAttachmentState(sender, attachmentId, AttachmentTransferState::Failed);
        state_.SetLastError(failure);
        return true;
    }
    // Hashing and renaming happen outside incomingAttachmentMutex_.
    if (done) FinishIncomingAttachment(std::move(finished));
    return true;
}

// ---------------------------------------------------------------------------
// Receive loop
// ---------------------------------------------------------------------------

void ChatClient::ReceiveLoop(SocketHandle sock) {
    AppendClientLog("ReceiveLoop start");
    const LinkTimings timings = ClientLinkTimings();
    SetSocketRecvTimeout(sock, timings.pollSec);
    auto lastFrameAt = std::chrono::steady_clock::now();
    bool keepaliveSent = false;
    while (!stopRequested_.load()) {
        // Key requests made while handling a burst of lines (e.g. the offline
        // PMs after login) are coalesced: they go out as batch KEY_GET lines
        // once no further line arrives within kKeyBatchWindowMs, the window
        // expires, or a line is full.
        while (true) {
            std::size_t queued = 0;
            std::chrono::steady_clock::time_point since;
            {
                std::lock_guard<std::mutex> lock(peerMutex_);
                queued = keyRequestQueue_.size();
                since = keyQueueSince_;
            }
            if (queued == 0) {
                // Names the server left unanswered (key-lookup budget) are asked again later.
                std::chrono::steady_clock::time_point retryAt;
                bool retry = false;
                {
                    std::lock_guard<std::mutex> lock(peerMutex_);
                    retry = keyRetryPending_;
                    retryAt = keyRetryAt_;
                }
                if (!retry) break;
                const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                    retryAt - std::chrono::steady_clock::now()).count();
                if (left > 0 && SocketReadable(sock, static_cast<int>(std::min<long long>(left, 1000)))) break;
                if (left > 0) continue;
                {
                    std::lock_guard<std::mutex> lock(peerMutex_);
                    keyRetryPending_ = false;
                    keyRequestQueue_.assign(keyRequestsInFlight_.begin(), keyRequestsInFlight_.end());
                    keyQueueSince_ = std::chrono::steady_clock::now();
                }
                FlushKeyRequests();
                break;
            }
            const auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - since).count();
            if (queued >= kMaxKeyGetNamesPerLine || waited >= kKeyBatchWindowMs ||
                !SocketReadable(sock, static_cast<int>(kKeyBatchWindowMs - waited))) {
                FlushKeyRequests();
            }
            break;
        }
        std::uint16_t frameType = 0;
        std::string line;
        const RecvStatus status = RecvFrameOrTimeout(sock, frameType, line, 1024 * 1024);
        if (status == RecvStatus::kTimeout) {
            // Idle link (SO_RCVTIMEO is only the polling interval).
            const auto idleSec = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - lastFrameAt).count();
            if (idleSec >= timings.deadSec) {
                AppendClientLog("ReceiveLoop link silent for " + std::to_string(idleSec) + " s; closing");
                break;
            }
            if (!keepaliveSent && idleSec >= timings.keepaliveSec && authVerified_.load()) {
                // Silent keep-alive: the PONG is ignored (no /ping outstanding).
                AppendClientLog("ReceiveLoop keepalive PING");
                keepaliveSent = SendRawLine("PING\n") >= 0;
            }
            continue;
        }
        if (status != RecvStatus::kOk) {
#ifdef _WIN32
            AppendClientLog("ReceiveLoop frame read failed wsa=" + std::to_string(WSAGetLastError()));
#else
            AppendClientLog("ReceiveLoop frame read failed errno=" + std::to_string(errno));
#endif
            break;
        }
        lastFrameAt = std::chrono::steady_clock::now();
        keepaliveSent = false;

        if (frameType == kFrameTypeAttachmentChunk) {
            HandleAttachmentChunkFrame(line);
            continue;
        }
        if (frameType != kFrameTypeText) {
            AppendClientLog("ReceiveLoop unsupported frame type=" + std::to_string(frameType));
            continue;
        }

        AppendClientLog("ReceiveLoop frame bytes=" + std::to_string(line.size()));
        if (line == "PING") {
            AppendClientLog("ReceiveLoop line=PING");
            SendRawLine("PONG\n");
        } else if (line == "PONG") {
            HandleServerPong();
        } else if (line.rfind("MSG:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=MSG");
            HandleRoomLine(line.substr(4), false);
        } else if (line.rfind("HIST:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=HIST");
            HandleRoomLine(line.substr(5), true);
        } else if (line.rfind("HISTORY_BEGIN:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=HISTORY_BEGIN");
            inHistory_ = true;
        } else if (line == "HISTORY_END") {
            AppendClientLog("ReceiveLoop line=HISTORY_END");
            inHistory_ = false;
        } else if (line.rfind("PM2:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=PM2");
            HandleIncomingSealed(line.substr(4), false);
        } else if (line.rfind("PMX:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=PMX");
            HandleIncomingSealed(line.substr(4), true);
        } else if (line.rfind("KEY:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=KEY");
            HandleKeyReply(line.substr(4));
        } else if (line.rfind("KEY_CHANGED:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=KEY_CHANGED");
            HandleKeyChanged(line.substr(12));
        } else if (line.rfind("ATTACH2:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=ATTACH2");
            HandleAttachmentBroadcast(line);
        } else if (line.rfind("AUTH_CHALLENGE2:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=AUTH_CHALLENGE2");
            if (!SendAuthProof(line)) {
                FailAuthFatal(UiText("Could not complete the authentication challenge.",
                                     "No se pudo completar el reto de autenticacion."));
                break;
            }
        } else if (line.rfind("AUTH_OK:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=AUTH_OK");
            if (!VerifyAuthOk(line)) {
                FailAuthFatal(UiText("Invalid server signature: mutual authentication failed. Connection closed.",
                                     "Firma del servidor invalida: autenticacion mutua fallida. Conexion cerrada."));
                break;
            }
        } else if (IsSystemNotice(line, "FIRST LOGIN")) {
            AppendClientLog("ReceiveLoop line=FIRST LOGIN");
            if (!authVerified_.load()) {
                FailAuthFatal(UiText("The server did not prove its identity (no valid AUTH_OK). Connection closed.",
                                     "El servidor no verifico su identidad (falta AUTH_OK valido). Conexion cerrada."));
                break;
            }
            state_.SetAuthActionPending(false);
            state_.SetCredentialChangePending(false);
            state_.SetMustChangeCredentials(true);
            state_.SetConnectionState(ConnState::FIRST_LOGIN_REQUIRED);
            state_.SetStatusDetail(UiText("First access detected. You must change ID and key.",
                                          "Primer acceso detectado. Debes cambiar el ID y la clave."));
            state_.ClearLastError();
        } else if (IsSystemNotice(line, "ACCESO CONCEDIDO")) {
            AppendClientLog("ReceiveLoop line=ACCESO CONCEDIDO");
            if (!authVerified_.load()) {
                FailAuthFatal(UiText("The server did not prove its identity (no valid AUTH_OK). Connection closed.",
                                     "El servidor no verifico su identidad (falta AUTH_OK valido). Conexion cerrada."));
                break;
            }
            // Credentials the identity file is protected with (new ones after a
            // first-login change, plus the old ones to migrate the existing file).
            std::string loginUser;
            std::string loginPass;
            std::string oldUser;
            std::string oldPass;
            {
                std::lock_guard<std::mutex> lock(reloginMutex_);
                if (!queuedLoginUser_.empty() && !queuedLoginPass_.empty()) {
                    loginUser = queuedLoginUser_;
                    loginPass = queuedLoginPass_;
                    oldUser = pendingLoginUser_;
                    oldPass = pendingLoginPass_;
                } else {
                    loginUser = pendingLoginUser_;
                    loginPass = pendingLoginPass_;
                }
            }
            RememberSessionCredentials();
            if (!loginUser.empty()) SetCurrentUser(loginUser);
            QueueAutoLogin("", "");
            state_.SetAuthenticated(true);
            state_.SetMustChangeCredentials(false);
            state_.SetAuthActionPending(false);
            state_.SetCredentialChangePending(false);
            state_.SetConnectionState(ConnState::AUTHENTICATED);
            state_.SetStatusDetail(UiText("Secure channel authenticated.", "Canal seguro autenticado."));
            state_.ClearLastError();
            if (LoadOrCreateIdentity(loginUser, loginPass, oldUser, oldPass)) {
                PublishIdentityKey();
            } else {
                state_.SetLastError(UiText("Could not prepare the identity key: private messages will not be available.",
                                           "No se pudo preparar la clave de identidad: los mensajes privados no estaran disponibles."));
            }
            WipeString(loginPass);
            WipeString(oldPass);
        } else if (line.rfind("SESSION:", 0) == 0) {
            AppendClientLog("ReceiveLoop line=SESSION");
            state_.SetStatusDetail(UiText("Secure session active.", "Sesion segura activa."));
        } else if (IsSystemNotice(line, "UPLINK ESTABLISHED")) {
            AppendClientLog("ReceiveLoop line=UPLINK ESTABLISHED");
            state_.SetConnectionState(ConnState::TOR_READY);
            if (!BannerHasProto2(line)) {
                AppendClientLog("ReceiveLoop incompatible protocol");
                bannerState_.store(2);
                SetStickyAuthError(UiText(kIncompatibleServerErrorEn, kIncompatibleServerError));
                backoffCancel_.store(false);
                reconnectDelaySeconds_.store(kFatalAuthBackoffSeconds);  // if the server drops us, do not hammer it
                state_.SetAuthActionPending(false);
                state_.SetStatusDetail(UiText("Incompatible server.", "Servidor incompatible."));
                state_.SetLastError(UiText(kIncompatibleServerErrorEn, kIncompatibleServerError));
                state_.AddSystemLog(std::string("SYSTEM: ") + kIncompatibleServerError);
                continue;
            }
            bannerState_.store(1);
            state_.SetStatusDetail(UiText("Tor channel established. Waiting for login.",
                                          "Canal Tor establecido. Esperando login."));
            state_.ClearLastError();
            ApplyStickyAuthError();
            {
                // Keep the reason for a forced disconnect visible on the login screen.
                std::lock_guard<std::mutex> lock(reloginMutex_);
                if (!disconnectNotice_.empty()) {
                    state_.SetLastError(disconnectNotice_);
                    disconnectNotice_.clear();
                }
            }
            std::string queuedUser;
            std::string queuedPass;
            if (ConsumeQueuedAutoLogin(queuedUser, queuedPass)) {
                AppendClientLog("ReceiveLoop auto-login");
                SendLogin(queuedUser, queuedPass);
            } else if (ConsumeRememberedCredentials(queuedUser, queuedPass)) {
                AppendClientLog("ReceiveLoop session-resume");
                state_.AddSystemLog("SYSTEM: Enlace restablecido. Reautenticando como " + queuedUser + "...");
                SendLogin(queuedUser, queuedPass);
            }
            WipeString(queuedPass);
        } else if (IsSystemNotice(line, "CLIENTE OBSOLETO")) {
            AppendClientLog("ReceiveLoop line=CLIENTE OBSOLETO");
            // The server closes the link; do not keep re-sending credentials to it.
            state_.AddSystemLog(line);
            FailAuthFatal(UiText("The server rejected this client as obsolete (protocol 2).",
                                 "El servidor rechazo este cliente como obsoleto (protocolo 2)."));
            break;
        } else if (IsSystemNotice(line, "ACTUALIZADO. RECONECTA")) {
            AppendClientLog("ReceiveLoop line=ACTUALIZADO");
            state_.SetMustChangeCredentials(false);
            state_.SetAuthActionPending(false);
            state_.SetCredentialChangePending(false);
            state_.SetConnectionState(ConnState::RECONNECTING);
            state_.SetStatusDetail(UiText("Credentials updated. Re-authenticating as soon as the channel is ready again...",
                                          "Credenciales actualizadas. Reautenticando en cuanto el canal vuelva a estar listo..."));
            state_.ClearLastError();
        } else if (IsSystemNotice(line, "ACTUALIZADO")) {
            AppendClientLog("ReceiveLoop line=ACTUALIZADO SIMPLE");
            state_.SetMustChangeCredentials(false);
            state_.SetAuthActionPending(false);
            state_.SetCredentialChangePending(false);
            state_.SetStatusDetail(UiText("Credentials updated. Completing access...",
                                          "Credenciales actualizadas. Finalizando acceso..."));
            state_.ClearLastError();
        } else if (IsSystemNotice(line, "CREDENCIALES INCORRECTAS")) {
            AppendClientLog("ReceiveLoop line=CREDENCIALES INCORRECTAS");
            ForgetSessionCredentials();
            ResetAuthExchange();
            state_.SetAuthActionPending(false);
            state_.SetConnectionState(ConnState::TOR_READY);
            state_.SetStatusDetail(UiText("Tor channel ready. Waiting for new credentials.",
                                          "Canal Tor listo. Esperando nuevas credenciales."));
            state_.SetLastError(UiText("Incorrect credentials.", "Credenciales incorrectas."));
            state_.AddSystemLog("SYSTEM: CREDENCIALES INCORRECTAS.");
        } else if (IsSystemNotice(line, "HWID NO RECONOCIDO")) {
            AppendClientLog("ReceiveLoop line=HWID NO RECONOCIDO");
            ForgetSessionCredentials();
            ResetAuthExchange();
            state_.SetAuthActionPending(false);
            state_.SetConnectionState(ConnState::TOR_READY);
            state_.SetStatusDetail(UiText("Tor channel ready. Access denied for this HWID.",
                                          "Canal Tor listo. Acceso denegado por HWID."));
            state_.SetLastError(UiText("This machine does not match the authorized HWID.",
                                       "Esta maquina no coincide con el HWID autorizado."));
            state_.AddSystemLog("SYSTEM: HWID NO RECONOCIDO.");
        } else if (IsSystemNotice(line, "ACCESO BLOQUEADO")) {
            AppendClientLog("ReceiveLoop line=ACCESO BLOQUEADO");
            ForgetSessionCredentials();
            ResetAuthExchange();
            if (state_.IsAuthenticated()) {
                std::lock_guard<std::mutex> lock(reloginMutex_);
                disconnectNotice_ = ServerNoticeText(line.substr(8));
            }
            state_.SetAuthActionPending(false);
            state_.SetCredentialChangePending(false);
            state_.SetConnectionState(ConnState::TOR_READY);
            state_.SetStatusDetail(UiText("Tor channel ready. Access blocked.", "Canal Tor listo. Acceso bloqueado."));
            state_.SetLastError(UiText("Access blocked for this machine.", "Acceso bloqueado para esta maquina."));
            state_.AddSystemLog("SYSTEM: ACCESO BLOQUEADO.");
        } else if (IsSystemNotice(line, "KICKED BY ADMIN") || IsSystemNotice(line, "SESION REEMPLAZADA")) {
            AppendClientLog("ReceiveLoop line=SESSION TERMINATED");
            // Do not silently fight the admin or a newer session of the same identity.
            ForgetSessionCredentials();
            {
                std::lock_guard<std::mutex> lock(reloginMutex_);
                disconnectNotice_ = ServerNoticeText(line.substr(8));
            }
            state_.SetLastError(ServerNoticeText(line.substr(8)));
            state_.AddSystemLog(line);
        } else if (IsSystemNotice(line, "ERROR ACTUALIZANDO USUARIO")) {
            AppendClientLog("ReceiveLoop line=ERROR ACTUALIZANDO USUARIO");
            QueueAutoLogin("", "");
            state_.SetCredentialChangePending(false);
            state_.SetConnectionState(ConnState::FIRST_LOGIN_REQUIRED);
            state_.SetStatusDetail(UiText("Could not complete the initial update.",
                                          "No se pudo completar la actualizacion inicial."));
            state_.SetLastError(UiText("Could not update the user or key.",
                                       "No se pudo actualizar el usuario o la clave."));
            state_.AddSystemLog("SYSTEM: ERROR ACTUALIZANDO USUARIO.");
        } else if (IsSystemNotice(line, "LIMITE DE CONSULTAS DE CLAVES EXCEDIDO")) {
            AppendClientLog("ReceiveLoop line=KEY LOOKUP LIMIT");
            // Unanswered names stay in flight (not keyless) and are retried later.
            std::lock_guard<std::mutex> lock(peerMutex_);
            if (!keyRetryPending_) {
                keyRetryPending_ = true;
                keyRetryAt_ = std::chrono::steady_clock::now() + std::chrono::seconds(kKeyLookupRetrySeconds);
            }
        } else if (IsSystemNotice(line, "TIEMPO DE AUTENTICACION AGOTADO") ||
                   IsSystemNotice(line, "LIMITE DE TRAFICO EXCEDIDO")) {
            AppendClientLog("ReceiveLoop line=SERVER CLOSE NOTICE");
            // The server closes the link: show why, and wait a little before
            // reconnecting instead of spinning.
            const std::string reason = line.substr(8);
            {
                std::lock_guard<std::mutex> lock(reloginMutex_);
                disconnectNotice_ = ServerNoticeText(reason);
            }
            backoffCancel_.store(false);
            reconnectDelaySeconds_.store(kTransientBackoffSeconds);
            state_.SetAuthActionPending(false);
            state_.SetCredentialChangePending(false);
            state_.SetLastError(ServerNoticeText(reason));
            state_.AddSystemLog(line);
            break;
        } else if (IsSystemNotice(line, "CLAVE PUBLICA RECHAZADA")) {
            AppendClientLog("ReceiveLoop line=KEY REJECTED");
            state_.SetLastError(UiText("The server rejected the public key.", "El servidor rechazo la clave publica."));
            state_.AddSystemLog(line);
        } else {
            AppendClientLog("ReceiveLoop line=UNHANDLED");
            state_.AddIncomingWireMessage(line);
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
            state_.SetStatusDetail(UiText("Set THE_RIVER_ONION before connecting.",
                                          "Configura THE_RIVER_ONION antes de conectar."));
            state_.SetLastError(UiText("Missing local configuration: THE_RIVER_ONION (the server's .onion address).",
                                       "Falta la configuracion local: THE_RIVER_ONION (direccion .onion del servidor)."));
            AppendClientLog("NetworkLoop missing private config");
            ApplyStickyAuthError();
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }
        state_.SetConnectionState(hadIdentity ? ConnState::RECONNECTING : ConnState::CONNECTING);
        state_.SetAuthenticated(false);
        state_.SetMustChangeCredentials(false);
        state_.SetAuthActionPending(false);
        state_.SetCredentialChangePending(false);
        state_.SetStatusDetail(hadIdentity ? UiText("Re-establishing the Tor link...", "Restableciendo enlace Tor...")
                                            : UiText("Connecting to the Tor network...", "Conectando a la red Tor..."));
        AppendClientLog("NetworkLoop CONNECTING");

        const int proxyPort = river::TorProxyPort();
        TorEndpoint endpoint{
            river::kTorProxyIp,
            proxyPort,
            river::OnionAddress(),
            static_cast<unsigned short>(river::kTorOnionPort)
        };
        // Auto-start only manages a Tor on the default SocksPort; with a custom
        // THE_RIVER_TOR_PROXY_PORT the proxy is the user's responsibility.
        if (proxyPort == river::kTorProxyPort && !IsTorProxyReachable(river::kTorProxyIp, proxyPort)) {
            AppendClientLog("NetworkLoop Tor proxy missing, attempting auto-start");
            EnsureLocalTorIsRunning();
        }
        SocketHandle sock = ConnectViaTor(endpoint);
        if (!IsSocketValid(sock)) {
            AppendClientLog("NetworkLoop ConnectViaTor failed");
            state_.SetConnectionState(ConnState::DISCONNECTED);
            if (IsTermuxEnvironment() && !IsTorProxyReachable(river::kTorProxyIp, proxyPort)) {
                state_.SetStatusDetail(UiText("No local Tor proxy detected at 127.0.0.1:" + std::to_string(proxyPort) + ".",
                                              "No se detecto un proxy Tor local en 127.0.0.1:" + std::to_string(proxyPort) + "."));
                state_.SetLastError(UiText(
                    "On Termux start tor before the client: run run_termux_client.sh with --start-tor or start tor manually.",
                    "En Termux debes iniciar tor antes del cliente. Ejecuta el script run_termux_client.sh con --start-tor o arranca tor manualmente."));
            } else {
                state_.SetStatusDetail(UiText("Could not open an onion circuit to the server.",
                                              "No se pudo abrir un circuito onion hacia el servidor."));
                state_.SetLastError(UiText("Tor unavailable or the hidden service is not responding.",
                                           "Tor no disponible o hidden service sin respuesta."));
            }
            ApplyStickyAuthError();
            for (int i = 0; i < 50 && !stopRequested_.load(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }

        bannerState_.store(0);
        inHistory_ = false;
        ResetAuthExchange();
        connGeneration_.fetch_add(1);
        reconnectDelaySeconds_.store(0);
        {
            std::lock_guard<std::mutex> lock(socketMutex_);
            socket_ = sock;
        }
        AppendClientLog("NetworkLoop TOR_OK");
        state_.SetConnectionState(ConnState::TOR_READY);
        state_.SetStatusDetail(UiText("Tor channel ready. Waiting for the server banner...",
                                      "Canal Tor listo. Esperando banner del servidor..."));
        state_.ClearLastError();
        ApplyStickyAuthError();
        tlsOnReceiveThread = true;
        ReceiveLoop(sock);
        tlsOnReceiveThread = false;
        CloseCurrentSocket();
        connGeneration_.fetch_add(1);  // aborts uploads still streaming to the old link
        ClearQueuedUploads();
        FailPendingIncomingAttachments("Enlace perdido durante la transferencia del adjunto.");
        // Identity keys live only while logged in; the next login reloads them.
        ClearE2EState(true);
        ResetAuthExchange();
        bannerState_.store(0);
        state_.SetAuthenticated(false);
        state_.SetConnectionState(ConnState::DISCONNECTED);
        state_.SetAuthActionPending(false);
        state_.SetCredentialChangePending(false);
        state_.SetStatusDetail(UiText("Channel closed. Retrying the link...", "Canal cerrado. Reintentando enlace..."));
        AppendClientLog("NetworkLoop DISCONNECTED");
        const int delay = reconnectDelaySeconds_.exchange(0);
        if (delay > 0) {
            AppendClientLog("NetworkLoop reconnect backoff");
            state_.SetStatusDetail(UiText("Retrying the link in " + std::to_string(delay) + " s.",
                                          "Reintento del enlace en " + std::to_string(delay) + " s."));
            ApplyStickyAuthError();
            for (int i = 0; i < delay * 10 && !stopRequested_.load() && !backoffCancel_.load(); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    AppendClientLog("NetworkLoop end");
}
