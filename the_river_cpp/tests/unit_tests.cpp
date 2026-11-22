// Tests rely on assert() side effects; keep them active in every build type.
#undef NDEBUG
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "common/base64.h"
#include "common/net_platform.h"
#include "common/secure_envelope.h"
#include "common/security_utils.h"

#ifndef _WIN32
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <atomic>
#include <chrono>
#include <thread>
#endif

namespace {

void TestBase64RoundTrip() {
    const std::string input = "The River payload 123";
    const std::string encoded = river::base64::EncodeString(input);

    std::string decoded;
    assert(river::base64::DecodeToString(encoded, decoded));
    assert(decoded == input);
}

void TestSha256Vector() {
    assert(HashPassword("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

void TestPasswordHashRoundTrip() {
    const std::string password = "correct-horse-key";
    const std::string storedHash = MakePasswordHash(password);

    assert(storedHash.rfind("pbkdf2-sha256$", 0) == 0);
    assert(VerifyPasswordHash(password, storedHash));
    assert(!VerifyPasswordHash("wrong-password", storedHash));
}

void TestPasswordVerifier() {
    const std::string password = "another-good-key";
    const std::string storedHash = MakePasswordHash(password);
    const std::vector<std::string> parts = {
        storedHash.substr(0, storedHash.rfind('$'))
    };

    const std::string verifier = DerivePasswordVerifier(password, parts[0]);
    assert(!verifier.empty());
    assert(verifier == storedHash);
}

void TestValidationRules() {
    assert(IsValidUsername("admin_01"));
    assert(!IsValidUsername("ab"));
    assert(!IsValidUsername("bad:name"));

    assert(IsStrongEnoughPassword("twelve-chars1"));
    assert(!IsStrongEnoughPassword("ten-chars1"));
    assert(!IsStrongEnoughPassword("invalid:separator"));
    assert(ConstantTimeEquals("abcdef", "abcdef"));
    assert(!ConstantTimeEquals("abcdef", "abcdeg"));
}

void TestSecureEnvelopeRoundTrip() {
    setenv("THE_RIVER_AES_KEY", "unit-test-key-with-enough-entropy", 1);

    const std::string plainText = "private message body";
    const std::string sealed = river::SealPayload(plainText);
    assert(sealed.rfind("v3|", 0) == 0);

    std::string opened;
    assert(river::OpenPayload(sealed, opened));
    assert(opened == plainText);

    std::string tampered = sealed;
    tampered.back() = tampered.back() == 'A' ? 'B' : 'A';
    assert(!river::OpenPayload(tampered, opened));

    const std::string binaryPlain("abc\0def", 7);
    const std::string binarySealed = river::SealPayloadBinary(binaryPlain);
    assert(binarySealed.rfind("RV4", 0) == 0);
    std::string binaryOpened;
    assert(river::OpenPayloadBinary(binarySealed, binaryOpened));
    assert(binaryOpened == binaryPlain);
}

void TestBinaryFrameRoundTrip() {
#ifndef _WIN32
    int sockets[2] = {-1, -1};
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);

    const std::string payload = "frame payload without newline";
    const bool sent = SendTextFrame(sockets[0], payload);
    if (!sent && errno == EPERM) {
        std::cerr << "skipping frame socket test: send blocked by sandbox\n";
        CloseSocketHandle(sockets[0]);
        CloseSocketHandle(sockets[1]);
        return;
    }
    assert(sent);

    std::string received;
    assert(RecvTextFrame(sockets[1], received, 1024));
    assert(received == payload);

    const std::string binaryPayload("bin\0payload", 11);
    assert(SendFrame(sockets[0], kFrameTypeAttachmentChunk, binaryPayload));
    std::uint16_t frameType = 0;
    std::string framePayload;
    assert(RecvFrame(sockets[1], frameType, framePayload, 1024));
    assert(frameType == kFrameTypeAttachmentChunk);
    assert(framePayload == binaryPayload);

    CloseSocketHandle(sockets[0]);
    CloseSocketHandle(sockets[1]);
#endif
}

#ifndef _WIN32
std::atomic<int> gSignalsHandled{0};
extern "C" void CountSignal(int) { gSignalsHandled.fetch_add(1); }

void SetRecvTimeoutMs(int sock, int ms) {
    timeval tv{};
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    assert(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);
}

// Regression (attachment picker dropped the link): a signal handled without
// SA_RESTART while recv() blocks (e.g. SIGCHLD from the file picker's
// children) makes recv() fail with EINTR. That must not end the frame read,
// neither before a frame nor in the middle of one.
void TestRecvSurvivesSignalInterrupt() {
    int sockets[2] = {-1, -1};
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    SetRecvTimeoutMs(sockets[1], 5000);  // with SO_RCVTIMEO recv() is never auto-restarted

    struct sigaction sa {};
    struct sigaction old {};
    sa.sa_handler = CountSignal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  // no SA_RESTART
    assert(sigaction(SIGUSR1, &sa, &old) == 0);

    const pthread_t reader = pthread_self();
    const std::string payload = "after the interruption";
    std::thread writer([&] {
        // Interrupt the blocked recv() a few times before the frame starts...
        for (int i = 0; i < 3; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            pthread_kill(reader, SIGUSR1);
        }
        // ...and in the middle of it (header first, then the payload).
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        std::string frame;
        {
            int tmp[2] = {-1, -1};
            assert(socketpair(AF_UNIX, SOCK_STREAM, 0, tmp) == 0);
            assert(SendTextFrame(tmp[0], payload));
            char buf[256];
            const ssize_t n = recv(tmp[1], buf, sizeof(buf), 0);
            assert(n > 0);
            frame.assign(buf, static_cast<std::size_t>(n));
            close(tmp[0]);
            close(tmp[1]);
        }
        assert(SendAll(sockets[0], frame.data(), 6));
        for (int i = 0; i < 2; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            pthread_kill(reader, SIGUSR1);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        assert(SendAll(sockets[0], frame.data() + 6, frame.size() - 6));
    });

    std::uint16_t type = 0;
    std::string received;
    const bool ok = RecvFrame(sockets[1], type, received, 1024);
    writer.join();
    assert(gSignalsHandled.load() >= 5);
    assert(ok);
    assert(type == kFrameTypeText);
    assert(received == payload);

    // The tolerant client variant behaves the same.
    gSignalsHandled.store(0);
    std::thread writer2([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        pthread_kill(reader, SIGUSR1);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        assert(SendTextFrame(sockets[0], payload));
    });
    received.clear();
    const RecvStatus status = RecvFrameOrTimeout(sockets[1], type, received, 1024);
    writer2.join();
    assert(gSignalsHandled.load() >= 1);
    assert(status == RecvStatus::kOk);
    assert(received == payload);

    sigaction(SIGUSR1, &old, nullptr);
    CloseSocketHandle(sockets[0]);
    CloseSocketHandle(sockets[1]);
}

// Regression (idle client reconnecting every ~60 s): SO_RCVTIMEO expiring on
// an idle link is reported as kTimeout by the client-side read, the link stays
// usable, and a frame that is merely slow mid-way is waited for. The strict
// RecvFrame (server) keeps treating a timeout as a failure.
void TestRecvTimeoutIsNotFatalForClientRead() {
    int sockets[2] = {-1, -1};
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    SetRecvTimeoutMs(sockets[1], 200);

    std::uint16_t type = 0;
    std::string received;
    assert(RecvFrameOrTimeout(sockets[1], type, received, 1024) == RecvStatus::kTimeout);
    assert(RecvFrameOrTimeout(sockets[1], type, received, 1024) == RecvStatus::kTimeout);
    assert(!RecvFrame(sockets[1], type, received, 1024));  // server semantics unchanged

    // Still usable after the timeouts.
    assert(SendTextFrame(sockets[0], "PING"));
    assert(RecvFrameOrTimeout(sockets[1], type, received, 1024) == RecvStatus::kOk);
    assert(received == "PING");

    // A frame stalled mid-way for ~1 timeout completes when 2 are allowed...
    int tmp[2] = {-1, -1};
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, tmp) == 0);
    assert(SendTextFrame(tmp[0], "slow frame"));
    char buf[64];
    const ssize_t n = recv(tmp[1], buf, sizeof(buf), 0);
    assert(n > 6);
    close(tmp[0]);
    close(tmp[1]);
    assert(SendAll(sockets[0], buf, 4));
    std::thread late([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        assert(SendAll(sockets[0], buf + 4, static_cast<std::size_t>(n) - 4));
    });
    assert(RecvFrameOrTimeout(sockets[1], type, received, 1024, 2) == RecvStatus::kOk);
    late.join();
    assert(received == "slow frame");

    // ...and fails when the stall outlasts the allowance.
    assert(SendAll(sockets[0], buf, 4));
    assert(RecvFrameOrTimeout(sockets[1], type, received, 1024, 0) == RecvStatus::kFailed);

    // A closed link is a failure, not a timeout.
    CloseSocketHandle(sockets[0]);
    int fresh[2] = {-1, -1};
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fresh) == 0);
    SetRecvTimeoutMs(fresh[1], 200);
    close(fresh[0]);
    assert(RecvFrameOrTimeout(fresh[1], type, received, 1024) == RecvStatus::kFailed);
    close(fresh[1]);
    CloseSocketHandle(sockets[1]);
}

// Client sockets are not inherited by the helper processes the client runs.
void TestClientSocketIsCloseOnExec() {
    const SocketHandle sock = CreateTcpSocket();
    assert(IsSocketValid(sock));
    const int flags = fcntl(sock, F_GETFD);
    assert(flags >= 0 && (flags & FD_CLOEXEC) != 0);
    CloseSocketHandle(sock);
}
#endif

}  // namespace

int main() {
    TestBase64RoundTrip();
    TestSha256Vector();
    TestPasswordHashRoundTrip();
    TestPasswordVerifier();
    TestValidationRules();
    TestSecureEnvelopeRoundTrip();
    TestBinaryFrameRoundTrip();
#ifndef _WIN32
    TestRecvSurvivesSignalInterrupt();
    TestRecvTimeoutIsNotFatalForClientRead();
    TestClientSocketIsCloseOnExec();
#endif

    std::cout << "river_unit_tests passed\n";
    return 0;
}
