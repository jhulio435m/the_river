#include "common/net_platform.h"

#include <cstddef>
#include <cstdint>
#include <cerrno>
#include <cstring>
#include <algorithm>
#include <string>

#ifndef _WIN32
#include <fcntl.h>
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace {

constexpr std::uint32_t kFrameMagic = 0x54525631;  // TRV1
constexpr std::size_t kFrameHeaderBytes = 10;
constexpr std::size_t kAbsoluteMaxPayloadBytes = 1024 * 1024;

void StoreU16(char* out, std::uint16_t value) {
    out[0] = static_cast<char>((value >> 8) & 0xff);
    out[1] = static_cast<char>(value & 0xff);
}

void StoreU32(char* out, std::uint32_t value) {
    out[0] = static_cast<char>((value >> 24) & 0xff);
    out[1] = static_cast<char>((value >> 16) & 0xff);
    out[2] = static_cast<char>((value >> 8) & 0xff);
    out[3] = static_cast<char>(value & 0xff);
}

std::uint16_t LoadU16(const char* in) {
    return static_cast<std::uint16_t>(
        (static_cast<unsigned char>(in[0]) << 8) |
        static_cast<unsigned char>(in[1]));
}

std::uint32_t LoadU32(const char* in) {
    return (static_cast<std::uint32_t>(static_cast<unsigned char>(in[0])) << 24) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(in[1])) << 16) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(in[2])) << 8) |
           static_cast<std::uint32_t>(static_cast<unsigned char>(in[3]));
}

}  // namespace

namespace {

enum class IoOutcome { kData, kClosed, kTimeout, kError };

#ifdef _WIN32
bool LastErrorIsInterrupt() { return WSAGetLastError() == WSAEINTR; }
bool LastErrorIsTimeout() {
    const int e = WSAGetLastError();
    return e == WSAETIMEDOUT || e == WSAEWOULDBLOCK;
}
#else
bool LastErrorIsInterrupt() { return errno == EINTR; }
bool LastErrorIsTimeout() { return errno == EAGAIN || errno == EWOULDBLOCK; }
#endif

// One recv() that is restarted when a signal interrupts it. Signals with a
// handler installed without SA_RESTART (and any handler at all while
// SO_RCVTIMEO is set: such recv() calls are never restarted by the kernel, see
// signal(7)) make recv() fail with EINTR; that is not a link failure.
IoOutcome RecvSome(SocketHandle sock, char* data, std::size_t size, std::size_t& got) {
    got = 0;
    while (true) {
        const int received = recv(sock, data, static_cast<int>(size), 0);
        if (received > 0) {
            got = static_cast<std::size_t>(received);
            return IoOutcome::kData;
        }
        if (received == 0) return IoOutcome::kClosed;
        if (LastErrorIsInterrupt()) continue;
        return LastErrorIsTimeout() ? IoOutcome::kTimeout : IoOutcome::kError;
    }
}

// Fills data[0..size). allowedTimeouts: how many SO_RCVTIMEO expiries are
// tolerated before giving up (0: the first timeout fails). idleTimeout is set
// when the very first recv() timed out with nothing read yet.
bool RecvExactImpl(SocketHandle sock, char* data, std::size_t size, int allowedTimeouts, bool* idleTimeout) {
    if (idleTimeout) *idleTimeout = false;
    if (!IsSocketValid(sock) || (data == nullptr && size > 0)) return false;

    std::size_t totalRead = 0;
    int timeouts = 0;
    while (totalRead < size) {
        std::size_t got = 0;
        const IoOutcome outcome = RecvSome(sock, data + totalRead, size - totalRead, got);
        if (outcome == IoOutcome::kData) {
            totalRead += got;
            continue;
        }
        if (outcome == IoOutcome::kTimeout) {
            if (totalRead == 0 && idleTimeout) {
                *idleTimeout = true;
                return false;
            }
            if (++timeouts <= allowedTimeouts) continue;
        }
        return false;
    }
    return true;
}

}  // namespace

bool SendAll(SocketHandle sock, const char* data, std::size_t size) {
    if (!IsSocketValid(sock) || (data == nullptr && size > 0)) return false;

    std::size_t totalSent = 0;
    while (totalSent < size) {
        const std::size_t remaining = size - totalSent;
        const int chunkSize = static_cast<int>(std::min<std::size_t>(remaining, 64 * 1024));
#ifdef _WIN32
        int sent = send(sock,
                        data + totalSent,
                        chunkSize,
                        0);
#else
        int sent = send(sock,
                        data + totalSent,
                        chunkSize,
                        MSG_NOSIGNAL);
#endif
        if (sent < 0 && LastErrorIsInterrupt()) continue;
        // A send timeout (SO_SNDTIMEO) stays fatal: the server relies on it to
        // drop peers that stopped reading.
        if (sent <= 0) return false;
        totalSent += static_cast<std::size_t>(sent);
    }
    return true;
}

bool SendLine(SocketHandle sock, const std::string& line) {
    return SendTextFrame(sock, line);
}

bool RecvExact(SocketHandle sock, char* data, std::size_t size) {
    return RecvExactImpl(sock, data, size, 0, nullptr);
}

bool SetSocketCloseOnExec(SocketHandle sock) {
    if (!IsSocketValid(sock)) return false;
#ifdef _WIN32
    return SetHandleInformation(reinterpret_cast<HANDLE>(sock), HANDLE_FLAG_INHERIT, 0) != 0;
#else
    const int flags = fcntl(sock, F_GETFD);
    if (flags < 0) return false;
    return (flags & FD_CLOEXEC) != 0 || fcntl(sock, F_SETFD, flags | FD_CLOEXEC) == 0;
#endif
}

SocketHandle CreateTcpSocket() {
#if defined(SOCK_CLOEXEC)
    SocketHandle sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (IsSocketValid(sock)) return sock;
#endif
    SocketHandle fallback = socket(AF_INET, SOCK_STREAM, 0);
    if (IsSocketValid(fallback)) SetSocketCloseOnExec(fallback);
    return fallback;
}

bool SendFrame(SocketHandle sock, std::uint16_t type, const std::string& payload) {
    if (payload.size() > kAbsoluteMaxPayloadBytes) return false;

    char header[kFrameHeaderBytes] = {};
    StoreU32(header, kFrameMagic);
    StoreU16(header + 4, type);
    StoreU32(header + 6, static_cast<std::uint32_t>(payload.size()));

    return SendAll(sock, header, sizeof(header)) &&
           (payload.empty() || SendAll(sock, payload.data(), payload.size()));
}

namespace {

RecvStatus RecvFrameImpl(SocketHandle sock, std::uint16_t& type, std::string& payload, std::size_t maxPayloadBytes,
                         int allowedMidFrameTimeouts, bool reportIdleTimeout) {
    payload.clear();
    type = 0;

    char header[kFrameHeaderBytes] = {};
    bool idle = false;
    // cppcheck-suppress bufferAccessOutOfBounds
    if (!RecvExactImpl(sock, header, sizeof(header), allowedMidFrameTimeouts, reportIdleTimeout ? &idle : nullptr))
        return idle ? RecvStatus::kTimeout : RecvStatus::kFailed;

    const std::uint32_t magic = LoadU32(header);
    if (magic != kFrameMagic) return RecvStatus::kFailed;

    type = LoadU16(header + 4);
    const std::uint32_t length = LoadU32(header + 6);
    if (length > maxPayloadBytes || length > kAbsoluteMaxPayloadBytes) return RecvStatus::kFailed;

    payload.assign(length, '\0');
    // cppcheck-suppress bufferAccessOutOfBounds
    if (length != 0 && !RecvExactImpl(sock, &payload[0], payload.size(), allowedMidFrameTimeouts, nullptr))
        return RecvStatus::kFailed;
    return RecvStatus::kOk;
}

}  // namespace

bool RecvFrame(SocketHandle sock, std::uint16_t& type, std::string& payload, std::size_t maxPayloadBytes) {
    return RecvFrameImpl(sock, type, payload, maxPayloadBytes, 0, false) == RecvStatus::kOk;
}

RecvStatus RecvFrameOrTimeout(SocketHandle sock, std::uint16_t& type, std::string& payload,
                              std::size_t maxPayloadBytes, int allowedMidFrameTimeouts) {
    return RecvFrameImpl(sock, type, payload, maxPayloadBytes, allowedMidFrameTimeouts, true);
}

bool SendTextFrame(SocketHandle sock, const std::string& payload) {
    return SendFrame(sock, kFrameTypeText, payload);
}

bool RecvTextFrame(SocketHandle sock, std::string& payload, std::size_t maxPayloadBytes) {
    std::uint16_t type = 0;
    if (!RecvFrame(sock, type, payload, maxPayloadBytes)) return false;
    return type == kFrameTypeText;
}
